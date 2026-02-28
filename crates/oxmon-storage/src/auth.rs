use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rand::RngExt;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// 生成一个 32 字节的加密安全随机 token
pub fn generate_token() -> String {
    let token_bytes: [u8; 32] = rand::rng().random();
    general_purpose::STANDARD.encode(token_bytes)
}

/// 使用 bcrypt 对 token 进行哈希
pub fn hash_token(token: &str) -> Result<String> {
    let hash = bcrypt::hash(token, bcrypt::DEFAULT_COST)?;
    Ok(hash)
}

/// 验证 token 是否匹配哈希值
pub fn verify_token(token: &str, hash: &str) -> Result<bool> {
    Ok(bcrypt::verify(token, hash)?)
}

/// Constant-time token comparison to prevent timing side-channel attacks.
/// Always compares all bytes regardless of mismatch position.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    // XOR all bytes, OR into accumulator — constant-time for equal-length inputs
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Token 加密器，使用 AES-256-GCM
pub struct TokenEncryptor {
    key_bytes: Vec<u8>,
}

impl TokenEncryptor {
    /// 从密钥文件加载或自动生成
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let key_path = data_dir.join("token.key");
        let key_bytes = if key_path.exists() {
            std::fs::read(&key_path)?
        } else {
            let rng = SystemRandom::new();
            let mut key = vec![0u8; 32];
            rng.fill(&mut key)
                .map_err(|_| anyhow::anyhow!("Failed to generate encryption key"))?;
            std::fs::write(&key_path, &key)?;
            // Restrict file permissions to owner-only (0600) on Unix
            #[cfg(unix)]
            {
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&key_path, perms)?;
            }
            tracing::info!(path = %key_path.display(), "Generated new token encryption key");
            key
        };

        if key_bytes.len() != 32 {
            anyhow::bail!(
                "Invalid token encryption key length: expected 32 bytes, got {}",
                key_bytes.len()
            );
        }

        Ok(Self { key_bytes })
    }

    /// 加密 token，返回 base64 编码的 nonce + ciphertext
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?;
        let key = LessSafeKey::new(unbound_key);

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        // nonce (12 bytes) + ciphertext + tag
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        Ok(general_purpose::STANDARD.encode(&result))
    }

    /// 解密 base64 编码的 nonce + ciphertext，返回原始 token
    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        let data = general_purpose::STANDARD.decode(encrypted)?;
        if data.len() < NONCE_LEN + aead::AES_256_GCM.tag_len() {
            anyhow::bail!("Encrypted data too short");
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?;
        let key = LessSafeKey::new(unbound_key);

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid nonce"))?;

        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        Ok(String::from_utf8(plaintext.to_vec())?)
    }
}

/// RSA-OAEP 密码加密器，用于登录/改密接口的密码安全传输。
/// 前端用公钥加密 `{"password":"...","timestamp":<unix_secs>}` → Base64，
/// 服务端用私钥解密并校验 timestamp 防重放。
pub struct PasswordEncryptor {
    private_key: RsaPrivateKey,
    public_key_pem: String,
}

/// 加密 payload 内部结构
#[derive(serde::Deserialize)]
struct EncryptedPayload {
    password: String,
    timestamp: i64,
}

/// timestamp 容差（秒）
const TIMESTAMP_TOLERANCE_SECS: i64 = 300;

impl PasswordEncryptor {
    /// 从文件加载或生成 RSA-2048 私钥，存储为 PEM 格式。
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let key_path = data_dir.join("login.key");
        let private_key = if key_path.exists() {
            let pem = std::fs::read_to_string(&key_path)?;
            RsaPrivateKey::from_pkcs8_pem(&pem)
                .map_err(|e| anyhow::anyhow!("Failed to parse login private key: {e}"))?
        } else {
            let mut rng = rand::rng();
            let key = RsaPrivateKey::new(&mut rng, 2048)
                .map_err(|e| anyhow::anyhow!("Failed to generate RSA key: {e}"))?;
            let pem = key
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| anyhow::anyhow!("Failed to encode private key PEM: {e}"))?;
            std::fs::write(&key_path, pem.as_bytes())?;
            #[cfg(unix)]
            {
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&key_path, perms)?;
            }
            tracing::info!(path = %key_path.display(), "Generated new login RSA key pair");
            key
        };

        let public_key = RsaPublicKey::from(&private_key);
        let public_key_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Failed to encode public key PEM: {e}"))?;

        Ok(Self {
            private_key,
            public_key_pem,
        })
    }

    /// 返回 PEM 编码的公钥字符串。
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// 返回 RSA 公钥（用于测试加密）。
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey::from(&self.private_key)
    }

    /// 解密前端传来的 Base64 编码加密密码。
    /// 返回解密后的明文密码。
    pub fn decrypt_password(&self, encrypted_base64: &str) -> Result<String> {
        let ciphertext = general_purpose::STANDARD
            .decode(encrypted_base64)
            .map_err(|e| anyhow::anyhow!("Invalid base64: {e}"))?;

        let padding = Oaep::<Sha256>::new();
        let plaintext = self
            .private_key
            .decrypt(padding, &ciphertext)
            .map_err(|_| anyhow::anyhow!("RSA decryption failed"))?;

        let payload_str = String::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("Decrypted payload is not valid UTF-8"))?;

        let payload: EncryptedPayload = serde_json::from_str(&payload_str)
            .map_err(|_| anyhow::anyhow!("Invalid payload format"))?;

        let now = chrono::Utc::now().timestamp();
        let diff = (now - payload.timestamp).abs();
        if diff > TIMESTAMP_TOLERANCE_SECS {
            anyhow::bail!("Timestamp expired or too far in the future");
        }

        Ok(payload.password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn should_generate_unique_tokens_each_call() {
        let token1 = generate_token();
        let token2 = generate_token();
        assert_ne!(token1, token2);
        assert!(token1.len() > 40); // Base64 encoded 32 bytes
    }

    #[test]
    fn should_verify_token_against_its_hash_and_reject_wrong_token() {
        let token = generate_token();
        let hash = hash_token(&token).unwrap();
        assert!(verify_token(&token, &hash).unwrap());
        assert!(!verify_token("wrong_token", &hash).unwrap());
    }

    #[test]
    fn should_decrypt_to_original_text_after_token_encryption() {
        let dir = TempDir::new().unwrap();
        let enc = TokenEncryptor::load_or_create(dir.path()).unwrap();

        let token = generate_token();
        let encrypted = enc.encrypt(&token).unwrap();

        // 密文不等于原文
        assert_ne!(encrypted, token);

        // 解密后等于原文
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, token);
    }

    #[test]
    fn should_decrypt_with_reloaded_key_when_key_is_persisted() {
        let dir = TempDir::new().unwrap();

        let enc1 = TokenEncryptor::load_or_create(dir.path()).unwrap();
        let token = "test-token-123";
        let encrypted = enc1.encrypt(token).unwrap();

        // 重新加载应使用同一密钥
        let enc2 = TokenEncryptor::load_or_create(dir.path()).unwrap();
        let decrypted = enc2.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, token);
    }

    #[test]
    fn should_fail_decryption_when_using_different_token_key() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();

        let enc1 = TokenEncryptor::load_or_create(dir1.path()).unwrap();
        let enc2 = TokenEncryptor::load_or_create(dir2.path()).unwrap();

        let token = "secret-token";
        let encrypted = enc1.encrypt(token).unwrap();

        // 不同密钥解密应失败
        assert!(enc2.decrypt(&encrypted).is_err());
    }

    /// 用公钥加密密码 payload 的辅助函数（测试用）
    fn encrypt_password_for_test(
        public_key: &RsaPublicKey,
        password: &str,
        timestamp: i64,
    ) -> String {
        let payload = serde_json::json!({
            "password": password,
            "timestamp": timestamp,
        });
        let padding = Oaep::<Sha256>::new();
        let mut rng = rand::rng();
        let ciphertext = public_key
            .encrypt(&mut rng, padding, payload.to_string().as_bytes())
            .expect("encryption should succeed");
        general_purpose::STANDARD.encode(&ciphertext)
    }

    #[test]
    fn should_decrypt_password_to_original_after_rsa_roundtrip() {
        let dir = TempDir::new().unwrap();
        let enc = PasswordEncryptor::load_or_create(dir.path()).unwrap();

        let now = chrono::Utc::now().timestamp();
        let encrypted = encrypt_password_for_test(&enc.public_key(), "my-secret", now);

        let decrypted = enc.decrypt_password(&encrypted).unwrap();
        assert_eq!(decrypted, "my-secret");
    }

    #[test]
    fn should_use_same_rsa_key_pair_after_reload_from_disk() {
        let dir = TempDir::new().unwrap();

        let enc1 = PasswordEncryptor::load_or_create(dir.path()).unwrap();
        let now = chrono::Utc::now().timestamp();
        let encrypted = encrypt_password_for_test(&enc1.public_key(), "persist-test", now);

        // 重新加载应使用同一密钥
        let enc2 = PasswordEncryptor::load_or_create(dir.path()).unwrap();
        let decrypted = enc2.decrypt_password(&encrypted).unwrap();
        assert_eq!(decrypted, "persist-test");
        assert_eq!(enc1.public_key_pem(), enc2.public_key_pem());
    }

    #[test]
    fn should_reject_password_when_timestamp_is_expired() {
        let dir = TempDir::new().unwrap();
        let enc = PasswordEncryptor::load_or_create(dir.path()).unwrap();

        let old_timestamp = chrono::Utc::now().timestamp() - 600; // 10 minutes ago
        let encrypted = encrypt_password_for_test(&enc.public_key(), "expired", old_timestamp);

        let result = enc.decrypt_password(&encrypted);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Timestamp expired"));
    }

    #[test]
    fn should_fail_password_decryption_when_using_different_rsa_key() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();

        let enc1 = PasswordEncryptor::load_or_create(dir1.path()).unwrap();
        let enc2 = PasswordEncryptor::load_or_create(dir2.path()).unwrap();

        let now = chrono::Utc::now().timestamp();
        let encrypted = encrypt_password_for_test(&enc1.public_key(), "wrong-key", now);

        assert!(enc2.decrypt_password(&encrypted).is_err());
    }

    #[test]
    fn should_return_error_when_ciphertext_is_invalid_base64() {
        let dir = TempDir::new().unwrap();
        let enc = PasswordEncryptor::load_or_create(dir.path()).unwrap();

        assert!(enc.decrypt_password("not-valid-base64!!!").is_err());
    }

    #[test]
    fn should_return_valid_pem_encoded_public_key() {
        let dir = TempDir::new().unwrap();
        let enc = PasswordEncryptor::load_or_create(dir.path()).unwrap();

        let pem = enc.public_key_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }
}
