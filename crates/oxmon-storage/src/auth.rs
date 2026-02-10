use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// 生成一个 32 字节的加密安全随机 token
pub fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    let token_bytes: [u8; 32] = rng.gen();
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_token() {
        let token1 = generate_token();
        let token2 = generate_token();
        assert_ne!(token1, token2);
        assert!(token1.len() > 40); // Base64 encoded 32 bytes
    }

    #[test]
    fn test_hash_and_verify() {
        let token = generate_token();
        let hash = hash_token(&token).unwrap();
        assert!(verify_token(&token, &hash).unwrap());
        assert!(!verify_token("wrong_token", &hash).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt() {
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
    fn test_encryptor_key_persistence() {
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
    fn test_wrong_key_fails() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();

        let enc1 = TokenEncryptor::load_or_create(dir1.path()).unwrap();
        let enc2 = TokenEncryptor::load_or_create(dir2.path()).unwrap();

        let token = "secret-token";
        let encrypted = enc1.encrypt(token).unwrap();

        // 不同密钥解密应失败
        assert!(enc2.decrypt(&encrypted).is_err());
    }
}
