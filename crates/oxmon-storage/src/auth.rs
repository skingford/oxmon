use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
