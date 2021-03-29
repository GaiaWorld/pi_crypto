//! aes gcm 模式加解密算法

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};

/// aes_128_gcm 加密算法
///
/// key: 128位
/// nonce: 96位随机数
/// content: 需要加密的内容
/// aad: 辅助数据，一般位空
pub fn aes_128_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    content: Vec<u8>,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    aes_gcm_encrypt(128, key, nonce, content, aad)
}

/// aes_256_gcm 加密算法
///
/// key: 256位
/// nonce: 96位随机数
/// content: 需要加密的内容
/// aad: 辅助数据，一般位空
pub fn aes_256_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    content: Vec<u8>,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    aes_gcm_encrypt(256, key, nonce, content, aad)
}

/// aes_128_gcm 解密算法
///
/// key: 128位
/// nonce: 96位随机数
/// content: 需要解密的内容
/// aad: 辅助数据，一般位空
pub fn aes_128_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    content: Vec<u8>,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    aes_gcm_decrypt(128, key, nonce, content, aad)
}

/// aes_256_gcm 解密算法
///
/// key: 256位
/// nonce: 96位随机数
/// content: 需要解密的内容
/// aad: 辅助数据，一般位空
pub fn aes_256_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    content: Vec<u8>,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    aes_gcm_decrypt(256, key, nonce, content, aad)
}

fn aes_gcm_encrypt(
    security_level: u32,
    key: &[u8],
    nonce: &[u8],
    mut content: Vec<u8>,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|e| e.to_string())?;

    match security_level {
        128 => {
            let less_safe_key =
                LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key).map_err(|e| e.to_string())?);
            match less_safe_key.seal_in_place_append_tag(
                Nonce::from(nonce),
                Aad::from(aad),
                &mut content,
            ) {
                Ok(()) => Ok(content),
                Err(e) => Err(e.to_string()),
            }
        }
        256 => {
            let less_safe_key =
                LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|e| e.to_string())?);
            match less_safe_key.seal_in_place_append_tag(
                Nonce::from(nonce),
                Aad::from(aad),
                &mut content,
            ) {
                Ok(()) => Ok(content),
                Err(e) => Err(e.to_string()),
            }
        }
        _ => {
            unreachable!()
        }
    }
}

fn aes_gcm_decrypt(
    security_level: u32,
    key: &[u8],
    nonce: &[u8],
    mut content: Vec<u8>,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|e| e.to_string())?;

    match security_level {
        128 => {
            let less_safe_key =
                LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key).map_err(|e| e.to_string())?);
            match less_safe_key.open_in_place(nonce, Aad::from(aad), &mut content) {
                Ok(plain_text) => Ok(plain_text.to_vec()),
                Err(e) => Err(e.to_string()),
            }
        }
        256 => {
            let less_safe_key =
                LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|e| e.to_string())?);
            match less_safe_key.open_in_place(nonce, Aad::from(aad), &mut content) {
                Ok(plain_text) => Ok(plain_text.to_vec()),
                Err(e) => Err(e.to_string()),
            }
        }
        _ => {
            unreachable!()
        }
    }
}

#[test]
fn test_aes_gcm() {
    use ring::rand::{SecureRandom, SystemRandom};

    let key = [1u8; 16];
    let content = b"hello world".to_vec();
    let aad = b"".to_vec();

    let rng = SystemRandom::new();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce).map_err(|e| e.to_string()).unwrap();

    let encrypted = aes_128_gcm_encrypt(&key, &nonce, content.clone(), &aad).unwrap();

    let decrypted = aes_128_gcm_decrypt(&key, &nonce, encrypted.clone(), &aad).unwrap();
    assert!(content == decrypted);

    let key = [1u8; 32];

    let encrypted = aes_256_gcm_encrypt(&key, &nonce, content.clone(), &aad).unwrap();
    let decrtyped = aes_256_gcm_decrypt(&key, &nonce, encrypted, &aad).unwrap();

    assert!(content == decrtyped);
}
