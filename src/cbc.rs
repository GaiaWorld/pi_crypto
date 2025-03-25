use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use std::error::Error;
use std::convert::TryInto;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

// 定义一个函数，用于AES-128-CBC-PKCS7解密
pub fn aes_128_cbc_pkcs7_dec(
    // 密钥
    key: &[u8],
    // 加密数据
    encrypted_data: &[u8],
    // 初始化向量
    iv: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    // 将密钥转换为16字节的数组
    let mut key: [u8; 16] = key.try_into().map_err(|_| "key must be 16 bytes")?;

    // 将初始化向量转换为16字节的数组
    let iv: [u8; 16] = iv.try_into().map_err(|_| "IV must be 16 bytes")?;

    // 创建一个AES-128-CBC解密器
    let cipher = Aes128CbcDec::new(&key.into(), &iv.into());
    // 将加密数据转换为可变向量
    let mut buf = encrypted_data.to_vec();
    // 解密数据
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    // 返回解密后的数据
    Ok(decrypted.into())
}
