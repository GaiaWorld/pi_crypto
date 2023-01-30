//! ed25519 椭圆曲线算法
//!
//! 使用ed25519进行密钥交换，签名和验证签名

use crypto::ed25519;
use pi_hash_value::{H256, H512};

/// 本地和远程实体进行密钥交换
///
/// peer_public_key: 远程公钥, local_private_key: 本地私钥
#[inline]
pub fn exchange(peer_public_key: &[u8], local_private_key: &[u8]) -> H256 {
    let shared_mont_x = ed25519::exchange(peer_public_key, local_private_key);
    H256::from(shared_mont_x)
}

/// 生成ed25519密钥对
///
/// seed: 种子
#[inline]
pub fn keypair(seed: &[u8]) -> (H512, H256) {
    let (secret, public_key) = ed25519::keypair(seed);
    (H512::from(secret), H256::from(public_key))
}

/// ed25519 签名
///
/// message: 待签名的数据， secret: 私钥， 返回签名结果
#[inline]
pub fn sign(message: &[u8], secret_key: &[u8]) -> H512 {
    let signature = ed25519::signature(message, secret_key);
    H512::from(signature)
}

/// ed25519 签名验证
///
/// message: 签名数据，public_key: 公钥， signature: 签名，返回验证是否成功
#[inline]
pub fn verify(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    ed25519::verify(message, public_key, signature)
}
