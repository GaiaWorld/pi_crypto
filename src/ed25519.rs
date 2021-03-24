/**
* 基于ed25519椭圆曲线的高效数字签名算法
*/
use crypto::ed25519;
use hash_value::{H256, H512};

/**
* 用于公钥交换
* 
* @param public_key 对方的公钥
* @param private_key 己方的私钥
* @returns 返回用于交换的公钥
*/
#[inline]
pub fn exchange(peer_public_key: &[u8], local_private_key: &[u8]) -> H256 {
	let shared_mont_x = ed25519::exchange(peer_public_key, local_private_key);
    H256::from(shared_mont_x)
}

/**
* 生成ed25519密钥对
* 
* @param seed 生成密钥的随机种子
* @returns 返回私钥和公钥
*/
#[inline]
pub fn keypair(seed: &[u8]) -> (H512, H256)  {
	let (secret, public_key) = ed25519::keypair(seed);
    (H512::from(secret), H256::from(public_key))
}

/**
* 签名
* 
* @param message 待签名的数据
* @param secret_key 私钥
* @returns 返回签名
*/
#[inline]
pub fn sign(message: &[u8], secret_key: &[u8]) -> H512 {
	let signature = ed25519::signature(message, secret_key);
    H512::from(signature)
}

/**
* 验证签名
*
* @param message 签名数据
* @param public_key 公钥
* @param signature 签名
* @returns 返回验证签名是否成功
*/
#[inline]
pub fn verify(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    ed25519::verify(message, public_key, signature)
}	