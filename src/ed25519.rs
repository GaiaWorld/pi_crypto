pub use rcrypto::digest::Digest;
use rcrypto::ed25519;
use hash_value::{H256, H512};

#[inline]
pub fn exchange(public_key: &[u8], private_key: &[u8]) -> H256 {
	let shared_mont_x = ed25519::exchange(public_key, private_key);
    H256::from(shared_mont_x)
}

#[inline]
pub fn keypair(seed: &[u8]) -> (H512, H256)  {
	let (secret, public_key) = ed25519::keypair(seed);
    (H512::from(secret), H256::from(public_key))
}

#[inline]
pub fn sign(message: &[u8], secret_key: &[u8]) -> H512 {
	let signature = ed25519::signature(message, secret_key);
    H512::from(signature)
}

#[inline]
pub fn verify(message: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
    ed25519::verify(message, public_key, signature)
}	