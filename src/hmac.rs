#![allow(non_snake_case)]
use hash_value::H256;
use ring::digest;
use ring::hmac::{self, SigningKey};

pub fn hmacSha256Sign(key: &[u8], data: &[u8]) -> H256 {
    let sign_key = SigningKey::new(&digest::SHA256, key);
    H256::from(hmac::sign(&sign_key, data).as_ref())
}

pub fn hmacSha256Verify(key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let sign_key = SigningKey::new(&digest::SHA256, key);
    hmac::verify_with_own_key(&sign_key, data, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{hmacSha256Sign, hmacSha256Verify, H256};
    use hex::FromHex;
    // test vector from: https://tools.ietf.org/html/rfc4231
    #[test]
    fn test_hmacSha256Sign() {
        let key = "Jefe";
        let data = "what do ya want for nothing?";
        let expected =
            H256::from("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let actual = hmacSha256Sign(key.as_ref(), data.as_ref());

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_hmacSha256Verify() {
        let key = Vec::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let data = Vec::from_hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
        let sig = Vec::from_hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
            .unwrap();

        assert!(hmacSha256Verify(key.as_ref(), data.as_ref(), sig.as_ref()));
    }
}
