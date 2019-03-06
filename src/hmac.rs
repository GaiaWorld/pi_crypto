#![allow(non_snake_case)]
use ring::digest as rdigest;
use ring::hmac::{self, SigningKey};

pub struct Hmac;

pub enum DigestAlgorithm {
	SHA1,
	SHA256,
	SHA384,
	SHA512,
}

impl Hmac {
    pub fn sign(alg: DigestAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
        match alg {
            DigestAlgorithm::SHA1 => hmac::sign(&SigningKey::new(&rdigest::SHA1, key), data)
                .as_ref()
                .to_vec(),
            DigestAlgorithm::SHA256 => hmac::sign(&SigningKey::new(&rdigest::SHA256, key), data)
                .as_ref()
                .to_vec(),
            DigestAlgorithm::SHA384 => hmac::sign(&SigningKey::new(&rdigest::SHA384, key), data)
                .as_ref()
                .to_vec(),
            DigestAlgorithm::SHA512 => hmac::sign(&SigningKey::new(&rdigest::SHA512, key), data)
                .as_ref()
                .to_vec(),
        }
    }

    pub fn verify(alg: DigestAlgorithm, key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        match alg {
            DigestAlgorithm::SHA1 => {
                hmac::verify_with_own_key(&SigningKey::new(&rdigest::SHA1, key), data, signature)
                    .is_ok()
            }
            DigestAlgorithm::SHA256 => {
                hmac::verify_with_own_key(&SigningKey::new(&rdigest::SHA256, key), data, signature)
                    .is_ok()
            }
            DigestAlgorithm::SHA384 => {
                hmac::verify_with_own_key(&SigningKey::new(&rdigest::SHA384, key), data, signature)
                    .is_ok()
            }
            DigestAlgorithm::SHA512 => {
                hmac::verify_with_own_key(&SigningKey::new(&rdigest::SHA512, key), data, signature)
                    .is_ok()
            }
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use hex::FromHex;
//     // test vector from: https://tools.ietf.org/html/rfc4231
//     #[test]
//     fn test_hmacSha256Sign() {
//         let key = "Jefe";
//         let data = "what do ya want for nothing?";
//         let expected =
//             Vec::from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
//                 .unwrap()
//                 .to_vec();

//         let actual = Hmac::sign(DigestAlgorithm::SHA256, key.as_ref(), data.as_ref()).to_vec();

//         assert_eq!(expected, actual);
//     }

//     #[test]
//     fn test_hmacSha256Verify() {
//         let key = Vec::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
//         let data = Vec::from_hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
//         let sig = Vec::from_hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
//             .unwrap();

//         assert!(Hmac::verify(
//             DigestAlgorithm::SHA256,
//             key.as_ref(),
//             data.as_ref(),
//             sig.as_ref()
//         ));
//     }
// }
