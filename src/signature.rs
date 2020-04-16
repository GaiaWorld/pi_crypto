/**
* 基于secp256k1的签名算法
*/
use secp256k1::{Message, sign, SecretKey, PublicKey, Signature, verify};

use ring::signature::{KeyPair, RsaKeyPair, EcdsaKeyPair as EcKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1};
use ring::{rand, signature};

/**
* 基于secp256k1的签名算法对象
*/
pub struct ECDSASecp256k1 {

}

impl ECDSASecp256k1 {
    /**
    * 构建基于secp256k1的签名算法对象
    * @returns 返回基于secp256k1的签名算法对象
    */
    pub fn new() -> Self {
        ECDSASecp256k1 {

        }
    }

    /**
    * 签名
    * @param msg 待签名数据，长度为32字节
    * @param sk 私钥，长度为32字节
    * @returns 返回签名
    */
    pub fn sign(&self, msg: &[u8], sk: &[u8]) -> Vec<u8> {
        let sk = match SecretKey::parse_slice(sk) {
            Ok(sk) => sk,
            Err(e) => {
                println!("decode secret key error = {:?}", e);
                return vec![]
            }
        };
        let msg = match Message::parse_slice(msg) {
            Ok(msg) => msg,
            Err(e) => {
                println!("ecdsa decode msg error = {:?}, msg = {:?}", e, msg);
                return vec![]
            }
        };

        let sig = sign(&msg, &sk);

        sig.0.serialize_der().as_ref().to_vec()
    }

    /**
    * 验证签名
    * @param msg 已签名数据，长度为32字节
    * @param sig 签名，长度为65~72字节
    * @param pk 公钥，长度为33或65字节
    * @returns 返回验证签名是否成功
    */
    pub fn verify(&self, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        let msg = match Message::parse_slice(msg) {
            Ok(msg) => msg,
            Err(e) => {
                println!("ecdsa decode msg error = {:?}, msg = {:?}", e, msg);
                return false
            }
        };
        let pk = match PublicKey::parse_slice(pk, None) {
            Ok(pk) => pk,
            Err(e) => {
                println!("ecdsa decode publick key error = {:?}, pk = {:?}", e, pk);
                return false
            }
        };
        let sig = match Signature::parse_der(sig) {
            Ok(sig) => sig,
            Err(e) => {
                println!("ecdsa decode sig error = {:?}, sig = {:?}", e, sig);
                return false
            }
        };

        verify(&msg, &sig, &pk)
    }
}

/**
* RSA签名算法填充类型
*/
pub enum PaddingAlg {
    // PKCS
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,

    // Probabilistic signature scheme
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
}

/**
* RSA签名算法对象
*/
pub struct Rsa {
    ctx: RsaKeyPair,
}

impl Rsa {
    /**
    * 从PKCS8格式的密钥数据生成RSA签名算法对象
    * @param input PKCS8格式的密钥数据
    * @returns 返回RSA签名算法对象
    */
    pub fn fromPKCS8(input: &[u8]) -> Rsa {
        Rsa {
            ctx: RsaKeyPair::from_pkcs8(input).unwrap(),
        }
    }

    /**
    * 获取RSA公钥
    * @returns 返回RSA公钥
    */
    pub fn public_key(&self) -> Vec<u8> {
        self.ctx.public_key().as_ref().to_vec()
    }

    /**
    * 使用当前RSA签名算法对象和指定的RSA签名算法填充类型，对指定的数据进行签名
    * @param padAlg RSA签名算法填充类型
    * @param msg 待签名的数据
    * @returns 签名
    */
    pub fn sign(&self, padAlg: PaddingAlg, msg: &[u8]) -> Vec<u8> {
        let mut signature = vec![0; self.ctx.public_modulus_len()];
        let rng = rand::SystemRandom::new();

        match padAlg {
            PaddingAlg::RSA_PKCS1_SHA256 => {
                let _ = self
                    .ctx
                    .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut signature)
                    .unwrap();
            }
            PaddingAlg::RSA_PKCS1_SHA384 => {
                let _ = self
                    .ctx
                    .sign(&signature::RSA_PKCS1_SHA384, &rng, msg, &mut signature);
            }
            PaddingAlg::RSA_PKCS1_SHA512 => {
                let _ = self
                    .ctx
                    .sign(&signature::RSA_PKCS1_SHA512, &rng, msg, &mut signature);
            }

            PaddingAlg::RSA_PSS_SHA256 => {
                let _ = self
                    .ctx
                    .sign(&signature::RSA_PSS_SHA256, &rng, msg, &mut signature);
            }
            PaddingAlg::RSA_PSS_SHA384 => {
                let _ = self
                    .ctx
                    .sign(&signature::RSA_PSS_SHA384, &rng, msg, &mut signature);
            }
            PaddingAlg::RSA_PSS_SHA512 => {
                let _ = self
                    .ctx
                    .sign(&signature::RSA_PSS_SHA512, &rng, msg, &mut signature);
            }
        }
        signature
    }

    /**
    * 验证使用指定的RSA签名算法填充类型和指定的RSA公钥的签名
    * @param padAlg RSA签名算法填充类型
    * @param msg 已签名的数据
    * @param sig 签名
    * @param pk RSA公钥
    * @returns 返回验证签名是否成功
    */
    pub fn verify(&self, padAlg: PaddingAlg, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        match padAlg {
            PaddingAlg::RSA_PKCS1_SHA256 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pk).verify(msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PKCS1_SHA384 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA384, pk).verify(msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PKCS1_SHA512 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA512, pk).verify(msg, sig)
                    .is_ok()
            }

            PaddingAlg::RSA_PSS_SHA256 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, pk).verify(msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PSS_SHA384 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA384, pk).verify(msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PSS_SHA512 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA512, pk).verify(msg, sig)
                    .is_ok()
            }
        }
    }
}

// NIST曲线, P256 和 p384
#[derive(Debug)]
pub enum EcdsaAlg {
    // Signing of ASN.1 DER-encoded ECDSA signatures using the P-256 curve and SHA-256.
    ECDSA_P256_SHA256_ASN1,
    // Signing of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and SHA-384.
    ECDSA_P384_SHA384_ASN1,
}

pub struct EcdsaKeyPair {
    key_pair: EcKeyPair
}

impl EcdsaKeyPair {
    // 产生pkcs8格式的密钥对
    pub fn generate_pkcs8(alg: EcdsaAlg) -> Vec<u8> {
        let rng = rand::SystemRandom::new();
        match alg {
            EcdsaAlg::ECDSA_P256_SHA256_ASN1 => {
                signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap().as_ref().to_vec()
            },
            EcdsaAlg::ECDSA_P384_SHA384_ASN1 => {
                signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap().as_ref().to_vec()
            },
        }
    }

    // 从私钥和公钥构建密钥对
    pub fn from_private_key_and_public_key(alg: EcdsaAlg, priv_key: &[u8], pub_key: &[u8]) -> Self {
        match alg {
            EcdsaAlg::ECDSA_P256_SHA256_ASN1 => {
                let key_pair = EcKeyPair::from_private_key_and_public_key(&ECDSA_P256_SHA256_ASN1_SIGNING, priv_key, pub_key).unwrap();
                Self {
                    key_pair
                }
            }
            EcdsaAlg::ECDSA_P384_SHA384_ASN1 => {
                let key_pair = EcKeyPair::from_private_key_and_public_key(&ECDSA_P384_SHA384_ASN1_SIGNING, priv_key, pub_key).unwrap();
                Self {
                    key_pair
                }
            }
        }
    }

    // 从pkcs8格式构建密钥对
    pub fn from_pkcs8(alg: EcdsaAlg, pkcs8: &[u8]) -> Self {
        let key_pair = match alg {
            EcdsaAlg::ECDSA_P256_SHA256_ASN1 => {
                signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8).unwrap()
            },
            EcdsaAlg::ECDSA_P384_SHA384_ASN1 => {
                signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8).unwrap()
            }
        };
        Self {
            key_pair
        }
    }

    // 签名
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = rand::SystemRandom::new();
        self.key_pair.sign(&rng, msg).unwrap().as_ref().to_vec()
    }

    // 取得公钥
    pub fn public_key(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }
}

// 验证签名
pub fn ecdsa_verify(alg: EcdsaAlg, pub_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let public_key = match alg {
        EcdsaAlg::ECDSA_P256_SHA256_ASN1 => {
            signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pub_key)
        }
        EcdsaAlg::ECDSA_P384_SHA384_ASN1 => {
            signature::UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pub_key)
        }
    };

    match public_key.verify(msg, sig) {
        Ok(()) => true,
        Err(_) => false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn test_secp256k1() {
        let sk = Vec::from_hex("16346fd1da236f810202853a3dc505d92b6b8597c15fd463e4e4494d8fc6a708")
            .unwrap();
        let pk = Vec::from_hex("044fbd4994b6c1d5790000fa0fdfe3afb1f5f3d2a4e78c3daac4c9176d020c5ca85c9a683154c43d0ce4ea0a43c3863875e27c0ea4a087dd5ef6615d41fc9c5b40").unwrap();
        let msg = [0xcd; 32];

        let secp = ECDSASecp256k1::new();

        let sig = secp.sign(&msg, &sk);
        assert!(secp.verify(&msg, &sig, pk.as_ref()));
    }

    #[test]
    fn test_rsa() {
        const MESSAGE: &[u8] = b"hello, world";
        let sk = include_bytes!("../tests/rsa-2048-private-key.pk8");
        let rsa = Rsa::fromPKCS8(sk);
        let pk = rsa.public_key();
        let sig = rsa.sign(PaddingAlg::RSA_PKCS1_SHA256, MESSAGE);
        assert!(rsa.verify(PaddingAlg::RSA_PKCS1_SHA256, MESSAGE, &sig, &pk));
    }

    #[test]
    fn test_ecdsa() {
        let msg = [97, 98, 99]; // "abc"
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(EcdsaAlg::ECDSA_P256_SHA256_ASN1);
        println!("pkcs8 bytes = {:?}", pkcs8_bytes);
        let key_pair = EcdsaKeyPair::from_pkcs8(EcdsaAlg::ECDSA_P256_SHA256_ASN1, &pkcs8_bytes);
        let sig = key_pair.sign(&msg);
        println!("sig = {:?}", sig);
        println!("pub key = {:?}", key_pair.public_key());

        let verify_result = ecdsa_verify(EcdsaAlg::ECDSA_P256_SHA256_ASN1, key_pair.public_key().as_ref(), &msg, &sig);
        assert_eq!(verify_result, true);
    }
}
