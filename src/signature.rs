/**
* 基于secp256k1的签名算法
*/
use secp256k1::key::PublicKey;
use secp256k1::key::SecretKey;
use secp256k1::{Message, Secp256k1, Signature};

use ring::signature::{KeyPair, RsaKeyPair};
use ring::{rand, signature};
use untrusted::Input;

/**
* 基于secp256k1的签名算法对象
*/
pub struct ECDSASecp256k1 {
    ctx: Secp256k1,
}

impl ECDSASecp256k1 {
    /**
    * 构建基于secp256k1的签名算法对象
    * @returns 返回基于secp256k1的签名算法对象
    */
    pub fn new() -> Self {
        ECDSASecp256k1 {
            ctx: Secp256k1::new(),
        }
    }

    /**
    * 签名
    * @param msg 待签名数据，长度为32字节
    * @param sk 私钥，长度为32字节
    * @returns 返回签名
    */
    pub fn sign(&self, msg: &[u8], sk: &[u8]) -> Vec<u8> {
        let sk = SecretKey::from_slice(&self.ctx, sk).unwrap();
        let msg = Message::from_slice(msg).unwrap();

        self.ctx.sign(&msg, &sk).unwrap().serialize_der(&self.ctx)
    }

    /**
    * 验证签名
    * @param msg 已签名数据，长度为32字节
    * @param sig 签名，长度为65~72字节
    * @param pk 公钥，长度为33或65字节
    * @returns 返回验证签名是否成功
    */
    pub fn verify(&self, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        let msg = Message::from_slice(msg).unwrap();
        let pk = PublicKey::from_slice(&self.ctx, pk).unwrap();
        let sig = Signature::from_der(&self.ctx, sig).unwrap();

        self.ctx.verify(&msg, &sig, &pk).is_ok()
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
        let input = Input::from(input);

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
        let public_key = Input::from(pk);
        let sig = Input::from(sig);
        let msg = Input::from(msg);

        match padAlg {
            PaddingAlg::RSA_PKCS1_SHA256 => {
                signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256, public_key, msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PKCS1_SHA384 => {
                signature::verify(&signature::RSA_PKCS1_2048_8192_SHA384, public_key, msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PKCS1_SHA512 => {
                signature::verify(&signature::RSA_PKCS1_2048_8192_SHA512, public_key, msg, sig)
                    .is_ok()
            }

            PaddingAlg::RSA_PSS_SHA256 => {
                signature::verify(&signature::RSA_PSS_2048_8192_SHA256, public_key, msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PSS_SHA384 => {
                signature::verify(&signature::RSA_PSS_2048_8192_SHA384, public_key, msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PSS_SHA512 => {
                signature::verify(&signature::RSA_PSS_2048_8192_SHA512, public_key, msg, sig)
                    .is_ok()
            }
        }
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
}
