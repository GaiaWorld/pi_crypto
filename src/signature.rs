//! ecdsa, rsa 签名算法

use libsecp256k1::{sign, verify, Message, PublicKey, SecretKey, Signature};
use ring::signature::{
    EcdsaKeyPair as EcKeyPair, KeyPair, RsaKeyPair, RsaPublicKeyComponents, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use ring::{rand, signature};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Hash, PaddingScheme, PublicKey as rsaPubkey, RsaPublicKey};
use simple_asn1::ASN1Block;

/// 基于secp256k1的签名算法对象
pub struct ECDSASecp256k1 {}

impl ECDSASecp256k1 {
    /// 构建基于secp256k1的签名算法对象
    pub fn new() -> Self {
        ECDSASecp256k1 {}
    }

    /// 签名
    ///
    /// msg: 待签名数据，长度为32字节
    /// sk: 私钥，长度为32字节
    pub fn sign(&self, msg: &[u8], sk: &[u8]) -> Vec<u8> {
        let sk = match SecretKey::parse_slice(sk) {
            Ok(sk) => sk,
            Err(e) => {
                println!("decode secret key error = {:?}", e);
                return vec![];
            }
        };
        let msg = match Message::parse_slice(msg) {
            Ok(msg) => msg,
            Err(e) => {
                println!("ecdsa decode msg error = {:?}, msg = {:?}", e, msg);
                return vec![];
            }
        };

        let sig = sign(&msg, &sk);

        sig.0.serialize_der().as_ref().to_vec()
    }

    /// 验证签名
    ///
    /// msg: 已签名数据，长度为32字节
    /// sig: 签名，长度为65~72字节
    /// pk: 公钥，长度为33或65字节
    pub fn verify(&self, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        let msg = match Message::parse_slice(msg) {
            Ok(msg) => msg,
            Err(e) => {
                println!("ecdsa decode msg error = {:?}, msg = {:?}", e, msg);
                return false;
            }
        };
        let pk = match PublicKey::parse_slice(pk, None) {
            Ok(pk) => pk,
            Err(e) => {
                println!("ecdsa decode publick key error = {:?}, pk = {:?}", e, pk);
                return false;
            }
        };
        let sig = match Signature::parse_der(sig) {
            Ok(sig) => sig,
            Err(e) => {
                println!("ecdsa decode sig error = {:?}, sig = {:?}", e, sig);
                return false;
            }
        };

        verify(&msg, &sig, &pk)
    }
}

/// RSA签名算法填充类型
pub enum PaddingAlg {
    /// PKCS
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,

    /// Probabilistic signature scheme
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
}

/// RSA签名算法对象
pub struct Rsa {
    ctx: RsaKeyPair,
}

impl Rsa {
    /// 从PKCS8格式的密钥数据生成RSA签名算法对象
    ///
    /// input: PKCS8格式的密钥数据
    pub fn fromPKCS8(input: &[u8]) -> Result<Rsa, String> {
        match RsaKeyPair::from_pkcs8(input) {
            Ok(ctx) => Ok(Rsa { ctx }),
            Err(e) => Err(e.description_().to_string()),
        }
    }

    /**
     * 获取RSA公钥
     * @returns 返回RSA公钥
     */
    pub fn public_key(&self) -> Vec<u8> {
        self.ctx.public_key().as_ref().to_vec()
    }

    /// 使用当前RSA签名算法对象和指定的RSA签名算法填充类型，对指定的数据进行签名
    ///
    /// padAlg: RSA签名算法填充类型
    /// msg: 待签名的数据
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

    /// 验证使用指定的RSA签名算法填充类型和指定的RSA公钥的签名
    ///
    /// padAlg: RSA签名算法填充类型
    /// msg: 已签名的数据
    /// sig: 签名
    /// pk: RSA公钥
    pub fn verify(padAlg: PaddingAlg, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        match padAlg {
            PaddingAlg::RSA_PKCS1_SHA256 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pk)
                    .verify(msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PKCS1_SHA384 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA384, pk)
                    .verify(msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PKCS1_SHA512 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA512, pk)
                    .verify(msg, sig)
                    .is_ok()
            }

            PaddingAlg::RSA_PSS_SHA256 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, pk)
                    .verify(msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PSS_SHA384 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA384, pk)
                    .verify(msg, sig)
                    .is_ok()
            }
            PaddingAlg::RSA_PSS_SHA512 => {
                signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA512, pk)
                    .verify(msg, sig)
                    .is_ok()
            }
        }
    }

    /// 验证alipy签名
    ///
    /// msg: 签名的数据
    /// sig: 签名
    /// pk: 公钥
    pub fn alipay_verify(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        let blocks = match simple_asn1::from_der(&pk) {
            Ok(blocks) => blocks,
            Err(_) => {
                println!("malformed public key");
                return false;
            }
        };
        let mut bit_strings = Vec::new();
        find_bit_string(&blocks, &mut bit_strings);
        if let Some(bs) = bit_strings.first() {
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, bs)
                .verify(msg, &sig)
                .is_ok()
        } else {
            false
        }
    }

    /// 验证SHA1WithRSA签名
    ///
    /// msg: 签名的数据
    /// sig: 签名
    /// pk: 公钥
    pub fn sha1withrsa_verify(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        if let Ok(public_key) = RsaPublicKey::from_public_key_der(&pk) {
            public_key
                .verify(
                    PaddingScheme::PKCS1v15Sign {
                        hash: Option::from(Hash::SHA1),
                    },
                    &msg,
                    &sig,
                )
                .is_ok()
        } else {
            false
        }

    }
}

fn find_bit_string(blocks: &[ASN1Block], mut result: &mut Vec<Vec<u8>>) {
    for block in blocks.iter() {
        match block {
            ASN1Block::BitString(_, _, bytes) => result.push(bytes.to_vec()),
            ASN1Block::Sequence(_, blocks) => find_bit_string(&blocks[..], &mut result),
            _ => (),
        }
    }
}

/// NIST曲线, P256 和 p384
#[derive(Debug)]
pub enum EcdsaAlg {
    // Signing of ASN.1 DER-encoded ECDSA signatures using the P-256 curve and SHA-256.
    ECDSA_P256_SHA256_ASN1,
    // Signing of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and SHA-384.
    ECDSA_P384_SHA384_ASN1,
}

pub struct EcdsaKeyPair {
    key_pair: EcKeyPair,
}

impl EcdsaKeyPair {
    /// 产生pkcs8格式的密钥对
    ///
    /// alg: 产生密钥对的曲线类型
    pub fn generate_pkcs8(alg: EcdsaAlg) -> Vec<u8> {
        let rng = rand::SystemRandom::new();
        match alg {
            EcdsaAlg::ECDSA_P256_SHA256_ASN1 => {
                signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .unwrap()
                    .as_ref()
                    .to_vec()
            }
            EcdsaAlg::ECDSA_P384_SHA384_ASN1 => {
                signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
                    .unwrap()
                    .as_ref()
                    .to_vec()
            }
        }
    }

    /// 从私钥和公钥构建密钥对
    ///
    /// alg: 产生密钥对的曲线类型
    /// priv_key: 私钥
    /// pub_key: 公钥
    pub fn from_private_key_and_public_key(alg: EcdsaAlg, priv_key: &[u8], pub_key: &[u8]) -> Self {
        match alg {
            EcdsaAlg::ECDSA_P256_SHA256_ASN1 => {
                let key_pair = EcKeyPair::from_private_key_and_public_key(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    priv_key,
                    pub_key,
                )
                .unwrap();
                Self { key_pair }
            }
            EcdsaAlg::ECDSA_P384_SHA384_ASN1 => {
                let key_pair = EcKeyPair::from_private_key_and_public_key(
                    &ECDSA_P384_SHA384_ASN1_SIGNING,
                    priv_key,
                    pub_key,
                )
                .unwrap();
                Self { key_pair }
            }
        }
    }

    /// 从pkcs8格式构建密钥对
    ///
    /// alg: 产生密钥对的曲线类型
    /// pkcs: pkcs格式的私钥
    pub fn from_pkcs8(alg: EcdsaAlg, pkcs8: &[u8]) -> Self {
        let key_pair = match alg {
            EcdsaAlg::ECDSA_P256_SHA256_ASN1 => {
                signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8).unwrap()
            }
            EcdsaAlg::ECDSA_P384_SHA384_ASN1 => {
                signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8).unwrap()
            }
        };
        Self { key_pair }
    }

    /// 签名
    ///
    /// msg: 签名数据
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = rand::SystemRandom::new();
        self.key_pair.sign(&rng, msg).unwrap().as_ref().to_vec()
    }

    /// 获取公钥
    pub fn public_key(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }
}

/// 验证ecdsa签名
///
/// alg: 产生密钥对的曲线类型
/// pub_key: 公钥
/// msg: 签名的数据
/// sig: 签名
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
        Err(_) => false,
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
        assert!(Rsa::verify(
            PaddingAlg::RSA_PKCS1_SHA256,
            MESSAGE,
            &sig,
            &pk
        ));
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

        let verify_result = ecdsa_verify(
            EcdsaAlg::ECDSA_P256_SHA256_ASN1,
            key_pair.public_key().as_ref(),
            &msg,
            &sig,
        );
        assert_eq!(verify_result, true);
    }

    #[test]
    fn test_alipay_verify() {
        let msg = br#"app_id=2018101761712502&auth_app_id=2018101761712502&buyer_id=2088202466133777&buyer_logon_id=446***@qq.com&buyer_pay_amount=0.01&charset=utf-8&fund_bill_list=[{"amount":"0.01","fundChannel":"ALIPAYACCOUNT"}]&gmt_create=2020-08-31 16:16:23&gmt_payment=2020-08-31 16:16:24&invoice_amount=0.01&notify_id=2020083100222161625033771438477577&notify_time=2020-08-31 16:16:25&notify_type=trade_status_sync&out_trade_no=104783005432152064&point_amount=0.00&receipt_amount=0.01&seller_email=register@kupay.io&seller_id=2088231960756623&subject=test&total_amount=0.01&trade_no=2020083122001433771402548536&trade_status=TRADE_SUCCESS&version=1.0"#;
        let pk = base64::decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAshixpgMR0jue/F2Wkq9Sf7Srd68uV9iJjfLMEuNl6iI8p3bp8zLkQd0hicm8oN7+L2SNstblROIpSNhBFPmCnl5wNLcsTZ04xNcmBbZKWZskrUVyQoiZ4haQQ2EQa7ScQlMHoupFMSxJVkFNznndjgVEOYzvonxfDPYWAtZ/6JhFKCJyh7WWMZEY5N+itx6nrSlq6Y9a54uOpUNdpontLnZ/Lh4TWC99Wwnt1cWxoL3wqodOp671FBlKXvhJb6y/p1oWBGSpXoxaFINpdNzTEhi5QgSFS4NwLVTO0fX7/2oxJDbJZhIdYoX7uOoweahyfCbUNZ+hBrVO3taTfZV91QIDAQAB").unwrap();
        let sig = base64::decode("WZlREg2BUvHZMhXRrbj1PBUqpyI4T0BPWOSeEW3BqYYSICMbIKXrXvdESBWtnjvrUEsu27Sq9LTbXG5fA4P+q6AK7oofxd0NfGtxGFR3h9y9T/w8oxkSAcnEmTbUM6RD7BTtUF9d9L3uHswRdMgygwEUscEdk1xs9/dzGhZAFK1g3wYKtVOaYyO2N78fAQ/Ro/THYZgAoTlEIFz2Yeyyy+dp9jObOQ3lgtgg0qGUtdT23PeSVsXjai0PWoThQmgRucrptxWagLsbvwirYpaYfbetjq+Rxn5mr1VwXgEjkL1Yeb5hb917QGDFHyG2rNS38m/XZ1Wjs1uHo2JXcnEWIA==").unwrap();

        assert!(Rsa::alipay_verify(msg, &sig, &pk))
    }
}
