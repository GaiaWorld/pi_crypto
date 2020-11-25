use jsonwebtoken::{EncodingKey, DecodingKey, Algorithm};
use jsonwebtoken::crypto::{sign, verify};

#[derive(Debug)]
pub enum JwtAlg {
    HS256,
    HS384,
    HS512,
    ES256,
    ES384,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
}

#[derive(Debug, Clone)]
pub struct SignKey {
    jwt_key_type: JwtKeyType,
    bin: Option<Vec<u8>>,
    string: Option<String>
}

impl SignKey {
    pub fn from_secret(secret: &[u8],) -> Self {
        Self {
            jwt_key_type: JwtKeyType::HMAC,
            bin: Some(secret.to_vec()),
            string: None
        }
    }

    pub fn from_base64_secret(secret: &str) -> Self {
        Self {
            jwt_key_type: JwtKeyType::HMAC_BASE64,
            bin: None,
            string: Some(secret.to_string())
        }
    }

    pub fn from_rsa_pem(key: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::RSA_PEM,
            bin: Some(key.to_vec()),
            string: None
        }
    }

    pub fn from_rsa_der(key: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::RSA_DER,
            bin: Some(key.to_vec()),
            string: None
        }
    }

    pub fn from_ec_pem(key: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::EC_PEM,
            bin: Some(key.to_vec()),
            string: None
        }
    }

    pub fn from_ec_der(key: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::EC_DER,
            bin: Some(key.to_vec()),
            string: None
        }
    }

}

#[derive(Debug)]
pub struct VerifyKey {
    jwt_key_type: JwtKeyType,
    bin: Option<Vec<u8>>,
    string: Option<String>
}

impl VerifyKey {
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::HMAC,
            bin: Some(secret.to_vec()),
            string: None
        }
    }

    pub fn from_base64_secret(secret: &str) -> Self {
        Self {
            jwt_key_type: JwtKeyType::HMAC_BASE64,
            bin: None,
            string: Some(secret.to_string())
        }
    }

    pub fn from_rsa_components(n: &str, e: &str) -> Self {
        Self {
            jwt_key_type: JwtKeyType::RSA_N_E,
            bin: None,
            string: Some([n, e].join(":"))
        }
    }

    pub fn from_rsa_pem(key: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::RSA_PEM,
            bin: Some(key.to_vec()),
            string: None
        }
    }

    pub fn from_rsa_der(key: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::RSA_DER,
            bin: Some(key.to_vec()),
            string: None
        }
    }

    pub fn from_ec_pem(key: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::EC_PEM,
            bin: Some(key.to_vec()),
            string: None
        }
    }

    pub fn from_ec_der(key: &[u8]) -> Self {
        Self {
            jwt_key_type: JwtKeyType::EC_DER,
            bin: Some(key.to_vec()),
            string: None
        }
    }
}

fn sign_internal(msg: &str, sk: SignKey, alg: Algorithm) -> Result<String, String> {
    let encoding_key = match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            match sk.jwt_key_type {
                JwtKeyType::HMAC => EncodingKey::from_secret(sk.bin.as_ref().unwrap()),
                JwtKeyType::HMAC_BASE64 => EncodingKey::from_base64_secret(sk.string.as_ref().unwrap()).unwrap(),
                _ => return  Err("HMAC sign key can't derive from other methods".to_string())
            }
        }

        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            match sk.jwt_key_type {
                JwtKeyType::RSA_PEM =>  EncodingKey::from_rsa_pem(sk.bin.as_ref().unwrap()).unwrap(),
                JwtKeyType::RSA_DER => EncodingKey::from_rsa_der(sk.bin.as_ref().unwrap()),
                _ => return Err("RSA sign key can't derive from other methods".to_string())
            }
        }

        Algorithm::ES256 | Algorithm::ES384 => {
           match sk.jwt_key_type {
               JwtKeyType::EC_PEM => EncodingKey::from_ec_pem(sk.bin.as_ref().unwrap()).unwrap(),
               JwtKeyType::EC_DER => EncodingKey::from_ec_der(sk.bin.as_ref().unwrap()),
               _ => return Err("Elliptic sign key can't derive from other methods".to_string())
           }
        }

        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
            return Err("unimplemented sign key for PS algorithm".to_string())
        }
    };

    sign(msg, &encoding_key, alg).map_err(|e|e.to_string())
}

/**
* Jwt 签名
*
* @param msg base64 url safe 编码的待签名字符串, 形式为："header.payload"
* @param sk 签名密钥
* @param alg 指定使用的签名算法，当前可以使用 Hmac, Rsa 和 Ec 算法
* @param signature 签名
* @returns 失败时返回空字符串，成功时返回签名后的字符串
*/
pub fn jwt_sign(msg: &str, sk: SignKey, alg: JwtAlg) -> String {
    let sig = match alg {
        JwtAlg::HS256 => sign_internal(msg, sk, Algorithm::HS256),
        JwtAlg::HS384 => sign_internal(msg, sk, Algorithm::HS384),
        JwtAlg::HS512 => sign_internal(msg, sk, Algorithm::HS512),
        JwtAlg::ES256 => sign_internal(msg, sk, Algorithm::ES256),
        JwtAlg::ES384 => sign_internal(msg, sk, Algorithm::ES384),
        JwtAlg::RS256 => sign_internal(msg, sk, Algorithm::RS256),
        JwtAlg::RS384 => sign_internal(msg, sk, Algorithm::RS384),
        JwtAlg::RS512 => sign_internal(msg, sk, Algorithm::RS512),
        JwtAlg::PS256 => sign_internal(msg, sk, Algorithm::PS256),
        JwtAlg::PS384 => sign_internal(msg, sk, Algorithm::PS384),
        JwtAlg::PS512 => sign_internal(msg, sk, Algorithm::PS512),
    };

    match sig {
        Ok(sig) => sig,
        Err(e) => {
            println!("jwt sign failed ---- msg = {:?}, alg = {:?}, error = {:?}", msg, alg, e.to_string());
            "".to_string()
        }
    }
}

fn verify_internal(sig: &str, msg: &str, vk: &VerifyKey, alg: Algorithm) -> Result<bool, String> {
    let decoding_key = match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            match vk.jwt_key_type {
                JwtKeyType::HMAC => DecodingKey::from_secret(vk.bin.as_ref().unwrap()),
                JwtKeyType::HMAC_BASE64 => DecodingKey::from_base64_secret(vk.string.as_ref().unwrap()).unwrap(),
                _ => return  Err("HMAC verify key can't derive from other methods".to_string())
            }
        }

        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            match vk.jwt_key_type {
                JwtKeyType::RSA_PEM => DecodingKey::from_rsa_pem(vk.bin.as_ref().unwrap()).unwrap(),
                JwtKeyType::RSA_DER => DecodingKey::from_rsa_der(vk.bin.as_ref().unwrap()),
                JwtKeyType::RSA_N_E => {
                    let rsa_pub_key = vk.string.as_ref().unwrap().split(":").collect::<Vec<&str>>();
                    DecodingKey::from_rsa_components(rsa_pub_key[0], rsa_pub_key[1])
                }
                _ => return  Err("RSA verify key can't derive from other methods".to_string())
            }
        }

        Algorithm::ES256 | Algorithm::ES384 => {
            match vk.jwt_key_type {
                JwtKeyType::EC_PEM => DecodingKey::from_ec_pem(vk.bin.as_ref().unwrap()).unwrap(),
                JwtKeyType::EC_DER => DecodingKey::from_ec_der(vk.bin.as_ref().unwrap()),
                _ => return  Err("Elliptic verify key can't derive from other methods".to_string())
            }
        }

        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
            return Err("unimplemented verify key for PS algorithm".to_string())
        }
    };
    verify(sig, msg, &decoding_key, alg).map_err(|e| e.to_string())
}

/**
* Jwt 验证签名
*
* @param sig 签名的base64字符串
* @param msg base64 url safe 编码的待签名字符串, 形式为： "header.payload"
* @param vk 验证签名的公钥
* @param alg 指定使用的签名算法，当前可以使用 Hmac, Rsa 和 Ec 算法
* @returns 成功返回 true, 失败返回 false
*/
pub fn jwt_verify(sig: &str, msg: &str, vk: &VerifyKey, alg: JwtAlg) -> bool {
    let res = match alg {
        JwtAlg::HS256 => verify_internal(sig, msg, vk, Algorithm::HS256),
        JwtAlg::HS384 => verify_internal(sig, msg, vk, Algorithm::HS384),
        JwtAlg::HS512 => verify_internal(sig, msg, vk, Algorithm::HS512),
        JwtAlg::ES256 => verify_internal(sig, msg, vk, Algorithm::ES256),
        JwtAlg::ES384 => verify_internal(sig, msg, vk, Algorithm::ES384),
        JwtAlg::RS256 => verify_internal(sig, msg, vk, Algorithm::RS256),
        JwtAlg::RS384 => verify_internal(sig, msg, vk, Algorithm::RS384),
        JwtAlg::RS512 => verify_internal(sig, msg, vk, Algorithm::RS512),
        JwtAlg::PS256 => verify_internal(sig, msg, vk, Algorithm::PS256),
        JwtAlg::PS384 => verify_internal(sig, msg, vk, Algorithm::PS384),
        JwtAlg::PS512 => verify_internal(sig, msg, vk, Algorithm::PS512),
    };

    match res {
        Ok(res) => res,
        Err(e) => {
            println!("jwt verify failed ---- sig = {:?}, msg = {:?}, vk = {:?}, alg = {:?}, error = {:?}", sig, msg, vk, alg, e.to_string());
            false
        }
    }
}

#[derive(Debug, Clone)]
enum JwtKeyType {
    RSA_PEM,
    RSA_DER,
    RSA_N_E,
    EC_PEM,
    EC_DER,
    HMAC,
    HMAC_BASE64
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    #[test]
    fn test_hmac_key() {
        let secret = "c2VjcmV0";
        let sign_key = SignKey::from_base64_secret(&secret);
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;

        let header_encoded = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let payload_encoded = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

        println!("header_encoded = {:?}\npayload_encoded = {:?}", header_encoded, payload_encoded);

        let to_be_signed = [header_encoded.clone(), payload_encoded.clone()].join(".");
        println!("to_be_signed = {:?}", to_be_signed);

        let sig = jwt_sign(&to_be_signed, sign_key, JwtAlg::HS256);

        println!("token = {:?}", [header_encoded, payload_encoded, sig.clone()].join("."));

        let verify_key = VerifyKey::from_base64_secret(&secret);

        let verify_result = jwt_verify(&sig, &to_be_signed, &verify_key, JwtAlg::HS256);

        println!("verify result = {:?}", verify_result);
        assert_eq!(verify_result, true);
    }

    #[test]
    fn test_rsa_key() {
        let privkey = include_str!("../tests/private_rsa_key_pkcs1.pem");
        let n = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
        let e = "AQAB";

        let sign_key = SignKey::from_rsa_pem(privkey.as_ref());

        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let payload = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;

        let header_encoded = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let payload_encoded = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

        println!("header_encoded = {:?}\npayload_encoded = {:?}", header_encoded, payload_encoded);

        let to_be_signed = [header_encoded.clone(), payload_encoded.clone()].join(".");

        println!("to_be_signed = {:?}", to_be_signed);

        let sig = jwt_sign(&to_be_signed, sign_key, JwtAlg::RS256);

        println!("base64 encoded sig = {:?}", base64::encode_config(&sig, base64::URL_SAFE_NO_PAD));

        println!("token = {:?}", [header_encoded, payload_encoded, sig.clone()].join("."));

        let verify_key = VerifyKey::from_rsa_components(n, e);

        let verify_result = jwt_verify(&sig, &to_be_signed, &verify_key, JwtAlg::RS256);

        println!("verify result = {:?}", verify_result);
        assert_eq!(verify_result, true);
    }

    #[test]
    fn test_ecdsa_key() {
        let privkey = include_str!("../tests/private_ecdsa_key.pem");

        let sign_key = SignKey::from_ec_pem(privkey.as_ref());

        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let payload = r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#;

        let header_encoded = base64::encode_config(header, base64::URL_SAFE_NO_PAD);
        let payload_encoded = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

        println!("header_encoded = {:?}\npayload_encoded = {:?}", header_encoded, payload_encoded);

        let to_be_signed = [header_encoded.clone(), payload_encoded.clone()].join(".");

        println!("to_be_signed = {:?}", to_be_signed);

        let sig = jwt_sign(&to_be_signed, sign_key, JwtAlg::ES256);

        println!("base64 encoded sig = {:?}", base64::encode_config(&sig, base64::URL_SAFE_NO_PAD));

        println!("token = {:?}", [header_encoded, payload_encoded, sig.clone()].join("."));

        let pubkey = include_str!("../tests/public_ecdsa_key.pem");

        let verify_key = VerifyKey::from_ec_pem(pubkey.as_ref());

        let verify_result = jwt_verify(&sig, &to_be_signed, &verify_key, JwtAlg::ES256);

        println!("verify result = {:?}", verify_result);
        assert_eq!(verify_result, true);
    }
}
