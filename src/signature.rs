use secp256k1::{Message, Secp256k1, Signature};
use secp256k1::key::PublicKey;
use secp256k1::key::SecretKey;

pub struct ECDSASecp256k1 {
    ctx: Secp256k1,
}

impl ECDSASecp256k1 {
    pub fn new() -> Self {
        ECDSASecp256k1 {
            ctx: Secp256k1::new(),
        }
    }

    // msg: must be 32 bytes
    // sk: must be 32 bytes
    pub fn sign(&self, msg: &[u8], sk: &[u8]) -> Vec<u8> {
        let sk = SecretKey::from_slice(&self.ctx, sk).unwrap();
        let msg = Message::from_slice(msg).unwrap();

        self.ctx.sign(&msg, &sk).unwrap().serialize_der(&self.ctx)
    }

    // verify der encoded signature
    // msg: mut be 32 bytes
    // sig: 65~72 bytes
    // pk: mut be 33 or 65 bytes
    pub fn verify(&self, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        let msg = Message::from_slice(msg).unwrap();
        let pk = PublicKey::from_slice(&self.ctx, pk).unwrap();
        let sig = Signature::from_der(&self.ctx, sig).unwrap();

        self.ctx.verify(&msg, &sig, &pk).is_ok()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test() {
        use super::*;
        use hex::FromHex;

        let sk = Vec::from_hex("16346fd1da236f810202853a3dc505d92b6b8597c15fd463e4e4494d8fc6a708").unwrap();
        let pk = Vec::from_hex("044fbd4994b6c1d5790000fa0fdfe3afb1f5f3d2a4e78c3daac4c9176d020c5ca85c9a683154c43d0ce4ea0a43c3863875e27c0ea4a087dd5ef6615d41fc9c5b40").unwrap();
        let msg = [0xcd; 32];

        let secp = ECDSASecp256k1::new();

        let sig = secp.sign(&msg, &sk);
        assert!(secp.verify(&msg, &sig, pk.as_ref()));
    }

}
