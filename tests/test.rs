#[cfg(test)]
extern crate pi_crypto;

use std::sync::Arc;
use pi_crypto::bls::*;

#[test]
fn test_bls() {
    assert!(bls_init(Curve::MclBnCurveFp254BNb));
    assert!(bls_get_op_unit_size() == 4);
    assert!(bls_get_curve_order(256).is_some());
    assert!(bls_get_field_order(256).is_some());
    bls_get_generator_of_g2();
    let default_id = bls_id_set_int(0x7fffffff);
    let dec_str = "23156878976321321325446789".to_string();
    let dec_id = bls_id_set_dec_str(dec_str.clone());
    assert!(dec_id.is_some());
    assert!(bls_id_get_dec_str(32, dec_id.as_ref().unwrap()) == Some(dec_str));
    let hex_str = "aabcdeABCDE0123789".to_string();
    let hex_id = bls_id_set_hex_str(hex_str.clone());
    assert!(hex_id.is_some());
    assert!(bls_id_get_hex_str(32, hex_id.as_ref().unwrap()) == Some(hex_str.to_ascii_lowercase()));

    let hex_id = bls_id_set_hex_str(hex_str.clone());
    let hex_id_s = bls_id_serialize(32, hex_id.as_ref().unwrap());
    assert!(hex_id_s.is_some());
    let copy_hex_id = bls_id_deserialize(hex_id_s.unwrap());
    assert!(copy_hex_id.is_some());
    assert!(bls_id_is_equal(hex_id.as_ref().unwrap(), copy_hex_id.as_ref().unwrap()));

    let sec_key = bls_hash_to_secret_key("adsf;akjfasdfasdf097-89067.n*&%%^$)(K)KJHJFGOO".to_string().into_bytes());
    assert!(sec_key.is_some());
    let sec_key_s = bls_secret_key_serialize(32, sec_key.as_ref().unwrap());
    assert!(sec_key_s.is_some());
    let copy_sec_key = bls_secret_key_deserialize(sec_key_s.unwrap());
    assert!(copy_sec_key.is_some());
    assert!(bls_secret_key_is_equal(sec_key.as_ref().unwrap(), copy_sec_key.as_ref().unwrap()));

    let pub_key = bls_get_public_key(sec_key.as_ref().unwrap());
    assert!(pub_key.is_some());
    let pub_key_s = bls_public_key_serialize(64, pub_key.as_ref().unwrap());
    assert!(pub_key_s.is_some());
    let copy_pub_key = bls_public_key_deserialize(pub_key_s.unwrap());
    assert!(copy_pub_key.is_some());
    assert!(bls_public_key_is_equal(pub_key.as_ref().unwrap(), copy_pub_key.as_ref().unwrap()));

    let sig = bls_get_pop(sec_key.as_ref().unwrap());
    assert!(sig.is_some());
    assert!(bls_verify_pop(sig.as_ref().unwrap(), pub_key.as_ref().unwrap()));
    let sig_s = bls_signature_serialize(32, sig.as_ref().unwrap());
    assert!(sig_s.is_some());
    let copy_sig = bls_signature_deserialize(sig_s.unwrap());
    assert!(copy_sig.is_some());
    assert!(bls_signature_is_equal(sig.as_ref().unwrap(), copy_sig.as_ref().unwrap()));

    let id0 = bls_id_set_int(1);
    let id1 = bls_id_set_int(3);
    let id2 = bls_id_set_int(6);
    let id3 = bls_id_set_int(8);
    let id4 = bls_id_set_int(9);

    let sec_key0 = bls_secret_key_share(sec_key.as_ref().unwrap(), 3, &id0);
    let sec_key1 = bls_secret_key_share(sec_key.as_ref().unwrap(), 3, &id1);
    let sec_key2 = bls_secret_key_share(sec_key.as_ref().unwrap(), 3, &id2);
    let sec_key3 = bls_secret_key_share(sec_key.as_ref().unwrap(), 3, &id3);
    let sec_key4 = bls_secret_key_share(sec_key.as_ref().unwrap(), 3, &id4);

    let mut id_vec = BlsIdVec::new(3);
    bls_add_id_to_vec(&mut id_vec, &id0);
    bls_add_id_to_vec(&mut id_vec, &id1);
    bls_add_id_to_vec(&mut id_vec, &id2);

    let mut sec_vec = BlsSecKeyVec::new(3);
    bls_add_secret_key_to_vec(&mut sec_vec, sec_key0.as_ref().unwrap());
    bls_add_secret_key_to_vec(&mut sec_vec, sec_key1.as_ref().unwrap());
    bls_add_secret_key_to_vec(&mut sec_vec, sec_key2.as_ref().unwrap());

    let msk = bls_secret_key_recover(&sec_vec, &id_vec, 3);
    assert!(msk.is_some());
    assert!(bls_secret_key_is_equal(msk.as_ref().unwrap(), sec_key.as_ref().unwrap()));

    let bin = Arc::new(vec![10, 10, 10, 10, 10, 10]);
    let sig = bls_sign(sec_key.as_ref().unwrap(), bin.clone());
    assert!(sig.is_some());
    assert!(bls_verify(sig.as_ref().unwrap(), pub_key.as_ref().unwrap(), bin.clone()));

    let sig0 = bls_sign(sec_key0.as_ref().unwrap(), bin.clone());
    let sig1 = bls_sign(sec_key1.as_ref().unwrap(), bin.clone());
    let sig2 = bls_sign(sec_key2.as_ref().unwrap(), bin.clone());
    let sig3 = bls_sign(sec_key3.as_ref().unwrap(), bin.clone());
    let sig4 = bls_sign(sec_key4.as_ref().unwrap(), bin.clone());

    let mut sig_vec = BlsSigVec::new(3);
    bls_add_signature_to_vec(&mut sig_vec, sig0.as_ref().unwrap());
    bls_add_signature_to_vec(&mut sig_vec, sig1.as_ref().unwrap());
    bls_add_signature_to_vec(&mut sig_vec, sig2.as_ref().unwrap());

    let msign = bls_signature_recover(&sig_vec, &id_vec, 3);
    assert!(bls_verify(msign.as_ref().unwrap(), pub_key.as_ref().unwrap(), bin.clone()));
}