use std::ptr::null;
use std::sync::Arc;
use std::ops::Drop;
use std::ffi::CString;
use libc::{c_void, c_uchar, c_char, c_int, size_t};

#[link(name = "blsc")]
extern "C" {
    fn blscInit(curve: c_int) -> c_int;
    fn blscGetOpUnitSize() -> size_t;
    fn blscGetCurveOrder(buf: *mut c_uchar, maxBufSize: size_t) -> c_int;
    fn blscGetFieldOrder(buf: *mut c_uchar, maxBufSize: size_t) -> c_int;
    fn blscGetGeneratorOfG2() -> *const c_void;
    fn blscIdSetInt(x: c_int) -> *const c_void;
    fn blscIdSetDecStr(buf: *const c_char, bufSize: size_t) -> *const c_void;
    fn blscIdSetHexStr(buf: *const c_char, bufSize: size_t) -> *const c_void;
    fn blscIdGetDecStr(buf: *mut c_uchar, maxBufSize: size_t, blsId: *const c_void) -> size_t;
    fn blscIdGetHexStr(buf: *mut c_uchar, maxBufSize: size_t, blsId: *const c_void) -> size_t;
    fn blscHashToSecretKey(buf: *const c_void, bufSize: size_t) -> *const c_void;
    fn blscGetPublicKey(secKey: *const c_void) -> *const c_void;
    fn blscGetPop(secKey: *const c_void) -> *const c_void;
    fn blscVerifyPop(sig: *const c_void, pubKey: *const c_void) -> c_int;
    fn blscIdSerialize(buf: *mut c_void, maxBufSize: size_t, blsId: *const c_void) -> size_t;
    fn blscSecretKeySerialize(buf: *mut c_void, maxBufSize: size_t, secKey: *const c_void) -> size_t;
    fn blscPublicKeySerialize(buf: *mut c_void, maxBufSize: size_t, pubKey: *const c_void) -> size_t;
    fn blscSignatureSerialize(buf: *mut c_void, maxBufSize: size_t, sig: *const c_void) -> size_t;
    fn blscIdDeserialize(buf: *const c_void, bufSize: size_t) -> *const c_void;
    fn blscSecretKeyDeserialize(buf: *const c_void, bufSize: size_t) -> *const c_void;
    fn blscPublicKeyDeserialize(buf: *const c_void, bufSize: size_t) -> *const c_void;
    fn blscSignatureDeserialize(buf: *const c_void, bufSize: size_t) -> *const c_void;
    fn blscIdIsEqual(lhs: *const c_void, rhs: *const c_void) -> c_int;
    fn blscSecretKeyIsEqual(lhs: *const c_void, rhs: *const c_void) -> c_int;
    fn blscPublicKeyIsEqual(lhs: *const c_void, rhs: *const c_void) -> c_int;
    fn blscSignatureIsEqual(lhs: *const c_void, rhs: *const c_void) -> c_int;
    fn blscSecretKeyAdd(sec_key: *const c_void, rhs: *const c_void);
    fn blscPublicKeyAdd(pub_key: *const c_void, rhs: *const c_void);
    fn blscSignatureAdd(sig: *const c_void, rhs: *const c_void);
    fn blscSecretKeyShare(msk: *const c_void, k: size_t, blsId: *const c_void) -> *const c_void;
    fn blscPublicKeyShare(mpk: *const c_void, k: size_t, blsId: *const c_void) -> *const c_void;
    fn blscAddIdToVec(blsIdVec: *const c_void, k: size_t, blsId: *const c_void) -> *const c_void;
    fn blscAddSecretKeyToVec(secKeyVec: *const c_void, k: size_t, secKey: *const c_void) -> *const c_void;
    fn blscAddPublicKeyToVec(pubKeyVec: *const c_void, k: size_t, pubKey: *const c_void) -> *const c_void;
    fn blscAddSignatureToVec(sigVec: *const c_void, k: size_t, sig: *const c_void) -> *const c_void;
    fn blscSecretKeyRecover(secKeyVec: *const c_void, blsIdVec: *const c_void, n: size_t) -> *const c_void;
    fn blscPublicKeyRecover(pubKeyVec: *const c_void, blsIdVec: *const c_void, n: size_t) -> *const c_void;
    fn blscSignatureRecover(sigVec: *const c_void, blsIdVec: *const c_void, n: size_t) -> *const c_void;
    fn blscSign(secKey: *const c_void, m: *const c_void, size: size_t) -> *const c_void;
    fn blscVerify(sig: *const c_void, pubKey: *const c_void, m: *const c_void, size: size_t) -> c_int;
    fn blscFree(ptr: *const c_void);
}

pub enum Curve {
	MclBnCurveFp254BNb = 0x0,
	MclBnCurveFp382_1,
	MclBnCurveFp382_2,
	MclBnCurveFp462,
	MclBnCurveSNARK1,
	MclBls12CurveFp381,
}

pub struct BlsId(*const c_void);

impl Drop for BlsId {
    fn drop(&mut self) {
        unsafe { blscFree(self.0) }
    }
}

pub struct BlsSecretKey(*const c_void);

impl Drop for BlsSecretKey {
    fn drop(&mut self) {
        unsafe { blscFree(self.0) }
    }
}

pub struct BlsPublicKey(*const c_void);

impl Drop for BlsPublicKey {
    fn drop(&mut self) {
        unsafe { blscFree(self.0) }
    }
}

pub struct BlsSignature(*const c_void);

impl Drop for BlsSignature {
    fn drop(&mut self) {
        unsafe { blscFree(self.0) }
    }
}

pub struct BlsIdVec(*const c_void, usize);

impl Drop for BlsIdVec {
    fn drop(&mut self) {
        unsafe { blscFree(self.0) }
    }
}

impl BlsIdVec {
    pub fn new(k: usize) -> Self {
        BlsIdVec(null(), k)
    }
}

pub struct BlsSecKeyVec(*const c_void, usize);

impl Drop for BlsSecKeyVec {
    fn drop(&mut self) {
        unsafe { blscFree(self.0) }
    }
}

impl BlsSecKeyVec {
    pub fn new(k: usize) -> Self {
        BlsSecKeyVec(null(), k)
    }
}

pub struct BlsPubKeyVec(*const c_void, usize);

impl Drop for BlsPubKeyVec {
    fn drop(&mut self) {
        unsafe { blscFree(self.0) }
    }
}

impl BlsPubKeyVec {
    pub fn new(k: usize) -> Self {
        BlsPubKeyVec(null(), k)
    }
}

pub struct BlsSigVec(*const c_void, usize);

impl Drop for BlsSigVec {
    fn drop(&mut self) {
        unsafe { blscFree(self.0) }
    }
}

impl BlsSigVec {
    pub fn new(k: usize) -> Self {
        BlsSigVec(null(), k)
    }
}

/*
* 线程安全的初始化
*/
pub fn bls_init(curve: Curve) -> bool {
    unsafe {
        if blscInit(curve as i32) != 0 {
            return false;
        }
        true
    }
}

pub fn bls_get_op_unit_size() -> usize {
    unsafe { blscGetOpUnitSize() }
}

pub fn bls_get_curve_order(max_buf_size: usize) -> Option<String> {
    unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(max_buf_size);
        buf.resize(max_buf_size, 0);
        let len = blscGetCurveOrder(buf.as_mut_ptr(), max_buf_size);
        if len == 0 {
            return None;
        }

        buf.truncate(len as usize);
        match String::from_utf8(buf) {
            Ok(string) => Some(string),
            _ => None,
        }
    }
}

pub fn bls_get_field_order(max_buf_size: usize) -> Option<String> {
    unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(max_buf_size);
        buf.resize(max_buf_size, 0);
        let len = blscGetFieldOrder(buf.as_mut_ptr(), max_buf_size);
        if len == 0 {
            return None;
        }
        
        buf.truncate(len as usize);
        match String::from_utf8(buf) {
            Ok(string) => Some(string),
            _ => None,
        }
    }
}

pub fn bls_get_generator_of_g2() -> BlsPublicKey {
    unsafe {
        BlsPublicKey(blscGetGeneratorOfG2())
    }
}

pub fn bls_id_set_int(x: i32) -> BlsId {
    unsafe {
        BlsId(blscIdSetInt(x))
    }
}

pub fn bls_id_set_dec_str(buf: String) -> Option<BlsId> {
    unsafe {
        let buf_size = buf.len();
        let ptr = blscIdSetDecStr(CString::new(buf).unwrap().as_ptr(), buf_size);
        if ptr.is_null() {
            return None;
        }
        Some(BlsId(ptr))
    }
}

pub fn bls_id_set_hex_str(buf: String) -> Option<BlsId> {
    unsafe {
        let buf_size = buf.len();
        let ptr = blscIdSetHexStr(CString::new(buf).unwrap().as_ptr(), buf_size);
        if ptr.is_null() {
            return None;
        }
        Some(BlsId(ptr))
    }
}

pub fn bls_id_get_dec_str(max_buf_size: usize, id: &BlsId) -> Option<String> {
    if max_buf_size == 0 {
        return None;
    }

    unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(max_buf_size);
        buf.resize(max_buf_size, 0);
        let len = blscIdGetDecStr(buf.as_mut_ptr(), max_buf_size, id.0);
        if len == 0 {
            return None;
        }
        
        buf.truncate(len as usize);
        match String::from_utf8(buf) {
            Ok(string) => Some(string),
            _ => None,
        }
    }
}

pub fn bls_id_get_hex_str(max_buf_size: usize, id: &BlsId) -> Option<String> {
    if max_buf_size == 0 {
        return None;
    }

    unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(max_buf_size);
        buf.resize(max_buf_size, 0);
        let len = blscIdGetHexStr(buf.as_mut_ptr(), max_buf_size, id.0);
        if len == 0 {
            return None;
        }
        
        buf.truncate(len as usize);
        match String::from_utf8(buf) {
            Ok(string) => Some(string),
            _ => None,
        }
    }
}

pub fn bls_hash_to_secret_key(buf: Vec<u8>) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscHashToSecretKey(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr))
    }
}

pub fn bls_get_public_key(sec_key: &BlsSecretKey) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscGetPublicKey(sec_key.0);
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr))
    }
}

pub fn bls_get_pop(sec_key: &BlsSecretKey) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscGetPop(sec_key.0);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr))
    }
}

pub fn bls_verify_pop(sig: &BlsSignature, pub_key: &BlsPublicKey) -> bool {
    unsafe {
        if blscVerifyPop(sig.0, pub_key.0) != 1 {
            return false;
        }
        true
    }
}

pub fn bls_id_serialize(max_buf_size: usize, id: &BlsId) -> Option<Vec<u8>> {
    unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(max_buf_size);
        buf.resize(max_buf_size, 0);
        let len = blscIdSerialize(buf.as_mut_ptr() as *mut c_void, max_buf_size, id.0);
        if len == 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }
}

pub fn bls_secret_key_serialize(max_buf_size: usize, sec_key: &BlsSecretKey) -> Option<Vec<u8>> {
    unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(max_buf_size);
        buf.resize(max_buf_size, 0);
        let len = blscSecretKeySerialize(buf.as_mut_ptr() as *mut c_void, max_buf_size, sec_key.0);
        if len == 0 {
            return None;
        }
        
        buf.truncate(len as usize);
        Some(buf)
    }
}

pub fn bls_public_key_serialize(max_buf_size: usize, pub_key: &BlsPublicKey) -> Option<Vec<u8>> {
    unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(max_buf_size);
        buf.resize(max_buf_size, 0);
        let len = blscPublicKeySerialize(buf.as_mut_ptr() as *mut c_void, max_buf_size, pub_key.0);
        if len == 0 {
            return None;
        }
        
        buf.truncate(len as usize);
        Some(buf)
    }
}

pub fn bls_signature_serialize(max_buf_size: usize, sig: &BlsSignature) -> Option<Vec<u8>> {
    unsafe {
        let mut buf: Vec<u8> = Vec::with_capacity(max_buf_size);
        buf.resize(max_buf_size, 0);
        let len = blscSignatureSerialize(buf.as_mut_ptr() as *mut c_void, max_buf_size, sig.0);
        if len == 0 {
            return None;
        }
        
        buf.truncate(len as usize);
        Some(buf)
    }
}

pub fn bls_id_deserialize(buf: Vec<u8>) -> Option<BlsId> {
    unsafe {
        let ptr = blscIdDeserialize(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsId(ptr))
    }
}

pub fn bls_secret_key_deserialize(buf: Vec<u8>) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscSecretKeyDeserialize(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr))
    }
}

pub fn bls_public_key_deserialize(buf: Vec<u8>) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscPublicKeyDeserialize(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr))
    }
}

pub fn bls_signature_deserialize(buf: Vec<u8>) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscSignatureDeserialize(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr))
    }
}

pub fn bls_id_is_equal(lhs: &BlsId, rhs: &BlsId) -> bool {
    unsafe {
        if blscIdIsEqual(lhs.0, rhs.0) == 0 {
            return false;
        }
        true
    }
}

pub fn bls_secret_key_is_equal(lhs: &BlsSecretKey, rhs: &BlsSecretKey) -> bool {
    unsafe {
        if blscSecretKeyIsEqual(lhs.0, rhs.0) == 0 {
            return false;
        }
        true
    }
}

pub fn bls_public_key_is_equal(lhs: &BlsPublicKey, rhs: &BlsPublicKey) -> bool {
    unsafe {
        if blscPublicKeyIsEqual(lhs.0, rhs.0) == 0 {
            return false;
        }
        true
    }
}

pub fn bls_signature_is_equal(lhs: &BlsSignature, rhs: &BlsSignature) -> bool {
    unsafe {
        if blscSignatureIsEqual(lhs.0, rhs.0) == 0 {
            return false;
        }
        true
    }
}

pub fn bls_secret_key_add(sec_key: &BlsSecretKey, rhs: &BlsSecretKey) {
    unsafe { blscSecretKeyAdd(sec_key.0, rhs.0); }
}

pub fn bls_public_key_add(pub_key: &BlsPublicKey, rhs: &BlsPublicKey) {
    unsafe { blscPublicKeyAdd(pub_key.0, rhs.0); }
}

pub fn bls_signature_add(sig: &BlsSignature, rhs: &BlsSignature) {
    unsafe { blscSignatureAdd(sig.0, rhs.0); }
}

pub fn bls_secret_key_share(src_key: &BlsSecretKey, k: usize, id: &BlsId) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscSecretKeyShare(src_key.0, k, id.0);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr))
    }
}

pub fn bls_public_key_share(src_key: &BlsPublicKey, k: usize, id: &BlsId) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscPublicKeyShare(src_key.0, k, id.0);
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr))
    }
}

pub fn bls_add_id_to_vec(vec: &mut BlsIdVec, id: &BlsId) {
    unsafe {
        let ptr = blscAddIdToVec(vec.0, vec.1, id.0);
        if ptr.is_null() {
            return;
        }
        vec.0 = ptr;
    }
}

pub fn bls_add_secret_key_to_vec(vec: &mut BlsSecKeyVec, sec_key: &BlsSecretKey) {
    unsafe {
        let ptr = blscAddSecretKeyToVec(vec.0, vec.1, sec_key.0);
        if ptr.is_null() {
            return;
        }
        vec.0 = ptr;
    }
}

pub fn bls_add_public_key_to_vec(vec: &mut BlsPubKeyVec, pub_key: &BlsPublicKey) {
    unsafe {
        let ptr = blscAddPublicKeyToVec(vec.0, vec.1, pub_key.0);
        if ptr.is_null() {
            return;
        }
        vec.0 = ptr;
    }
}

pub fn bls_add_signature_to_vec(vec: &mut BlsSigVec, sig: &BlsSignature) {
    unsafe {
        let ptr = blscAddSignatureToVec(vec.0, vec.1, sig.0);
        if ptr.is_null() {
            return;
        }
        vec.0 = ptr;
    }
}

pub fn bls_secret_key_recover(sec_key_vec: &BlsSecKeyVec, id_vec: &BlsIdVec, n: usize) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscSecretKeyRecover(sec_key_vec.0, id_vec.0, n);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr))
    }
}

pub fn bls_public_key_recover(pub_key_vec: &BlsPubKeyVec, id_vec: &BlsIdVec, n: usize) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscPublicKeyRecover(pub_key_vec.0, id_vec.0, n);
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr))
    }
}

pub fn bls_signature_recover(sig_vec: &BlsSigVec, id_vec: &BlsIdVec, n: usize) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscSignatureRecover(sig_vec.0, id_vec.0, n);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr))
    }
}

pub fn bls_sign(sec_key: &BlsSecretKey, data: Arc<Vec<u8>>) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscSign(sec_key.0, data.as_ptr() as *const c_void, data.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr))
    }
}

pub fn bls_verify(sig: &BlsSignature, pub_key: &BlsPublicKey, data: Arc<Vec<u8>>) -> bool {
    unsafe {
        if blscVerify(sig.0, pub_key.0, data.as_ptr() as *const c_void, data.len()) != 1 {
            return false;
        }
        true
    }
}

