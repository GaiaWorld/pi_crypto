/**
* 基于BLS的门限签名算法
*/
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
    fn blscGetIdFromVec(blsIdVec: *const c_void, index: size_t) -> *const c_void;
    fn blscAddIdToVec(blsIdVec: *const c_void, k: size_t, blsId: *const c_void) -> *const c_void;
    fn blscGetSecretKeyFromVec(secKeyVec: *const c_void, index: size_t) -> *const c_void;
    fn blscAddSecretKeyToVec(secKeyVec: *const c_void, k: size_t, secKey: *const c_void) -> *const c_void;
    fn blscGetSecretKeyVec(secKeyVec: *const c_void) -> *const c_void;
    fn blscGetPublicKeyFromVec(pubKeyVec: *const c_void, index: size_t) -> *const c_void;
    fn blscAddPublicKeyToVec(pubKeyVec: *const c_void, k: size_t, pubKey: *const c_void) -> *const c_void;
    fn blscGetPublicKeyVec(pubKeyVec: *const c_void) -> *const c_void;
    fn blscGetSignatureFromVec(sigIdVec: *const c_void, index: size_t) -> *const c_void;
    fn blscAddSignatureToVec(sigVec: *const c_void, k: size_t, sig: *const c_void) -> *const c_void;
    fn blscGetSignatureVec(sigVec: *const c_void) -> *const c_void;
    fn blscSecretKeyRecover(secKeyVec: *const c_void, blsIdVec: *const c_void, n: size_t) -> *const c_void;
    fn blscPublicKeyRecover(pubKeyVec: *const c_void, blsIdVec: *const c_void, n: size_t) -> *const c_void;
    fn blscSignatureRecover(sigVec: *const c_void, blsIdVec: *const c_void, n: size_t) -> *const c_void;
    fn blscSign(secKey: *const c_void, m: *const c_void, size: size_t) -> *const c_void;
    fn blscVerify(sig: *const c_void, pubKey: *const c_void, m: *const c_void, size: size_t) -> c_int;
    fn blscFree(ptr: *const c_void);
}

/**
* BLS算法的曲线类型
*/
pub enum Curve {
	MclBnCurveFp254BNb = 0x0,
	MclBnCurveFp382_1,
	MclBnCurveFp382_2,
	MclBnCurveFp462,
	MclBnCurveSNARK1,
	MclBls12CurveFp381,
}

/**
* BLS算法的成员唯一id
*/
pub struct BlsId(*const c_void, bool);

impl Drop for BlsId {
    fn drop(&mut self) {
        if self.1 {
            unsafe { blscFree(self.0) }
        }
    }
}

/**
* BLS算法的私钥
*/
pub struct BlsSecretKey(*const c_void, bool);

impl Drop for BlsSecretKey {
    fn drop(&mut self) {
        if self.1 {
            unsafe { blscFree(self.0) }
        }
    }
}

/**
* BLS算法的公钥
*/
pub struct BlsPublicKey(*const c_void, bool);

impl Drop for BlsPublicKey {
    fn drop(&mut self) {
        if self.1 {
            unsafe { blscFree(self.0) }
        }
    }
}

/**
* BLS算法的签名
*/
pub struct BlsSignature(*const c_void, bool);

impl Drop for BlsSignature {
    fn drop(&mut self) {
        if self.1 {
            unsafe { blscFree(self.0) }
        }
    }
}

/**
* BLS算法的成员唯一id向量
*/
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

/**
* BLS算法私钥向量
*/
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

/**
* BLS算法公钥向量
*/
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

/**
* BLS算法签名向量
*/
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

/**
* BLS算法初始化环境，只需要初始化一次
* @param curve BLS算法的曲线类型
* @returns 返回初始化是否成功
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
        BlsPublicKey(blscGetGeneratorOfG2(), true)
    }
}

/**
* 指定唯一的整数，获取BLS算法的成员唯一id
* @param x 唯一的整数
* @returns 返回BLS算法的成员唯一id
*/
pub fn bls_id_set_int(x: i32) -> BlsId {
    unsafe {
        BlsId(blscIdSetInt(x), true)
    }
}

/**
* 指定唯一的Dec字节串，获取BLS算法的成员唯一id
* @param buf 唯一的Dec字符串
* @returns 返回BLS算法的成员唯一id，可为空
*/
pub fn bls_id_set_dec_str(buf: String) -> Option<BlsId> {
    unsafe {
        let buf_size = buf.len();
        let ptr = blscIdSetDecStr(CString::new(buf).unwrap().as_ptr(), buf_size);
        if ptr.is_null() {
            return None;
        }
        Some(BlsId(ptr, true))
    }
}

/**
* 指定唯一的Hex字节串，获取BLS算法的成员唯一id
* @param buf 唯一的Hex字符串
* @returns 返回BLS算法的成员唯一id，可为空
*/
pub fn bls_id_set_hex_str(buf: String) -> Option<BlsId> {
    unsafe {
        let buf_size = buf.len();
        let ptr = blscIdSetHexStr(CString::new(buf).unwrap().as_ptr(), buf_size);
        if ptr.is_null() {
            return None;
        }
        Some(BlsId(ptr, true))
    }
}

/**
* 通过BLS算法的成员唯一id，获取唯一Dec字符串
* @param max_buf_size 最大的缓冲大小
* @param id BLS算法的成员唯一id
* @returns 返回唯一Dec字符串，可为空
*/
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

/**
* 通过BLS算法的成员唯一id，获取唯一Hex字符串
* @param max_buf_size 最大的缓冲大小
* @param id BLS算法的成员唯一id
* @returns 返回唯一Hex字符串，可为空
*/
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

/**
* 生成指定种子的BLS私钥
* @param buf 种子的二进制数据
* @returns 返回BLS私钥，可为空
*/
pub fn bls_hash_to_secret_key(buf: Vec<u8>) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscHashToSecretKey(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr, true))
    }
}

/**
* 获取指定BLS私钥的公钥
* @param sec_key BLS私钥
* @returns 返回BLS公钥，可为空
*/
pub fn bls_get_public_key(sec_key: &BlsSecretKey) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscGetPublicKey(sec_key.0);
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr, true))
    }
}

/**
* 获取指定BLS私钥的签名
* @param sec_key BLS私钥
* @returns 返回签名，可为空
*/
pub fn bls_get_pop(sec_key: &BlsSecretKey) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscGetPop(sec_key.0);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr, true))
    }
}

/**
* 验证BLS私钥的签名
* @param sig BLS私钥的签名
* @param pub_key BLS公钥
* @returns 返回验证签名是否成功
*/
pub fn bls_verify_pop(sig: &BlsSignature, pub_key: &BlsPublicKey) -> bool {
    unsafe {
        if blscVerifyPop(sig.0, pub_key.0) != 1 {
            return false;
        }
        true
    }
}

/**
* 序列化BLS算法的成员唯一id
* @param max_buf_size 最大的缓冲大小
* @param id BLS算法的成员唯一id
* @returns 返回序列化数据，可为空
*/
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

/**
* 序列化BLS私钥
* @param max_buf_size 最大的缓冲大小
* @param sec_key BLS私钥
* @returns 返回序列化数据，可为空
*/
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

/**
* 序列化BLS公钥
* @param max_buf_size 最大的缓冲大小
* @param pub_key BLS公钥
* @returns 返回序列化数据，可为空
*/
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

/**
* 序列化BLS签名
* @param max_buf_size 最大的缓冲大小
* @param sig BLS签名
* @returns 返回序列化数据，可为空
*/
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

/**
* 反序列化BLS算法的成员唯一id
* @param buf 序列化数据
* @returns 返回BLS算法的成员唯一id，可为空
*/
pub fn bls_id_deserialize(buf: Vec<u8>) -> Option<BlsId> {
    unsafe {
        let ptr = blscIdDeserialize(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsId(ptr, false))
    }
}

/**
* 反序列化BLS私钥
* @param buf 序列化数据
* @returns 返回BLS私钥，可为空
*/
pub fn bls_secret_key_deserialize(buf: Vec<u8>) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscSecretKeyDeserialize(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr, false))
    }
}

/**
* 反序列化BLS公钥
* @param buf 序列化数据
* @returns 返回BLS公钥，可为空
*/
pub fn bls_public_key_deserialize(buf: Vec<u8>) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscPublicKeyDeserialize(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr, false))
    }
}

/**
* 反序列化BLS签名
* @param buf 序列化数据
* @returns 返回BLS签名，可为空
*/
pub fn bls_signature_deserialize(buf: Vec<u8>) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscSignatureDeserialize(buf.as_ptr() as *const c_void, buf.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr, false))
    }
}

/**
* 检查两个指定的BLS算法的成员唯一id是否相同
* @param lhs BLS算法的成员唯一id
* @param rhs BLS算法的成员唯一id
* @returns 返回是否相同
*/
pub fn bls_id_is_equal(lhs: &BlsId, rhs: &BlsId) -> bool {
    unsafe {
        if blscIdIsEqual(lhs.0, rhs.0) == 0 {
            return false;
        }
        true
    }
}

/**
* 检查两个指定的BLS私钥是否相同
* @param lhs BLS私钥
* @param rhs BLS私钥
* @returns 返回是否相同
*/
pub fn bls_secret_key_is_equal(lhs: &BlsSecretKey, rhs: &BlsSecretKey) -> bool {
    unsafe {
        if blscSecretKeyIsEqual(lhs.0, rhs.0) == 0 {
            return false;
        }
        true
    }
}

/**
* 检查两个指定的BLS公钥是否相同
* @param lhs BLS公钥
* @param rhs BLS公钥
* @returns 返回是否相同
*/
pub fn bls_public_key_is_equal(lhs: &BlsPublicKey, rhs: &BlsPublicKey) -> bool {
    unsafe {
        if blscPublicKeyIsEqual(lhs.0, rhs.0) == 0 {
            return false;
        }
        true
    }
}

/**
* 检查两个指定的BLS签名是否相同
* @param lhs BLS签名
* @param rhs BLS签名
* @returns 返回是否相同
*/
pub fn bls_signature_is_equal(lhs: &BlsSignature, rhs: &BlsSignature) -> bool {
    unsafe {
        if blscSignatureIsEqual(lhs.0, rhs.0) == 0 {
            return false;
        }
        true
    }
}

/**
* 在指定的主BLS私钥上增加一个副BLS私钥
* @param sec_key 主BLS私钥
* @param rhs 副BLS私钥
*/
pub fn bls_secret_key_add(sec_key: &BlsSecretKey, rhs: &BlsSecretKey) {
    unsafe { blscSecretKeyAdd(sec_key.0, rhs.0); }
}

/**
* 在指定的主BLS公钥上增加一个副BLS公钥
* @param pub_key 主BLS公钥
* @param rhs 副BLS公钥
*/
pub fn bls_public_key_add(pub_key: &BlsPublicKey, rhs: &BlsPublicKey) {
    unsafe { blscPublicKeyAdd(pub_key.0, rhs.0); }
}

/**
* 在指定的主BLS主签名上增加一个副BLS签名
* @param sig 主BLS签名
* @param rhs 副BLS签名
*/
pub fn bls_signature_add(sig: &BlsSignature, rhs: &BlsSignature) {
    unsafe { blscSignatureAdd(sig.0, rhs.0); }
}

/**
* 生成指定主私钥、共享人数、共享人的成员唯一id
* @param src_key BLS主私钥
* @param k 共享人数
* @param id BLS算法的成员唯一id
* @returns 返回共享的BLS私钥，可为空
*/
pub fn bls_secret_key_share(src_key: &BlsSecretKey, k: usize, id: &BlsId) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscSecretKeyShare(src_key.0, k, id.0);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr, true))
    }
}

/**
* 生成指定主公钥、共享人数、共享人的成员唯一id
* @param src_key BLS主公钥
* @param k 共享人数
* @param id BLS算法的成员唯一id
* @returns 返回共享的BLS公钥，可为空
*/
pub fn bls_public_key_share(src_key: &BlsPublicKey, k: usize, id: &BlsId) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscPublicKeyShare(src_key.0, k, id.0);
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr, true))
    }
}

/**
* 获取成员唯一id向量中指定序号的成员唯一id
* @param vec BLS算法的成员唯一id向量
* @param index 序号
* @returns 返回BLS算法的成员唯一id，可为空
*/
pub fn bls_get_id_from_vec(vec: &BlsIdVec, index: usize) -> Option<BlsId> {
    unsafe {
        let ptr = blscGetIdFromVec(vec.0, index);
        if ptr.is_null() {
            return None;
        }
        Some(BlsId(ptr, false))
    }
}

/**
* 在指定的成员唯一id向量中增加指定的成员唯一id
* @param vec BLS算法的成员唯一id向量
* @param id BLS算法的成员唯一id
*/
pub fn bls_add_id_to_vec(vec: &mut BlsIdVec, id: &BlsId) {
    unsafe {
        let ptr = blscAddIdToVec(vec.0, vec.1, id.0);
        if ptr.is_null() {
            return;
        }
        vec.0 = ptr;
    }
}

/**
* 获取私钥向量中指定序号的私钥
* @param vec BLS私钥向量
* @param index 序号
* @returns 返回BLS私钥，可为空
*/
pub fn bls_get_secret_key_from_vec(vec: &BlsSecKeyVec, index: usize) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscGetSecretKeyFromVec(vec.0, index);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr, false))
    }
}

/**
* 在指定的私钥向量中增加指定的私钥
* @param vec BLS私钥向量
* @param sec_key BLS私钥
*/
pub fn bls_add_secret_key_to_vec(vec: &mut BlsSecKeyVec, sec_key: &BlsSecretKey) {
    unsafe {
        let ptr = blscAddSecretKeyToVec(vec.0, vec.1, sec_key.0);
        if ptr.is_null() {
            return;
        }
        vec.0 = ptr;
    }
}

/**
* 获取指定私钥向量的组合私钥
* @param vec BLS私钥向量
* @returns 返回组合私钥，可为空
*/
pub fn bls_get_secret_key_vec(vec: &BlsSecKeyVec) -> Option<BlsSecretKey> {
    unsafe {
        if vec.0.is_null() {
            return None;
        }
        Some(BlsSecretKey(blscGetSecretKeyVec(vec.0), false))
    }
}

/**
* 获取公钥向量中指定序号的公钥
* @param vec BLS公钥向量
* @param index 序号
* @returns 返回BLS公钥，可为空
*/
pub fn bls_get_public_key_from_vec(vec: &BlsPubKeyVec, index: usize) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscGetPublicKeyFromVec(vec.0, index);
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr, false))
    }
}

/**
* 在指定的公钥向量中增加指定的公钥
* @param vec BLS公钥向量
* @param sec_key BLS公钥
*/
pub fn bls_add_public_key_to_vec(vec: &mut BlsPubKeyVec, pub_key: &BlsPublicKey) {
    unsafe {
        let ptr = blscAddPublicKeyToVec(vec.0, vec.1, pub_key.0);
        if ptr.is_null() {
            return;
        }
        vec.0 = ptr;
    }
}

/**
* 获取指定公钥向量的组合公钥
* @param vec BLS公钥向量
* @returns 返回组合公钥，可为空
*/
pub fn bls_get_public_key_vec(vec: &BlsPubKeyVec) -> Option<BlsPublicKey> {
    unsafe {
        if vec.0.is_null() {
            return None;
        }
        Some(BlsPublicKey(blscGetPublicKeyVec(vec.0), false))
    }
}

/**
* 获取签名向量中指定序号的签名
* @param vec BLS签名向量
* @param index 序号
* @returns 返回BLS签名，可为空
*/
pub fn bls_get_signature_from_vec(vec: &BlsSigVec, index: usize) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscGetSignatureFromVec(vec.0, index);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr, false))
    }
}

/**
* 在指定的签名向量中增加指定的签名
* @param vec BLS签名向量
* @param sec_key BLS签名
*/
pub fn bls_add_signature_to_vec(vec: &mut BlsSigVec, sig: &BlsSignature) {
    unsafe {
        let ptr = blscAddSignatureToVec(vec.0, vec.1, sig.0);
        if ptr.is_null() {
            return;
        }
        vec.0 = ptr;
    }
}

/**
* 获取指定签名向量的组合签名
* @param vec BLS签名向量
* @returns 返回组合签名，可为空
*/
pub fn bls_get_signature_key_vec(vec: &BlsSigVec) -> Option<BlsSignature> {
    unsafe {
        if vec.0.is_null() {
            return None;
        }
        Some(BlsSignature(blscGetSignatureVec(vec.0), false))
    }
}

/**
* 通过指定长度的私钥向量和成员唯一id向量，恢复主私钥
* @param sec_key_vec BLS私钥向量
* @param id_vec BLS算法的成员唯一id向量
* @param n 向量的长度
* @returns 返回主私钥，可为空
*/
pub fn bls_secret_key_recover(sec_key_vec: &BlsSecKeyVec, id_vec: &BlsIdVec, n: usize) -> Option<BlsSecretKey> {
    unsafe {
        let ptr = blscSecretKeyRecover(sec_key_vec.0, id_vec.0, n);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSecretKey(ptr, true))
    }
}

/**
* 通过指定长度的公钥向量和成员唯一id向量，恢复主公钥
* @param pub_key_vec BLS公钥向量
* @param id_vec BLS算法的成员唯一id向量
* @param n 向量的长度
* @returns 返回主公钥，可为空
*/
pub fn bls_public_key_recover(pub_key_vec: &BlsPubKeyVec, id_vec: &BlsIdVec, n: usize) -> Option<BlsPublicKey> {
    unsafe {
        let ptr = blscPublicKeyRecover(pub_key_vec.0, id_vec.0, n);
        if ptr.is_null() {
            return None;
        }
        Some(BlsPublicKey(ptr, true))
    }
}

/**
* 通过指定长度的签名向量和成员唯一id向量，恢复主签名
* @param sec_key_vec BLS签名向量
* @param id_vec BLS算法的成员唯一id向量
* @param n 向量的长度
* @returns 返回主签名，可为空
*/
pub fn bls_signature_recover(sig_vec: &BlsSigVec, id_vec: &BlsIdVec, n: usize) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscSignatureRecover(sig_vec.0, id_vec.0, n);
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr, true))
    }
}

/**
* BLS签名
* @param sec_key BLS私钥
* @param data 待签名的数据
* @returns 返回签名，可为空
*/
pub fn bls_sign(sec_key: &BlsSecretKey, data: Arc<Vec<u8>>) -> Option<BlsSignature> {
    unsafe {
        let ptr = blscSign(sec_key.0, data.as_ptr() as *const c_void, data.len());
        if ptr.is_null() {
            return None;
        }
        Some(BlsSignature(ptr, true))
    }
}

/**
* 验证BLS签名
* @param sig BLS签名
* @param pub_key BLS公钥
* @param data 已签名数据
* @returns 返回验证签名是否成功
*/
pub fn bls_verify(sig: &BlsSignature, pub_key: &BlsPublicKey, data: Arc<Vec<u8>>) -> bool {
    unsafe {
        if blscVerify(sig.0, pub_key.0, data.as_ptr() as *const c_void, data.len()) != 1 {
            return false;
        }
        true
    }
}

