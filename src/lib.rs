#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

//! 常用加密码学算法
//! # 哈希算法
//! 
//! # 签名算法
//! # hmac算法
//! # jwt算法
//! # 密码学安全的随机数

pub mod digest;
pub mod ed25519;
#[cfg(feature="bls")]
pub mod bls;
pub mod hmac;
pub mod signature;
pub mod random;
pub mod jwt;
