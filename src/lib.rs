#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::new_without_default)]

//! 常用的密码学算法
//! 包括哈希，椭圆曲线，hmac, jwt, 密码学安全的随机数生成等

pub mod aes;
#[cfg(feature = "bls")]
pub mod bls;
pub mod digest;
pub mod ed25519;
pub mod hmac;
pub mod jwt;
pub mod random;
pub mod signature;
