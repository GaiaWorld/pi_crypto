//! 安全的随机数生成器

use ring::rand::{SecureRandom, SystemRandom};

/// 获取指定长度的密码学安全随机数据
pub fn genSecureRandBytes(len: usize) -> Vec<u8> {
    let mut dst = vec![0; len];
    let r = SystemRandom::new();
    r.fill(&mut dst)
        .expect("Fatal error: can't get rand bytes from system");

    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_bytes() {
        let b = genSecureRandBytes(32);
        println!("{:?}", b);
    }
}
