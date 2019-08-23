/**
* 安全的随机数生成器
*/
use ring::rand::{SecureRandom, SystemRandom};

/**
* 获取一个安全随机数
* @param len 随机数大小
* @returns 返回安全随机数
*/
pub fn genSecureRandBytes(len: usize) -> Vec<u8> {
    let mut dst = vec![0; len];
    let r = SystemRandom::new();
    r.fill(&mut dst).expect("Fatal error: can't get rand bytes from system");

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
