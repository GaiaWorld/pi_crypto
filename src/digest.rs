/**
* SHA加密算法
*/
use ring::digest as rdigest;

/**
* SHA加密算法类型
*/
pub enum DigestAlgorithm {
	SHA1,
	SHA256,
	SHA384,
	SHA512,
}

/**
* SHA加密
* @param alg SHA加密算法类型
* @param data 待加密的数据
* @returns 返回加密数据
*/
pub fn digest(alg: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
	match alg {
		DigestAlgorithm::SHA1 => rdigest::digest(&rdigest::SHA1, data).as_ref().to_vec(),
		DigestAlgorithm::SHA256 => rdigest::digest(&rdigest::SHA256, data).as_ref().to_vec(),
		DigestAlgorithm::SHA384 => rdigest::digest(&rdigest::SHA384, data).as_ref().to_vec(),
		DigestAlgorithm::SHA512 => rdigest::digest(&rdigest::SHA512, data).as_ref().to_vec(),
	}
}

// #[cfg(test)]
// mod tests {
// 	use super::*;
// 	use hex::FromHex;

// 	#[test]
// 	fn test_sha1() {
// 		let computed = digest(DigestAlgorithm::SHA1, b"abc");
// 		let expected = Vec::from_hex("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
// 		assert_eq!(computed, expected);
// 	}
// 	// more tests here
// }
