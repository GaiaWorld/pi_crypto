use ring::digest as rdigest;
use crypto::md5::Md5;
use crypto::digest::Digest;

/// SHA哈希算法类型
pub enum DigestAlgorithm {
	MD5,
	SHA1,
	SHA256,
	SHA384,
	SHA512,
}

/**
* 计算二进制数据的SHA哈希
*
* @param alg SHA哈希算法类型
* @param data 待哈希的数据
* @returns 返回哈希值
*/
pub fn digest(alg: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
	match alg {
		DigestAlgorithm::MD5 => {
			let mut md5 = Md5::new();
			md5.input(data);
			let mut out = vec![0u8; 16];
			md5.result(&mut out);
			out
		}
		DigestAlgorithm::SHA1 => rdigest::digest(&rdigest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref().to_vec(),
		DigestAlgorithm::SHA256 => rdigest::digest(&rdigest::SHA256, data).as_ref().to_vec(),
		DigestAlgorithm::SHA384 => rdigest::digest(&rdigest::SHA384, data).as_ref().to_vec(),
		DigestAlgorithm::SHA512 => rdigest::digest(&rdigest::SHA512, data).as_ref().to_vec(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex::FromHex;

	#[test]
	fn test_sha1() {
		let computed = digest(DigestAlgorithm::SHA1, b"abc");
		let expected = Vec::from_hex("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
		assert_eq!(computed, expected);
	}
	#[test]
	fn test_md5() {
		let computed = digest(DigestAlgorithm::MD5, b"abc");
		let expected = Vec::from_hex("900150983CD24FB0D6963F7D28E17F72").unwrap();
		assert_eq!(computed, expected);
	}
}
