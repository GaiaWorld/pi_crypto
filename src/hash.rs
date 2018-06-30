pub use rcrypto::digest::Digest;
use std::hash::Hasher;
use rcrypto::sha3::{Sha3};
use rcrypto::ripemd160::Ripemd160;
use siphasher::sip::SipHasher24;
use pi_math::hash::{H32, H160, H256};

pub struct DHash160 {
	sha256: Sha3,
	ripemd: Ripemd160,
}

impl Default for DHash160 {
	fn default() -> Self {
		DHash160 {
			sha256: Sha3::keccak256(),
			ripemd: Ripemd160::new(),
		}
	}
}

impl DHash160 {
	pub fn new() -> Self {
		DHash160::default()
	}
}

impl Digest for DHash160 {
	fn input(&mut self, d: &[u8]) {
		self.sha256.input(d)
	}

	fn result(&mut self, out: &mut [u8]) {
		let mut tmp = [0u8; 32];
		self.sha256.result(&mut tmp);
		self.ripemd.input(&tmp);
		self.ripemd.result(out);
		self.ripemd.reset();
	}

	fn reset(&mut self) {
		self.sha256.reset();
	}

	fn output_bits(&self) -> usize {
		160
	}

	fn block_size(&self) -> usize {
		64
	}
}

pub struct DHash256 {
	hasher: Sha3,
}

impl Default for DHash256 {
	fn default() -> Self {
		DHash256 {
			hasher: Sha3::keccak256(),
		}
	}
}

impl DHash256 {
	pub fn new() -> Self {
		DHash256::default()
	}

	pub fn finish(mut self) -> H256 {
		let mut result = H256::default();
		self.result(&mut *result);
		result
	}
}

impl Digest for DHash256 {
	fn input(&mut self, d: &[u8]) {
		self.hasher.input(d)
	}

	fn result(&mut self, out: &mut [u8]) {
		self.hasher.result(out);
		self.hasher.reset();
		self.hasher.input(out);
		self.hasher.result(out);
	}

	fn reset(&mut self) {
		self.hasher.reset();
	}

	fn output_bits(&self) -> usize {
		256
	}

	fn block_size(&self) -> usize {
		64
	}
}

/// RIPEMD160
#[inline]
pub fn ripemd160(input: &[u8]) -> H160 {
	let mut result = H160::default();
	let mut hasher = Ripemd160::new();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// Sha3-Keccak256
#[inline]
pub fn keccak256(input: &[u8]) -> H256 {
	let mut result = H256::default();
	let mut hasher = Sha3::keccak256();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// Sha3-Keccak256 and RIPEMD160
#[inline]
pub fn dhash160(input: &[u8]) -> H160 {
	let mut result = H160::default();
	let mut hasher = DHash160::new();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// Double Sha3-Keccak256
#[inline]
pub fn dhash256(input: &[u8]) -> H256 {
	let mut result = H256::default();
	let mut hasher = DHash256::new();
	hasher.input(input);
	hasher.result(&mut *result);
	result
}

/// SipHash-2-4
#[inline]
pub fn siphash24(key0: u64, key1: u64, input: &[u8]) -> u64 {
	let mut hasher = SipHasher24::new_with_keys(key0, key1);
	hasher.write(input);
	hasher.finish()
}

/// Data checksum
#[inline]
pub fn checksum(data: &[u8]) -> H32 {
	let mut result = H32::default();
	result.copy_from_slice(&dhash256(data)[0..4]);
	result
}

#[cfg(test)]
mod tests {
	use super::{ripemd160, keccak256, dhash160, dhash256, siphash24, checksum};
	#[test]
	fn test_ripemd160() {
		let expected = "108f07b8382412612c048d07d13f814118445acd".into();
		let result = ripemd160(b"hello");
		assert_eq!(result, expected);
	}

	#[test]
	fn test_keccak256() {
		let expected = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8".into();
		let result = keccak256(b"hello");
		assert_eq!(result, expected);

        let expected = "7624778dedc75f8b322b9fa1632a610d40b85e106c7d9bf0e743a9ce291b9c6f".into();
		let result = keccak256(b"hi");
		assert_eq!(result, expected);
	}

	#[test]
	fn test_dhash160() {
		let expected = "828636e4af6f5476e22104fe0bb921482e9aaf03".into();
		let result = dhash160(b"hello");
		assert_eq!(result, expected);

		let expected = "e7918733ee56ed9a3d2298b7212a7b064432b8cc".into();
		let result = dhash160(b"210292be03ed9475445cc24a34a115c641a67e4ff234ccb08cb4c5cea45caa526cb26ead6ead6ead6ead6eadac");
		assert_eq!(result, expected);
	}

	#[test]
	fn test_dhash256() {
		let expected = "5d301403171467692c18ed2549c8e41e0c3f7451d43554323cf5cd1bed64b2bb".into();
		let result = dhash256(b"hello");
		assert_eq!(result, expected);
	}

	#[test]
	fn test_siphash24() {
		let expected = 0x74f839c593dc67fd_u64;
		let result = siphash24(0x0706050403020100_u64, 0x0F0E0D0C0B0A0908_u64, &[0; 1]);
		assert_eq!(result, expected);
	}

	#[test]
	fn test_checksum() {
		assert_eq!(checksum(b"hello"), "5d301403".into());
	}
}
