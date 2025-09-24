// Copyright 2024, Horizen Labs, Inc.
// Copyright 2021 0KIMS association.
//
// freda_verifier is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// freda_verifier is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with freda_verifier.  If not, see <http://www.gnu.org/licenses/>.

use substrate_bn::arith::U256;

pub(crate) trait Hasher {
    fn hash(&self) -> [u8; 32];
}

impl Hasher for [u8] {
    fn hash(&self) -> [u8; 32] {
        use digest::Digest;
        sha3::Keccak256::digest(self).into()
    }
}

const MAX_HASH_LEN: usize = 25;

impl Hasher for &[U256] {
    fn hash(&self) -> [u8; 32] {
        if self.len() > MAX_HASH_LEN {
            panic!("Too many elements in hasher");
        }
        let mut buffer = [0_u8; MAX_HASH_LEN * 32];
        for (pos, d) in self.iter().enumerate() {
            d.to_big_endian(&mut buffer[pos * 32..(pos + 1) * 32])
                .expect("BUG: should never fails!");
        }
        buffer[0..self.len() * 32].hash()
    }
}

impl Hasher for [U256] {
    fn hash(&self) -> [u8; 32] {
        (&self).hash()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        macros::{fr, u256},
        utils::IntoFr,
    };
    use rstest::rstest;

    use super::*;

    impl<const S: usize> Hasher for [U256; S] {
        fn hash(&self) -> [u8; 32] {
            self.as_slice().hash()
        }
    }

    #[rstest]
    #[case::zero(fr!("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), [U256::zero()])]
    #[case::zero_of_zero(fr!("20aa000426f73d95c72abaf47f289e50874dd894230eee8e3e67ccc2a42d61d8"), [u256!("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563")])]
    #[case::zero_zero(fr!("1c053d5dd362f3501993d420ba93e87eb29b2bb845ddeefe74b26929c7ba5fb2"), [U256::zero(), U256::zero()])]
    #[case::zero_zero_zero(fr!("160bbcda5f7abc0bf6dbdd2720f72234c32292be4f6b386a4707aac730c08c20"), [U256::zero(), U256::zero(), U256::zero()])]
    #[case::some_u256(fr!("07d87f7eed9223d1a55da14bb15eb643a549958a8e4006dba9367247b039b571"), 
    [u256!("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), U256::zero()])]
    #[case::some_u256(fr!("189b3f9023ec42435ff11d489e03af64b7632d6c8e6e413a504ae617e1282d97"), 
    [u256!("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), U256::zero(), u256!("20aa000426f73d95c72abaf47f289e50874dd894230eee8e3e67ccc2a42d61d8")])]
    fn generate_valid_hash_against_the_one_used_in_the_solidity_impl(
        #[case] expected: substrate_bn::Fr,
        #[case] input: impl Hasher,
    ) {
        // All challenges are corrected to be Fr element (computed a module)
        assert_eq!(expected, input.hash().into_fr())
    }
}
