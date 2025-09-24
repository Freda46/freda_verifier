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

macro_rules! u256 {
    ($s:literal) => {{
        const STRING: &'static [u8] = $s.as_bytes();
        $crate::macros::decode(STRING)
    }};
}
pub(crate) use u256;

#[cfg(test)]
macro_rules! fr {
    ($s:literal) => {{
        use $crate::macros::u256;
        u256!($s).into_fr()
    }};
}
#[cfg(test)]
pub(crate) use fr;

#[cfg(test)]
macro_rules! u256s {
    ($($s:literal),*) => {{
        use $crate::macros::u256;

        [$(u256!($s)),*]
    }};
    ($($s:literal,)*) => {
        u256s![$($s),*]
    };
}
#[cfg(test)]
pub(crate) use u256s;

const fn next_hex_char(string: &[u8], mut pos: usize) -> Option<(u8, usize)> {
    while pos < string.len() {
        let raw_val = string[pos];
        pos += 1;
        let val = match raw_val {
            b'0'..=b'9' => raw_val - 48,
            b'A'..=b'F' => raw_val - 55,
            b'a'..=b'f' => raw_val - 87,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            0..=127 => panic!("Encountered invalid ASCII character"),
            _ => panic!("Encountered non-ASCII character"),
        };
        return Some((val, pos));
    }
    None
}

const fn next_byte(string: &[u8], pos: usize) -> Option<(u8, usize)> {
    let (half1, pos) = match next_hex_char(string, pos) {
        Some(v) => v,
        None => return None,
    };
    let (half2, pos) = match next_hex_char(string, pos) {
        Some(v) => v,
        None => panic!("Odd number of hex characters"),
    };
    Some(((half1 << 4) + half2, pos))
}

pub(crate) const fn decode(string: &[u8]) -> U256 {
    let mut buf = [0u128; 2];
    let mut buf_pos = 1;
    let mut pos = 0;
    let mut bytes = 0;
    while let Some((byte, new_pos)) = next_byte(string, pos) {
        if bytes == 16 {
            bytes = 0;
            buf_pos -= 1;
        }
        buf[buf_pos] = buf[buf_pos] << 8 | byte as u128;
        bytes += 1;
        pos = new_pos;
    }
    assert!(
        bytes == 16 && buf_pos == 0,
        "You should provide exactly 32 bytes hex"
    );
    U256(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decode_u256_correctly() {
        let expected = U256::from_slice(&hex_literal::hex!(
            "2bb635ee7d9e1790de1d6ccec2d1e13dec5c4beffd75d71520107c791857c45e"
        ))
        .unwrap();
        assert_eq!(
            expected,
            u256!("2bb635ee7d9e1790de1d6ccec2d1e13dec5c4beffd75d71520107c791857c45e")
        );
    }
}
