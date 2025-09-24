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

#![cfg(feature = "serde")]

pub mod fr {
    use substrate_bn::{arith::U256, Fr};

    use crate::utils::{IntoBytes, IntoFr};

    pub fn serialize<S>(fr: &Fr, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let u256 = fr.into_u256();
        if s.is_human_readable() {
            ethnum::serde::decimal::serialize(&ethnum::U256::from_words(u256.0[1], u256.0[0]), s)
        } else {
            s.serialize_bytes(&u256.into_bytes())
        }
    }

    pub fn deserialize<'de, D>(data: D) -> Result<Fr, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if data.is_human_readable() {
            let u256: ethnum::U256 = ethnum::serde::decimal::deserialize(data)?;
            Ok(U256([u256.0[0], u256.0[1]]).into_fr())
        } else {
            <[u8; 32] as serde::Deserialize>::deserialize(data).map(IntoFr::into_fr)
        }
    }
}

mod fq {
    use substrate_bn::{arith::U256, Fq};

    use crate::utils::{IntoBytes, IntoU256};

    pub fn serialize<S>(fq: &Fq, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let u256 = fq.into_u256();
        if s.is_human_readable() {
            ethnum::serde::decimal::serialize(&ethnum::U256::from_words(u256.0[1], u256.0[0]), s)
        } else {
            s.serialize_bytes(&u256.into_bytes())
        }
    }

    pub fn deserialize<'de, D>(data: D) -> Result<Fq, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let u256 = if data.is_human_readable() {
            let u256: ethnum::U256 = ethnum::serde::decimal::deserialize(data)?;
            U256([u256.0[0], u256.0[1]])
        } else {
            <[u8; 32] as serde::Deserialize>::deserialize(data).map(IntoU256::into_u256)?
        };
        Fq::from_u256(u256).map_err(|_e| serde::de::Error::custom("Invalid Fq value"))
    }
}

mod fq2 {
    use serde::{Deserialize, Serialize};
    use substrate_bn::{Fq, Fq2};

    #[derive(Serialize, Deserialize)]
    struct Fq2Serde(
        #[serde(with = "super::fq")] Fq,
        #[serde(with = "super::fq")] Fq,
    );

    pub fn serialize<S>(fq2: &Fq2, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Fq2Serde(fq2.real(), fq2.imaginary()).serialize(s)
    }

    pub fn deserialize<'de, D>(data: D) -> Result<Fq2, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fq2 = Fq2Serde::deserialize(data)?;
        Ok(Fq2::new(fq2.0, fq2.1))
    }
}

pub mod g2 {
    use serde::{Deserialize, Serialize};
    use substrate_bn::{AffineG2, Fq2, Group, G2};

    #[derive(Serialize, Deserialize)]
    struct G2Serde(
        #[serde(with = "super::fq2")] Fq2,
        #[serde(with = "super::fq2")] Fq2,
        #[serde(with = "super::fq2")] Fq2,
    );

    pub fn serialize<S>(g2: &G2, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        G2Serde(g2.x(), g2.y(), g2.z()).serialize(s)
    }

    fn check_point<'de, D>(point: &G2) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut check = point.clone();
        check.normalize();
        AffineG2::new(check.x(), check.y())
            .map_err(|_e| serde::de::Error::custom("Invalid G2 point"))?;
        Ok(())
    }

    pub fn deserialize<'de, D>(data: D) -> Result<G2, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let g2 = G2Serde::deserialize(data)?;
        let candidate = G2::new(g2.0, g2.1, g2.2);
        check_point::<D>(&candidate)?;
        Ok(candidate)
    }
}

pub mod g1 {
    use serde::{Deserialize, Serialize};
    use substrate_bn::{AffineG1, Fq, Group, G1};

    #[derive(Serialize, Deserialize)]
    struct G1Serde(
        #[serde(with = "super::fq")] Fq,
        #[serde(with = "super::fq")] Fq,
        #[serde(with = "super::fq")] Fq,
    );

    pub fn serialize<S>(g1: &G1, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        G1Serde(g1.x(), g1.y(), g1.z()).serialize(s)
    }

    fn check_point<'de, D>(point: &G1) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut check = point.clone();
        check.normalize();
        AffineG1::new(check.x(), check.y())
            .map_err(|_e| serde::de::Error::custom("Invalid G1 point"))?;
        Ok(())
    }

    pub fn deserialize<'de, D>(data: D) -> Result<G1, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let g1 = G1Serde::deserialize(data)?;
        let candidate = G1::new(g1.0, g1.1, g1.2);
        check_point::<D>(&candidate)?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod should {
    use ::serde::Deserialize;
    use pretty_assertions::assert_eq;

    use super::super::*;

    // Just because `json!` macro need `vec!` macro.
    #[cfg(feature = "std")]
    #[test]
    fn serialize_the_valid_json() {
        let vk = VerificationKey::default();

        let serialized = serde_json::to_string(&vk).unwrap();

        let v: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        let expected = serde_json::json!({
        "power": 24,
        "k1": "2",
        "k2": "3",
        "w": "5709868443893258075976348696661355716898495876243883251619397131511003808859",
        "w3": "21888242871839275217838484774961031246154997185409878258781734729429964517155",
        "w4": "21888242871839275217838484774961031246007050428528088939761107053157389710902",
        "w8": "19540430494807482326159819597004422086093766032135589407132600596362845576832",
        "wr": "18200100796661656210024324131237448517259556535315737226009542456080026430510",
        "X_2": [
        [
        "21831381940315734285607113342023901060522397560371972897001948545212302161822",
        "17231025384763736816414546592865244497437017442647097510447326538965263639101"
        ],
        [
        "2388026358213174446665280700919698872609886601280537296205114254867301080648",
        "11507326595632554467052522095592665270651932854513688777769618397986436103170"
        ],
        [
        "1",
        "0"
        ]
        ],
        "C0": [
        "7436841426934271843999872946312645822871802402068881571108027575346498207286",
        "18448034242258174646222819724328439025708531082946938915005051387020977719791",
        "1"
        ]
        });
        assert_eq!(expected, v);
    }

    #[test]
    fn deserialize_the_verification_key_json() {
        let json = r#"
        {
            "protocol": "freda",
            "curve": "bn128",
            "nPublic": 1,
            "power": 24,
            "k1": "2",
            "k2": "3",
            "w": "5709868443893258075976348696661355716898495876243883251619397131511003808859",
            "w3": "21888242871839275217838484774961031246154997185409878258781734729429964517155",
            "w4": "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "w8": "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            "wr": "18200100796661656210024324131237448517259556535315737226009542456080026430510",
            "X_2": [
            [
            "21831381940315734285607113342023901060522397560371972897001948545212302161822",
            "17231025384763736816414546592865244497437017442647097510447326538965263639101"
            ],
            [
            "2388026358213174446665280700919698872609886601280537296205114254867301080648",
            "11507326595632554467052522095592665270651932854513688777769618397986436103170"
            ],
            [
            "1",
            "0"
            ]
            ],
            "C0": [
            "7436841426934271843999872946312645822871802402068881571108027575346498207286",
            "18448034242258174646222819724328439025708531082946938915005051387020977719791",
            "1"
            ]
        }
        "#;
        let vk: VerificationKey = serde_json::from_str(json).unwrap();

        assert_eq!(VerificationKey::default(), vk);
    }

    #[test]
    fn serialize_deserialize_default_key() {
        let vk = VerificationKey::default();
        let json = serde_json::to_string(&vk).unwrap();
        let other = serde_json::from_str(&json).unwrap();

        assert_eq!(vk, other);
    }

    #[test]
    fn serialize_deserialize_in_a_non_human_readable_format() {
        let vk = VerificationKey::default();
        let mut buffer = [0_u8; 600];
        ciborium::into_writer(&vk, buffer.as_mut_slice()).unwrap();
        let other = ciborium::from_reader(buffer.as_slice()).unwrap();
        assert_eq!(vk, other);
    }

    #[test]
    #[should_panic(expected = "Invalid G1 point")]
    fn raise_error_if_try_to_deserialize_an_invalid_g1_point() {
        let json = r#"["1", "2", "3"]"#;
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Test(#[cfg_attr(feature = "serde", serde(with = "super::g1"))] G1);

        serde_json::from_str::<Test>(json).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid G2 point")]
    fn raise_error_if_try_to_deserialize_an_invalid_g2_point() {
        let json = r#"[["1", "2"], ["3", "4"], ["5", "6"]]"#;
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Test(#[cfg_attr(feature = "serde", serde(with = "super::g2"))] G2);

        serde_json::from_str::<Test>(json).unwrap();
    }
}
