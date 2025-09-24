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

use snafu::Snafu;
use substrate_bn::{arith::U256, AffineG1, FieldError, Fq, Fr, GroupError, G1};

use crate::utils::IntoBytes;

#[derive(Clone, PartialEq, Debug)]
pub struct ProofData([U256; 24]);
pub type ProofRawData = [u8; 32 * 24];

#[cfg_attr(
    feature = "serde",
    derive(::serde::Serialize, ::serde::Deserialize),
    serde(rename_all = "SCREAMING_SNAKE_CASE")
)]
/// Proof's Polynomial.
pub struct Polynomials {
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::g1"))]
    pub c1: G1,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::g1"))]
    pub c2: G1,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::g1"))]
    pub w1: G1,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::g1"))]
    pub w2: G1,
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
/// Proof's Evaluation values.
pub struct Evaluations {
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub ql: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub qr: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub qm: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub qo: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub qc: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub s1: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub s2: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub s3: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub a: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub b: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub c: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub z: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub zw: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub t1w: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub t2w: Fr,
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::fr"))]
    pub inv: Fr,
}

/// The Proof data: use the implemented conversion traits `TryFrom` to build it.
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Proof {
    pub polynomials: Polynomials,
    pub evaluations: Evaluations,
}

#[derive(Snafu, Debug)]
pub enum ProofDataError {
    #[snafu(display("Invalid field proof data '{field}': {error:?}"))]
    InvalidField {
        field: &'static str,
        error: FieldError,
    },
    #[snafu(display("Invalid point proof data '{field}': {error:?}"))]
    InvalidGroup {
        field: &'static str,
        error: GroupError,
    },
}

#[derive(Debug)]
pub enum ProofFields {
    C1,
    C2,
    W1,
    W2,
    Ql,
    Qr,
    Qm,
    Qo,
    Qc,
    S1,
    S2,
    S3,
    A,
    B,
    C,
    Z,
    Zw,
    T1w,
    T2w,
    Inv,
}

impl TryFrom<&ProofData> for Polynomials {
    type Error = ProofDataError;

    fn try_from(data: &ProofData) -> Result<Self, Self::Error> {
        use ProofFields::*;
        Ok(Self {
            c1: read_g1(C1, &data.0[..2])?,
            c2: read_g1(C2, &data.0[2..4])?,
            w1: read_g1(W1, &data.0[4..6])?,
            w2: read_g1(W2, &data.0[6..8])?,
        })
    }
}

impl TryFrom<&ProofData> for Evaluations {
    type Error = ProofDataError;

    fn try_from(data: &ProofData) -> Result<Self, Self::Error> {
        use ProofFields::*;
        Ok(Self {
            ql: read_fr(Ql, data.0[8])?,
            qr: read_fr(Qr, data.0[9])?,
            qm: read_fr(Qm, data.0[10])?,
            qo: read_fr(Qo, data.0[11])?,
            qc: read_fr(Qc, data.0[12])?,
            s1: read_fr(S1, data.0[13])?,
            s2: read_fr(S2, data.0[14])?,
            s3: read_fr(S3, data.0[15])?,
            a: read_fr(A, data.0[16])?,
            b: read_fr(B, data.0[17])?,
            c: read_fr(C, data.0[18])?,
            z: read_fr(Z, data.0[19])?,
            zw: read_fr(Zw, data.0[20])?,
            t1w: read_fr(T1w, data.0[21])?,
            t2w: read_fr(T2w, data.0[22])?,
            inv: read_fr(Inv, data.0[23])?,
        })
    }
}

impl From<Proof> for ProofData {
    fn from(value: Proof) -> Self {
        Self([
            value.polynomials.c1.x().into_u256(),
            value.polynomials.c1.y().into_u256(),
            value.polynomials.c2.x().into_u256(),
            value.polynomials.c2.y().into_u256(),
            value.polynomials.w1.x().into_u256(),
            value.polynomials.w1.y().into_u256(),
            value.polynomials.w2.x().into_u256(),
            value.polynomials.w2.y().into_u256(),
            value.evaluations.ql.into_u256(),
            value.evaluations.qr.into_u256(),
            value.evaluations.qm.into_u256(),
            value.evaluations.qo.into_u256(),
            value.evaluations.qc.into_u256(),
            value.evaluations.s1.into_u256(),
            value.evaluations.s2.into_u256(),
            value.evaluations.s3.into_u256(),
            value.evaluations.a.into_u256(),
            value.evaluations.b.into_u256(),
            value.evaluations.c.into_u256(),
            value.evaluations.z.into_u256(),
            value.evaluations.zw.into_u256(),
            value.evaluations.t1w.into_u256(),
            value.evaluations.t2w.into_u256(),
            value.evaluations.inv.into_u256(),
        ])
    }
}

impl From<[U256; 24]> for ProofData {
    fn from(value: [U256; 24]) -> Self {
        Self(value)
    }
}

impl From<ProofData> for ProofRawData {
    fn from(value: ProofData) -> Self {
        let mut out = [0_u8; core::mem::size_of::<Self>()];
        value
            .0
            .into_iter()
            .flat_map(|it| it.into_bytes().into_iter())
            .enumerate()
            .for_each(|(pos, v)| out[pos] = v);
        out
    }
}

impl From<Proof> for ProofRawData {
    fn from(value: Proof) -> Self {
        ProofData::from(value).into()
    }
}

impl TryFrom<&ProofData> for Proof {
    type Error = ProofDataError;

    fn try_from(data: &ProofData) -> Result<Self, Self::Error> {
        Ok(Self {
            polynomials: Polynomials::try_from(data)?,
            evaluations: Evaluations::try_from(data)?,
        })
    }
}

impl TryFrom<ProofData> for Proof {
    type Error = ProofDataError;

    fn try_from(data: ProofData) -> Result<Self, Self::Error> {
        (&data).try_into()
    }
}

impl TryFrom<&ProofRawData> for Proof {
    type Error = ProofDataError;

    fn try_from(data: &ProofRawData) -> Result<Self, Self::Error> {
        ProofData([
            U256::from_slice(&data[0x000..0x020]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x020..0x040]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x040..0x060]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x060..0x080]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x080..0x0A0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x0A0..0x0C0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x0C0..0x0E0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x0E0..0x100]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x100..0x120]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x120..0x140]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x140..0x160]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x160..0x180]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x180..0x1A0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x1A0..0x1C0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x1C0..0x1E0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x1E0..0x200]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x200..0x220]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x220..0x240]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x240..0x260]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x260..0x280]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x280..0x2A0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x2A0..0x2C0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x2C0..0x2E0]).expect("Cannot fail to read 32 bytes"),
            U256::from_slice(&data[0x2E0..0x300]).expect("Cannot fail to read 32 bytes"),
        ])
        .try_into()
    }
}

impl ProofFields {
    fn str(&self) -> &'static str {
        match self {
            ProofFields::C1 => "c1",
            ProofFields::C2 => "c2",
            ProofFields::W1 => "w1",
            ProofFields::W2 => "w2",
            ProofFields::Ql => "ql",
            ProofFields::Qr => "qr",
            ProofFields::Qm => "qm",
            ProofFields::Qo => "qo",
            ProofFields::Qc => "qc",
            ProofFields::S1 => "s1",
            ProofFields::S2 => "s2",
            ProofFields::S3 => "s3",
            ProofFields::A => "a",
            ProofFields::B => "b",
            ProofFields::C => "c",
            ProofFields::Z => "z",
            ProofFields::Zw => "zw",
            ProofFields::T1w => "t1w",
            ProofFields::T2w => "t2w",
            ProofFields::Inv => "inv",
        }
    }

    fn x_str(&self) -> &'static str {
        match self {
            ProofFields::C1 => "c1.x",
            ProofFields::C2 => "c2.x",
            ProofFields::W1 => "w1.x",
            ProofFields::W2 => "w2.x",
            _ => "__undefined__x__",
        }
    }

    fn y_str(&self) -> &'static str {
        match self {
            ProofFields::C1 => "c1.y",
            ProofFields::C2 => "c2.y",
            ProofFields::W1 => "w1.y",
            ProofFields::W2 => "w2.y",
            _ => "__undefined__y__",
        }
    }
}

fn read_g1(field: ProofFields, data: &[U256]) -> Result<G1, ProofDataError> {
    let x = read_fq(field.x_str(), data[0])?;
    let y = read_fq(field.y_str(), data[1])?;
    AffineG1::new(x, y)
        .map_err(|e| ProofDataError::InvalidGroup {
            field: field.str(),
            error: e,
        })
        .map(Into::into)
}

fn read_fq(addr: &'static str, data: U256) -> Result<Fq, ProofDataError> {
    Fq::from_u256(data).map_err(|e| ProofDataError::InvalidField {
        field: addr,
        error: e,
    })
}

fn read_fr(field: ProofFields, data: U256) -> Result<Fr, ProofDataError> {
    Fr::new(data).ok_or_else(|| ProofDataError::InvalidField {
        field: field.str(),
        error: FieldError::NotMember,
    })
}

#[cfg(test)]
mod should {
    use rstest::rstest;

    use crate::macros::{u256, u256s};

    use super::*;

    const PROOF_DATA: ProofData = ProofData(u256s![
        "17f87a599ca7d3a86ffd7de8cf12adcfd418136c14aec5ced91f4a49b2975c2c",
        "1287c8ed2b2009c6fe9031e272439442d8ccda251de9c8737c2e5af3689a1767",
        "1b74f0d660e9e88f0f8f87c6e32be65cb71204e4fd385c29fa93f3aa043c26ba",
        "2581eb0d9e2b5942ec8ffc9d61650e05d049c8d35b986f1224b6876d12b6194b",
        "1da25c0ab8021a9b52681e5510be5f2e38bc5daf6ade3d58a0d54711aa33c534",
        "1fed05884b416a93d551d27a6fdf683972568ff0d2c9a26c8425d0604c3b77a9",
        "2ca037535c6e9d94a8cf15511dd38a5a43377816242ce93846d8f882306f39a3",
        "17daf2a44ced35aa8ac02921c5f8c0557f30290d5940f52e2d1fa4608ea5b1db",
        "0954ff268194b6e09677a8e930a1cf8e38b5315807ed8b393954b626263896d9",
        "184f910581d502641cd8cff4512b1d4e382932b55dc8d816484b9de0c9c43630",
        "1a345a58b9a9f87ac671a3f7bb17032c41a75a537f9101a5aeb83009feeef401",
        "0c74addd2dbe0ee47fcfc2b1cf5cec3c5e86692ef48f1c0235fad1d7a01c668e",
        "03372f5c6df30567156e9a2788f8a404033b4cc12591084918018425b36c85e1",
        "20120c2975a7dfb730fdae333a771049473e4c13eb3ccd85911d8a6e1a8ec19f",
        "00e2b3945fa3224f8f395791ed78709d153044397bf0a48cc41a2007b5228086",
        "012b96cd44c4f4ea2fdc8beb2414e0bb5b3c9de9df1a938044e522e1c6fff631",
        "25008ebe0c16aac088bc38cbb5f487b5601673421aa31462869c8c992e4ca321",
        "181f1c35924e14d4b3aa39a55331f016e7a1bda6b0562f227493c38f2bcd94aa",
        "1ea83ce07e30d84945c0a665d1f9e0e93fd2db9f3a61fd9c05f33e753715dbec",
        "1deed29feb3a59387ea9b087fc0c6b36b2a69124da7ced65b852d1535a385b64",
        "1a950c68fe0cd92b6f4e83890b62a8e115f126ba0399084b6def365ed80fe360",
        "27887a2f0b8a87c873b171d74db622cd77e67291bee1c59a9fa7f00ca0b87e95",
        "09c6dfcc7db43ceee36998f660efa5e1c485a083a43c497b8e1061ab2b9bc0c2",
        "1948698c7b7f3b4c2b6f8ca07f6ca519c27dc72e87e67bbe4675a92a92371897",
    ]);

    const PROOF_RAW_DATA: ProofRawData = hex_literal::hex!(
        r#"
        17f87a599ca7d3a86ffd7de8cf12adcfd418136c14aec5ced91f4a49b2975c2c
        1287c8ed2b2009c6fe9031e272439442d8ccda251de9c8737c2e5af3689a1767
        1b74f0d660e9e88f0f8f87c6e32be65cb71204e4fd385c29fa93f3aa043c26ba
        2581eb0d9e2b5942ec8ffc9d61650e05d049c8d35b986f1224b6876d12b6194b
        1da25c0ab8021a9b52681e5510be5f2e38bc5daf6ade3d58a0d54711aa33c534
        1fed05884b416a93d551d27a6fdf683972568ff0d2c9a26c8425d0604c3b77a9
        2ca037535c6e9d94a8cf15511dd38a5a43377816242ce93846d8f882306f39a3
        17daf2a44ced35aa8ac02921c5f8c0557f30290d5940f52e2d1fa4608ea5b1db
        0954ff268194b6e09677a8e930a1cf8e38b5315807ed8b393954b626263896d9
        184f910581d502641cd8cff4512b1d4e382932b55dc8d816484b9de0c9c43630
        1a345a58b9a9f87ac671a3f7bb17032c41a75a537f9101a5aeb83009feeef401
        0c74addd2dbe0ee47fcfc2b1cf5cec3c5e86692ef48f1c0235fad1d7a01c668e
        03372f5c6df30567156e9a2788f8a404033b4cc12591084918018425b36c85e1
        20120c2975a7dfb730fdae333a771049473e4c13eb3ccd85911d8a6e1a8ec19f
        00e2b3945fa3224f8f395791ed78709d153044397bf0a48cc41a2007b5228086
        012b96cd44c4f4ea2fdc8beb2414e0bb5b3c9de9df1a938044e522e1c6fff631
        25008ebe0c16aac088bc38cbb5f487b5601673421aa31462869c8c992e4ca321
        181f1c35924e14d4b3aa39a55331f016e7a1bda6b0562f227493c38f2bcd94aa
        1ea83ce07e30d84945c0a665d1f9e0e93fd2db9f3a61fd9c05f33e753715dbec
        1deed29feb3a59387ea9b087fc0c6b36b2a69124da7ced65b852d1535a385b64
        1a950c68fe0cd92b6f4e83890b62a8e115f126ba0399084b6def365ed80fe360
        27887a2f0b8a87c873b171d74db622cd77e67291bee1c59a9fa7f00ca0b87e95
        09c6dfcc7db43ceee36998f660efa5e1c485a083a43c497b8e1061ab2b9bc0c2
        1948698c7b7f3b4c2b6f8ca07f6ca519c27dc72e87e67bbe4675a92a92371897
        "#
    );

    #[test]
    fn read_a_valid_proof() {
        Proof::try_from(&PROOF_DATA).unwrap();
    }

    #[test]
    fn read_a_valid_raw_proof() {
        Proof::try_from(&PROOF_RAW_DATA).unwrap();
    }

    #[test]
    fn convert_proof_in_proof_data() {
        assert_eq!(PROOF_DATA, Proof::try_from(&PROOF_DATA).unwrap().into());
    }

    #[test]
    fn convert_proof_in_raw_proof_data() {
        assert_eq!(
            PROOF_RAW_DATA,
            ProofRawData::from(Proof::try_from(&PROOF_RAW_DATA).unwrap())
        );
    }

    #[rstest]
    #[should_panic(expected = r#""c1", error: NotOnCurve"#)]
    #[case::invalid_curve(0, U256::from(0))]
    #[should_panic(expected = r#""w2.y", error: NotMember"#)]
    #[case::invalid_field_curve(7, u256!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"))]
    #[should_panic(expected = r#""ql", error: NotMember"#)]
    #[case::invalid_field_edge_case(8, u256!("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"))]
    #[case::valid_field_edge_case(8, u256!("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"))]
    fn reject_invalid_proof_data(#[case] id: usize, #[case] value: U256) {
        let mut proof_data = PROOF_DATA.clone();
        proof_data.0[id] = value;
        Proof::try_from(&proof_data).unwrap();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_a_valid_snarkjs_proof() {
        let json = r#"
        {
            "protocol": "freda",
            "curve": "bn128",
            "polynomials": {
                "C1": [
                "19512952758028491405934790115790312944649901939821135923885427424035043432523",
                "14556573045681247107321758464038638460236603165915844088653795891137636966580",
                "1"
                ],
                "C2": [
                "18724765532860887462293740304560312103629598712675774059706825360379977966561",
                "14533846076669948037568538427127727867276686064060198244794640904541487914310",
                "1"
                ],
                "W1": [
                "18433064140714518735926988684235687309803035076187502211354351663568191930935",
                "14788057617464302331557630380512402745218864581677826595197645173223539673357",
                "1"
                ],
                "W2": [
                "16578902799151672151956332367598573028719537462531716854255433720543688684250",
                "21622823131302647207265406578951014306163648459064954245545121280505919027356",
                "1"
                ]
            },
            "evaluations": {
                "ql": "18137169988004520649554381379919736533761028898864355980977573474774839426808",
                "qr": "20404082766518508880627958927869090077251470748406210835504197196401842200720",
                "qm": "707461819326729660985337250976599267781706195992934524838013487904784094085",
                "qo": "18963438173828461591436352330653675208295853959010167304990158722672578932373",
                "qc": "0",
                "s1": "13524886271252282626956626393365051655320699188917745152708417704896009650580",
                "s2": "3174783679655029387130611916286066252438878675967458260277093528819580058722",
                "s3": "21577928273077063144453890504595174724360613180856082038860286291422143482499",
                "a": "10974786676655016445248972047105688770512999913871262036359224483296214498183",
                "b": "21083250626163147629372415164899163984499137689834405549506537520836126119194",
                "c": "18485668148010316467769714971633785148294508157898193267298903173050206942624",
                "z": "16553584390052184118636614382976559370280626167659817002054727638080918750406",
                "zw": "4415347360457194011128422992457486517452412864360300524180855069319812783387",
                "t1w": "14054646597435401354125275990480383598795508549938505679628793738166042203625",
                "t2w": "13096655044313949187605874896346306929343048005668253765142398343590307027689",
                "inv": "7456529870837358461413290055129561230845481425037098795678169994084881795519"
            }
        }
        "#;

        assert!(serde_json::from_str::<Proof>(json).is_ok());
    }
}
