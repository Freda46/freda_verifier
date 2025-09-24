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

use rand::Rng;
use rstest::{fixture, rstest};

use crate::macros::u256s;

use super::*;

#[fixture]
fn valid_proof() -> Proof {
    ProofData::from(u256s![
        "283e3f25323d02dabdb94a897dc2697a3b930d8781381ec574af89a201a91d5a",
        "2c2808c59f5c736ff728eedfea58effc2443722e78b2eb4e6759a278e9246d60",
        "0f9c56dc88e043ce0b90c402e96b1f4b1a246f4d0d69a4c340bc910e1f2fd805",
        "19e465e01bd7629f175931feed102cb6459a1be7b08018b93c142e961d0352d8",
        "0b8e5d340df28c2f454c5a2535ca01a230bb945ee24b1171481a9a2c6496fed6",
        "1cf8878e40adb52dc27da5e79718f118467319d15d64fed460d69d951376ac63",
        "1a6c44faaec76e296b43fe720d700a63fd530f9064878b5f72f2ffe7458c2f03",
        "1ac6ed8c1e0758dfb3702ed29bbc0c14b5e727c164b3ade07b9f164af0be54b0",
        "143b1a6534b2dcf2bd660e1b5b420d86c0c350fd9d614b639c5df98009f1375e",
        "141259679021d0a6a3aa3aae2516bace4a4a651265217ec0ea7c0d7f89b98710",
        "0abcc93d98ff40bae16eff6c29955f7a37155bb25672b12eb5074dcb7c3e2b00",
        "1718a257cca21ee593d1ba9f8e91e5168aed8e0b1893e11a6b583d975e747f80",
        "08a8c2150a04d8f867945ca1740dc3fc3b2fc4daff61b4725fb294435a1b9010",
        "1803690ae70fc212b7e929de9a22a4642ef4772546cf93ffd1b1196a3d9113a3",
        "009c506755578932ca3630508ca1ed6ee83df5ec9e26cb0b5800a70967a1a93a",
        "04d142b6a532935a31d84f75d16929df6d38c3a210ac4f435a8024dfb7e6c1f3",
        "246d58038a943f237325b44f03d106e523adfec4324615a2dd09e1e5b9143b41",
        "1c1cf09ee411cf9864d30df4904099920cee9ae8134d45dfeb29e46115d2e740",
        "098674b8fc2ca31fac6fcc9302860654fdc1b522b7e064b0759bc5924f332fa9",
        "21121b5af880f83fbce02f19dabb8f684593e7322fb80bfc0d054797b1d4eff4",
        "11b01bf68f81f2032ae4f7fc514bd76ca1b264f3989a92e6b3d74cda4f8a7149",
        "20e4c02f5a71082a8bcf5be0b5750a244bd040a776ec541dfc2c8ae73180e924",
        "0ada5414d66387211eec80d7d9d48498efa1e646d64bb1bf8775b3796a9fd0bf",
        "0fdf8244018ce57b018c093e2f75ed77d8dbdb1a7b60a2da671de2efe5f6b9d7",
    ])
    .try_into()
    .unwrap()
}

#[fixture]
fn valid_pubs() -> Public {
    u256!("0d69b94acdfaca5bacc248a60b35b925a2374644ce0c1205db68228c8921d9d9").into()
}

#[fixture]
fn vk() -> VerificationKey {
    VerificationKey::default()
}

#[rstest]
fn compute_valid_check_paring(vk: VerificationKey, valid_proof: Proof, valid_pubs: Public) {
    let vk_data = (&vk).into();

    let challenges = Challenges::build(&vk_data, &valid_proof, &valid_pubs);
    let (inverse, l1) = challenges
        .compute_inverse(&vk_data, valid_proof.evaluations.inv)
        .unwrap();
    let pi = Proof::compute_pi(&valid_pubs, l1);
    let r0 = valid_proof.compute_r0(&challenges, &inverse.li_s0_inv);
    let r1 = valid_proof.compute_r1(&challenges, pi, inverse.zh_inv, &inverse.li_s1_inv);
    let r2 = valid_proof.compute_r2(
        &vk_data,
        &challenges,
        l1,
        inverse.zh_inv,
        &inverse.li_s2_inv,
    );

    let (f, e, j) =
        valid_proof.compute_fej(&vk, &challenges, r0, r1, r2, inverse.den_h1, inverse.den_h2);

    let result = valid_proof.check_paring(&challenges, &vk, f, e, j);

    assert!(result.is_ok())
}

#[rstest]
fn verify_valid_proof(vk: VerificationKey, valid_proof: Proof, valid_pubs: Public) {
    assert!(verify(&vk, &valid_proof, &valid_pubs).is_ok())
}

#[cfg(feature = "std")]
#[cfg(feature = "serde")]
mod verify_valid_deserialized_proof {
    use ::serde::Deserialize;

    use super::*;
    use std::path::PathBuf;

    #[rstest]
    fn from_given_files(#[files("resources/proves/*.json")] path: PathBuf) {
        #[derive(Deserialize)]
        struct Data {
            proof: String,
            pubs: String,
            vk: VerificationKey,
        }

        let Data { proof, pubs, vk } =
            serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
        let proof: Proof = (&<ProofRawData>::try_from(hex::decode(proof).unwrap()).unwrap())
            .try_into()
            .unwrap();
        let pubs: Public = <[u8; 32]>::try_from(hex::decode(pubs).unwrap())
            .unwrap()
            .into();
        verify(&vk, &proof, &pubs).unwrap()
    }
}
mod reject {
    use crate::proof::ProofFields;

    use super::*;

    #[fixture]
    fn rng() -> impl Rng {
        rand::thread_rng()
    }

    impl ProofFields {
        fn perturbed(&self, mut proof: Proof, rng: &mut impl Rng) -> Proof {
            let random = Fr::random(rng);
            match self {
                ProofFields::C1 => {
                    proof.polynomials.c1 = proof.polynomials.c1 * random;
                }
                ProofFields::C2 => {
                    proof.polynomials.c2 = proof.polynomials.c2 * random;
                }
                ProofFields::W1 => {
                    proof.polynomials.w1 = proof.polynomials.w1 * random;
                }
                ProofFields::W2 => {
                    proof.polynomials.w2 = proof.polynomials.w2 * random;
                }
                ProofFields::Ql => {
                    proof.evaluations.ql = random;
                }
                ProofFields::Qr => {
                    proof.evaluations.qr = random;
                }
                ProofFields::Qm => {
                    proof.evaluations.qm = random;
                }
                ProofFields::Qo => {
                    proof.evaluations.qo = random;
                }
                ProofFields::Qc => {
                    proof.evaluations.qc = random;
                }
                ProofFields::S1 => {
                    proof.evaluations.s1 = random;
                }
                ProofFields::S2 => {
                    proof.evaluations.s2 = random;
                }
                ProofFields::S3 => {
                    proof.evaluations.s3 = random;
                }
                ProofFields::A => {
                    proof.evaluations.a = random;
                }
                ProofFields::B => {
                    proof.evaluations.b = random;
                }
                ProofFields::C => {
                    proof.evaluations.c = random;
                }
                ProofFields::Z => {
                    proof.evaluations.z = random;
                }
                ProofFields::Zw => {
                    proof.evaluations.zw = random;
                }
                ProofFields::T1w => {
                    proof.evaluations.t1w = random;
                }
                ProofFields::T2w => {
                    proof.evaluations.t2w = random;
                }
                ProofFields::Inv => {
                    proof.evaluations.inv = random;
                }
            }
            proof
        }
    }
    use ProofFields::*;

    #[rstest]
    fn an_invalid_proof(
        mut rng: impl Rng,
        vk: VerificationKey,
        valid_proof: Proof,
        valid_pubs: Public,
        #[values(
            C1, C2, W1, W2, Ql, Qr, Qm, Qo, Qc, S1, S2, S3, A, B, C, Z, Zw, T1w, T2w, Inv
        )]
        change: ProofFields,
    ) {
        let perturbed_proof = change.perturbed(valid_proof, &mut rng);

        assert!(verify(&vk, &perturbed_proof, &valid_pubs).is_err())
    }

    #[derive(Debug)]
    pub enum VkFields {
        Power,
        K1,
        K2,
        W,
        W3,
        W4,
        W8,
        Wr,
        X2,
        C0,
    }

    impl VkFields {
        fn perturbed(&self, mut vk: VerificationKey, rng: &mut impl Rng) -> VerificationKey {
            let random = Fr::random(rng);
            let mut change = |v: &mut u8| {
                let orig = *v;
                while *v == orig {
                    *v = rng.gen();
                }
            };
            match self {
                VkFields::Power => change(&mut vk.power),
                VkFields::K1 => {
                    vk.k1 = random;
                }
                VkFields::K2 => {
                    vk.k1 = random;
                }
                VkFields::W => {
                    vk.w = random;
                }
                VkFields::W3 => {
                    vk.w3 = random;
                }
                VkFields::W4 => {
                    vk.w4 = random;
                }
                VkFields::W8 => {
                    vk.w8 = random;
                }
                VkFields::Wr => {
                    vk.wr = random;
                }
                VkFields::X2 => {
                    vk.x2 = vk.x2 * random;
                }
                VkFields::C0 => {
                    vk.c0 = vk.c0 * random;
                }
            }
            vk
        }
    }

    use VkFields::*;
    #[rstest]
    fn an_invalid_vk(
        mut rng: impl Rng,
        valid_proof: Proof,
        valid_pubs: Public,
        vk: VerificationKey,
        #[values(Power, K1, K2, W, W3, W4, W8, Wr, X2, C0)] change: VkFields,
    ) {
        let perturbed_vk = change.perturbed(vk, &mut rng);

        assert!(verify(&perturbed_vk, &valid_proof, &valid_pubs).is_err())
    }

    #[rstest]
    #[should_panic]
    fn an_invalid_public_input(mut rng: impl Rng, valid_proof: Proof) {
        let vk = VerificationKey::default();

        verify(
            &vk,
            &valid_proof,
            &U256::random(
                &mut rng,
                &u256!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            )
            .into(),
        )
        .unwrap();
    }

    #[rstest]
    #[should_panic(expected = "InvalidInverse")]
    fn an_invalid_inverse(
        mut rng: impl Rng,
        #[from(valid_proof)] mut proof: Proof,
        valid_pubs: Public,
    ) {
        let vk = VerificationKey::default();

        proof.evaluations.inv = Fr::random(&mut rng);
        verify(&vk, &proof, &valid_pubs).unwrap()
    }
}
