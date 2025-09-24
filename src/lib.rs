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

#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

use macros::u256;
use snafu::Snafu;
use substrate_bn::{arith::U256, pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};

use hash::Hasher as _;
use utils::IntoFq as _;
use utils::IntoFr as _;

pub(crate) mod hash;
mod key;
mod macros;
mod proof;
pub(crate) mod serde;
pub(crate) mod utils;

pub use proof::Proof;

/// The verification key.
pub use key::VerificationKey;
/// The proof data as `U256` fixed array.
pub use proof::ProofData;
/// The proof data as fixed size bytes array.
pub use proof::ProofRawData;

/// The public input data.
pub struct Public(U256);

impl From<U256> for Public {
    fn from(inner: U256) -> Self {
        Self(inner)
    }
}

impl From<[u8; 32]> for Public {
    fn from(inner: [u8; 32]) -> Self {
        Self(U256::from_slice(&inner).expect("Cannot fails: is a 32-byte array"))
    }
}

impl TryFrom<&[u8]> for Public {
    type Error = core::array::TryFromSliceError;

    fn try_from(inner: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(inner).map(Into::into)
    }
}

/// Verification Error
#[derive(Snafu, Debug)]
pub enum VerifyError {
    /// The provided inverse is wrong
    #[snafu(display(
        "Invalid provided inverse is {inverse:?} that's not the inverse of {computed:?}"
    ))]
    InvalidInverse { inverse: Fr, computed: Fr },
    /// Cannot verify the pairing for this proof
    #[snafu(display("Cannot verify paring"))]
    NotPairing,
}

/// Use the given verification key `vk` to verify the `proof`` against the given `pubs` public inputs.
/// Can fail if:
/// - the provided inverse in the proof is wrong
/// - the pair checking is wrong
pub fn verify(vk: &VerificationKey, proof: &Proof, pubs: &Public) -> Result<(), VerifyError> {
    let vk_data = vk.into();
    let challenges = Challenges::build(&vk_data, proof, pubs);
    let (inverse, l1) = challenges.compute_inverse(&vk_data, proof.evaluations.inv)?;
    let pi = Proof::compute_pi(pubs, l1);
    let r0 = proof.compute_r0(&challenges, &inverse.li_s0_inv);
    let r1 = proof.compute_r1(&challenges, pi, inverse.zh_inv, &inverse.li_s1_inv);
    let r2 = proof.compute_r2(
        &vk_data,
        &challenges,
        l1,
        inverse.zh_inv,
        &inverse.li_s2_inv,
    );

    let (f, e, j) = proof.compute_fej(
        vk_data.vk,
        &challenges,
        r0,
        r1,
        r2,
        inverse.den_h1,
        inverse.den_h2,
    );

    proof.check_paring(&challenges, vk_data.vk, f, e, j)
}

struct VkData<'a> {
    vk: &'a VerificationKey,
    precomputed: PrecomputedData,
}

impl<'a> From<&'a VerificationKey> for VkData<'a> {
    fn from(vk: &'a VerificationKey) -> Self {
        Self {
            vk,
            precomputed: vk.into(),
        }
    }
}

struct PrecomputedData {
    pub n: Fr,
    pub w3: [Fr; 2],
    pub w4: [Fr; 3],
    pub w8: [Fr; 7],
}

impl From<&VerificationKey> for PrecomputedData {
    fn from(vk: &VerificationKey) -> Self {
        let w3 = [vk.w3, vk.w3 * vk.w3];
        let w4_2 = vk.w4 * vk.w4;
        let w4 = [vk.w4, w4_2, vk.w4 * w4_2];
        let mut w8: [Fr; 7] = [Fr::zero(); 7];
        w8[0] = vk.w8;
        for i in 1..7 {
            w8[i] = w8[i - 1] * vk.w8;
        }
        Self {
            n: 2.into_fr().pow((vk.power as u64).into_fr()),
            w3,
            w4,
            w8,
        }
    }
}

impl Proof {
    /// Compute public input polynomial evaluation PI(xi)
    fn compute_pi(p: &Public, l1: Fr) -> Fr {
        -l1 * p.0.into_fr()
    }

    /// Compute r0(y) by interpolating the polynomial r0(X) using 8 points (x,y)
    /// where x = {h9, h0w8, h0w8^2, h0w8^3, h0w8^4, h0w8^5, h0w8^6, h0w8^7}
    /// and   y = {C0(h0), C0(h0w8), C0(h0w8^2), C0(h0w8^3), C0(h0w8^4), C0(h0w8^5), C0(h0w8^6), C0(h0w8^7)}
    /// and computing C0(xi)
    fn compute_r0(&self, challenges: &Challenges, li_s0_inv: &LiS0) -> Fr {
        let base = challenges.y.pow(8_u64.into_fr()) - challenges.xi;
        let evaluations = &self.evaluations;

        let coefficients = [
            evaluations.ql,
            evaluations.qr,
            evaluations.qo,
            evaluations.qm,
            evaluations.qc,
            evaluations.s1,
            evaluations.s2,
            evaluations.s3,
        ];

        // Compute c0Value = ql + (h0w8[i]) qr + (h0w8[i])^2 qo + (h0w8[i])^3 qm + (h0w8[i])^4 qc +
        //                      + (h0w8[i])^5 S1 + (h0w8[i])^6 S2 + (h0w8[i])^7 S3
        polynomial_eval(base, &coefficients, &challenges.h0_w8, li_s0_inv, None)
    }

    /// Compute r1(y) by interpolating the polynomial r1(X) using 4 points (x,y)
    /// where x = {h1, h1w4, h1w4^2, h1w4^3}
    /// and   y = {C1(h1), C1(h1w4), C1(h1w4^2), C1(h1w4^3)}
    /// and computing T0(xi)
    fn compute_r1(&self, challenges: &Challenges, pi: Fr, zh_inv: Fr, li_s1_inv: &LiS1) -> Fr {
        let base = challenges.y.pow(4_u64.into_fr()) - challenges.xi;
        let evaluations = &self.evaluations;

        let t0 = ((evaluations.ql * evaluations.a)
            + (evaluations.qr * evaluations.b)
            + (evaluations.qm * evaluations.a * evaluations.b)
            + (evaluations.qo * evaluations.c)
            + evaluations.qc
            + pi)
            * zh_inv;
        let coefficients = [evaluations.a, evaluations.b, evaluations.c, t0];

        polynomial_eval(base, &coefficients, &challenges.h1_w4, li_s1_inv, None)
    }

    /// Compute r2(y) by interpolating the polynomial r2(X) using 6 points (x,y)
    /// where x = {[h2, h2w3, h2w3^2], [h3, h3w3, h3w3^2]}
    /// and   y = {[C2(h2), C2(h2w3), C2(h2w3^2)], [CChallenges::C0x.into_fr()2(h3), C2(h3w3), C2(h3w3^2)]}
    /// and computing T1(xi) and T2(xi)
    fn compute_r2(
        &self,
        vk: &VkData,
        challenges: &Challenges,
        l1: Fr,
        zh_inv: Fr,
        li_s2_inv: &LiS2,
    ) -> Fr {
        let base = challenges.y.pow(6_u64.into_fr())
            - (challenges.y.pow(3_u64.into_fr()) * challenges.xi * (Fr::one() + vk.vk.w))
            + (challenges.xi * challenges.xi * vk.vk.w);
        let evaluations = &self.evaluations;

        let beta_xi = challenges.beta * challenges.xi;
        let t1 = (evaluations.z - Fr::one()) * l1 * zh_inv;
        let t2 = (((evaluations.a + beta_xi + challenges.gamma)
            * (evaluations.b + beta_xi * vk.vk.k1 + challenges.gamma)
            * (evaluations.c + beta_xi * vk.vk.k2 + challenges.gamma)
            * evaluations.z)
            - ((evaluations.a + challenges.beta * evaluations.s1 + challenges.gamma)
                * (evaluations.b + challenges.beta * evaluations.s2 + challenges.gamma)
                * (evaluations.c + challenges.beta * evaluations.s3 + challenges.gamma)
                * evaluations.zw))
            * zh_inv;

        let coefficients = [evaluations.z, t1, t2];
        let gamma = polynomial_eval(
            base,
            &coefficients,
            &challenges.h2_w3,
            &li_s2_inv[..3],
            None,
        );

        let coefficients = [evaluations.zw, evaluations.t1w, evaluations.t2w];
        polynomial_eval(
            base,
            &coefficients,
            &challenges.h3_w3,
            &li_s2_inv[3..],
            Some(gamma),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_fej(
        &self,
        vk: &VerificationKey,
        challenges: &Challenges,
        r0: Fr,
        r1: Fr,
        r2: Fr,
        den_h1: Fr,
        den_h2: Fr,
    ) -> (G1, G1, G1) {
        let polynomials = &self.polynomials;
        let numerator = challenges
            .h0_w8
            .iter()
            .fold(Fr::one(), |acc, h0_w8_i| acc * (challenges.y - *h0_w8_i));
        let quotient1 = challenges.alpha * numerator * den_h1;
        let quotient2 = challenges.alpha * challenges.alpha * numerator * den_h2;
        let f = polynomials.c1 * quotient1 + polynomials.c2 * quotient2 + vk.c0;
        let e = Challenges::g1() * (r0 + quotient1 * r1 + quotient2 * r2);
        let j = polynomials.w1 * numerator;

        (f, e, j)
    }

    fn check_paring(
        &self,
        challenges: &Challenges,
        vk: &VerificationKey,
        f: G1,
        e: G1,
        j: G1,
    ) -> Result<(), VerifyError> {
        let polynomials = &self.polynomials;
        let f = f - e - j + polynomials.w2 * challenges.y;
        if pairing_batch(&[(f, Challenges::g2_pair()), (-polynomials.w2, vk.x2)]) == Gt::one() {
            Ok(())
        } else {
            Err(VerifyError::NotPairing)
        }
    }
}

fn polynomial_eval(
    base: Fr,
    coefficients: &[Fr],
    challenges: &[Fr],
    inv: &[Fr],
    acc: Option<Fr>,
) -> Fr {
    let mut acc = acc.unwrap_or(Fr::zero());
    for (i, root) in challenges.iter().enumerate() {
        let mut h = Fr::one();
        let mut c1_value = Fr::zero();
        for c in coefficients {
            c1_value = c1_value + (*c) * h;
            h = h * *root;
        }
        acc = acc + c1_value * base * inv[i];
    }
    acc
}

trait FRedaConstants {
    fn g1() -> G1 {
        AffineG1::new(Fq::one(), 2.into_fq())
            .expect("(1, 2) Should be a valid G1 point")
            .into()
    }

    const G2_X1: U256 = u256!("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed");
    const G2_X2: U256 = u256!("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2");
    const G2_Y1: U256 = u256!("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa");
    const G2_Y2: U256 = u256!("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b");

    fn g2_pair() -> G2 {
        let g2x1 = Fq::from_u256(Self::G2_X1).expect("G2x1 should be a valid Fq point");
        let g2x2 = Fq::from_u256(Self::G2_X2).expect("G2x2 should be a valid Fq point");
        let g2y1 = Fq::from_u256(Self::G2_Y1).expect("G2y1 should be a valid Fq point");
        let g2y2 = Fq::from_u256(Self::G2_Y2).expect("G2y2 should be a valid Fq point");
        AffineG2::new(Fq2::new(g2x1, g2x2), Fq2::new(g2y1, g2y2))
            .expect("Should be on curve")
            .into()
    }
}

#[derive(Debug)]
struct Challenges {
    beta: Fr,
    gamma: Fr,
    h0_w8: [Fr; 8],
    h1_w4: [Fr; 4],
    h2_w3: [Fr; 3],
    h3_w3: [Fr; 3],
    xi: Fr,
    zh: Fr,
    alpha: Fr,
    y: Fr,
}

type LiS0 = [Fr; 8];
type LiS1 = [Fr; 4];
type LiS2 = [Fr; 6];

#[derive(Debug, PartialEq)]
struct Inverse {
    li_s0_inv: LiS0,
    li_s1_inv: LiS1,
    li_s2_inv: LiS2,
    den_h1: Fr,
    den_h2: Fr,
    zh_inv: Fr,
}

impl Challenges {
    fn build(vk: &VkData, proof: &Proof, public: &Public) -> Self {
        let precomputed = &vk.precomputed;
        let vk = vk.vk;
        let Proof {
            ref polynomials,
            ref evaluations,
        } = proof;

        let beta = [
            vk.c0.x().into_u256(),
            vk.c0.y().into_u256(),
            public.0,
            polynomials.c1.x().into_u256(),
            polynomials.c1.y().into_u256(),
        ]
        .hash()
        .into_fr();
        let gamma = [beta.into_u256()].hash().into_fr();
        let xi_seed = [
            gamma.into_u256(),
            polynomials.c2.x().into_u256(),
            polynomials.c2.y().into_u256(),
        ]
        .hash()
        .into_fr();
        let xi_seed_2 = xi_seed * xi_seed;
        let xi_seed_3 = xi_seed * xi_seed_2;
        let h0_w8 = [
            xi_seed_3,
            xi_seed_3 * precomputed.w8[0],
            xi_seed_3 * precomputed.w8[1],
            xi_seed_3 * precomputed.w8[2],
            xi_seed_3 * precomputed.w8[3],
            xi_seed_3 * precomputed.w8[4],
            xi_seed_3 * precomputed.w8[5],
            xi_seed_3 * precomputed.w8[6],
        ];
        let xi_seed_6 = xi_seed_3 * xi_seed_3;
        let h1_w4 = [
            xi_seed_6,
            xi_seed_6 * precomputed.w4[0],
            xi_seed_6 * precomputed.w4[1],
            xi_seed_6 * precomputed.w4[2],
        ];
        let xi_seed_8 = xi_seed_6 * xi_seed_2;
        let h2_w3 = [
            xi_seed_8,
            xi_seed_8 * precomputed.w3[0],
            xi_seed_8 * precomputed.w3[1],
        ];
        let h3_w3_0 = xi_seed_8 * vk.wr;
        let h3_w3 = [
            h3_w3_0,
            h3_w3_0 * precomputed.w3[0],
            h3_w3_0 * precomputed.w3[1],
        ];
        let xi = xi_seed_8 * xi_seed_8 * xi_seed_8;
        let zh = xi.pow(precomputed.n) - Fr::one();
        let alpha = [
            xi_seed.into_u256(),
            evaluations.ql.into_u256(),
            evaluations.qr.into_u256(),
            evaluations.qm.into_u256(),
            evaluations.qo.into_u256(),
            evaluations.qc.into_u256(),
            evaluations.s1.into_u256(),
            evaluations.s2.into_u256(),
            evaluations.s3.into_u256(),
            evaluations.a.into_u256(),
            evaluations.b.into_u256(),
            evaluations.c.into_u256(),
            evaluations.z.into_u256(),
            evaluations.zw.into_u256(),
            evaluations.t1w.into_u256(),
            evaluations.t2w.into_u256(),
        ]
        .hash()
        .into_fr();
        let y = [
            alpha.into_u256(),
            polynomials.w1.x().into_u256(),
            polynomials.w1.y().into_u256(),
        ]
        .hash()
        .into_fr();
        Self {
            beta,
            gamma,
            h0_w8,
            h1_w4,
            h2_w3,
            h3_w3,
            xi,
            zh,
            alpha,
            y,
        }
    }

    fn compute_li_s0(&self) -> LiS0 {
        let den1 = self.h0_w8[0].pow(6_u64.into_fr()) * 8_u64.into_fr();
        [
            den1 * self.h0_w8[0] * (self.y - self.h0_w8[0]),
            den1 * self.h0_w8[7] * (self.y - self.h0_w8[1]),
            den1 * self.h0_w8[6] * (self.y - self.h0_w8[2]),
            den1 * self.h0_w8[5] * (self.y - self.h0_w8[3]),
            den1 * self.h0_w8[4] * (self.y - self.h0_w8[4]),
            den1 * self.h0_w8[3] * (self.y - self.h0_w8[5]),
            den1 * self.h0_w8[2] * (self.y - self.h0_w8[6]),
            den1 * self.h0_w8[1] * (self.y - self.h0_w8[7]),
        ]
    }

    fn compute_li_s1(&self) -> LiS1 {
        let den1 = self.h1_w4[0] * self.h1_w4[0] * 4_u64.into_fr();
        [
            den1 * self.h1_w4[0] * (self.y - self.h1_w4[0]),
            den1 * self.h1_w4[3] * (self.y - self.h1_w4[1]),
            den1 * self.h1_w4[2] * (self.y - self.h1_w4[2]),
            den1 * self.h1_w4[1] * (self.y - self.h1_w4[3]),
        ]
    }

    fn compute_li_s2(&self, w: Fr) -> LiS2 {
        let den1_0 = 3_u64.into_fr() * self.h2_w3[0] * (self.xi - self.xi * w);
        let den1_1 = 3_u64.into_fr() * self.h3_w3[0] * (self.xi * w - self.xi);
        [
            den1_0 * self.h2_w3[0] * (self.y - self.h2_w3[0]),
            den1_0 * self.h2_w3[2] * (self.y - self.h2_w3[1]),
            den1_0 * self.h2_w3[1] * (self.y - self.h2_w3[2]),
            den1_1 * self.h3_w3[0] * (self.y - self.h3_w3[0]),
            den1_1 * self.h3_w3[2] * (self.y - self.h3_w3[1]),
            den1_1 * self.h3_w3[1] * (self.y - self.h3_w3[2]),
        ]
    }

    fn compute_eval_l1_base(&self, n: Fr) -> Fr {
        n * (self.xi - Fr::one())
    }

    fn compute_den_h1_base(&self) -> Fr {
        let w = self.y - self.h1_w4[0];
        let w = w * (self.y - self.h1_w4[1]);
        let w = w * (self.y - self.h1_w4[2]);
        w * (self.y - self.h1_w4[3])
    }

    fn compute_den_h2_base(&self) -> Fr {
        let w = self.y - self.h2_w3[0];
        let w = w * (self.y - self.h2_w3[1]);
        let w = w * (self.y - self.h2_w3[2]);
        let w = w * (self.y - self.h3_w3[0]);
        let w = w * (self.y - self.h3_w3[1]);
        w * (self.y - self.h3_w3[2])
    }

    fn compute_inverse(&self, vk: &VkData, expected: Fr) -> Result<(Inverse, Fr), VerifyError> {
        let den_h1_base = self.compute_den_h1_base();
        let den_h2_base = self.compute_den_h2_base();
        let mut data = [Fr::zero(); 22];
        data[0] = self.zh;
        data[1] = data[0] * den_h1_base;
        data[2] = data[1] * den_h2_base;
        let mut cursor = 3;
        let li_s0 = self.compute_li_s0();
        for elem in li_s0 {
            data[cursor] = data[cursor - 1] * elem;
            cursor += 1;
        }
        let li_s1 = self.compute_li_s1();
        for elem in li_s1 {
            data[cursor] = data[cursor - 1] * elem;
            cursor += 1;
        }
        let li_s2 = self.compute_li_s2(vk.vk.w);
        for elem in li_s2 {
            data[cursor] = data[cursor - 1] * elem;
            cursor += 1;
        }

        let eval_l1_base = self.compute_eval_l1_base(vk.precomputed.n);
        data[cursor] = data[cursor - 1] * eval_l1_base;
        let value = data[cursor];

        if Fr::one() != value * expected {
            return Err(VerifyError::InvalidInverse {
                inverse: expected,
                computed: value,
            });
        }
        data[cursor] = expected;
        cursor -= 1;
        // We get l1 from batches and we compute the polynomial evaluation L1(x)
        let l1 = data[cursor + 1] * data[cursor] * self.zh;
        data[cursor] = data[cursor + 1] * eval_l1_base;
        cursor -= 1;
        let mut li_s2_inv = [Fr::zero(); 6];
        for (pos, elem) in li_s2.into_iter().enumerate().rev() {
            li_s2_inv[pos] = data[cursor + 1] * data[cursor];
            data[cursor] = data[cursor + 1] * elem;
            cursor -= 1;
        }
        let mut li_s1_inv = [Fr::zero(); 4];
        for (pos, elem) in li_s1.into_iter().enumerate().rev() {
            li_s1_inv[pos] = data[cursor + 1] * data[cursor];
            data[cursor] = data[cursor + 1] * elem;
            cursor -= 1;
        }
        let mut li_s0_inv = [Fr::zero(); 8];
        for (pos, elem) in li_s0.into_iter().enumerate().rev() {
            li_s0_inv[pos] = data[cursor + 1] * data[cursor];
            data[cursor] = data[cursor + 1] * elem;
            cursor -= 1;
        }
        let den_h2 = data[cursor + 1] * data[cursor];
        data[cursor] = data[cursor + 1] * den_h2_base;
        cursor -= 1;
        let den_h1 = data[cursor + 1] * data[cursor];
        data[cursor] = data[cursor + 1] * den_h1_base;
        let zh_inv = data[cursor];
        Ok((
            Inverse {
                li_s0_inv,
                li_s1_inv,
                li_s2_inv,
                den_h1,
                den_h2,
                zh_inv,
            },
            l1,
        ))
    }
}

impl FRedaConstants for Challenges {}

#[cfg(test)]
mod should;
