// Copyright 2024, Horizen Labs, Inc.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::borrow::Cow;
use core::marker::PhantomData;
use frame_support::weights::Weight;
use hp_verifiers::{Verifier, VerifyError};

pub mod benchmarking;
mod verifier_should;
pub mod vk;
mod weight;

pub const PUBS_SIZE: usize = 32;
pub const PROOF_SIZE: usize = 24 * 32;
pub type Pubs = [u8; PUBS_SIZE];
pub type Proof = [u8; PROOF_SIZE];
pub use weight::WeightInfo;

#[pallet_verifiers::verifier]
pub struct Freda;

impl Verifier for Freda {
    type Proof = Proof;

    type Pubs = Pubs;

    type Vk = vk::Vk;

    fn hash_context_data() -> &'static [u8] {
        b"freda"
    }

    fn verify_proof(
        vk: &Self::Vk,
        raw_proof: &Self::Proof,
        raw_pubs: &Self::Pubs,
    ) -> Result<Option<Weight>, VerifyError> {
        let vk: freda_verifier::VerificationKey = vk
            .clone()
            .try_into_freda_vk_unchecked()
            .map_err(|e| log::debug!("Invalid Vk: {e:?}"))
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        let pubs: freda_verifier::Public = (*raw_pubs).into();
        let proof = freda_verifier::Proof::try_from(raw_proof)
            .map_err(|e| log::debug!("Cannot extract raw proof data: {e:?}"))
            .map_err(|_| VerifyError::InvalidProofData)?;
        log::trace!(
            "Extracted public inputs [{:?}...{:?}] and proof data [{:?}...{:?}]",
            &raw_pubs[0],
            &raw_pubs[PUBS_SIZE - 1],
            &raw_proof[0],
            &raw_proof[PROOF_SIZE - 1]
        );

        freda_verifier::verify(&vk, &proof, &pubs)
            .inspect_err(|e| log::debug!("Proof verification failed: {e:?}"))
            .map_err(|_| VerifyError::VerifyError)
            .map(|_| None)
    }

    fn validate_vk(vk: &Self::Vk) -> Result<(), hp_verifiers::VerifyError> {
        let _: freda_verifier::VerificationKey = vk
            .clone()
            .try_into()
            .map_err(|e| log::debug!("Invalid Vk: {e:?}"))
            .map_err(|_| VerifyError::InvalidVerificationKey)?;
        Ok(())
    }

    fn pubs_bytes(pubs: &Self::Pubs) -> Cow<'_, [u8]> {
        Cow::Borrowed(pubs)
    }
}

/// The struct to use in runtime pallet configuration to map the weight computed by this crate
/// benchmarks to the weight needed by the `pallet-verifiers`.
/// In this case the implementation doesn't depends from the kind of proof or public input and
/// the crate's benchmarks are mapped 1-1 to the `pallet-verifiers`'s one.
pub struct FredaWeight<W: weight::WeightInfo>(PhantomData<W>);

impl<W: weight::WeightInfo> pallet_verifiers::WeightInfo<Freda> for FredaWeight<W> {
    fn register_vk(_vk: &<Freda as hp_verifiers::Verifier>::Vk) -> Weight {
        W::register_vk()
    }

    fn unregister_vk() -> Weight {
        W::unregister_vk()
    }

    fn verify_proof(
        _proof: &<Freda as Verifier>::Proof,
        _pubs: &<Freda as Verifier>::Pubs,
    ) -> Weight {
        W::verify_proof()
    }

    fn get_vk() -> Weight {
        W::get_vk()
    }

    fn validate_vk(_vk: &<Freda as Verifier>::Vk) -> Weight {
        W::validate_vk()
    }

    fn compute_statement_hash(
        _proof: &<Freda as Verifier>::Proof,
        _pubs: &<Freda as Verifier>::Pubs,
    ) -> Weight {
        W::compute_statement_hash()
    }
}
