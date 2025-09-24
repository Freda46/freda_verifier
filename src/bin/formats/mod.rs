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

use anyhow::{anyhow, Context, Result};
use clap::ValueEnum;
use freda_verifier::{Proof, ProofRawData};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Format {
    /// Json
    Json,
    /// Bytes
    Bytes,
    /// Hex String
    HexString,
}

impl Format {
    pub fn read_poof(self, data: &[u8]) -> Result<Proof> {
        match self {
            Format::Json => serde_json::from_slice(data)
                .with_context(|| format!("Failed to read proof from json")),
            Format::Bytes => {
                proof_from_slice(data).with_context(|| format!("Failed to read proof from bytes"))
            }
            Format::HexString => {
                let data = if data.starts_with(b"0x") {
                    &data[2..]
                } else {
                    data
                };
                hex::decode(data)
                    .with_context(|| format!("Invalid hex string"))
                    .and_then(|bytes| proof_from_slice(&bytes))
                    .with_context(|| format!("Failed to read proof from hex"))
            }
        }
    }
}

fn proof_from_slice(input: &[u8]) -> Result<Proof> {
    ProofRawData::try_from(input)
        .map_err(|_| {
            anyhow!(
                "Invalid proof bytes size: expected={}",
                std::mem::size_of::<ProofRawData>(),
            )
        })
        .and_then(|data| {
            Proof::try_from(&data).with_context(|| format!("Failed to read proof from bytes"))
        })
}
