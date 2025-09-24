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

use anyhow::{Context, Result};
use clap::Parser;
use freda_verifier::{verify, Public, VerificationKey};
use substrate_bn::arith::U256;

#[derive(Parser, Debug)]
#[command(name = "verifier")]
#[command(about = "Verify freda-proofs")]
#[command(version)]
struct Cli {
    /// Proof format
    #[arg(
        short,
        long,
        value_name = "FORMAT",
        value_enum,
        default_value_t = formats::Format::HexString
    )]
    proof_fmt: formats::Format,

    /// Verification Key Json File
    vk: std::path::PathBuf,

    /// Proof File
    proof: std::path::PathBuf,

    /// Public input hex string
    pubs: String,
}

mod formats;

pub fn main() -> Result<()> {
    let cli = Cli::parse();
    let proof = std::fs::read(&cli.proof)
        .with_context(|| format!("Failed to read proof data from {:?}", &cli.proof))
        .and_then(|data| cli.proof_fmt.read_poof(data.as_slice()))
        .with_context(|| format!("Failed to read proof from file {:?}", &cli.proof))?;
    let vk: VerificationKey = serde_json::from_reader(
        std::fs::File::open(&cli.vk)
            .with_context(|| format!("Failed to open verification key file {:?}", &cli.vk))?,
    )
    .with_context(|| format!("Failed to deserialize verification key from {:?}", &cli.vk))?;
    let pubs = parse_pubs(&cli.pubs)?;
    verify(&vk, &proof, &pubs).with_context(|| format!("Failed to verify proof"))?;
    println!("Proof verified successfully");
    Ok(())
}

fn parse_pubs(pubs: &str) -> Result<Public> {
    ethnum::U256::from_str_prefixed(pubs)
        .with_context(|| format!("Invalid 256 string"))
        .map(|u256| Public::from(U256([u256.0[0], u256.0[1]])))
}
