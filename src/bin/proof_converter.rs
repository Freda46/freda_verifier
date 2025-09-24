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
use freda_verifier::{Proof, ProofRawData};

#[derive(Parser, Debug)]
#[command(name = "proof-converter")]
#[command(about = "Converts freda-proofs formats")]
#[command(version)]
struct Cli {
    /// Input type
    #[arg(
        short,
        long,
        value_name = "FORMAT",
        value_enum,
        default_value_t = formats::Format::Json
    )]
    in_fmt: formats::Format,

    /// Output type
    #[arg(
        short,
        long,
        value_name = "FORMAT",
        value_enum,
        default_value_t = formats::Format::HexString
    )]
    out_fmt: formats::Format,

    /// Input file
    input: std::path::PathBuf,

    /// Output file [or stdout if not specified]
    output: Option<std::path::PathBuf>,
}

mod formats;

pub fn main() -> Result<()> {
    let cli = Cli::parse();
    let proof = std::fs::read(&cli.input)
        .with_context(|| format!("Failed to read proof data from {:?}", &cli.input))
        .and_then(|data| cli.in_fmt.read_poof(data.as_slice()))
        .with_context(|| format!("Failed to read proof from file {:?}", &cli.input))?;
    let mut out = out_file(cli.output.as_ref())?;
    match cli.out_fmt {
        formats::Format::Json => serde_json::to_writer_pretty(out, &proof)
            .with_context(|| format!("Cannot serialize proof to json"))?,
        formats::Format::Bytes => out
            .write_all(&ProofRawData::from(proof))
            .with_context(|| format!("Cannot serialize proof to bytes"))?,
        formats::Format::HexString => out
            .write_all(render_proof_hex(proof).as_bytes())
            .with_context(|| format!("Cannot serialize proof to hex string"))?,
    }

    Ok(())
}

fn out_file(output: Option<&std::path::PathBuf>) -> Result<Box<dyn std::io::Write>> {
    let from_path = output
        .map(|p| {
            std::fs::File::create(&p)
                .with_context(|| format!("Failed to create output file {:?}", &p))
        })
        .transpose()?
        .map(|f| Box::new(f) as Box<dyn std::io::Write>);
    Ok(from_path.unwrap_or_else(|| Box::new(std::io::stdout()) as Box<dyn std::io::Write>))
}

fn render_proof_hex(proof: Proof) -> String {
    format!("0x{}", hex::encode(ProofRawData::from(proof)))
}
