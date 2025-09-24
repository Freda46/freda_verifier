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

#![cfg(feature = "bins")]
use std::process::Command;

use rstest::{fixture, rstest};

mod formats;

#[fixture]
fn bin() -> Command {
    test_bin::get_test_bin("verifier")
}

mod should {
    use std::path::Path;

    use super::*;
    use crate::formats::Formats;

    const VALID_VK: &'static str = "resources/bins/verification_key.json";
    const ZKSYNC_VK: &'static str = "resources/bins/zksync_vk.json";
    const VALID_PUBS_HEX: &'static str =
        "0x110d778eaf8b8ef7ac10f8ac239a14df0eb292a8d1b71340d527b26301a9ab08";
    const VALID_PUBS_DEC: &'static str =
        "7713112592372404476342535432037683616424591277138491596200192981572885523208";

    #[rstest]
    fn show_help(mut bin: Command) {
        let output = bin.arg("--help").output().unwrap();

        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());
    }

    #[rstest]
    fn verify(
        mut bin: Command,
        #[values(Formats::Json, Formats::Bytes, Formats::HexString)] proof: Formats,
        #[values(VALID_PUBS_DEC, VALID_PUBS_HEX)] pubs: &str,
    ) {
        let output = bin
            .arg("-p")
            .arg(proof.name())
            .arg(Path::new(VALID_VK))
            .arg(proof.resource_path())
            .arg(pubs)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "STDERR: {}",
            std::str::from_utf8(output.stderr.as_slice()).unwrap_or("Cannot show output")
        );
        assert!(output.stderr.is_empty());
        assert!(
            to_str(&output.stdout).contains("verified"),
            "Invalid message: {}",
            to_str(&output.stdout)
        );
    }

    #[rstest]
    fn reject_proofs_related_to_other_vk(mut bin: Command) {
        let proof = Formats::Json;
        let output = bin
            .arg("-p")
            .arg(proof.name())
            .arg(Path::new(ZKSYNC_VK))
            .arg(proof.resource_path())
            .arg(VALID_PUBS_HEX)
            .output()
            .unwrap();

        assert!(!output.status.success(), "Should fail");
        assert!(!output.stderr.is_empty());
    }

    #[rstest]
    fn reject_invalid_proof_format(mut bin: Command) {
        let proof = Formats::Json;
        let output = bin
            .arg("-p")
            .arg(proof.name())
            .arg(Path::new("resources/bins/verification_key.json"))
            .arg(Formats::HexString.resource_path())
            .arg("123")
            .output()
            .unwrap();

        assert!(!output.status.success(), "Should fail");
        assert!(!output.stderr.is_empty());
    }

    #[rstest]
    fn reject_proofs_with_wrong_public_inputs(mut bin: Command) {
        let proof = Formats::Json;
        let output = bin
            .arg("-p")
            .arg(proof.name())
            .arg(Path::new("resources/bins/verification_key.json"))
            .arg(proof.resource_path())
            .arg("123")
            .output()
            .unwrap();

        assert!(!output.status.success(), "Should fail");
        assert!(!output.stderr.is_empty());
    }

    #[rstest]
    fn use_hex_as_default_format(mut bin: Command) {
        let output = bin
            .arg(Path::new(VALID_VK))
            .arg(Formats::HexString.resource_path())
            .arg(VALID_PUBS_HEX)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "STDERR: {}",
            std::str::from_utf8(output.stderr.as_slice()).unwrap_or("Cannot show output")
        );
        assert!(output.stderr.is_empty());
    }

    fn to_str(data: &[u8]) -> String {
        std::str::from_utf8(data).unwrap().to_string()
    }
}
