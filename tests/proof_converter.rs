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
    test_bin::get_test_bin("proof-converter")
}

mod should {
    use std::io::Write;

    use super::*;
    use crate::formats::Formats;
    use pretty_assertions::assert_eq;

    #[rstest]
    fn show_help(mut bin: Command) {
        let output = bin.arg("--help").output().unwrap();

        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());
    }

    #[rstest]
    fn convert(
        mut bin: Command,
        #[values(Formats::Json, Formats::Bytes, Formats::HexString)] from_fmt: Formats,
        #[values(Formats::Json, Formats::Bytes, Formats::HexString)] to_fmt: Formats,
    ) {
        let tmpfile = tempfile::NamedTempFile::new().unwrap();

        let output = bin
            .arg("-i")
            .arg(from_fmt.name())
            .arg("-o")
            .arg(to_fmt.name())
            .arg(from_fmt.resource_path())
            .arg(tmpfile.path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "STDERR: {}",
            std::str::from_utf8(output.stderr.as_slice()).unwrap_or("Cannot show output")
        );
        assert!(output.stderr.is_empty());
        assert!(output.stdout.is_empty(), "Should contains no output!");

        let expected = std::fs::read(to_fmt.expected_path()).unwrap();
        let computed = std::fs::read(tmpfile.path()).unwrap();

        match to_fmt {
            Formats::Json | Formats::HexString => assert_eq!(to_str(&expected), to_str(&computed)),
            Formats::Bytes => assert_eq!(expected, computed),
        }
    }

    #[rstest]
    fn convert_to_std_out(
        mut bin: Command,
        #[values(Formats::Json, Formats::Bytes, Formats::HexString)] from_fmt: Formats,
        #[values(Formats::Json, Formats::Bytes, Formats::HexString)] to_fmt: Formats,
    ) {
        let output = bin
            .arg("-i")
            .arg(from_fmt.name())
            .arg("-o")
            .arg(to_fmt.name())
            .arg(from_fmt.resource_path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "STDERR: {}",
            std::str::from_utf8(output.stderr.as_slice()).unwrap_or("Cannot show output")
        );
        assert!(output.stderr.is_empty());

        let expected = std::fs::read(to_fmt.expected_path()).unwrap();
        let computed = output.stdout;

        match to_fmt {
            Formats::Json | Formats::HexString => assert_eq!(to_str(&expected), to_str(&computed)),
            Formats::Bytes => assert_eq!(expected, computed),
        }
    }

    #[rstest]
    fn use_json_as_default_format_input_and_hex_as_default_format_output(mut bin: Command) {
        let output = bin.arg(Formats::Json.resource_path()).output().unwrap();

        assert!(
            output.status.success(),
            "STDERR: {}",
            std::str::from_utf8(output.stderr.as_slice()).unwrap_or("Cannot show output")
        );
        assert!(output.stderr.is_empty());

        let expected = std::fs::read(Formats::HexString.expected_path()).unwrap();
        let computed = output.stdout;

        assert_eq!(to_str(&expected), to_str(&computed));
    }

    #[rstest]
    fn accept_also_not_0x_prefixed_hex_string(mut bin: Command) {
        let out = tempfile::NamedTempFile::new().unwrap();
        let mut input = tempfile::NamedTempFile::new().unwrap();
        // 0x prefix from hex proof and write it in input file.
        let hex = std::fs::read(Formats::HexString.resource_path()).unwrap();
        input.write_all(&hex[2..]).unwrap();

        let output = bin
            .arg("-i")
            .arg(Formats::HexString.name())
            .arg("-o")
            .arg(Formats::Json.name())
            .arg(input.path())
            .arg(out.path())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "STDERR: {}",
            std::str::from_utf8(output.stderr.as_slice()).unwrap_or("Cannot show output")
        );
        assert!(output.stderr.is_empty());

        let expected = to_str(&std::fs::read(Formats::Json.expected_path()).unwrap());
        let computed = to_str(&std::fs::read(out).unwrap());

        assert_eq!(expected, computed)
    }

    #[rstest]
    fn return_error_when_input_is_invalid(mut bin: Command) {
        let output = bin
            .arg("-i")
            .arg(Formats::HexString.name())
            .arg(Formats::Bytes.resource_path())
            .output()
            .unwrap();

        assert!(!output.status.success(), " Should fails!");
        assert!(to_str(&output.stderr).contains("Invalid hex string"));
    }

    fn to_str(data: &[u8]) -> String {
        std::str::from_utf8(data).unwrap().to_string()
    }
}
