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

use std::path::PathBuf;

pub enum Formats {
    Json,
    Bytes,
    HexString,
}
impl Formats {
    pub fn resource(&self) -> &'static str {
        match self {
            Formats::Json => "proof.json",
            Formats::Bytes => "proof.bin",
            Formats::HexString => "proof.hex",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Formats::Json => "json",
            Formats::Bytes => "bytes",
            Formats::HexString => "hex-string",
        }
    }

    pub fn resource_path(&self) -> PathBuf {
        PathBuf::from(format!("resources/bins/{}", self.resource()))
    }

    #[allow(unused)]
    pub fn expected_path(&self) -> PathBuf {
        match self {
            Formats::Json => PathBuf::from(format!("resources/bins/expected.json")),
            _ => self.resource_path(),
        }
    }
}
