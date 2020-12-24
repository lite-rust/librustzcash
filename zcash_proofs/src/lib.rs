//! *Zcash circuits and proofs.*
//!
//! `zcash_proofs` contains the zk-SNARK circuits used by Zcash, and the APIs for creating
//! and verifying proofs.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey, VerifyingKey};
use bls12_381::Bls12;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

#[cfg(feature = "directories")]
use directories::BaseDirs;
#[cfg(feature = "directories")]
use std::path::PathBuf;

pub mod circuit;
pub mod constants;
mod hashreader;
pub mod sapling;
pub mod sprout;

#[cfg(any(feature = "local-prover", feature = "bundled-prover"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "local-prover", feature = "bundled-prover")))
)]
pub mod prover;

// Circuit names
#[cfg(feature = "local-prover")]
const SAPLING_SPEND_NAME: &str = "sapling-spend.params";
#[cfg(feature = "local-prover")]
const SAPLING_OUTPUT_NAME: &str = "sapling-output.params";

// Circuit hashes
const SAPLING_SPEND_HASH: &str = "25fd9a0d1c1be0526c14662947ae95b758fe9f3d7fb7f55e9b4437830dcc6215a7ce3ea465914b157715b7a4d681389ea4aa84438190e185d5e4c93574d3a19a";
const SAPLING_OUTPUT_HASH: &str = "a1cb23b93256adce5bce2cb09cefbc96a1d16572675ceb691e9a3626ec15b5b546926ff1c536cfe3a9df07d796b32fdfc3e5d99d65567257bf286cd2858d71a6";
const SPROUT_HASH: &str = "_";

#[cfg(feature = "download-params")]
const DOWNLOAD_URL: &str = "https://download.z.cash/downloads";

/// Returns the default folder that the Zcash proving parameters are located in.
#[cfg(feature = "directories")]
#[cfg_attr(docsrs, doc(cfg(feature = "directories")))]
pub fn default_params_folder() -> Option<PathBuf> {
    BaseDirs::new().map(|base_dirs| {
        if cfg!(any(windows, target_os = "macos")) {
            base_dirs.data_dir().join("ZcashParams")
        } else {
            base_dirs.home_dir().join(".zcash-params")
        }
    })
}

/// Download the Zcash Sapling parameters, storing them in the default location.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
pub fn download_parameters() -> Result<(), minreq::Error> {
    // Ensure that the default Zcash parameters location exists.
    let params_dir = default_params_folder().ok_or(io::Error::new(
        io::ErrorKind::Other,
        "Could not load default params folder",
    ))?;
    std::fs::create_dir_all(&params_dir)?;

    let fetch_params = |name: &str, expected_hash: &str| -> Result<(), minreq::Error> {
        use std::io::Write;

        // Download the parts directly (Sapling parameters are small enough for this).
        let part_1 = minreq::get(format!("{}/{}.part.1", DOWNLOAD_URL, name)).send()?;
        let part_2 = minreq::get(format!("{}/{}.part.2", DOWNLOAD_URL, name)).send()?;

        // Verify parameter file hash.
        let hash = blake2b_simd::State::new()
            .update(part_1.as_bytes())
            .update(part_2.as_bytes())
            .finalize()
            .to_hex();
        if &hash != expected_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} failed validation (expected: {}, actual: {}, fetched {} bytes)",
                    name,
                    expected_hash,
                    hash,
                    part_1.as_bytes().len() + part_2.as_bytes().len()
                ),
            )
            .into());
        }

        // Write parameter file.
        let mut f = File::create(params_dir.join(name))?;
        f.write_all(part_1.as_bytes())?;
        f.write_all(part_2.as_bytes())?;
        Ok(())
    };

    fetch_params(SAPLING_SPEND_NAME, SAPLING_SPEND_HASH)?;
    fetch_params(SAPLING_OUTPUT_NAME, SAPLING_OUTPUT_HASH)?;

    Ok(())
}

pub fn load_parameters(
    spend_path: &Path,
    output_path: &Path,
    sprout_path: Option<&Path>,
) -> (
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Option<PreparedVerifyingKey<Bls12>>,
) {
    // Load from each of the paths
    let spend_fs = File::open(spend_path).expect("couldn't load Sapling spend parameters file");
    let output_fs = File::open(output_path).expect("couldn't load Sapling output parameters file");
    let sprout_fs =
        sprout_path.map(|p| File::open(p).expect("couldn't load Sprout groth16 parameters file"));

    parse_parameters(
        BufReader::with_capacity(1024 * 1024, spend_fs),
        BufReader::with_capacity(1024 * 1024, output_fs),
        sprout_fs.map(|fs| BufReader::with_capacity(1024 * 1024, fs)),
    )
}

/// Parse Bls12 keys from bytes as serialized by [`Parameters::write`].
///
/// This function will panic if it encounters unparseable data.
pub fn parse_parameters<R: io::Read>(
    spend_fs: R,
    output_fs: R,
    sprout_fs: Option<R>,
) -> (
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Option<PreparedVerifyingKey<Bls12>>,
) {
    let mut spend_fs = hashreader::HashReader::new(spend_fs);
    let mut output_fs = hashreader::HashReader::new(output_fs);
    let mut sprout_fs = sprout_fs.map(hashreader::HashReader::new);

    // Deserialize params
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");
    let output_params = Parameters::<Bls12>::read(&mut output_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");

    // We only deserialize the verifying key for the Sprout parameters, which
    // appears at the beginning of the parameter file. The rest is loaded
    // during proving time.
    let sprout_vk = sprout_fs.as_mut().map(|mut fs| {
        VerifyingKey::<Bls12>::read(&mut fs)
            .expect("couldn't deserialize Sprout Groth16 verifying key")
    });

    // There is extra stuff (the transcript) at the end of the parameter file which is
    // used to verify the parameter validity, but we're not interested in that. We do
    // want to read it, though, so that the BLAKE2b computed afterward is consistent
    // with `b2sum` on the files.
    let mut sink = io::sink();
    io::copy(&mut spend_fs, &mut sink)
        .expect("couldn't finish reading Sapling spend parameter file");
    io::copy(&mut output_fs, &mut sink)
        .expect("couldn't finish reading Sapling output parameter file");
    if let Some(mut sprout_fs) = sprout_fs.as_mut() {
        io::copy(&mut sprout_fs, &mut sink)
            .expect("couldn't finish reading Sprout groth16 parameter file");
    }

    if spend_fs.into_hash() != SAPLING_SPEND_HASH {
        panic!("Sapling spend parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    if output_fs.into_hash() != SAPLING_OUTPUT_HASH {
        panic!("Sapling output parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    if sprout_fs
        .map(|fs| fs.into_hash() != SPROUT_HASH)
        .unwrap_or(false)
    {
        panic!("Sprout groth16 parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    // Prepare verifying keys
    let spend_vk = prepare_verifying_key(&spend_params.vk);
    let output_vk = prepare_verifying_key(&output_params.vk);
    let sprout_vk = sprout_vk.map(|vk| prepare_verifying_key(&vk));

    (spend_params, spend_vk, output_params, output_vk, sprout_vk)
}
