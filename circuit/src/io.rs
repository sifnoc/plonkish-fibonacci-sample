use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    path::Path,
};

use plonkish_backend::backend::PlonkishBackend;
use serde::{Deserialize, Serialize};

use crate::PlonkishComponents;

/// Read SRS from file.
pub fn read_srs_path<PC: PlonkishComponents>(path: &Path) -> PC::Param {
    let filename = path.as_os_str().to_str().unwrap();
    PC::ProvingBackend::setup_custom(filename).unwrap()
}

// This method only for prover/verifier params
pub fn save_to_file<P: AsRef<Path>, T: Serialize>(
    path: &P,
    data: &T,
) -> Result<(), Box<dyn Error>> {
    let serialized_data = bincode::serialize(data)?;
    let mut file = File::create(path)?;
    file.write_all(&serialized_data)?;
    Ok(())
}

pub fn load_from_file<P: AsRef<Path> + ?Sized, T: for<'de> Deserialize<'de>>(
    path: &P,
) -> Result<T, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let deserialized_data = bincode::deserialize(&buffer)?;
    Ok(deserialized_data)
}

/// Read a proving key from the file.
pub fn read_pk<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    load_from_file::<_, T>(path).unwrap()
}

/// Read a verification key from the file.
pub fn read_vk<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    load_from_file::<_, T>(path).unwrap()
}
