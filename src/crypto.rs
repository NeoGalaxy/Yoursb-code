//! module to encrypt the data

use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};

use crate::{
    _try,
    errors::{self, YoursbError},
};

/// Encrypts the designated file into the desiganted path
pub fn encrypt<S: Iterator<Item = u8>>(
    input_data: S,
    output_path: &Path,
    key: &chacha20poly1305::Key,
) -> Result<(), errors::Error> {
    // let mut input = _try!(fs::File::open(input_path), [input_path.to_owned()]);
    let mut buffer = Vec::new();
    buffer.extend(input_data);
    // _try!(input.read_to_end(&mut buffer), [input_path.to_owned()]);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, buffer.as_ref()).unwrap();

    if let Some(parent) = output_path.parent() {
        _try!(fs::create_dir_all(parent), [parent.to_owned()]);
    }

    let mut output = _try!(fs::File::create(output_path), [output_path.to_owned()]);

    _try!(output.write_all(&nonce), [output_path.to_owned()]);
    _try!(output.write_all(&ciphertext), [output_path.to_owned()]);

    Ok(())
}

/// Decrypts the designated file into the desiganted path
pub fn decrypt(input_path: &Path, key: &chacha20poly1305::Key) -> Result<Vec<u8>, errors::Error> {
    let mut input = _try!(fs::File::open(input_path), [input_path.to_owned()]);
    let mut buffer = Vec::new();
    _try!(input.read_to_end(&mut buffer), [input_path.to_owned()]);
    let cipher = ChaCha20Poly1305::new(key);

    // nonce are of size 12
    let (nonce, ciphertext) = buffer.split_at(12);

    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| errors::Error::InvalidKeyError)?;

    Ok(plaintext)
}
