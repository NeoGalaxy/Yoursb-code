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

pub fn encrypt(
    input_path: &Path,
    output_path: &Path,
    key: &chacha20poly1305::Key,
) -> Result<(), errors::Error> {
    let mut input = _try!(fs::File::open(input_path), [input_path.to_owned()]);
    let mut buffer = Vec::new();
    _try!(input.read_to_end(&mut buffer), [input_path.to_owned()]);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, buffer.as_ref()).unwrap();

    let mut output = _try!(fs::File::create(output_path), [output_path.to_owned()]);

    _try!(output.write_all(&nonce), [output_path.to_owned()]);
    _try!(output.write_all(&ciphertext), [output_path.to_owned()]);

    Ok(())
}

pub fn decrypt(
    input_path: &Path,
    output_path: &Path,
    key: &chacha20poly1305::Key,
) -> Result<(), errors::Error> {
    let mut input = _try!(fs::File::open(input_path), [input_path.to_owned()]);
    let mut buffer = Vec::new();
    _try!(input.read_to_end(&mut buffer), [input_path.to_owned()]);
    let cipher = ChaCha20Poly1305::new(key);

    // nonce are of size 12
    let (nonce, ciphertext) = buffer.split_at(12);

    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| errors::Error::InvalidKeyError)?;

    _try!(fs::write(output_path, plaintext), [output_path.to_owned()]);

    Ok(())
}
