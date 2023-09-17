//! module to encrypt the data

use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

use chacha20poly1305::{
    aead::{
        rand_core::RngCore,
        stream::{DecryptorBE32, EncryptorBE32},
        OsRng,
    },
    XChaCha20Poly1305,
};

use crate::{
    _try,
    errors::{self, YoursbError},
};

/// Encrypts the designated file into the desiganted path
pub fn encrypt_to<S: Iterator<Item = u8>>(
    input_data: S,
    output_path: &Path,
    key: &chacha20poly1305::Key,
) -> Result<(), errors::Error> {
    if let Some(parent) = output_path.parent() {
        _try!(fs::create_dir_all(parent), [parent.to_owned()]);
    }

    let mut output_file = _try!(fs::File::create(output_path), [output_path.to_owned()]);

    let res: Vec<_> = encrypt(input_data, key).collect::<Result<_, _>>()?;
    _try!(output_file.write_all(&res), [output_path.to_owned()]);

    Ok(())
}

/// Encrypts the designated file into the desiganted path
pub fn encrypt<S: Iterator<Item = u8>>(
    input_data: S,
    key: &chacha20poly1305::Key,
) -> impl Iterator<Item = Result<u8, errors::Error>> {
    let mut buffer = [0; 500];
    let mut buffer_i = 0;

    let mut nonce: [u8; 19] = Default::default();
    OsRng.fill_bytes(&mut nonce);
    let mut stream = Some(EncryptorBE32::<XChaCha20Poly1305>::new(key, &nonce.into()));

    let content = input_data
        .map(Some)
        .chain([None])
        .filter_map(move |c| {
            let mut local_stream = stream.take().unwrap();
            if let Some(c) = c {
                buffer[buffer_i] = c;
                buffer_i += 1;
                let ret = if buffer_i == buffer.len() {
                    buffer_i = 0;
                    Some(
                        local_stream
                            .encrypt_next(buffer.as_slice())
                            .unwrap()
                            .into_iter(),
                    )
                } else {
                    None
                };
                stream = Some(local_stream);
                ret
            } else {
                let res = local_stream
                    .encrypt_last(&buffer[0..buffer_i])
                    .unwrap()
                    .into_iter();
                Some(res)
            }
        })
        .flatten();

    nonce.into_iter().chain(content).map(Ok)
}

/// Decrypts the designated file into the desiganted path
pub fn decrypt_from(
    input_path: &Path,
    key: &chacha20poly1305::Key,
) -> Result<Vec<u8>, errors::Error> {
    let mut input = _try!(fs::File::open(input_path), [input_path.to_owned()]);
    let mut buffer = Vec::new();
    _try!(input.read_to_end(&mut buffer), [input_path.to_owned()]);

    let res = decrypt(buffer.into_iter(), key).collect::<Result<_, _>>()?;

    Ok(res)
}

/// Decrypts the designated file into the desiganted path
pub fn decrypt<I: Iterator<Item = u8>>(
    mut input: I,
    key: &chacha20poly1305::Key,
) -> impl Iterator<Item = Result<u8, errors::Error>> {
    let mut buffer = [0; 500 + 16];

    let mut buffer_i = 0;

    let mut nonce = [0; 19];
    for n in nonce.iter_mut() {
        *n = input
            .next()
            .expect("File is not encrypted (file smaller than nonce size)");
    }

    let mut stream = Some(DecryptorBE32::<XChaCha20Poly1305>::new(key, &nonce.into()));

    input
        .map(Some)
        .chain([None])
        .filter_map(move |c| {
            let mut local_stream = stream.take().unwrap();
            if let Some(c) = c {
                buffer[buffer_i] = c;
                buffer_i += 1;
                let ret = if buffer_i == buffer.len() {
                    buffer_i = 0;
                    Some(local_stream.decrypt_next(buffer.as_slice()))
                } else {
                    None
                };
                stream = Some(local_stream);
                ret
            } else {
                dbg!(buffer_i);
                let res = local_stream.decrypt_last(&buffer[0..buffer_i]);
                Some(res)
            }
        })
        .flat_map(Enumerator::new)
}

struct Enumerator {
    v: Result<Vec<u8>, chacha20poly1305::Error>,
    i: usize,
}

impl Enumerator {
    fn new(arg: Result<Vec<u8>, chacha20poly1305::Error>) -> Self {
        Self { v: arg, i: 0 }
    }
}

impl Iterator for Enumerator {
    type Item = Result<u8, errors::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        match &self.v {
            Ok(v) => {
                let res = *v.get(self.i)?;
                self.i += 1;
                Some(Ok(res))
            }
            Err(_) => {
                if self.i > 0 {
                    None
                } else {
                    self.i += 1;
                    Some(Err(errors::Error::InvalidKeyError))
                }
            }
        }
    }
}
