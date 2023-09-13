//! This module is aimed towards manging the keys, encrypting and decrypting them.

use crate::{
    errors::{Error::InvalidPasswordError, YoursbError},
    passwords::pass_input,
};
use std::{
    fs::File,
    io::{stdout, Read, Write},
    path::Path,
};

use chacha20poly1305::{
    aead::{Aead, OsRng},
    AeadCore, ChaCha20Poly1305, KeyInit,
};

use crate::{
    _try,
    errors::{self, Error::ConsoleError},
};

/// Create a key and encrypt it with a passphrase
pub fn new_key(keypath: &Path) -> Result<(), errors::Error> {
    println!("Creating key...\n");

    let mut keyfile = _try!(File::create(keypath), [keypath.to_owned()]);

    println!("A new key will get generated, protected by the password you'll enter.\n");

    let mut password = pass_input("Enter a new password", Some(32))?.into_bytes();

    while password.len() < 32 {
        password.push(0)
    }

    let padded_password: [u8; 32] = password
        .try_into()
        .expect("Padded password doesn't do 32 bytes");

    println!("Password set.");
    println!();

    println!("Generating a key...");
    let key = ChaCha20Poly1305::generate_key(OsRng);
    let key: &[u8] = &key;

    println!();
    println!("Encrypting key with password...");

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = ChaCha20Poly1305::new((&padded_password).into());
    let cipherkey = cipher.encrypt(&nonce, key).unwrap();

    _try!(keyfile.write_all(&nonce), [keypath.to_owned()]);
    _try!(keyfile.write_all(&cipherkey), [keypath.to_owned()]);
    println!("Done.");
    Ok(())
}

/// Decrypts an encrypted key using a passphrase
pub fn unlock_key(keypath: &Path) -> Result<[u8; 32], errors::Error> {
    println!("Opening key file...\n");

    let mut keyfile = _try!(File::open(keypath), [keypath.to_owned()]);

    let mut password = loop {
        print!("Enter the password: ");
        stdout().flush().map_err(ConsoleError)?;
        let pass = rpassword::read_password().map_err(ConsoleError)?;
        println!();
        if pass.len() > 32 {
            println!("Too long password, max is 32 characters.");
            println!();
        } else {
            break pass.into_bytes();
        }
    };

    while password.len() < 32 {
        password.push(0)
    }

    let padded_password: [u8; 32] = password
        .try_into()
        .expect("Padded password doesn't do 32 bytes");

    let mut nonce = [0; 12];
    let mut cipherkey = Vec::new();
    _try!(keyfile.read_exact(&mut nonce), [keypath.to_owned()]);
    _try!(keyfile.read_to_end(&mut cipherkey), [keypath.to_owned()]);

    let cipher = ChaCha20Poly1305::new((&padded_password).into());

    let key = cipher
        .decrypt((&nonce).into(), cipherkey.as_ref())
        .map_err(|_| InvalidPasswordError)?;

    println!("Password valid.");

    Ok(key.try_into().expect("Encrypted key is not the right size"))
}
