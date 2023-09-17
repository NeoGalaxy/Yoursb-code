//! This module is aimed towards manging the keys, encrypting and decrypting them.

use crate::{
    crypto::{decrypt_from, encrypt},
    errors::YoursbError,
    passwords::pass_input,
};
use std::{
    fs::File,
    io::{stdout, Write},
    path::Path,
};

use chacha20poly1305::{aead::OsRng, KeyInit, XChaCha20Poly1305};

use crate::{
    _try,
    errors::{self, Error::ConsoleError},
};

pub fn ask_passphase() -> Result<[u8; 32], errors::Error> {
    let mut password = loop {
        print!("Enter the passphrase: ");
        stdout().flush().map_err(ConsoleError)?;
        let pass = rpassword::read_password().map_err(ConsoleError)?;
        println!();
        if pass.len() > 32 {
            println!("Too long passphrase, max is 32 characters.");
            println!();
        } else {
            break pass.into_bytes();
        }
    };

    while password.len() < 32 {
        password.push(0)
    }

    Ok(password
        .try_into()
        .expect("Padded passphrase doesn't do 32 bytes"))
}

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
    let key = XChaCha20Poly1305::generate_key(OsRng);
    let key: &[u8] = &key;

    println!();
    println!("Encrypting key with password...");

    let res: Vec<_> =
        encrypt(key.iter().copied(), (&padded_password).into()).collect::<Result<_, _>>()?;

    _try!(keyfile.write_all(&res), [keypath.to_owned()]);

    println!("Done.");
    Ok(())
}

/// Decrypts an encrypted key using a passphrase
pub fn unlock_key(keypath: &Path) -> Result<[u8; 32], errors::Error> {
    let key = unlock_key_with(keypath, &ask_passphase()?)?;
    println!("Passphrase valid.");

    Ok(key)
}

/// Decrypts an encrypted key using a passphrase
pub fn unlock_key_with(keypath: &Path, passphrase: &[u8; 32]) -> Result<[u8; 32], errors::Error> {
    let key = decrypt_from(keypath, passphrase.into())?;

    Ok(key.try_into().expect("Encrypted key is not the right size"))
}
