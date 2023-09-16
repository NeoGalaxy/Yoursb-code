//! module to encrypt the data

use core::{ffi::CStr, mem::size_of};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use libc::{fclose, fopen, fread, FILE};

use crate::Finish;

const BUFFER_LEN: usize = 500;
const TAG_SIZE: usize = 16;

pub struct FileDecrypter {
    file: *mut FILE,
    cipher: ChaCha20Poly1305,
    // nonces are of size 12 + \0
    nonce: [u8; 12],
}

impl Drop for FileDecrypter {
    fn drop(&mut self) {
        unsafe { fclose(self.file) };
    }
}

impl Iterator for FileDecrypter {
    type Item = [u8; BUFFER_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        let mut in_buffer = [0; BUFFER_LEN + TAG_SIZE];
        let mut out_buffer = [0; BUFFER_LEN];

        let size_read = unsafe {
            fread(
                in_buffer.as_mut_ptr() as *mut _,
                size_of::<u8>(),
                BUFFER_LEN + TAG_SIZE,
                self.file,
            )
        };

        if size_read == 0 {
            return None;
        }

        if size_read < TAG_SIZE {
            unsafe { "ERROR: chunk has no tag".finish() };
        }

        let (text, tag) = in_buffer[0..size_read].split_at(size_read - TAG_SIZE);

        let tag: &[u8; TAG_SIZE] = tag.try_into().expect("fatal error");

        self.cipher
            .decrypt_in_place_detached((&self.nonce).into(), text, &mut out_buffer, tag.into())
            .expect("ERROR: could not decrypt");
        Some(out_buffer)
    }
}

/// Decrypts the designated file into the desiganted path
pub fn decrypt(input_path: &CStr, key: &chacha20poly1305::Key) -> FileDecrypter {
    let encrypted_file = unsafe { fopen(input_path.as_ptr(), "r".as_ptr() as _) };

    let cipher = ChaCha20Poly1305::new(key);

    // nonces are of size 12
    let mut nonce = [0; 12];

    let nb_read = unsafe {
        fread(
            nonce.as_mut_ptr() as *mut _,
            size_of::<u8>(),
            12,
            encrypted_file,
        )
    };

    if nb_read < 12 {
        unsafe { "File too short: it was not encrypted by YourSBCode".finish() };
    };

    FileDecrypter {
        file: encrypted_file,
        cipher,
        nonce,
    }
}
