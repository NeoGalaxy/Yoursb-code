//! module to encrypt the data

use core::{ffi::CStr, mem::size_of};

use chacha20poly1305::{
    aead::{heapless::Vec, stream::DecryptorBE32},
    XChaCha20Poly1305,
};
use libc::{fclose, fopen, fread, FILE};

use crate::{utils::eprintln, Finish};

const BUFFER_LEN: usize = 500;
const TAG_SIZE: usize = 16;

pub struct FileDecrypter {
    file: *mut FILE,
    cipher: Option<DecryptorBE32<XChaCha20Poly1305>>,
}

impl Drop for FileDecrypter {
    fn drop(&mut self) {
        unsafe { fclose(self.file) };
    }
}

impl Iterator for FileDecrypter {
    type Item = Option<Vec<u8, { BUFFER_LEN + TAG_SIZE }>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut cipher = self.cipher.take()?; // Stop here if finished

        let mut buffer: Vec<_, { BUFFER_LEN + TAG_SIZE }> = Vec::new();

        let size_read = unsafe {
            fread(
                buffer.as_mut_ptr() as *mut _,
                size_of::<u8>(),
                BUFFER_LEN + TAG_SIZE,
                self.file,
            )
        };

        if size_read == 0 {
            return None;
        }

        if size_read < TAG_SIZE {
            panic!("ERROR: chunk is too small");
        }

        unsafe { buffer.set_len(size_read) };

        let res = if size_read == BUFFER_LEN + TAG_SIZE {
            let tmp = cipher.decrypt_next_in_place(b"", &mut buffer);
            self.cipher = Some(cipher);
            tmp
        } else {
            cipher.decrypt_last_in_place(b"", &mut buffer)
        };
        match res {
            Ok(()) => Some(Some(buffer)),
            Err(_) => Some(None),
        }
    }
}

/// Decrypts the designated file into the desiganted path
pub fn decrypt(input_path: &CStr, key: &chacha20poly1305::Key) -> FileDecrypter {
    let encrypted_file = unsafe { fopen(input_path.as_ptr(), "r".as_ptr() as _) };

    if encrypted_file.is_null() {
        unsafe { "File does not exist".finish() };
    }

    // nonces are of size 24
    let mut nonce = [0; 19];

    let nb_read = unsafe {
        fread(
            nonce.as_mut_ptr() as *mut _,
            size_of::<u8>(),
            19,
            encrypted_file,
        )
    };

    if nb_read < 19 {
        unsafe { "File too short: it was not encrypted by YourSBCode".finish() };
    };

    let cipher = DecryptorBE32::<XChaCha20Poly1305>::new(key, &nonce.into());

    FileDecrypter {
        file: encrypted_file,
        cipher: Some(cipher),
    }
}
