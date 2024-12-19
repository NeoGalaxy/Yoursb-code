//! module to encrypt the data

use chacha20poly1305::{
    aead::{heapless::Vec, stream::DecryptorBE32},
    XChaCha20Poly1305,
};

use crate::interfaces::EncryptionKey;

const BUFFER_LEN: usize = 500;
const TAG_SIZE: usize = 16;

pub trait Read {
    type Error;
    fn read(&mut self, data: &mut [u8]) -> Result<usize, Self::Error>;
}

pub enum DecryptionError<ReadErr> {
    ReadError(ReadErr),
    /// The content had an incorrect size. It was either not encrypted using yoursb-code,
    /// or was corrupted.
    ///
    /// If the error was obtained Decrypter on creation, then there was no nonce in the file
    /// (i.e. the file didn't have the minimum 20 required chars (or 24? to check)).
    ///
    /// If the error was encountered later on, then a chunk had an incorrect size (the file
    /// might have been truncated or extended)
    SmallChunk,
    CipherError,
}

pub struct Decrypter<R> {
    file: R,
    cipher: Option<DecryptorBE32<XChaCha20Poly1305>>,
}

impl<R: Read> Iterator for Decrypter<R> {
    type Item = Result<Vec<u8, { BUFFER_LEN + TAG_SIZE }>, DecryptionError<R::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut cipher = self.cipher.take()?; // Stop here if finished or if encountered error

        let mut buffer: Vec<_, { BUFFER_LEN + TAG_SIZE }> = Vec::new();

        let size_read = match self.file.read(&mut buffer) {
            Ok(l) => l,
            Err(err) => return Some(Err(DecryptionError::ReadError(err))),
        };

        if size_read == 0 {
            return None;
        }

        if size_read < TAG_SIZE {
            return Some(Err(DecryptionError::SmallChunk));
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
            Ok(()) => Some(Ok(buffer)),
            Err(err) => Some(Err(DecryptionError::CipherError)),
        }
    }
}

impl<R: Read> Decrypter<R> {
    /// Decrypts the designated content
    pub fn new(mut input: R, key: &EncryptionKey) -> Result<Self, DecryptionError<R::Error>> {
        // nonces are of size 24
        let mut nonce = [0; 19];

        let nb_read = input.read(&mut nonce).map_err(DecryptionError::ReadError)?;

        if nb_read < 19 {
            return Err(DecryptionError::SmallChunk);
        };

        let cipher = DecryptorBE32::<XChaCha20Poly1305>::new(key.into(), &nonce.into());

        Ok(Decrypter {
            file: input,
            cipher: Some(cipher),
        })
    }
}
