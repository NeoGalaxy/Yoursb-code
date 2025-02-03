//! module to encrypt the data

use argon2::{password_hash::SaltString, Argon2};
use chacha20poly1305::{
    aead::{
        self,
        heapless::Vec,
        stream::{DecryptorBE32, EncryptorBE32},
    },
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, Rng, RngCore};

use crate::interfaces::{
    CryptedEncryptionKey, EncryptionKey, InitInstanceContext, CRYPTED_ENCRYPTION_KEY_SIZE,
};

pub const BUFFER_LEN: usize = 500;
pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 19;

pub trait Read {
    type Error;
    fn read(&mut self, data: &mut [u8]) -> Result<usize, Self::Error>;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Never {}

impl Read for &[u8] {
    type Error = Never;
    fn read(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
        let len = out.len().min(self.len());
        let (a, b) = self.split_at(len);
        out[..len].copy_from_slice(a);
        *self = b;
        Ok(len)
    }
}

#[derive(Debug)]
pub enum KeyDecryptionError {
    DecryptionError(DecryptionError<Never>),
    PasswordHashingError(argon2::Error),
    InvalidPassphrase,
}

pub fn decrypt_key(
    key: CryptedEncryptionKey,
    pass: impl AsRef<str>,
) -> Result<EncryptionKey, KeyDecryptionError> {
    let mut hash = [0u8; 32];
    Argon2::default()
        .hash_password_into(
            pass.as_ref().as_bytes(),
            key.salt.as_str().as_bytes(),
            &mut hash,
        )
        .map_err(KeyDecryptionError::PasswordHashingError)?;
    let mut decrypter =
        Decrypter::new(key.key.as_slice(), &hash).map_err(KeyDecryptionError::DecryptionError)?;

    let key = match decrypter.next().unwrap() {
        Ok(v) => v,
        Err(DecryptionError::CipherError) => return Err(KeyDecryptionError::InvalidPassphrase),
        Err(DecryptionError::ReadError(n)) => match n {},
        Err(DecryptionError::SmallChunk) => {
            panic!("the encrypted key size is invalid (SmallChunk)")
        }
    };
    assert!(
        decrypter.next().is_none(),
        "the decrypted key size is invalid (multiple chunks)"
    );

    Ok(key
        .into_array()
        .expect("the decrypted key size is invalid (not 32)"))
}

pub fn create_key(pass: impl AsRef<str>, ctx: &impl InitInstanceContext) -> CryptedEncryptionKey {
    let salt = SaltString::generate(ctx.salt_rng());
    let mut pass_hash = [0; 32];
    Argon2::default()
        .hash_password_into(
            pass.as_ref().as_bytes(),
            salt.as_str().as_bytes(),
            &mut pass_hash,
        )
        .unwrap();

    let decrypted: [u8; 32] = ctx.key_rng().gen();
    let key: Vec<u8, CRYPTED_ENCRYPTION_KEY_SIZE> =
        Encrypter::new(decrypted.as_slice(), &pass_hash)
            .unwrap()
            .flat_map(|x| x.unwrap())
            .collect();

    CryptedEncryptionKey {
        key: key.into_array().unwrap(),
        salt,
    }
}

#[derive(Debug)]
pub enum DecryptionError<ReadErr> {
    /// An error occured on the reader while reading the content to decrypt
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

        buffer.resize_default(BUFFER_LEN).unwrap();

        let size_read = match self.file.read(&mut buffer) {
            Ok(l) => l,
            Err(err) => return Some(Err(DecryptionError::ReadError(err))),
        };

        if size_read == 0 {
            return None;
        }

        buffer.truncate(size_read);

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
            Err(aead::Error) => Some(Err(DecryptionError::CipherError)),
        }
    }
}

impl<R: Read> Decrypter<R> {
    /// Decrypts the designated content
    pub fn new(mut input: R, key: &EncryptionKey) -> Result<Self, DecryptionError<R::Error>> {
        let mut nonce = [0; NONCE_SIZE];

        let nb_read = input.read(&mut nonce).map_err(DecryptionError::ReadError)?;

        if nb_read < NONCE_SIZE {
            return Err(DecryptionError::SmallChunk);
        };

        let cipher = DecryptorBE32::<XChaCha20Poly1305>::new(key.into(), &nonce.into());

        Ok(Decrypter {
            file: input,
            cipher: Some(cipher),
        })
    }
}

#[derive(Debug)]
pub enum EncryptionError<ReadErr> {
    /// An error occured on the reader while reading the content to decrypt
    ReadError(ReadErr),
    CipherError,
}

pub struct Encrypter<R> {
    file: R,
    cipher: Option<EncryptorBE32<XChaCha20Poly1305>>,
    nonce: Option<[u8; NONCE_SIZE]>,
}

impl<R: Read> Iterator for Encrypter<R> {
    type Item = Result<Vec<u8, { BUFFER_LEN + TAG_SIZE }>, EncryptionError<R::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(nonce) = self.nonce.take() {
            let mut buffer = Vec::new();
            buffer.extend(nonce);
            return Some(Ok(buffer));
        }

        let mut cipher = self.cipher.take()?; // Stop here if finished or if encountered error

        let mut buffer: Vec<u8, { BUFFER_LEN + TAG_SIZE }> = Vec::new();

        buffer.resize_default(BUFFER_LEN).unwrap();

        let size_read = match self.file.read(&mut buffer) {
            Ok(l) => l,
            Err(err) => return Some(Err(EncryptionError::ReadError(err))),
        };

        if size_read == 0 {
            return None;
        }

        buffer.truncate(size_read);

        let res = if size_read == BUFFER_LEN {
            let tmp = cipher.encrypt_next_in_place(b"", &mut buffer);
            self.cipher = Some(cipher);
            tmp
        } else {
            cipher.encrypt_last_in_place(b"", &mut buffer)
        };
        match res {
            Ok(()) => Some(Ok(buffer)),
            Err(_) => Some(Err(EncryptionError::CipherError)),
        }
    }
}

impl<R: Read> Encrypter<R> {
    /// Encrypts the designated content
    pub fn new(input: R, key: &EncryptionKey) -> Result<Self, EncryptionError<R::Error>> {
        let mut nonce = [0; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let cipher = EncryptorBE32::<XChaCha20Poly1305>::new(key.into(), &nonce.into());

        Ok(Encrypter {
            file: input,
            cipher: Some(cipher),
            nonce: Some(nonce),
        })
    }
}
