//! module to encrypt the data

use core::iter;

use argon2::{password_hash::SaltString, Argon2};
use chacha20poly1305::{
    aead::{
        self,
        heapless::{self, Vec},
        stream::{DecryptorBE32, EncryptorBE32},
    },
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, Rng, RngCore};

use crate::interfaces::{
    CryptedEncryptionKey, EncryptionKey, InitInstanceContext, WritableInstance,
    CRYPTED_ENCRYPTION_KEY_SIZE,
};

pub const BUFFER_LEN: usize = 500;
pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 19;

pub trait YsbcRead {
    type Error;
    fn read(&mut self, data: &mut [u8]) -> Result<usize, Self::Error>;
}
impl<R: YsbcRead + ?Sized> YsbcRead for &mut R {
    type Error = R::Error;
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        (**self).read(buf)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Never {}

impl YsbcRead for &[u8] {
    type Error = Never;
    fn read(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
        let len = out.len().min(self.len());
        let (a, b) = self.split_at(len);
        out[..len].copy_from_slice(a);
        *self = b;
        Ok(len)
    }
}
#[cfg(feature = "std")]
impl YsbcRead for std::fs::File {
    type Error = std::io::Error;
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        std::io::Read::read(self, buf)
    }
}

pub use argon2::Error as Argon2Error;

#[derive(Debug)]
pub enum KeyDecryptionError {
    DecryptionError(DecryptionError<Never>),
    PasswordHashingError(Argon2Error),
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

    let mut key = [0u8; 32];
    match decrypter.read(&mut key) {
        Ok(v) => assert_eq!(v, 32, "the decrypted key size is too small (<32bytes)"),
        Err(DecryptionError::CipherError) => return Err(KeyDecryptionError::InvalidPassphrase),
        Err(DecryptionError::ReadError(n)) => match n {},
        Err(DecryptionError::SmallChunk) => {
            panic!("the encrypted key size is invalid (SmallChunk)")
        }
    };
    let mut tmp = [0u8; 1];
    assert_eq!(
        decrypter.read(&mut tmp),
        Ok(0),
        "the decrypted key size is too big (>32bytes)"
    );

    Ok(key)
}

pub fn create_key<Ctx: InitInstanceContext>(
    pass: impl AsRef<str>,
    ctx: &Ctx,
) -> CryptedEncryptionKey
where
    Ctx::Instance: WritableInstance<Ctx>,
{
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

    let mut encrypter = Encrypter::new(decrypted.as_slice(), &pass_hash).unwrap();
    let key: Vec<u8, CRYPTED_ENCRYPTION_KEY_SIZE> = iter::repeat(())
        .map(|()| {
            let mut buf = heapless::Vec::<u8, { BUFFER_LEN + TAG_SIZE }>::new();
            buf.resize_default(BUFFER_LEN + TAG_SIZE).unwrap();
            let read_size = encrypter.read(&mut buf).unwrap();
            buf.truncate(read_size);
            buf
        })
        .take_while(|b| !b.is_empty())
        .flatten()
        .collect();

    CryptedEncryptionKey {
        key: key.into_array().unwrap(),
        salt,
    }
}

#[derive(Debug, PartialEq)]
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
    buffer: Vec<u8, { BUFFER_LEN + TAG_SIZE }>,
    buffer_index: usize,
}

/*impl<R: Read> Iterator for Decrypter<R> {
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
}*/

impl<R: YsbcRead> Decrypter<R> {
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
            buffer: Vec::default(),
            buffer_index: 0,
        })
    }
}

impl<R: YsbcRead> YsbcRead for Decrypter<R> {
    type Error = DecryptionError<R::Error>;
    fn read(&mut self, data: &mut [u8]) -> Result<usize, Self::Error> {
        if self.buffer_index < self.buffer.len() {
            let len = data.len().min(self.buffer.len() - self.buffer_index);
            data[0..len].copy_from_slice(&self.buffer[self.buffer_index..self.buffer_index + len]);
            self.buffer_index += len;
            return Ok(len);
        }

        self.buffer.truncate(0);
        self.buffer_index = 0;

        // Stop here if finished or if encountered error
        let Some(mut cipher) = self.cipher.take() else {
            return Ok(0);
        };

        self.buffer.resize_default(BUFFER_LEN + TAG_SIZE).unwrap();

        let mut size_read = match self.file.read(&mut self.buffer) {
            Ok(l) => l,
            Err(err) => return Err(DecryptionError::ReadError(err)),
        };

        if size_read == 0 {
            self.buffer.truncate(0);
            return Ok(0);
        }

        while size_read < self.buffer.len() {
            let additionnal_size_read = self.file.read(&mut self.buffer[size_read..]).unwrap_or(0);
            if additionnal_size_read == 0 {
                break;
            }
            size_read += additionnal_size_read;
        }

        if size_read < TAG_SIZE {
            self.buffer.truncate(0);
            return Err(DecryptionError::SmallChunk);
        }

        self.buffer.truncate(size_read);

        let res = if size_read == BUFFER_LEN + TAG_SIZE {
            let tmp = cipher.decrypt_next_in_place(b"", &mut self.buffer);
            self.cipher = Some(cipher);
            tmp
        } else {
            cipher.decrypt_last_in_place(b"", &mut self.buffer)
        };
        match res {
            Ok(()) => self.read(data),
            Err(aead::Error) => Err(DecryptionError::CipherError),
        }
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
    buffer: Vec<u8, { BUFFER_LEN + TAG_SIZE }>,
    buffer_index: usize,
}

/*impl<R: Read> Iterator for Encrypter<R> {
    type Item = Result<Vec<u8, { BUFFER_LEN + TAG_SIZE }>, EncryptionError<R::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.buffer.is_empty() {
            return Some(Ok(mem::take(&mut self.buffer)));
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
}*/

impl<R: YsbcRead> Encrypter<R> {
    /// Encrypts the designated content
    pub fn new(input: R, key: &EncryptionKey) -> Result<Self, EncryptionError<R::Error>> {
        let mut nonce = [0; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let cipher = EncryptorBE32::<XChaCha20Poly1305>::new(key.into(), &nonce.into());

        Ok(Encrypter {
            file: input,
            cipher: Some(cipher),
            buffer: Vec::from_slice(&nonce).unwrap(),
            buffer_index: 0,
        })
    }
}

impl<R: YsbcRead> YsbcRead for Encrypter<R> {
    type Error = EncryptionError<R::Error>;
    fn read(&mut self, data: &mut [u8]) -> Result<usize, Self::Error> {
        if self.buffer_index < self.buffer.len() {
            let len = data.len().min(self.buffer.len() - self.buffer_index);
            data[0..len].copy_from_slice(&self.buffer[self.buffer_index..self.buffer_index + len]);
            self.buffer_index += len;
            return Ok(len);
        }

        self.buffer.truncate(0);
        self.buffer_index = 0;

        // Stop here if finished or if encountered error
        let Some(mut cipher) = self.cipher.take() else {
            return Ok(0);
        };

        self.buffer.resize_default(BUFFER_LEN).unwrap();

        let mut size_read = match self.file.read(&mut self.buffer) {
            Ok(l) => l,
            Err(err) => return Err(EncryptionError::ReadError(err)),
        };

        if size_read == 0 {
            self.buffer.truncate(0);
            return Ok(0);
        }

        while size_read < self.buffer.len() {
            let additionnal_size_read = self.file.read(&mut self.buffer[size_read..]).unwrap_or(0);
            if additionnal_size_read == 0 {
                break;
            }
            size_read += additionnal_size_read;
        }

        self.buffer.truncate(size_read);

        let res = if size_read == BUFFER_LEN {
            let tmp = cipher.encrypt_next_in_place(b"", &mut self.buffer);
            self.cipher = Some(cipher);
            tmp
        } else {
            cipher.encrypt_last_in_place(b"", &mut self.buffer)
        };
        match res {
            Ok(()) => self.read(data),
            Err(_) => Err(EncryptionError::CipherError),
        }
    }
}
