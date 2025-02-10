use core::fmt::{Debug, Display};

use alloc::string::String;
use argon2::password_hash::rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

macro_rules! indicate {
    ($ctx:expr, $($content:tt)*) => {
        $crate::interfaces::Context::indicate($ctx, format_args!($($content)*))
    };
}
pub(crate) use indicate;

use crate::crypto::{YsbcRead, NONCE_SIZE, TAG_SIZE};

pub use argon2::password_hash::SaltString;

pub type EncryptionKey = [u8; 32];
pub const CRYPTED_ENCRYPTION_KEY_SIZE: usize = 32 + TAG_SIZE + NONCE_SIZE;

#[derive(Clone, Debug)]
pub struct CryptedEncryptionKey {
    pub key: [u8; CRYPTED_ENCRYPTION_KEY_SIZE],
    pub salt: SaltString,
}

pub trait Context: Sized {
    type Instance: Instance<Self>;
    type FilePath<const IS_PASSWORD: bool>: FilePath<
        IS_PASSWORD,
        Leaf = Self::FileLeaf<IS_PASSWORD>,
    >;
    type FileLeaf<const IS_PASSWORD: bool>: FileLeaf<
        IS_PASSWORD,
        Path = Self::FilePath<IS_PASSWORD>,
    >;
    type InstanceLoc: Display;

    type FileRead: YsbcRead;
    type Error;

    fn indicate<T: Display>(&self, val: T);

    fn prompt_secret<T: Display>(&self, txt: T) -> impl AsRef<str>;
    fn set_clipboard(&self, content: &str);
}

pub trait InitInstanceContext
where
    Self: Context,
    Self::Instance: WritableInstance<Self>,
{
    type CharsDist: CharsDist;

    fn new_instance(
        path: Self::InstanceLoc,
        key: CryptedEncryptionKey,
    ) -> Result<Self::Instance, Self::Error>;

    fn key_rng(&self) -> impl CryptoRngCore;
    fn salt_rng(&self) -> impl CryptoRngCore;
}

pub trait Instance<Ctx: Context>: Sized {
    fn locate() -> Result<Ctx::InstanceLoc, Ctx::Error>;

    fn open(loc: Ctx::InstanceLoc) -> Result<Self, Ctx::Error>;

    fn get_key(&mut self) -> Result<CryptedEncryptionKey, Ctx::Error>;
    // fn set_key(&mut self, key: CryptedEncryptionKey) -> Result<(), Ctx::Error>;

    fn get_element<const IS_PASSWORD: bool>(
        &self,
        path: &Ctx::FileLeaf<IS_PASSWORD>,
    ) -> Result<Ctx::FileRead, Ctx::Error>;

    fn list_content<const IS_PASSWORD: bool>(
        &self,
        directory: Ctx::FilePath<IS_PASSWORD>,
    ) -> Result<impl Iterator<Item = Result<PathOrLeaf<Ctx, IS_PASSWORD>, Ctx::Error>>, Ctx::Error>;
}

pub trait WritableInstance<Ctx: InitInstanceContext>: Instance<Ctx>
where
    Ctx::Instance: WritableInstance<Ctx>,
{
    fn write_element<const IS_PASSWORD: bool, R: YsbcRead>(
        &mut self,
        path: &Ctx::FileLeaf<IS_PASSWORD>,
        content: R,
    ) -> Result<(), Ctx::Error>;

    fn delete_element<const IS_PASSWORD: bool>(
        &mut self,
        path: &Ctx::FileLeaf<IS_PASSWORD>,
    ) -> Result<(), Ctx::Error>;

    fn delete(self) -> Result<(), (Ctx::Error, Self)>;
}

pub trait FilePath<const IS_PASSWORD: bool>: Clone {
    type Leaf: FileLeaf<IS_PASSWORD>;
    fn root() -> Self;
    fn with_dir(self, dir: impl AsRef<str>) -> Self;
    fn get_suffix(&self, prefix: &Self) -> &str;
    fn file(self, dir: impl AsRef<str>) -> Self::Leaf;
}
pub trait FileLeaf<const IS_PASSWORD: bool>: Display + Debug {
    type Path: FilePath<IS_PASSWORD>;
    fn get_suffix(&self, prefix: &Self::Path) -> &str;
}

pub enum PathOrLeaf<Ctx: Context, const IS_PASSWORD: bool> {
    Path(Ctx::FilePath<IS_PASSWORD>),
    Leaf(Ctx::FileLeaf<IS_PASSWORD>),
}

impl<Ctx: Context, const IS_PASSWORD: bool> PathOrLeaf<Ctx, IS_PASSWORD>
where
    Ctx::FileLeaf<IS_PASSWORD>: Into<Ctx::FilePath<IS_PASSWORD>>,
{
    pub fn into_filepath(self) -> Ctx::FilePath<IS_PASSWORD> {
        match self {
            PathOrLeaf::Path(p) => p,
            PathOrLeaf::Leaf(l) => l.into(),
        }
    }
}

pub trait CharsDist {
    fn char_ranges(&self) -> impl ExactSizeIterator<Item = (char, char)> + '_;
}

pub enum NewPasswordDetails<Ctx: InitInstanceContext>
where
    Ctx::Instance: WritableInstance<Ctx>,
{
    Prompt,
    Known(String),
    Random {
        len: u16,
        allowed_chars: Ctx::CharsDist,
    },
    // ToPrompt,
}

#[derive(Debug)]
pub struct DecryptedPassword<Ctx: Context> {
    pub id: ElementId<Ctx, true>,
    pub value: Password,
}

#[derive(Debug)]
pub struct DecryptedFile<Ctx: Context, R: YsbcRead> {
    pub id: ElementId<Ctx, false>,
    pub content: R,
}

#[derive(Debug)]
pub struct ElementId<Ctx: Context, const IS_PASSWORD: bool>(pub Ctx::FileLeaf<IS_PASSWORD>);
// pub struct PasswordId<Ctx: Context>(pub(crate) Ctx::FileLeaf<true>);
// pub struct FileId<Ctx: Context>(pub(crate) Ctx::FileLeaf<false>);

#[derive(Debug, Serialize, Deserialize)]
/// A password with optionnal data
pub struct Password {
    pub password: String,
    pub data: Option<String>,
}
