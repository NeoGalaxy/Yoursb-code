use core::fmt::{Debug, Display};

use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::commands::Commands;

macro_rules! indicate {
    ($ctx:expr, $($content:tt)*) => {
        $crate::interfaces::Context::indicate($ctx, format_args!($($content)*))
    };
}
pub(crate) use indicate;

pub type EncryptionKey = [u8; 32];

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
    type CharsDist: CharsDist;

    type Error;

    fn indicate<T: Display>(&self, val: T);

    fn prompt_passkey(&self) -> impl AsRef<str>;
    fn set_clipboard(&self, content: &str);
}

pub trait InitInstanceContext: Context {
    fn new_instance(path: Self::InstanceLoc) -> Self::Instance;
}

pub trait Instance<Ctx: Context>: Sized {
    fn locate() -> Ctx::InstanceLoc;

    fn open(loc: Ctx::InstanceLoc) -> Result<Self, Ctx::Error>;

    fn unlock_key(&mut self, commands: &Commands<Ctx>) -> Result<EncryptionKey, Ctx::Error>;

    fn get_element<const IS_PASSWORD: bool>(
        &self,
        path: &Ctx::FileLeaf<IS_PASSWORD>,
    ) -> Result<String, Ctx::Error>;

    fn list_content<const IS_PASSWORD: bool>(
        &self,
        directory: Ctx::FilePath<IS_PASSWORD>,
    ) -> Result<impl Iterator<Item = Result<PathOrLeaf<Ctx, IS_PASSWORD>, Ctx::Error>>, Ctx::Error>;

    fn write_element<const IS_PASSWORD: bool>(
        &mut self,
        path: &Ctx::FileLeaf<IS_PASSWORD>,
        content: String,
    ) -> Result<(), Ctx::Error>;

    fn delete(self) -> Result<(), Ctx::Error>;
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

pub enum NewPasswordDetails<Ctx: Context> {
    Known(String),
    Random {
        len: u16,
        allowed_chars: Ctx::CharsDist,
    },
    // ToPrompt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordContent<'a> {
    pub password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<&'a str>,
}

pub struct DecryptedPassword<Ctx: Context> {
    pub id: PasswordId<Ctx>,
    pub value: Password,
}

pub struct DecryptedFile<Ctx: Context> {
    pub id: FileId<Ctx>,
    pub content: String,
}

pub struct PasswordId<Ctx: Context>(pub(crate) Ctx::FileLeaf<true>);
pub struct FileId<Ctx: Context>(pub(crate) Ctx::FileLeaf<false>);

#[derive(Serialize, Deserialize)]
/// A password with optionnal data
pub struct Password {
    pub password: String,
    pub data: Option<String>,
}