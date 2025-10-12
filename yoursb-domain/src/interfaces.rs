use core::fmt::{Debug, Display};

use alloc::string::String;
use argon2::password_hash::rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

macro_rules! indicate {
    ($ctx:expr, $($content:tt)*) => {
        // $crate::interfaces::SyncContext::indicate($ctx, format_args!($($content)*))
        $ctx.indicate(format_args!($($content)*))
    };
}
pub(crate) use indicate;
use zeroize::Zeroizing;

use crate::crypto::{self, AsyncYsbcRead, YsbcRead, NONCE_SIZE, TAG_SIZE};

pub use argon2::password_hash::SaltString;

pub type EncryptionKey = [u8; 32];
pub const CRYPTED_ENCRYPTION_KEY_SIZE: usize = 32 + TAG_SIZE + NONCE_SIZE;

pub struct PasswordInput<const S: usize> {
    content: Zeroizing<[char; S]>,
    len: Zeroizing<usize>,
    cursor_pos: Zeroizing<usize>,
}

pub enum PasswordInputEvent<'a> {
    MoveTo(usize),
    MoveRelative(isize),
    TypeChar(char),
    TypeText(&'a str),
    DelRelativeRange(isize),
}

impl PasswordInput<64> {
    pub(crate) fn into_secret(self) -> Zeroizing<([u8; const { 64 * 4 }], usize)> {
        let mut len = 0;
        let mut res = [0; 64 * 4];
        for c in &self.content[..*self.len] {
            len += c.encode_utf8(&mut res[len..]).len();
        }
        Zeroizing::new((res, len))
    }
}

impl<const S: usize> PasswordInput<S> {
    pub(crate) fn new() -> Self {
        PasswordInput {
            content: Zeroizing::new(['\0'; S]),
            len: Zeroizing::new(0),
            cursor_pos: Zeroizing::new(0),
        }
    }

    pub fn update(&mut self, event: PasswordInputEvent<'_>) {
        match event {
            PasswordInputEvent::MoveTo(pos) => *self.cursor_pos = pos.min(*self.len),
            PasswordInputEvent::MoveRelative(diff) => {
                if diff < 0 {
                    *self.cursor_pos = self.cursor_pos.saturating_sub(diff.unsigned_abs())
                } else {
                    *self.cursor_pos = self.cursor_pos.saturating_add(diff as usize).min(*self.len)
                }
            }
            PasswordInputEvent::TypeChar(c) => {
                let new_cursor_pos = *self.cursor_pos + 1;
                self.content
                    .copy_within(*self.cursor_pos..*self.len, new_cursor_pos);
                self.content[*self.cursor_pos] = c;
                *self.len += 1;
                *self.cursor_pos = new_cursor_pos;
            }
            PasswordInputEvent::TypeText(txt) => {
                let new_cursor_pos = *self.cursor_pos + txt.chars().count();
                self.content
                    .copy_within(*self.cursor_pos..*self.len, new_cursor_pos);
                for (c, v) in self.content[*self.cursor_pos..new_cursor_pos]
                    .iter_mut()
                    .zip(txt.chars())
                {
                    *c = v;
                }
                *self.len += txt.len();
                *self.cursor_pos = new_cursor_pos;
            }
            PasswordInputEvent::DelRelativeRange(size) => {
                let slice_to_rm = if size < 0 {
                    (*self.cursor_pos - size.unsigned_abs())..*self.cursor_pos
                } else {
                    *self.cursor_pos..(*self.cursor_pos + (size as usize))
                };
                *self.len = self.len.saturating_sub(slice_to_rm.end - slice_to_rm.start);
                self.content
                    .copy_within(slice_to_rm.end..*self.len, slice_to_rm.start);
                *self.cursor_pos = slice_to_rm.start;
            }
        }
    }
    pub fn display_txt(&self, buffer: &mut String) {
        buffer.truncate(*self.len);
        while buffer.len() < *self.len {
            buffer.push('*');
        }
    }
    pub fn get_cursor_pos(&self) -> usize {
        *self.cursor_pos
    }
}

#[derive(Clone, Debug)]
pub struct CryptedEncryptionKey {
    pub key: [u8; CRYPTED_ENCRYPTION_KEY_SIZE],
    pub salt: SaltString,
}

pub trait Context: Sized {
    type FilePath<const IS_PASSWORD: bool>: FilePath<
        IS_PASSWORD,
        Leaf = Self::FileLeaf<IS_PASSWORD>,
    >;
    type FileLeaf<const IS_PASSWORD: bool>: FileLeaf<
        IS_PASSWORD,
        Path = Self::FilePath<IS_PASSWORD>,
    >;
    type InstanceLoc: Display;

    type Error: From<crypto::KeyDecryptionError>;
}

pub trait SyncContext: Context {
    type Instance: Instance<Self>;
    type FileRead: YsbcRead;

    fn indicate<T: Display>(&self, val: T);

    /// To ensure that any memory space with the secret is zero'ed, the
    /// responsibility of handling the value is
    fn prompt_secret<T: Display>(&self, txt: T, password_input: &mut PasswordInput<64>);
    fn set_clipboard(&self, content: &str);
}

pub trait AsyncContext: Context {
    type Instance: AsyncInstance<Self>;
    type FileRead: AsyncYsbcRead;

    fn indicate<T: Display>(&self, val: T) -> impl std::future::Future<Output = ()> + Send;

    fn prompt_secret<T: Display>(
        &self,
        txt: T,
    ) -> impl core::future::Future<Output = impl AsRef<str>>;
    fn set_clipboard(&self, content: &str) -> impl core::future::Future<Output = ()>;
}

pub trait InitInstanceContext
where
    Self: SyncContext,
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

pub trait AsyncInitInstanceContext
where
    Self: AsyncContext,
    Self::Instance: AsyncWritableInstance<Self>,
{
    type CharsDist: CharsDist;

    fn new_instance(
        path: Self::InstanceLoc,
        key: CryptedEncryptionKey,
    ) -> impl core::future::Future<Output = Result<Self::Instance, Self::Error>>;

    fn key_rng(&self) -> impl CryptoRngCore;
    fn salt_rng(&self) -> impl CryptoRngCore;
}

pub trait Instance<Ctx: SyncContext>: Sized {
    fn open(loc: Option<Ctx::InstanceLoc>) -> Result<Self, Ctx::Error>;

    fn location(&self) -> Ctx::InstanceLoc;

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

pub trait AsyncInstance<Ctx: AsyncContext>: Sized {
    fn open(
        loc: Option<Ctx::InstanceLoc>,
    ) -> impl core::future::Future<Output = Result<Self, Ctx::Error>>;

    fn location(&self) -> Ctx::InstanceLoc;

    fn get_key(
        &mut self,
    ) -> impl core::future::Future<Output = Result<CryptedEncryptionKey, Ctx::Error>>;

    fn get_element<const IS_PASSWORD: bool>(
        &self,
        path: &Ctx::FileLeaf<IS_PASSWORD>,
    ) -> impl core::future::Future<Output = Result<Ctx::FileRead, Ctx::Error>>;

    fn list_content<const IS_PASSWORD: bool>(
        &self,
        directory: Ctx::FilePath<IS_PASSWORD>,
    ) -> impl core::future::Future<
        Output = Result<
            impl Iterator<Item = Result<PathOrLeaf<Ctx, IS_PASSWORD>, Ctx::Error>>,
            Ctx::Error,
        >,
    >;
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

pub trait AsyncWritableInstance<Ctx: AsyncInitInstanceContext>: AsyncInstance<Ctx>
where
    Ctx::Instance: AsyncWritableInstance<Ctx>,
{
    fn write_element<const IS_PASSWORD: bool, R: YsbcRead>(
        &mut self,
        path: &Ctx::FileLeaf<IS_PASSWORD>,
        content: R,
    ) -> impl core::future::Future<Output = Result<(), Ctx::Error>>;

    fn delete_element<const IS_PASSWORD: bool>(
        &mut self,
        path: &Ctx::FileLeaf<IS_PASSWORD>,
    ) -> impl core::future::Future<Output = Result<(), Ctx::Error>>;

    fn delete(self) -> impl core::future::Future<Output = Result<(), (Ctx::Error, Self)>>;
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

#[derive(Debug)]
pub enum PathOrLeaf<Ctx: Context, const IS_PASSWORD: bool> {
    Path(Ctx::FilePath<IS_PASSWORD>),
    Leaf(Ctx::FileLeaf<IS_PASSWORD>),
}

impl<Ctx: SyncContext, const IS_PASSWORD: bool> PathOrLeaf<Ctx, IS_PASSWORD>
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
pub struct DecryptedPassword<Ctx: SyncContext> {
    pub id: ElementId<Ctx, true>,
    pub value: Password,
}

#[derive(Debug)]
pub struct DecryptedFile<Ctx: SyncContext, R: YsbcRead> {
    pub id: ElementId<Ctx, false>,
    pub content: R,
}

#[derive(Debug)]
pub struct ElementId<Ctx: SyncContext, const IS_PASSWORD: bool>(pub Ctx::FileLeaf<IS_PASSWORD>);
// pub struct PasswordId<Ctx: Context>(pub(crate) Ctx::FileLeaf<true>);
// pub struct FileId<Ctx: Context>(pub(crate) Ctx::FileLeaf<false>);

#[derive(Debug, Serialize, Deserialize)]
/// A password with optionnal data
pub struct Password {
    pub password: String,
    pub data: Option<String>,
}
