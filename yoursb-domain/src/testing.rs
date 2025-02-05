#![cfg(all(test, feature = "std"))]

use core::iter;
use std::{
    dbg,
    fmt::Display,
    fs::{self, create_dir_all, read_dir},
    io::Write as _,
    path::{Path, PathBuf},
    prelude::rust_2021::*,
    println,
};

use argon2::{
    password_hash::{rand_core::CryptoRngCore, SaltString},
    Argon2,
};
use chacha20poly1305::aead::heapless;
use rand::rngs::OsRng;

use crate::{
    crypto::{Encrypter, YsbcRead, BUFFER_LEN, TAG_SIZE},
    interfaces::{
        CharsDist, Context, CryptedEncryptionKey, FileLeaf, FilePath, InitInstanceContext,
        Instance, PathOrLeaf, CRYPTED_ENCRYPTION_KEY_SIZE,
    },
};

#[derive(Debug)]
pub struct TestCtx;

impl TestCtx {
    pub const INSTANCE_PASS: &str = "blblbl";
}

#[derive(Debug)]
pub struct TestInstance {
    root: PathBuf,
    key: CryptedEncryptionKey,
}
impl TestInstance {
    fn compute_path(&self, path: &PathBuf, is_password: bool) -> PathBuf {
        self.root
            .join(if is_password { "pass" } else { "files" })
            .join(path)
    }
}

pub struct TestCDist;

impl Context for TestCtx {
    type Instance = TestInstance;

    type FilePath<const IS_PASSWORD: bool> = PathBuf;

    type FileLeaf<const IS_PASSWORD: bool> = PathBufLeaf;

    type InstanceLoc = String;

    type CharsDist = TestCDist;

    type FileRead = std::fs::File;
    type Error = ();

    fn indicate<T: core::fmt::Display>(&self, val: T) {
        println!("[indicate] {val}");
    }

    fn prompt_secret<T>(&self, prompt: T) -> impl core::convert::AsRef<str>
    where
        T: core::fmt::Display,
    {
        println!("[prompt_secret] {prompt}");
        if prompt.to_string().contains("instance") {
            let pass = Self::INSTANCE_PASS;
            println!(">> return passphrase: {pass}");
            pass.to_string()
        } else {
            let mut res = String::new();
            std::io::stdin().read_line(&mut res).unwrap();
            if res.get(res.len() - 1..res.len()) == Some("\n") {
                res.pop();
            }
            res
        }
    }

    fn set_clipboard(&self, content: &str) {
        println!("[set_clipboard] {content}");
    }
}

impl InitInstanceContext for TestCtx {
    fn new_instance(
        path: Self::InstanceLoc,
        key: CryptedEncryptionKey,
    ) -> Result<Self::Instance, <TestCtx as Context>::Error> {
        let _ = create_dir_all(&path);
        Ok(TestInstance {
            root: path.into(),
            key,
        })
    }
    fn key_rng(&self) -> impl CryptoRngCore {
        OsRng
    }
    fn salt_rng(&self) -> impl CryptoRngCore {
        OsRng
    }
}

impl Instance<TestCtx> for TestInstance {
    fn locate() -> <TestCtx as Context>::InstanceLoc {
        "<located instance>".to_string()
    }

    fn open(loc: <TestCtx as Context>::InstanceLoc) -> Result<Self, <TestCtx as Context>::Error> {
        assert!(Path::new(&loc).is_dir());

        let decrypted = [1u8; 32];

        let pass = TestCtx::INSTANCE_PASS;
        let salt = SaltString::from_b64("saltyhehe").unwrap();
        let mut pass_hash = [0; 32];
        Argon2::default()
            .hash_password_into(pass.as_bytes(), salt.as_str().as_bytes(), &mut pass_hash)
            .unwrap();

        let mut encrypter = Encrypter::new(decrypted.as_slice(), &pass_hash).unwrap();
        let key: Vec<u8> = iter::repeat(())
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

        assert_eq!(key.len(), CRYPTED_ENCRYPTION_KEY_SIZE);

        let root = Path::new(&loc).canonicalize().unwrap();
        Ok(Self {
            root: dbg!(root),
            key: CryptedEncryptionKey {
                key: key.try_into().unwrap(),
                salt,
            },
        })
    }

    fn get_key(
        &mut self,
    ) -> Result<crate::interfaces::CryptedEncryptionKey, <TestCtx as Context>::Error> {
        Ok(self.key.clone())
    }

    fn get_element<const IS_PASSWORD: bool>(
        &self,
        path: &<TestCtx as Context>::FileLeaf<IS_PASSWORD>,
    ) -> Result<<TestCtx as Context>::FileRead, <TestCtx as Context>::Error> {
        let path = self.compute_path(path.as_ref(), IS_PASSWORD);
        Ok(fs::File::open(path).unwrap())
    }

    fn list_content<const IS_PASSWORD: bool>(
        &self,
        directory: <TestCtx as Context>::FilePath<IS_PASSWORD>,
    ) -> Result<
        impl Iterator<
            Item = Result<
                crate::interfaces::PathOrLeaf<TestCtx, IS_PASSWORD>,
                <TestCtx as Context>::Error,
            >,
        >,
        <TestCtx as Context>::Error,
    > {
        let p = self.compute_path(&directory, IS_PASSWORD);
        match read_dir(p) {
            Ok(d) => Ok(d.map(|p| {
                if let Ok(p) = p {
                    let p = p.path();
                    Ok(if p.is_dir() {
                        PathOrLeaf::Path(p)
                    } else {
                        PathOrLeaf::Leaf(PathBufLeaf(p))
                    })
                } else {
                    Err(())
                }
            })),
            Err(_) => Err(()),
        }
    }

    fn write_element<const IS_PASSWORD: bool, R: YsbcRead>(
        &mut self,
        path: &<TestCtx as Context>::FileLeaf<IS_PASSWORD>,
        mut content: R,
    ) -> Result<(), <TestCtx as Context>::Error> {
        let path = self.compute_path(path.as_ref(), IS_PASSWORD);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let mut buffer = [0u8; BUFFER_LEN + TAG_SIZE];
        let mut file = fs::File::create(path).unwrap();
        loop {
            let nb_read = match content.read(&mut buffer) {
                Ok(0) => break,
                Ok(v) => v,
                Err(_err) => panic!("blblblbl"),
            };
            file.write_all(&buffer[..nb_read]).unwrap();
        }
        Ok(())
    }

    fn delete(self) -> Result<(), (<TestCtx as Context>::Error, Self)> {
        let _ = fs::remove_dir_all(self.root);
        Ok(())
    }
}

impl CharsDist for TestCDist {
    fn char_ranges(&self) -> impl ExactSizeIterator<Item = (char, char)> + '_ {
        [('a', 'z'), ('A', 'Z'), ('0', '9')].into_iter()
    }
}

#[derive(Debug)]
pub struct PathBufLeaf(pub PathBuf);
impl Display for PathBufLeaf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl From<PathBufLeaf> for PathBuf {
    fn from(value: PathBufLeaf) -> Self {
        value.0
    }
}

impl AsRef<PathBuf> for PathBufLeaf {
    fn as_ref(&self) -> &PathBuf {
        &self.0
    }
}

impl<const IS_PASSWORD: bool> FilePath<IS_PASSWORD> for PathBuf {
    type Leaf = PathBufLeaf;

    fn root() -> Self {
        PathBuf::from("/")
    }

    fn with_dir(mut self, dir: impl AsRef<str>) -> Self {
        self.push(dir.as_ref());
        self
    }

    fn get_suffix(&self, prefix: &Self) -> &str {
        self.strip_prefix(prefix).unwrap().to_str().unwrap()
    }

    fn file(self, _dir: impl AsRef<str>) -> Self::Leaf {
        todo!()
    }
}
impl<const IS_PASSWORD: bool> FileLeaf<IS_PASSWORD> for PathBufLeaf {
    type Path = PathBuf;

    fn get_suffix(&self, prefix: &Self::Path) -> &str {
        self.0.strip_prefix(prefix).unwrap().to_str().unwrap()
    }
}
