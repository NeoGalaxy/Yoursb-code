use std::{
    fmt::Display,
    fs::{self, create_dir_all},
    io::{stdin, stdout, Read, Write},
    ops::{Deref, DerefMut},
    path::PathBuf,
    str::FromStr,
};

use chacha20poly1305::aead::rand_core::CryptoRngCore;
use rand::rngs::OsRng;
use yoursb_domain::interfaces::{
    CharsDist, Context, CryptedEncryptionKey, FileLeaf, FilePath, InitInstanceContext, Instance,
    PathOrLeaf, SaltString, CRYPTED_ENCRYPTION_KEY_SIZE,
};

use crate::repo::{find_global_repo, find_local_repo, RepoPath, KEY_NAME, LOCAL_REPO_SUBDIR};

#[derive(Debug)]
pub struct CliCtx;

#[derive(Debug)]
pub struct CliInstance {
    pub root: PathBuf,
}

impl CliInstance {
    fn compute_path(&self, path: &PathBuf, is_password: bool) -> PathBuf {
        self.root
            .join(if is_password { "passwords" } else { "files" })
            .join(path)
    }
}

impl Context for CliCtx {
    type Instance = CliInstance;

    type FilePath<const IS_PASSWORD: bool> = PathBufPath;

    type FileLeaf<const IS_PASSWORD: bool> = PathBufLeaf;

    type InstanceLoc = RepoPath;

    type CharsDist = CliCharDist;

    type Error = ();

    fn indicate<T: core::fmt::Display>(&self, val: T) {
        println!("{val}");
    }

    fn prompt_secret<T>(&self, prompt: T) -> impl core::convert::AsRef<str>
    where
        T: core::fmt::Display,
    {
        print!("{prompt}: ");
        stdout().flush().unwrap();
        let mut line = String::new();
        stdin().read_line(&mut line).unwrap();
        line.trim().to_string()
    }

    fn set_clipboard(&self, content: &str) {
        println!("[set_clipboard] {content}");
    }
}

impl InitInstanceContext for CliCtx {
    fn new_instance(
        loc: Self::InstanceLoc,
        key: CryptedEncryptionKey,
    ) -> Result<Self::Instance, <CliCtx as Context>::Error> {
        let path = loc.get_path().unwrap();

        let keypath = path.join(KEY_NAME);
        if keypath.exists() {
            // return Err(errors::Error::RepoAlreadyExists);
            panic!("RepoAlreadyExists");
        }

        if let Some(p) = keypath.parent() {
            let _ = create_dir_all(p);
        }

        let mut file = fs::File::create(&keypath).unwrap();
        file.write_all(&key.key).unwrap();
        file.write_all(b"\n").unwrap();
        file.write_all(key.salt.as_str().as_bytes()).unwrap();

        Ok(Self::Instance::open(loc).unwrap())
    }
    fn key_rng(&self) -> impl CryptoRngCore {
        OsRng
    }
    fn salt_rng(&self) -> impl CryptoRngCore {
        OsRng
    }
}

impl Instance<CliCtx> for CliInstance {
    fn locate() -> <CliCtx as Context>::InstanceLoc {
        find_local_repo()
            .unwrap()
            .map(|p| RepoPath::Local(Some(p)))
            .unwrap_or(RepoPath::Global)
    }

    fn open(loc: <CliCtx as Context>::InstanceLoc) -> Result<Self, <CliCtx as Context>::Error> {
        let ysbc_dir = match loc {
            RepoPath::Global => find_global_repo().unwrap(),
            RepoPath::Local(None) => find_local_repo().unwrap().unwrap(),
            RepoPath::Local(Some(path)) => path.canonicalize().unwrap().join(LOCAL_REPO_SUBDIR),
        };

        if !ysbc_dir.is_dir() {
            todo!()
        }

        // Check key

        Ok(Self { root: ysbc_dir })
    }

    fn get_key(&mut self) -> Result<CryptedEncryptionKey, <CliCtx as Context>::Error> {
        let keypath = self.root.join(KEY_NAME);
        if keypath.exists() {
            // return Err(errors::Error::RepoAlreadyExists);
            panic!("RepoAlreadyExists");
        }

        if let Some(p) = keypath.parent() {
            let _ = create_dir_all(p);
        }

        let mut file = fs::File::open(&keypath).unwrap();
        let mut key = [0u8; CRYPTED_ENCRYPTION_KEY_SIZE];
        file.read_exact(&mut key).unwrap();
        let mut newline = [0u8; 1];
        file.read_exact(&mut newline).unwrap();
        assert_eq!(&newline, b"\n");
        let mut salt = Vec::new();
        file.read_to_end(&mut salt).unwrap();
        let salt = String::from_utf8(salt).unwrap();

        Ok(CryptedEncryptionKey {
            key,
            salt: SaltString::from_b64(&salt).unwrap(),
        })
    }

    fn get_element<const IS_PASSWORD: bool>(
        &self,
        path: &<CliCtx as Context>::FileLeaf<IS_PASSWORD>,
    ) -> Result<std::vec::Vec<u8>, <CliCtx as Context>::Error> {
        let path = self.compute_path(path.as_ref(), IS_PASSWORD);
        Ok(fs::read(path).unwrap())
    }

    fn list_content<const IS_PASSWORD: bool>(
        &self,
        directory: <CliCtx as Context>::FilePath<IS_PASSWORD>,
    ) -> Result<
        impl Iterator<
            Item = Result<
                yoursb_domain::interfaces::PathOrLeaf<CliCtx, IS_PASSWORD>,
                <CliCtx as Context>::Error,
            >,
        >,
        <CliCtx as Context>::Error,
    > {
        let p = self.compute_path(&directory, IS_PASSWORD);
        match fs::read_dir(p) {
            Ok(d) => Ok(d.map(|p| {
                if let Ok(p) = p {
                    let p = p.path();
                    Ok(if p.is_dir() {
                        PathOrLeaf::Path(p.into())
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

    fn write_element<const IS_PASSWORD: bool>(
        &mut self,
        path: &<CliCtx as Context>::FileLeaf<IS_PASSWORD>,
        content: std::vec::Vec<u8>,
    ) -> Result<(), <CliCtx as Context>::Error> {
        let path = self.compute_path(path.as_ref(), IS_PASSWORD);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(path, content).unwrap();
        Ok(())
    }

    fn delete(self) -> Result<(), <CliCtx as Context>::Error> {
        let _ = fs::remove_dir_all(self.root);
        Ok(())
    }
}

/// A representation of the allowed chars in a password. It contains a vector
/// of the allowed intervals of characters.
///
/// It can be parsed from a string, see the [`allowed_chars`](crate::Cli.allowed_chars)
/// command-line argument for more details.
#[derive(Clone, Debug)]
pub struct CliCharDist(Vec<(char, char)>);

/// An error kind indicating the parsing of a [`CliCharDist`] didn't go well.
#[derive(Clone, Debug)]
pub struct InvalidSyntax {
    pos: usize,
}

impl Display for InvalidSyntax {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Invalid syntax at index {}", self.pos))
    }
}

impl std::error::Error for InvalidSyntax {}

impl FromStr for CliCharDist {
    type Err = InvalidSyntax;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars().enumerate().peekable();
        let mut res = vec![];
        while let Some((_, c)) = chars.next() {
            if c == ' ' {
                continue;
            }

            let start = c;
            if let Some((_, '.')) = chars.peek() {
                chars.next().unwrap();
                if let Some((i, '.')) = chars.peek().copied() {
                    let end = chars
                        .nth(1)
                        .and_then(|(_, c)| if c == ' ' { None } else { Some(c) })
                        .ok_or(InvalidSyntax { pos: i })?;
                    if start > end {
                        return Err(InvalidSyntax { pos: i });
                    }
                    res.push((start, end));
                    continue;
                }

                res.push((start, start));
                res.push(('.', '.'));
                continue;
            }

            res.push((start, start));
        }

        Ok(Self(res))
    }
}

impl CharsDist for CliCharDist {
    fn char_ranges(&self) -> impl ExactSizeIterator<Item = (char, char)> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Debug, Clone)]
pub struct PathBufPath(pub PathBuf);
impl Display for PathBufPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}
impl DerefMut for PathBufPath {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Deref for PathBufPath {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct PathBufLeaf(pub PathBuf);
impl Display for PathBufLeaf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl From<PathBufPath> for PathBuf {
    fn from(value: PathBufPath) -> Self {
        value.0
    }
}
impl From<PathBuf> for PathBufPath {
    fn from(value: PathBuf) -> Self {
        Self(value)
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

impl<const IS_PASSWORD: bool> FilePath<IS_PASSWORD> for PathBufPath {
    type Leaf = PathBufLeaf;

    fn root() -> Self {
        PathBufPath(PathBuf::from("/"))
    }

    fn with_dir(mut self, dir: impl AsRef<str>) -> Self {
        self.push(dir.as_ref());
        self
    }

    fn get_suffix(&self, prefix: &Self) -> &str {
        self.strip_prefix(&prefix.0).unwrap().to_str().unwrap()
    }

    fn file(self, _dir: impl AsRef<str>) -> Self::Leaf {
        todo!()
    }
}
impl<const IS_PASSWORD: bool> FileLeaf<IS_PASSWORD> for PathBufLeaf {
    type Path = PathBufPath;

    fn get_suffix(&self, prefix: &Self::Path) -> &str {
        self.0.strip_prefix(&prefix.0).unwrap().to_str().unwrap()
    }
}
