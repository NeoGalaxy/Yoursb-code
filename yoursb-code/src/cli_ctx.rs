use std::{
    fmt::Display,
    fs::{self, create_dir_all, File},
    io::{stdin, stdout, Read, Write},
    ops::{Deref, DerefMut},
    path::PathBuf,
    str::FromStr,
};

use chacha20poly1305::aead::rand_core::CryptoRngCore;
use rand::rngs::OsRng;
use yoursb_domain::{
    crypto::{YsbcRead, BUFFER_LEN, TAG_SIZE},
    interfaces::{
        CharsDist, Context, CryptedEncryptionKey, FileLeaf, FilePath, InitInstanceContext,
        Instance, PathOrLeaf, SaltString, CRYPTED_ENCRYPTION_KEY_SIZE,
    },
};

use crate::{
    _try,
    errors::{self, CorruptionError, Error},
    repo::{find_global_repo, find_local_repo, RepoPath, KEY_NAME, LOCAL_REPO_SUBDIR},
};

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

    type FileRead = File;

    type Error = errors::Error;

    fn indicate<T: core::fmt::Display>(&self, val: T) {
        println!("{val}");
    }

    fn prompt_secret<T>(&self, prompt: T) -> impl core::convert::AsRef<str>
    where
        T: core::fmt::Display,
    {
        print!("{prompt}: ");
        let _ = stdout().flush();
        let mut line = String::new();
        loop {
            match stdin().read_line(&mut line) {
                Ok(_) => break,
                Err(err) => match err.kind() {
                    std::io::ErrorKind::Interrupted => (),
                    _ => panic!("{}", err),
                },
            }
        }
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
    ) -> Result<Self::Instance, errors::Error> {
        let path = loc.get_path()?;

        let keypath = path.join(KEY_NAME);
        if keypath.exists() {
            return Err(errors::Error::RepoAlreadyExists);
        }

        if let Some(p) = keypath.parent() {
            let _ = create_dir_all(p);
        }

        let mut file = _try!([keypath] fs::File::create(&keypath));
        _try!([keypath] file.write_all(&key.key));
        _try!([keypath] file.write_all(b"\n"));
        _try!([keypath] file.write_all(key.salt.as_str().as_bytes()));

        Self::Instance::open(loc)
    }
    fn key_rng(&self) -> impl CryptoRngCore {
        OsRng
    }
    fn salt_rng(&self) -> impl CryptoRngCore {
        OsRng
    }
}

impl Instance<CliCtx> for CliInstance {
    fn locate() -> Result<RepoPath, errors::Error> {
        Ok(find_local_repo()?
            .map(|p| RepoPath::Local(Some(p)))
            .unwrap_or(RepoPath::Global))
    }

    fn open(loc: <CliCtx as Context>::InstanceLoc) -> Result<Self, errors::Error> {
        let ysbc_dir = match loc {
            RepoPath::Global => find_global_repo(),
            RepoPath::Local(None) => find_local_repo()?,
            RepoPath::Local(Some(path)) => {
                path.canonicalize().ok().map(|p| p.join(LOCAL_REPO_SUBDIR))
            }
        };

        let Some(ysbc_dir) = ysbc_dir else {
            return Err(Error::NoRepo);
        };

        if !ysbc_dir.is_dir() {
            return Err(Error::NoRepo);
        }

        // Check key

        Ok(Self { root: ysbc_dir })
    }

    fn get_key(&mut self) -> Result<CryptedEncryptionKey, errors::Error> {
        let keypath = self.root.join(KEY_NAME);
        if keypath.exists() {
            return Err(errors::Error::RepoAlreadyExists);
        }

        if let Some(p) = keypath.parent() {
            let _ = create_dir_all(p);
        }

        let mut file = _try!([keypath] fs::File::open(&keypath));
        let mut key = [0u8; CRYPTED_ENCRYPTION_KEY_SIZE];
        file.read_exact(&mut key)
            .map_err(|_| CorruptionError::InvalidKeyfile)?;
        let mut newline = [0u8; 1];
        file.read_exact(&mut newline)
            .map_err(|_| CorruptionError::InvalidKeyfile)?;
        if &newline != b"\n" {
            return Err(CorruptionError::InvalidKeyfile.into());
        }

        let mut salt = Vec::new();
        _try!([keypath] file.read_to_end(&mut salt));
        let salt = String::from_utf8(salt).map_err(|_| CorruptionError::InvalidKeyfile)?;

        Ok(CryptedEncryptionKey {
            key,
            salt: SaltString::from_b64(&salt).map_err(|_| CorruptionError::InvalidKeyfile)?,
        })
    }

    fn get_element<const IS_PASSWORD: bool>(
        &self,
        path: &<CliCtx as Context>::FileLeaf<IS_PASSWORD>,
    ) -> Result<fs::File, errors::Error> {
        let path = self.compute_path(path.as_ref(), IS_PASSWORD);
        Ok(_try!([path] fs::File::open(&path)))
    }

    fn list_content<const IS_PASSWORD: bool>(
        &self,
        directory: <CliCtx as Context>::FilePath<IS_PASSWORD>,
    ) -> Result<
        impl Iterator<
            Item = Result<
                yoursb_domain::interfaces::PathOrLeaf<CliCtx, IS_PASSWORD>,
                errors::Error,
            >,
        >,
        errors::Error,
    > {
        let dir_path = self.compute_path(&directory, IS_PASSWORD);
        let d = _try!([dir_path] fs::read_dir(&dir_path));
        Ok(d.map(move |p| {
            let p = _try!([dir_path.clone()] p);
            let p = p.path();
            Ok(if p.is_dir() {
                PathOrLeaf::Path(p.into())
            } else {
                PathOrLeaf::Leaf(PathBufLeaf(p))
            })
        }))
    }

    fn write_element<const IS_PASSWORD: bool, R: YsbcRead>(
        &mut self,
        path: &<CliCtx as Context>::FileLeaf<IS_PASSWORD>,
        mut content: R,
    ) -> Result<(), errors::Error> {
        let path = self.compute_path(path.as_ref(), IS_PASSWORD);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let mut buffer = [0u8; BUFFER_LEN + TAG_SIZE];
        let mut file = _try!([path] fs::File::create(&path));
        loop {
            let nb_read = match content.read(&mut buffer).ok().unwrap() {
                0 => break,
                v => v,
            };
            _try!([path] file.write_all(&buffer[..nb_read]));
        }
        Ok(())
    }

    fn delete(self) -> std::result::Result<(), (errors::Error, CliInstance)> {
        let _ = fs::remove_dir_all(self.root);
        Ok(())
    }
    fn delete_element<const IS_PASSWORD: bool>(
        &mut self,
        path: &PathBufLeaf,
    ) -> std::result::Result<(), errors::Error> {
        _try!([path.0.clone()] fs::remove_file(&path.0));
        if let Some(parent) = path.0.parent() {
            let _ = fs::remove_dir(parent);
        }
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
