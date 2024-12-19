#![cfg(test)]

use std::{
    fmt::Display,
    fs::{self, read_dir},
    path::PathBuf,
    prelude::rust_2021::*,
    println,
};

use crate::interfaces::{CharsDist, Context, FileLeaf, FilePath, Instance, PathOrLeaf};

struct TestCtx {}

struct TestInstance {
    root: PathBuf,
}
impl TestInstance {
    fn compute_path(&self, path: &PathBuf, is_password: bool) -> PathBuf {
        self.root
            .join(if is_password { "pass" } else { "files" })
            .join(path)
    }
}

struct TestCDist {}

impl Context for TestCtx {
    type Instance = TestInstance;

    type FilePath<const IS_PASSWORD: bool> = PathBuf;

    type FileLeaf<const IS_PASSWORD: bool> = PathBufLeaf;

    type InstanceLoc = String;

    type CharsDist = TestCDist;

    type Error = ();

    fn indicate<T: core::fmt::Display>(&self, val: T) {
        println!("[indicate] {val}");
    }

    fn prompt_passkey(&self) -> impl AsRef<str> {
        ""
    }

    fn set_clipboard(&self, content: &str) {
        println!("[set_clipboard] {content}");
    }
}

impl Instance<TestCtx> for TestInstance {
    fn locate() -> <TestCtx as Context>::InstanceLoc {
        "<located instance>".to_string()
    }

    fn open(loc: <TestCtx as Context>::InstanceLoc) -> Result<Self, <TestCtx as Context>::Error> {
        Ok(Self { root: loc.into() })
    }

    fn unlock_key(
        &mut self,
        commands: &crate::commands::Commands<TestCtx>,
    ) -> Result<crate::interfaces::EncryptionKey, <TestCtx as Context>::Error> {
        todo!()
    }

    fn get_element<const IS_PASSWORD: bool>(
        &self,
        path: &<TestCtx as Context>::FileLeaf<IS_PASSWORD>,
    ) -> Result<String, <TestCtx as Context>::Error> {
        todo!()
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

    fn write_element<const IS_PASSWORD: bool>(
        &mut self,
        path: &<TestCtx as Context>::FileLeaf<IS_PASSWORD>,
        content: String,
    ) -> Result<(), <TestCtx as Context>::Error> {
        let path = self.compute_path(path.as_ref(), IS_PASSWORD);
        fs::write(path, content).unwrap();
        Ok(())
    }

    fn delete(self) -> Result<(), <TestCtx as Context>::Error> {
        let _ = fs::remove_dir_all(self.root.join("backup"));
        fs::rename(&self.root, self.root.join("backup")).unwrap();
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
        todo!()
    }

    fn with_dir(self, dir: impl AsRef<str>) -> Self {
        todo!()
    }

    fn get_suffix(&self, prefix: &Self) -> &str {
        todo!()
    }

    fn file(self, dir: impl AsRef<str>) -> Self::Leaf {
        todo!()
    }
}
impl<const IS_PASSWORD: bool> FileLeaf<IS_PASSWORD> for PathBufLeaf {
    type Path = PathBuf;

    fn get_suffix(&self, prefix: &Self::Path) -> &str {
        todo!()
    }
}
