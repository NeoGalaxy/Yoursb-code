//! Module relative to anything helping finding a project

use std::{
    env::current_dir,
    ffi::OsStr,
    fmt::Display,
    fs::read_dir,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::{
    _try,
    errors::{self, YoursbError},
    InputFilePosArg, OutputFilePosArg,
};

/// The name of the directory in which everything is stored when in a local dir
pub const LOCAL_PROJECT_SUBDIR: &str = ".yoursbcode";

/// The name of the directory in which everything is stored when in the config dir
pub const GLOBAL_CONFIG_NAME: &str = "yoursbcode";

/// The name of the key file
pub const KEY_NAME: &str = "key";

/// The subdirectory in which files are stored
pub const FILES_DIR: &str = "files";

/// A datastructure meant to designate if we use the global project or a local one.
/// It implements [`FromStr`] with as format either `global`, `local` or `local:<path>`.
#[derive(Clone)]
pub enum ProjectPath {
    Local(Option<PathBuf>),
    Global,
}

/// A file position in the CLI. Either inside the instance or a path from current dir
pub enum FilePos {
    Internal(PathBuf),
    External(PathBuf),
}

impl From<InputFilePosArg> for FilePos {
    fn from(value: InputFilePosArg) -> Self {
        if let Some(i) = value.internal {
            Self::Internal(i)
        } else if let Some(e) = value.external {
            Self::External(e)
        } else {
            panic!("Expected `InternalPosArg` to have either an internal or external value");
        }
    }
}

impl From<OutputFilePosArg> for FilePos {
    fn from(value: OutputFilePosArg) -> Self {
        if let Some(i) = value.internal {
            Self::Internal(i)
        } else if let Some(e) = value.external {
            Self::External(e)
        } else {
            panic!("Expected `InternalPosArg` to have either an internal or external value");
        }
    }
}

impl FilePos {
    pub fn to_path(self, project_path: &Path) -> PathBuf {
        match self {
            FilePos::External(e) => e,
            FilePos::Internal(i) => project_path.join(FILES_DIR).join(i),
        }
    }
}

/// Error when the project path has an invalid syntax
#[derive(Debug)]
pub struct InvalidSyntax();

impl Display for InvalidSyntax {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(r#"Invalid syntax, only "global", "local" and "local:<path>" are accepted."#)
    }
}

impl std::error::Error for InvalidSyntax {
    fn description(&self) -> &str {
        r#"Invalid syntax, only "global", "local" and "local:<path>" are accepted."#
    }
}

impl FromStr for ProjectPath {
    type Err = InvalidSyntax;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "global" {
            Ok(ProjectPath::Global)
        } else if s == "local" {
            Ok(ProjectPath::Local(None))
        } else if let Some(path) = s.strip_prefix("local:") {
            let mut path: PathBuf = path.into();
            if !path.ends_with(LOCAL_PROJECT_SUBDIR) {
                path.push(LOCAL_PROJECT_SUBDIR);
            }
            Ok(ProjectPath::Local(Some(path)))
        } else {
            Err(InvalidSyntax())
        }
    }
}

impl ProjectPath {
    pub fn find(&self) -> Result<PathBuf, errors::Error> {
        match self {
            ProjectPath::Local(Some(path)) => path
                .canonicalize()
                .map_err(|e| errors::Error::FileError(path.clone(), e)),
            ProjectPath::Local(None) => {
                find_local_projet().and_then(|proj| proj.ok_or(errors::Error::NoLocalProj))
            }
            ProjectPath::Global => find_global_project().ok_or(errors::Error::NoConfigDir),
        }
    }

    pub fn get_path(&self) -> Result<PathBuf, errors::Error> {
        match self {
            ProjectPath::Local(Some(path)) => Ok(path.to_owned()),
            ProjectPath::Local(None) => Ok(current_dir()
                .unwrap_or(".".into())
                .join(LOCAL_PROJECT_SUBDIR)),
            ProjectPath::Global => Ok(dirs::config_local_dir()
                .ok_or(errors::Error::NoConfigDir)?
                .join(GLOBAL_CONFIG_NAME)),
        }
    }
}

/// Runs [`find_parent_projet`] followed by [`find_config_project`], searching
/// for the first project it can find.
///
/// Returns `Some(project)` if a project is found, and `None` otherwise
///
/// May error saying that the current directory can't be accessed.
pub fn find_project() -> Result<PathBuf, errors::Error> {
    find_local_projet()?
        .or_else(find_global_project)
        .ok_or(errors::Error::NoProject)
}

/// Seaches for a project in the current dir and all its parents. Returns `Err(...)` if there's
/// an issue knowing the current directory, and returns `Ok(None)` if no projet was found.
///
/// If a project is found, returns `Ok(path)` with the path directing to the root dir of the
/// project
pub fn find_local_projet() -> Result<Option<PathBuf>, errors::Error> {
    let dir = _try!(current_dir(), [".".into()]);

    for parent in dir.ancestors() {
        let path = parent.join(LOCAL_PROJECT_SUBDIR);
        if path.exists() {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// Searches for a project in the config directories, returns `None` if it can't be found.
pub fn find_global_project() -> Option<PathBuf> {
    let config_dir = dirs::config_local_dir()?.join(GLOBAL_CONFIG_NAME);
    config_dir.canonicalize().ok()
}

/// Searches for files and directory in the project root directory `root` with the prefix `prefix`.
///
/// Does not recursively seaches for files in found directories
pub fn find_files(
    root: PathBuf,
    prefix: &str,
) -> Result<impl Iterator<Item = Result<PathBuf, errors::Error>>, errors::Error> {
    let final_path = root.join(FILES_DIR).join(prefix);

    let (dir, file_prefix) = if final_path.is_dir() {
        (prefix.into(), String::from(""))
    } else {
        let prefix = Path::new(prefix);
        (
            prefix.parent().unwrap_or(Path::new("")).to_owned(),
            prefix
                .file_name()
                .unwrap_or(OsStr::new(""))
                .to_str()
                .unwrap()
                .to_owned(),
        )
    };

    // To allow both closures to own it
    let dir2 = dir.clone();

    Ok(_try!(
        read_dir(root.join(FILES_DIR).join(dir.clone())),
        [dir.to_owned()]
    )
    .map(move |subdir| {
        let subpath = _try!(subdir, [(dir).to_owned()]);
        Ok(subpath.file_name())
    })
    .filter(move |e| {
        e.as_ref()
            .map(|name| name.to_string_lossy().starts_with(&file_prefix))
            .unwrap_or(true)
    })
    .map(move |e| e.map(|name| dir2.join(name))))
}
