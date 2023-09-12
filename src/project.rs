use std::{env::current_dir, fmt::Display, path::PathBuf, str::FromStr};

use crate::{
    _try,
    errors::{self, YoursbError},
};

/// The name of the directory in which everything is stored when in a local dir
pub const LOCAL_PROJECT_SUBDIR: &str = ".yoursbcode";

/// The name of the directory in which everything is stored when in the config dir
pub const GLOBAL_CONFIG_NAME: &str = "yoursbcode";

/// The name of the key file
pub const KEY_NAME: &str = "key";

/// The subdirectory in which files are stored
pub const FILES_DIR: &str = "files";

/// A datastructure meant to designate if we use the global project or a local one
#[derive(Clone)]
pub enum ProjectPath {
    Local(Option<PathBuf>),
    Global,
}

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

pub fn find_global_project() -> Option<PathBuf> {
    let config_dir = dirs::config_local_dir()?.join(GLOBAL_CONFIG_NAME);
    config_dir.canonicalize().ok()
}
