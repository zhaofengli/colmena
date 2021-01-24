use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::ops::Deref;

use serde::{Serialize, Deserialize};

use super::{Host, NixResult, NixError};

/// A Nix store path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorePath(PathBuf);

impl StorePath {
    /// Returns the raw store path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Determines whether the path points to a derivation.
    pub fn is_derivation(&self) -> bool {
        if let Some(ext) = self.0.extension() {
            ext == "drv"
        } else {
            false
        }
    }

    /// Converts the store path into a store derivation.
    pub fn to_derivation<T: TryFrom<Vec<StorePath>>>(self) -> Option<StoreDerivation<T>> {
        if self.is_derivation() {
            Some(StoreDerivation::<T>::from_store_path_unchecked(self))
        } else {
            None
        }
    }
}

impl Deref for StorePath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<String> for StorePath {
    type Error = NixError;

    fn try_from(s: String) -> NixResult<Self> {
        if s.starts_with("/nix/store/") {
            Ok(Self(s.into()))
        } else {
            Err(NixError::InvalidStorePath)
        }
    }
}

impl Into<PathBuf> for StorePath {
    fn into(self) -> PathBuf {
        self.0
    }
}

/// A store derivation (.drv) that will result in a T when built.
pub struct StoreDerivation<T: TryFrom<Vec<StorePath>>>{
    path: StorePath,
    _target: PhantomData<T>,
}

impl<T: TryFrom<Vec<StorePath>>> StoreDerivation<T> {
    fn from_store_path_unchecked(path: StorePath) -> Self {
        Self {
            path,
            _target: PhantomData,
        }
    }
}

impl<T: TryFrom<Vec<StorePath>, Error=NixError>> StoreDerivation<T> {
    /// Builds the store derivation on a host, resulting in a T.
    pub async fn realize(&self, host: &mut dyn Host) -> NixResult<T> {
        let paths: Vec<StorePath> = host.realize(&self.path).await?;
        paths.try_into()
    }
}
