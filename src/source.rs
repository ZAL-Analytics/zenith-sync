pub mod smb;

use std::fmt;
use std::future::Future;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemotePath(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid remote path `{path}`: {reason}")]
pub struct InvalidPath {
    path: String,
    reason: &'static str,
}

impl RemotePath {
    pub fn root() -> Self {
        Self::default()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|component| !component.is_empty())
    }

    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or_default()
    }

    pub fn join(&self, name: &str) -> Result<Self, InvalidPath> {
        let child: Self = name.parse()?;
        if child.components().count() != 1 {
            return Err(InvalidPath {
                path: name.to_owned(),
                reason: "expected a single name",
            });
        }
        if self.is_root() {
            return Ok(child);
        }
        Ok(Self(format!("{}/{}", self.0, child.0)))
    }
}

impl FromStr for RemotePath {
    type Err = InvalidPath;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let invalid = |reason| InvalidPath {
            path: path.to_owned(),
            reason,
        };
        if path.contains('\0') {
            return Err(invalid("contains a NUL byte"));
        }
        if path.starts_with('/') {
            return Err(invalid("must be relative to the share root"));
        }
        let mut components = Vec::new();
        for component in path.split('/') {
            match component {
                "" | "." => {}
                ".." => return Err(invalid("`..` is not allowed")),
                c if c.contains(['\\', ':']) => {
                    return Err(invalid("`\\` and `:` are not allowed"));
                }
                c => components.push(c),
            }
        }
        Ok(Self(components.join("/")))
    }
}

impl fmt::Display for RemotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            f.write_str("/")
        } else {
            f.write_str(&self.0)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: RemotePath,
    pub size: u64,
    pub mtime: SystemTime,
    pub file_id: FileId,
    pub is_dir: bool,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_dir { 'd' } else { '-' };
        write!(
            f,
            "{kind} {:>14} {} {}",
            self.size,
            Rfc3339(self.mtime),
            self.path.file_name()
        )
    }
}

struct Rfc3339(SystemTime);

impl fmt::Display for Rfc3339 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = match self.0.duration_since(UNIX_EPOCH) {
            Ok(elapsed) => elapsed.as_secs() as i64,
            Err(before) => -(before.duration().as_secs_f64().ceil() as i64),
        };
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    }
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    InvalidPath(#[from] InvalidPath),
    #[error("cannot connect to {url}")]
    Connect {
        url: String,
        #[source]
        source: ::smb::Error,
    },
    #[error("smb error on {path}")]
    Smb {
        path: RemotePath,
        #[source]
        source: ::smb::Error,
    },
    #[error("{0} is not a directory")]
    NotADirectory(RemotePath),
    #[error("{0} is not a file")]
    NotAFile(RemotePath),
}

pub trait ReadAt {
    fn read_at(
        &self,
        buf: &mut [u8],
        offset: u64,
    ) -> impl Future<Output = Result<usize, Error>> + Send;
}

pub trait Source {
    type Reader: ReadAt + Send + Sync;

    fn list(&self, path: &RemotePath) -> impl Future<Output = Result<Vec<Entry>, Error>> + Send;

    fn stat(&self, path: &RemotePath) -> impl Future<Output = Result<Entry, Error>> + Send;

    fn open_read(
        &self,
        path: &RemotePath,
    ) -> impl Future<Output = Result<Self::Reader, Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn path(s: &str) -> RemotePath {
        s.parse().unwrap()
    }

    #[test]
    fn normalizes_empty_and_dot_components() {
        assert_eq!(path("Engineering//a/./b/").as_str(), "Engineering/a/b");
        assert!(path("").is_root());
        assert!(path(".").is_root());
    }

    #[test]
    fn rejects_unsafe_paths() {
        for bad in ["/abs", "a/../b", "..", "a\0b", "a\\b", "C:/x", "a/b:stream"] {
            assert!(bad.parse::<RemotePath>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn join_appends_single_name() {
        assert_eq!(RemotePath::root().join("a").unwrap(), path("a"));
        assert_eq!(path("a/b").join("c").unwrap(), path("a/b/c"));
        assert!(path("a").join("b/c").is_err());
        assert!(path("a").join("..").is_err());
        assert!(path("a").join("").is_err());
    }

    #[test]
    fn components_and_file_name() {
        let p = path("a/b/c.txt");
        assert_eq!(p.components().collect::<Vec<_>>(), ["a", "b", "c.txt"]);
        assert_eq!(p.file_name(), "c.txt");
        assert_eq!(RemotePath::root().components().count(), 0);
    }

    #[test]
    fn display_shows_root_as_slash() {
        assert_eq!(RemotePath::root().to_string(), "/");
        assert_eq!(path("a/b").to_string(), "a/b");
    }

    #[test]
    fn formats_rfc3339() {
        let at = |secs| Rfc3339(UNIX_EPOCH + Duration::from_secs(secs)).to_string();
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_791_547_384), "2026-10-09T12:03:04Z");
        assert_eq!(
            Rfc3339(UNIX_EPOCH - Duration::from_secs(1)).to_string(),
            "1969-12-31T23:59:59Z"
        );
    }

    #[test]
    fn entry_display() {
        let entry = Entry {
            path: path("Engineering/report.pdf"),
            size: 1234,
            mtime: UNIX_EPOCH,
            file_id: FileId(7),
            is_dir: false,
        };
        assert_eq!(
            entry.to_string(),
            "-           1234 1970-01-01T00:00:00Z report.pdf"
        );
    }
}
