use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use secrecy::SecretString;

#[derive(Debug, Clone)]
pub enum Password {
    File(PathBuf),
    Env(String),
    Command(String),
    Plain(SecretString),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read password file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "password file {path} must not be accessible by group or others (mode {mode:o}), run chmod 600"
    )]
    Insecure { path: PathBuf, mode: u32 },
    #[error("environment variable `{0}` is not set or not valid utf-8")]
    Env(String),
    #[error("cannot run password command")]
    Spawn(#[source] io::Error),
    #[error("password command exited with {0}")]
    Status(ExitStatus),
    #[error("password command printed invalid utf-8")]
    Utf8,
}

impl Password {
    pub fn resolve(&self) -> Result<SecretString, Error> {
        match self {
            Password::File(path) => {
                let read = |source| Error::Read {
                    path: path.clone(),
                    source,
                };
                let mode = mode(path).map_err(read)?;
                if mode & 0o077 != 0 {
                    return Err(Error::Insecure {
                        path: path.clone(),
                        mode,
                    });
                }
                Ok(first_line(fs::read_to_string(path).map_err(read)?))
            }
            Password::Env(name) => std::env::var(name)
                .map(SecretString::from)
                .map_err(|_| Error::Env(name.clone())),
            Password::Command(command) => {
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .stdin(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .output()
                    .map_err(Error::Spawn)?;
                if !output.status.success() {
                    return Err(Error::Status(output.status));
                }
                let text = String::from_utf8(output.stdout).map_err(|_| Error::Utf8)?;
                Ok(first_line(text))
            }
            Password::Plain(secret) => Ok(secret.clone()),
        }
    }
}

pub(super) fn mode(path: &Path) -> io::Result<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

fn first_line(mut text: String) -> SecretString {
    let len = text.trim_end_matches(['\r', '\n']).len();
    text.truncate(len);
    SecretString::from(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn password_file(body: &str, mode: u32) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pass");
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        (dir, path)
    }

    #[test]
    fn file_strips_trailing_newline() {
        let (_dir, path) = password_file("s3cret\n", 0o600);
        let secret = Password::File(path).resolve().unwrap();
        assert_eq!(secret.expose_secret(), "s3cret");
    }

    #[test]
    fn file_readable_by_others_is_rejected() {
        let (_dir, path) = password_file("s3cret", 0o644);
        let err = Password::File(path).resolve().unwrap_err();
        assert!(matches!(err, Error::Insecure { mode: 0o644, .. }));
    }

    #[test]
    fn missing_file_is_an_error() {
        let err = Password::File("/nonexistent/zs-pass".into())
            .resolve()
            .unwrap_err();
        assert!(matches!(err, Error::Read { .. }));
    }

    #[test]
    fn env_reads_variable() {
        let expected = std::env::var("PATH").unwrap();
        let secret = Password::Env("PATH".into()).resolve().unwrap();
        assert_eq!(secret.expose_secret(), expected);
    }

    #[test]
    fn missing_env_is_an_error() {
        let err = Password::Env("ZS_SURELY_UNSET_VARIABLE_8F2A".into())
            .resolve()
            .unwrap_err();
        assert!(matches!(err, Error::Env(_)));
    }

    #[test]
    fn command_uses_first_line_of_stdout() {
        let secret = Password::Command("printf 'from-cmd\\n'".into())
            .resolve()
            .unwrap();
        assert_eq!(secret.expose_secret(), "from-cmd");
    }

    #[test]
    fn failing_command_is_an_error() {
        let err = Password::Command("exit 3".into()).resolve().unwrap_err();
        assert!(matches!(err, Error::Status(_)));
    }

    #[test]
    fn plain_is_returned_as_is() {
        let secret = Password::Plain("inline".into()).resolve().unwrap();
        assert_eq!(secret.expose_secret(), "inline");
    }

    #[test]
    fn debug_does_not_leak_plain_password() {
        let debug = format!("{:?}", Password::Plain("hunter2".into()));
        assert!(!debug.contains("hunter2"));
    }
}
