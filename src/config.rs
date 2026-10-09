mod password;

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::Deserialize;

pub use password::{Error as PasswordError, Password};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("include cycle through {0}")]
    IncludeCycle(PathBuf),
    #[error("{kind} name `{name}` must be non-empty and must not contain `:`")]
    InvalidName { kind: &'static str, name: String },
    #[error("duplicate {kind} `{name}`")]
    Duplicate { kind: &'static str, name: String },
    #[error("remote `{remote}` refers to unknown auth `{auth}`")]
    UnknownAuth { remote: String, auth: String },
    #[error("mirror `{mirror}` refers to unknown remote `{remote}`")]
    UnknownMirrorRemote { mirror: String, remote: String },
    #[error("unknown remote `{0}`")]
    UnknownRemote(String),
    #[error(
        "{path} contains a plain password and must not be accessible by group or others (mode {mode:o}), run chmod 600"
    )]
    InsecurePlainPassword { path: PathBuf, mode: u32 },
    #[error("HOME is not set")]
    NoHome,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct SmbUrl {
    host: String,
    share: String,
}

impl SmbUrl {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn share(&self) -> &str {
        &self.share
    }

    pub fn to_unc(&self) -> String {
        format!(r"\\{}\{}", self.host, self.share)
    }
}

impl TryFrom<String> for SmbUrl {
    type Error = String;

    fn try_from(url: String) -> Result<Self, Self::Error> {
        let invalid = || format!("invalid url `{url}`, expected smb://host/share");
        let rest = url.strip_prefix("smb://").ok_or_else(invalid)?;
        let (host, share) = rest
            .trim_end_matches('/')
            .split_once('/')
            .ok_or_else(invalid)?;
        if [host, share]
            .iter()
            .any(|part| part.is_empty() || part.contains(['/', '\\', '\0']))
        {
            return Err(invalid());
        }
        Ok(Self {
            host: host.to_owned(),
            share: share.to_owned(),
        })
    }
}

impl fmt::Display for SmbUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "smb://{}/{}", self.host, self.share)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    pub name: String,
    pub url: SmbUrl,
    pub auth: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mirror {
    pub name: String,
    pub remote: String,
    pub target: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawAuth")]
pub struct Auth {
    pub username: String,
    pub domain: Option<String>,
    pub password: Password,
}

impl Auth {
    pub fn principal(&self) -> String {
        match &self.domain {
            Some(domain) => format!(r"{domain}\{}", self.username),
            None => self.username.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuth {
    username: String,
    domain: Option<String>,
    password_file: Option<PathBuf>,
    password_env: Option<String>,
    password_command: Option<String>,
    password: Option<SecretString>,
}

impl TryFrom<RawAuth> for Auth {
    type Error = &'static str;

    fn try_from(raw: RawAuth) -> Result<Self, Self::Error> {
        let password = match (
            raw.password_file,
            raw.password_env,
            raw.password_command,
            raw.password,
        ) {
            (Some(path), None, None, None) => Password::File(path),
            (None, Some(name), None, None) => Password::Env(name),
            (None, None, Some(command), None) => Password::Command(command),
            (None, None, None, Some(secret)) => Password::Plain(secret),
            _ => {
                return Err(
                    "set exactly one of password_file, password_env, password_command, password",
                );
            }
        };
        Ok(Self {
            username: raw.username,
            domain: raw.domain,
            password,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    include: Vec<PathBuf>,
    #[serde(default)]
    remote: Vec<Remote>,
    #[serde(default)]
    mirror: Vec<Mirror>,
    #[serde(default)]
    auth: BTreeMap<String, Auth>,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub remotes: Vec<Remote>,
    pub mirrors: Vec<Mirror>,
    pub auths: BTreeMap<String, Auth>,
}

impl Config {
    pub fn default_path() -> Result<PathBuf, Error> {
        let base = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => home()?.join(".config"),
        };
        Ok(base.join("zenith-sync").join("config.toml"))
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let mut config = Self::default();
        config.merge_file(path, &mut Vec::new())?;
        config.validate()?;
        Ok(config)
    }

    pub fn remote(&self, name: &str) -> Result<&Remote, Error> {
        self.remotes
            .iter()
            .find(|remote| remote.name == name)
            .ok_or_else(|| Error::UnknownRemote(name.to_owned()))
    }

    pub fn auth(&self, remote: &Remote) -> Result<&Auth, Error> {
        self.auths
            .get(&remote.auth)
            .ok_or_else(|| Error::UnknownAuth {
                remote: remote.name.clone(),
                auth: remote.auth.clone(),
            })
    }

    fn merge_file(&mut self, path: &Path, stack: &mut Vec<PathBuf>) -> Result<(), Error> {
        let path = fs::canonicalize(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if stack.contains(&path) {
            return Err(Error::IncludeCycle(path));
        }
        let text = fs::read_to_string(&path).map_err(|source| Error::Read {
            path: path.clone(),
            source,
        })?;
        let mut file: File = toml::from_str(&text).map_err(|source| Error::Parse {
            path: path.clone(),
            source,
        })?;
        let dir = path.parent().unwrap_or(Path::new("/"));

        for (name, auth) in &file.auth {
            if matches!(auth.password, Password::Plain(_)) {
                check_private(&path)?;
                tracing::warn!(
                    "auth `{name}` in {} uses a plain password, prefer password_file, password_env or password_command",
                    path.display()
                );
            }
        }
        for auth in file.auth.values_mut() {
            if let Password::File(file_path) = &mut auth.password {
                *file_path = resolve(dir, file_path)?;
            }
        }
        for mirror in &mut file.mirror {
            mirror.target = resolve(dir, &mirror.target)?;
        }

        self.remotes.append(&mut file.remote);
        self.mirrors.append(&mut file.mirror);
        for (name, auth) in file.auth {
            match self.auths.entry(name) {
                Entry::Vacant(entry) => {
                    entry.insert(auth);
                }
                Entry::Occupied(entry) => {
                    return Err(Error::Duplicate {
                        kind: "auth",
                        name: entry.key().clone(),
                    });
                }
            }
        }

        stack.push(path.clone());
        for include in &file.include {
            self.merge_file(&resolve(dir, include)?, stack)?;
        }
        stack.pop();
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        check_names("remote", self.remotes.iter().map(|remote| &remote.name))?;
        check_names("mirror", self.mirrors.iter().map(|mirror| &mirror.name))?;
        check_names("auth", self.auths.keys())?;
        for remote in &self.remotes {
            self.auth(remote)?;
        }
        for mirror in &self.mirrors {
            if self.remote(&mirror.remote).is_err() {
                return Err(Error::UnknownMirrorRemote {
                    mirror: mirror.name.clone(),
                    remote: mirror.remote.clone(),
                });
            }
        }
        Ok(())
    }
}

fn check_names<'a>(
    kind: &'static str,
    names: impl Iterator<Item = &'a String>,
) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for name in names {
        if name.is_empty() || name.contains(':') {
            return Err(Error::InvalidName {
                kind,
                name: name.clone(),
            });
        }
        if !seen.insert(name) {
            return Err(Error::Duplicate {
                kind,
                name: name.clone(),
            });
        }
    }
    Ok(())
}

fn check_private(path: &Path) -> Result<(), Error> {
    let mode = password::mode(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if mode & 0o077 != 0 {
        return Err(Error::InsecurePlainPassword {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

fn home() -> Result<PathBuf, Error> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or(Error::NoHome)
}

fn resolve(dir: &Path, path: &Path) -> Result<PathBuf, Error> {
    match path.strip_prefix("~") {
        Ok(rest) => Ok(home()?.join(rest)),
        Err(_) => Ok(dir.join(path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::os::unix::fs::PermissionsExt;

    const BASE: &str = r#"
        [[remote]]
        name = "example"
        url = "smb://fileserver.example.com/files$"
        auth = "example"

        [[mirror]]
        name = "data"
        remote = "example"
        target = "mirror/data"

        [auth.example]
        username = "alice"
        domain = "EXAMPLE"
        password_file = "example.pass"
    "#;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    fn load(body: &str) -> (tempfile::TempDir, Result<Config, Error>) {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "config.toml", body);
        let config = Config::load(&path);
        (dir, config)
    }

    #[test]
    fn loads_full_config() {
        let (dir, config) = load(BASE);
        let config = config.unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();

        let remote = config.remote("example").unwrap();
        assert_eq!(remote.url.host(), "fileserver.example.com");
        assert_eq!(remote.url.share(), "files$");
        assert_eq!(remote.url.to_unc(), r"\\fileserver.example.com\files$");

        let auth = config.auth(remote).unwrap();
        assert_eq!(auth.principal(), r"EXAMPLE\alice");
        assert!(matches!(&auth.password, Password::File(p) if *p == root.join("example.pass")));

        assert_eq!(config.mirrors[0].target, root.join("mirror/data"));
    }

    #[test]
    fn principal_without_domain_is_username() {
        let (_dir, config) = load(
            r#"
            [auth.local]
            username = "guest"
            password_env = "ZS_PASS"
        "#,
        );
        assert_eq!(config.unwrap().auths["local"].principal(), "guest");
    }

    #[test]
    fn includes_are_merged_relative_to_including_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("conf.d")).unwrap();
        write(dir.path(), "conf.d/example.toml", BASE);
        let main = write(
            dir.path(),
            "config.toml",
            r#"
            include = ["conf.d/example.toml"]

            [[remote]]
            name = "other"
            url = "smb://other/share"
            auth = "example"
        "#,
        );
        let config = Config::load(&main).unwrap();
        let names: Vec<_> = config.remotes.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["other", "example"]);
        let root = fs::canonicalize(dir.path()).unwrap();
        assert_eq!(config.mirrors[0].target, root.join("conf.d/mirror/data"));
    }

    #[test]
    fn include_cycle_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.toml", r#"include = ["b.toml"]"#);
        let b = write(dir.path(), "b.toml", r#"include = ["a.toml"]"#);
        let err = Config::load(&b).unwrap_err();
        assert!(matches!(err, Error::IncludeCycle(_)));
    }

    #[test]
    fn missing_include_is_a_read_error() {
        let (_dir, config) = load(r#"include = ["nope.toml"]"#);
        assert!(matches!(config.unwrap_err(), Error::Read { .. }));
    }

    #[test]
    fn duplicate_remote_across_includes_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "base.toml", BASE);
        let main = write(
            dir.path(),
            "config.toml",
            r#"
            include = ["base.toml"]
            [[remote]]
            name = "example"
            url = "smb://x/y"
            auth = "example"
        "#,
        );
        let err = Config::load(&main).unwrap_err();
        assert!(matches!(err, Error::Duplicate { kind: "remote", .. }));
    }

    #[test]
    fn duplicate_auth_across_includes_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "base.toml", BASE);
        let main = write(
            dir.path(),
            "config.toml",
            r#"
            include = ["base.toml"]
            [auth.example]
            username = "x"
            password_env = "X"
        "#,
        );
        let err = Config::load(&main).unwrap_err();
        assert!(matches!(err, Error::Duplicate { kind: "auth", .. }));
    }

    #[test]
    fn unknown_auth_is_rejected() {
        let (_dir, config) = load(
            r#"
            [[remote]]
            name = "r"
            url = "smb://h/s"
            auth = "missing"
        "#,
        );
        assert!(matches!(config.unwrap_err(), Error::UnknownAuth { .. }));
    }

    #[test]
    fn unknown_mirror_remote_is_rejected() {
        let (_dir, config) = load(
            r#"
            [[mirror]]
            name = "m"
            remote = "missing"
            target = "/tmp/m"
        "#,
        );
        assert!(matches!(
            config.unwrap_err(),
            Error::UnknownMirrorRemote { .. }
        ));
    }

    #[test]
    fn remote_name_with_colon_is_rejected() {
        let (_dir, config) = load(&BASE.replace(r#"name = "example""#, r#"name = "a:b""#));
        assert!(matches!(config.unwrap_err(), Error::InvalidName { .. }));
    }

    #[test]
    fn unknown_remote_lookup_fails() {
        let (_dir, config) = load(BASE);
        assert!(matches!(
            config.unwrap().remote("nope"),
            Err(Error::UnknownRemote(_))
        ));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let (_dir, config) = load("colour = \"red\"");
        assert!(matches!(config.unwrap_err(), Error::Parse { .. }));
    }

    #[test]
    fn multiple_password_sources_are_rejected() {
        let (_dir, config) = load(
            r#"
            [auth.a]
            username = "u"
            password_env = "X"
            password_command = "echo x"
        "#,
        );
        assert!(matches!(config.unwrap_err(), Error::Parse { .. }));
    }

    #[test]
    fn missing_password_source_is_rejected() {
        let (_dir, config) = load(
            r#"
            [auth.a]
            username = "u"
        "#,
        );
        assert!(matches!(config.unwrap_err(), Error::Parse { .. }));
    }

    #[test]
    fn plain_password_requires_private_config() {
        let body = r#"
            [auth.a]
            username = "u"
            password = "inline"
        "#;
        let (_dir, config) = load(body);
        assert!(matches!(
            config.unwrap_err(),
            Error::InsecurePlainPassword { mode: 0o644, .. }
        ));

        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "config.toml", body);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let config = Config::load(&path).unwrap();
        let secret = config.auths["a"].password.resolve().unwrap();
        assert_eq!(secret.expose_secret(), "inline");
    }

    #[test]
    fn tilde_expands_to_home() {
        let home = home().unwrap();
        assert_eq!(
            resolve(Path::new("/etc"), Path::new("~/x/y")).unwrap(),
            home.join("x/y")
        );
        assert_eq!(
            resolve(Path::new("/etc"), Path::new("/abs")).unwrap(),
            PathBuf::from("/abs")
        );
        assert_eq!(
            resolve(Path::new("/etc"), Path::new("rel")).unwrap(),
            PathBuf::from("/etc/rel")
        );
    }

    #[test]
    fn default_path_ends_with_config_toml() {
        assert!(
            Config::default_path()
                .unwrap()
                .ends_with("zenith-sync/config.toml")
        );
    }

    #[test]
    fn invalid_urls_are_rejected() {
        for url in [
            "http://h/s",
            "smb://h",
            "smb:///s",
            "smb://h/",
            "smb://h/s/sub",
            "smb://h/s\\x",
        ] {
            assert!(SmbUrl::try_from(url.to_owned()).is_err(), "{url}");
        }
    }

    #[test]
    fn url_trailing_slash_is_allowed() {
        let url = SmbUrl::try_from("smb://h/s/".to_owned()).unwrap();
        assert_eq!(url.to_string(), "smb://h/s");
    }
}
