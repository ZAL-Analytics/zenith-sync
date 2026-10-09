use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const CONFIG: &str = r#"
[[remote]]
name = "csh-data"
url = "smb://127.0.0.1/Data$"
auth = "csh"

[auth.csh]
username = "arsalan"
password_file = "csh.pass"
"#;

fn run(config_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zenith-sync"))
        .arg("--config")
        .arg(config_dir.join("config.toml"))
        .args(args)
        .output()
        .unwrap()
}

fn setup(pass_mode: u32) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.toml"), CONFIG).unwrap();
    let pass = dir.path().join("csh.pass");
    fs::write(&pass, "hunter2\n").unwrap();
    fs::set_permissions(&pass, fs::Permissions::from_mode(pass_mode)).unwrap();
    dir
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn unknown_remote_fails() {
    let dir = setup(0o600);
    let output = run(dir.path(), &["ls", "nope:Engineering"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown remote `nope`"));
}

#[test]
fn target_without_colon_fails() {
    let dir = setup(0o600);
    let output = run(dir.path(), &["ls", "csh-data"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("expected REMOTE:PATH"));
}

#[test]
fn insecure_password_file_fails_without_leaking_password() {
    let dir = setup(0o644);
    let output = run(dir.path(), &["check", "csh-data"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("must not be accessible by group or others"));
    assert!(!err.contains("hunter2"));
}

#[test]
fn missing_config_fails() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(dir.path(), &["check", "csh-data"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot load config"));
}
