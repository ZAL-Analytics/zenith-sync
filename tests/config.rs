use std::fs;
use std::os::unix::fs::PermissionsExt;

use secrecy::ExposeSecret;
use zenith_sync::config::Config;

#[test]
fn loads_split_config_and_resolves_password_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir(root.join("secrets")).unwrap();
    let pass = root.join("secrets/example.pass");
    fs::write(&pass, "s3cret\n").unwrap();
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        root.join("auth.toml"),
        r#"
        [auth.example]
        username = "alice"
        domain = "EXAMPLE"
        password_file = "secrets/example.pass"
        "#,
    )
    .unwrap();
    let main = root.join("config.toml");
    fs::write(
        &main,
        r#"
        include = ["auth.toml"]

        [[remote]]
        name = "example"
        url = "smb://fileserver.example.com/files$"
        auth = "example"
        "#,
    )
    .unwrap();

    let config = Config::load(&main).unwrap();
    let remote = config.remote("example").unwrap();
    let auth = config.auth(remote).unwrap();
    assert_eq!(auth.principal(), r"EXAMPLE\alice");
    assert_eq!(auth.password.resolve().unwrap().expose_secret(), "s3cret");
}
