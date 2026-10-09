use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use zenith_sync::config::Config;
use zenith_sync::source::smb::SmbSource;
use zenith_sync::source::{RemotePath, Source};

#[derive(Parser)]
#[command(version, about = "Read-only mirror of network shares to btrfs")]
struct Cli {
    #[arg(long, global = true, help = "Path to config.toml")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Connect to a remote and verify access")]
    Check { remote: String },
    #[command(about = "List a directory on a remote")]
    Ls {
        #[arg(value_name = "REMOTE:PATH")]
        target: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    let cli = Cli::parse();

    let config_path = match cli.config {
        Some(path) => path,
        None => Config::default_path()?,
    };
    let config = Config::load(&config_path)
        .with_context(|| format!("cannot load config {}", config_path.display()))?;

    let (remote_name, path) = match &cli.command {
        Command::Check { remote } => (remote.as_str(), RemotePath::root()),
        Command::Ls { target } => split_target(target)?,
    };
    let remote = config.remote(remote_name)?;
    let auth = config.auth(remote)?;
    let password = auth
        .password
        .resolve()
        .with_context(|| format!("cannot get password for auth `{}`", remote.auth))?;

    tokio::runtime::Runtime::new()?.block_on(async {
        let source = SmbSource::connect(&remote.url, &auth.principal(), &password).await?;
        match cli.command {
            Command::Check { .. } => {
                source.stat(&path).await?;
                println!("ok {} ({})", remote.name, remote.url);
            }
            Command::Ls { .. } => {
                let mut entries = source.list(&path).await?;
                entries.sort_by(|a, b| a.path.cmp(&b.path));
                for entry in entries {
                    println!("{entry}");
                }
            }
        }
        Ok(())
    })
}

fn split_target(target: &str) -> Result<(&str, RemotePath)> {
    let Some((remote, path)) = target.split_once(':') else {
        bail!("expected REMOTE:PATH, got `{target}`");
    };
    Ok((remote, path.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_remote_and_path() {
        let (remote, path) = split_target("example:docs/x").unwrap();
        assert_eq!(remote, "example");
        assert_eq!(path.as_str(), "docs/x");
        assert!(split_target("example:").unwrap().1.is_root());
    }

    #[test]
    fn rejects_target_without_colon_or_with_bad_path() {
        assert!(split_target("example").is_err());
        assert!(split_target("example:../x").is_err());
    }
}
