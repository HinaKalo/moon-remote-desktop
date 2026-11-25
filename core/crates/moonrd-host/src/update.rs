//! Signed, per-user updates for the portable host. Checked before starting a session.
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use moonrd_session::release::RelhubManifest;
use reqwest::{Client, redirect::Policy};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const BASE: &str = "https://release.moonl.cloud/v1/apps/moon-remote";
const PLATFORM: &str = "windows-x64-host";
const MAX_PACKAGE_BYTES: i64 = 64 * 1024 * 1024;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
type UpdateError = Box<dyn Error + Send + Sync>;

pub fn build_code() -> i64 {
    option_env!("MOONRD_HOST_BUILD")
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct CheckResponse {
    manifest: RelhubManifest,
}

pub fn client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .build()
}

pub async fn check(http: &Client) -> Result<Option<RelhubManifest>, UpdateError> {
    let code = build_code();
    if code == 0 {
        return Ok(None);
    }
    let url = format!("{BASE}/check?platform={PLATFORM}&channel=stable&versionCode={code}");
    let response: CheckResponse = http
        .get(url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let release = response.manifest;
    validate(&release)?;
    Ok((release.version_code > code).then_some(release))
}

fn validate(release: &RelhubManifest) -> Result<(), UpdateError> {
    release.verify().map_err(io::Error::other)?;
    if release.app != "moon-remote"
        || release.platform != PLATFORM
        || release.channel != "stable"
        || !(1..=MAX_PACKAGE_BYTES).contains(&release.size)
        || release.version_name != format!("0.1.{}", release.version_code)
        || release.file != format!("moon-remote-{}-{PLATFORM}.zip", release.version_name)
    {
        return Err(io::Error::other("invalid Core release manifest").into());
    }
    Ok(())
}

pub async fn stage(
    http: &Client,
    release: &RelhubManifest,
    data: &Path,
) -> Result<TempDir, UpdateError> {
    let url = format!(
        "{BASE}/{PLATFORM}/releases/{}/download",
        release.version_code
    );
    let mut response = http
        .get(url)
        .timeout(Duration::from_secs(90))
        .send()
        .await?
        .error_for_status()?;
    let mut package = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if package.len() + chunk.len() > release.size as usize {
            return Err(io::Error::other("Core download exceeded its signed size").into());
        }
        package.extend_from_slice(&chunk);
    }
    if package.len() != release.size as usize
        || !format!("{:x}", Sha256::digest(&package)).eq_ignore_ascii_case(&release.sha256)
    {
        return Err(io::Error::other("Core download failed its size or SHA-256 check").into());
    }

    let releases = data.join("releases");
    fs::create_dir_all(&releases)?;
    let download = tempfile::tempdir_in(&releases)?;
    let archive = download.path().join("package.zip");
    fs::write(&archive, package)?;
    let staged = tempfile::Builder::new()
        .prefix(&format!("{}-", release.version_name))
        .tempdir_in(&releases)?;
    let windows = PathBuf::from(
        std::env::var_os("SystemRoot").ok_or_else(|| io::Error::other("SystemRoot not set"))?,
    );
    let powershell = windows.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let unpack = "$ErrorActionPreference = 'Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory($env:MOONRD_CORE_PACKAGE, $env:MOONRD_CORE_STAGE)";
    let status = tokio::process::Command::new(powershell)
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-Command", unpack])
        .env("MOONRD_CORE_PACKAGE", archive)
        .env("MOONRD_CORE_STAGE", staged.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    if !status.success() {
        return Err(io::Error::other("could not unpack the signed Core update").into());
    }
    for file in [
        "moonrd-host.exe",
        "moonrd-agent.exe",
        "easytier/easytier-core.exe",
        "easytier/easytier-cli.exe",
        "easytier/Packet.dll",
    ] {
        if !staged.path().join(file).is_file() {
            return Err(io::Error::other(format!("Core update missing {file}")).into());
        }
    }
    Ok(staged)
}

pub async fn prepare(data: &Path) -> Result<Option<(i64, TempDir)>, UpdateError> {
    let http = client()?;
    let Some(release) = check(&http).await? else {
        return Ok(None);
    };
    let staged = stage(&http, &release, data).await?;
    Ok(Some((release.version_code, staged)))
}

pub async fn activate(
    data: &Path,
    code: i64,
    staged: TempDir,
    background: bool,
) -> Result<(), UpdateError> {
    let handshake = tempfile::tempdir_in(data)?;
    let marker = handshake.path().join("ready");
    let exe = staged.path().join("moonrd-host.exe");
    let mut command = tokio::process::Command::new(&exe);
    command
        .creation_flags(CREATE_NO_WINDOW)
        .current_dir(staged.path())
        .arg("--update-ready")
        .arg(&marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if background {
        command.arg("--background");
    }
    let mut child = command.spawn()?;
    let expected = code.to_string();
    let result = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "updated Core exited with {status}"
                    )));
                }
                if fs::read_to_string(&marker).is_ok_and(|value| value == expected) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await??;
        if crate::autostart::is_enabled() {
            crate::autostart::set_enabled(&exe, true)?;
        }
        Ok::<_, UpdateError>(())
    }
    .await;
    match result {
        Ok(()) => {
            let _ = staged.keep();
            Ok(())
        }
        Err(error) => {
            let _ = child.kill().await;
            Err(error)
        }
    }
}
