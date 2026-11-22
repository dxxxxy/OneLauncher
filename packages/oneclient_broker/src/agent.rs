//! The launcher-owned javaagent added to every game
//!
//! Built from `agent/src` by `agent/build.py` and
//! embedded here, so the launcher always ships the agent it was tested with.
//! It is written to a content-addressed file and checked on every launch: a
//! sandboxed game can't write there, and an unsandboxed one that tampered
//! with it gets it replaced

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const JAR: &[u8] = include_bytes!("../agent/oneclient-agent.jar");

pub fn sha256() -> String {
    hex(&Sha256::digest(JAR))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Makes sure `<dir>/oneclient-agent-<sha256>.jar` exists and is the embedded
/// jar, and returns its path
pub async fn install(dir: &Path) -> Result<PathBuf, polyio::IOError> {
    let path = dir.join(format!("oneclient-agent-{}.jar", &sha256()[..16]));
    let current = polyio::read(&path).await.ok();
    if current.as_deref() != Some(JAR) {
        polyio::create_dir_all(dir).await?;
        polyio::write_atomic(&path, JAR).await?;
    }
    Ok(path)
}

/// `-javaagent:` plus the properties the agent needs; the key goes in the
/// environment instead (see [`crate::KEY_ENV`])
pub fn jvm_arguments(jar: &Path, broker: &crate::RunningBroker) -> Vec<String> {
    vec![
        format!("-javaagent:{}", jar.display()),
        broker.jvm_property(),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_embedded_jar_is_a_jar() {
        assert!(
            super::JAR.starts_with(b"PK"),
            "agent jar missing or corrupt"
        );
    }
}
