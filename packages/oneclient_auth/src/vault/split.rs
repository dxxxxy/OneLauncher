//! The Secret Service hands an unlocked item to anything on the session
//! bus, and a sandboxed game reaches that bus wherever bubblewrap can't run
//! (Ubuntu 24.04's AppArmor leaves only Landlock, which can't hide it). So
//! the keyring never holds the secrets themselves: it holds a random pad,
//! and the secrets XORed with that pad live in a file in the launcher's
//! folder, which no sandbox shows a game. Either half alone says nothing.
//! Each save draws a fresh pad, so no pad is used twice.
//!
//! The file is written under a new name first, then the keyring is pointed
//! at it, then older files go: a crash at any point leaves a pair that
//! still matches.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use super::SecretBackend;
use crate::error::{AuthError, AuthResult};

/// Starts the keyring's half; anything else there is a whole secrets blob
/// from before the split
const MAGIC: &[u8; 8] = b"OCSPLIT1";
const ID_LEN: usize = 16;
/// Halves are padded to a multiple of this, so their size says little about
/// how many accounts there are
const BLOCK: usize = 4096;
const FILE_PREFIX: &str = "auth.share-";

pub struct SplitStore {
    keyring: Arc<dyn SecretBackend>,
    dir: PathBuf,
    /// The keyring held a whole secrets blob: the next save splits it
    legacy: AtomicBool,
}

impl SplitStore {
    pub fn new(keyring: Arc<dyn SecretBackend>, dir: PathBuf) -> Self {
        Self {
            keyring,
            dir,
            legacy: AtomicBool::new(false),
        }
    }

    fn share_path(&self, id: &[u8]) -> PathBuf {
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{FILE_PREFIX}{hex}"))
    }

    /// Files of earlier saves, all but `keep`
    fn remove_other_shares(&self, keep: &Path) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ours = entry.file_name().to_string_lossy().starts_with(FILE_PREFIX);
            if ours && path != keep {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    while out.len() < len {
        out.extend_from_slice(&rand::random::<[u8; 32]>());
    }
    out.truncate(len);
    out
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// `len | sha256 | data`, zero-padded to a whole number of blocks
fn frame(data: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(data.len() + 36);
    framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
    framed.extend_from_slice(&Sha256::digest(data));
    framed.extend_from_slice(data);
    let blocks = framed.len().div_ceil(BLOCK).max(1);
    framed.resize(blocks * BLOCK, 0);
    framed
}

fn unframe(framed: &[u8]) -> Option<Vec<u8>> {
    let len = u32::from_be_bytes(framed.get(..4)?.try_into().ok()?) as usize;
    let hash = framed.get(4..36)?;
    let data = framed.get(36..36 + len)?;
    (Sha256::digest(data).as_slice() == hash).then(|| data.to_vec())
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
}

impl SecretBackend for SplitStore {
    fn name(&self) -> &'static str {
        self.keyring.name()
    }

    fn load(&self) -> AuthResult<Option<Vec<u8>>> {
        let Some(half) = self.keyring.load()? else {
            return Ok(None);
        };
        let Some(rest) = half.strip_prefix(MAGIC.as_slice()) else {
            self.legacy.store(true, Ordering::Relaxed);
            return Ok(Some(half));
        };
        let (Some(id), Some(pad)) = (rest.get(..ID_LEN), rest.get(ID_LEN..)) else {
            tracing::warn!("the keyring's half of the secrets is cut short");
            return Ok(None);
        };
        let file = match std::fs::read(self.share_path(id)) {
            Ok(file) => file,
            // the other half is gone for good: nothing left to read
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!("the file half of the secrets is missing");
                return Ok(None);
            }
            Err(err) => {
                return Err(AuthError::Vault(format!(
                    "could not read the secrets file: {err}"
                )));
            }
        };
        if file.len() != pad.len() {
            tracing::warn!("the two halves of the secrets don't match");
            return Ok(None);
        }
        match unframe(&xor(&file, pad)) {
            Some(data) => Ok(Some(data)),
            None => {
                tracing::warn!("the two halves of the secrets don't match");
                Ok(None)
            }
        }
    }

    fn store(&self, data: &[u8]) -> AuthResult<()> {
        let framed = frame(data);
        let pad = random_bytes(framed.len());
        let id = random_bytes(ID_LEN);
        let path = self.share_path(&id);

        std::fs::create_dir_all(&self.dir)
            .and_then(|()| write_private(&path, &xor(&framed, &pad)))
            .map_err(|err| AuthError::Vault(format!("could not write the secrets file: {err}")))?;

        let mut half = Vec::with_capacity(MAGIC.len() + ID_LEN + pad.len());
        half.extend_from_slice(MAGIC);
        half.extend_from_slice(&id);
        half.extend_from_slice(&pad);
        if let Err(err) = self.keyring.store(&half) {
            // the keyring still points at the previous file, which stays
            let _ = std::fs::remove_file(&path);
            return Err(err);
        }
        self.legacy.store(false, Ordering::Relaxed);
        self.remove_other_shares(&path);
        Ok(())
    }

    fn needs_migration(&self) -> bool {
        self.legacy.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::MemoryBackend;
    use super::super::{AccountSecrets, Secrets, Vault, encode};
    use super::*;

    const REFRESH: &str = "M.C123_refresh-token-that-must-never-sit-whole-in-the-keyring";

    fn secrets() -> Secrets {
        let mut map = Secrets::new();
        map.insert(
            uuid::Uuid::from_u128(1),
            AccountSecrets {
                access_token: "eyJ.access".into(),
                refresh_token: REFRESH.into(),
            },
        );
        map
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w == needle.as_bytes())
    }

    fn shares(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(FILE_PREFIX)
            })
            .collect()
    }

    #[tokio::test]
    async fn neither_half_holds_the_secrets() {
        let dir = polyio::tempdir().await.unwrap();
        let keyring = MemoryBackend::default();
        let store = SplitStore::new(Arc::new(keyring.clone()), dir.dir_path().to_path_buf());
        let mut vault = Vault::new(
            Some(Arc::new(store)),
            dir.dir_path().join("auth.secrets.json"),
        );
        vault.save(&secrets()).await.unwrap();

        let half = keyring.data.lock().unwrap().clone().unwrap();
        assert!(half.starts_with(MAGIC));
        assert!(!contains(&half, REFRESH));
        let files = shares(dir.dir_path());
        assert_eq!(files.len(), 1);
        assert!(!contains(&std::fs::read(&files[0]).unwrap(), REFRESH));

        let store = SplitStore::new(Arc::new(keyring), dir.dir_path().to_path_buf());
        let mut reopened = Vault::new(
            Some(Arc::new(store)),
            dir.dir_path().join("auth.secrets.json"),
        );
        assert_eq!(reopened.load().await, secrets());
    }

    #[tokio::test]
    async fn every_save_draws_a_new_pad_and_cleans_up() {
        let dir = polyio::tempdir().await.unwrap();
        let keyring = MemoryBackend::default();
        let store = SplitStore::new(Arc::new(keyring.clone()), dir.dir_path().to_path_buf());
        let data = encode(&secrets()).unwrap();
        store.store(&data).unwrap();
        let first = keyring.data.lock().unwrap().clone().unwrap();
        store.store(&data).unwrap();
        let second = keyring.data.lock().unwrap().clone().unwrap();
        assert_ne!(first, second);
        assert_eq!(shares(dir.dir_path()).len(), 1);
        assert_eq!(store.load().unwrap(), Some(data));
    }

    #[tokio::test]
    async fn a_whole_blob_from_before_is_split_on_first_load() {
        let dir = polyio::tempdir().await.unwrap();
        let keyring = MemoryBackend::default();
        *keyring.data.lock().unwrap() = Some(encode(&secrets()).unwrap());
        let store = SplitStore::new(Arc::new(keyring.clone()), dir.dir_path().to_path_buf());
        let mut vault = Vault::new(
            Some(Arc::new(store)),
            dir.dir_path().join("auth.secrets.json"),
        );

        assert_eq!(vault.load().await, secrets());
        let half = keyring.data.lock().unwrap().clone().unwrap();
        assert!(
            half.starts_with(MAGIC),
            "the old blob is still whole in the keyring"
        );
        assert!(!contains(&half, REFRESH));
        assert_eq!(shares(dir.dir_path()).len(), 1);
    }

    #[tokio::test]
    async fn a_failed_keyring_write_keeps_the_previous_pair() {
        let dir = polyio::tempdir().await.unwrap();
        let keyring = MemoryBackend::default();
        let store = SplitStore::new(Arc::new(keyring.clone()), dir.dir_path().to_path_buf());
        let data = encode(&secrets()).unwrap();
        store.store(&data).unwrap();

        *keyring.fail.lock().unwrap() = true;
        assert!(store.store(b"newer").is_err());
        *keyring.fail.lock().unwrap() = false;
        assert_eq!(store.load().unwrap(), Some(data));
        assert_eq!(shares(dir.dir_path()).len(), 1);
    }

    #[tokio::test]
    async fn a_lost_file_reads_as_nothing_stored() {
        let dir = polyio::tempdir().await.unwrap();
        let keyring = MemoryBackend::default();
        let store = SplitStore::new(Arc::new(keyring), dir.dir_path().to_path_buf());
        store.store(&encode(&secrets()).unwrap()).unwrap();
        for file in shares(dir.dir_path()) {
            std::fs::remove_file(file).unwrap();
        }
        assert_eq!(store.load().unwrap(), None);
        // and the next save works
        store.store(b"fresh").unwrap();
        assert_eq!(store.load().unwrap(), Some(b"fresh".to_vec()));
    }
}
