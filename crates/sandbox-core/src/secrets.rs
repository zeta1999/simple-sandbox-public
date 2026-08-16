//! Resolve policy secret references into env vars using secure-memory buffers.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use sandbox_policy::SecretRef;
use secure_memory::LockedBuffer;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret source unavailable: {0}")]
    Unavailable(String),
    #[error("secure-memory error: {0}")]
    SecureMemory(String),
    #[error("unsupported secret from '{0}' (use env:NAME, file:PATH, or value:TEXT)")]
    Unsupported(String),
}

/// Map of env var → locked secret bytes (UTF-8).
pub struct SecretMap {
    inner: HashMap<String, LockedBuffer>,
}

impl SecretMap {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn insert(&mut self, env: String, buf: LockedBuffer) {
        self.inner.insert(env, buf);
    }

    /// Materialize as plaintext env pairs for child process injection.
    /// Caller should drop this map promptly after spawn.
    pub fn to_env_pairs(&self) -> Result<Vec<(String, String)>, SecretError> {
        let mut out = Vec::new();
        for (k, buf) in &self.inner {
            let bytes = buf
                .as_slice()
                .map_err(|e| SecretError::SecureMemory(e.to_string()))?;
            let s = std::str::from_utf8(bytes)
                .map_err(|e| SecretError::Unavailable(format!("secret {k} not utf-8: {e}")))?
                .to_string();
            out.push((k.clone(), s));
        }
        Ok(out)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for SecretMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a list of secret refs. Values are held in LockedBuffer until converted.
pub fn resolve_secrets(refs: &[SecretRef], search_root: &Path) -> Result<SecretMap, SecretError> {
    let mut map = SecretMap::new();
    for r in refs {
        let bytes = load_secret_bytes(&r.from, search_root)?;
        let buf = LockedBuffer::from_bytes(&bytes)
            .map_err(|e| SecretError::SecureMemory(e.to_string()))?;
        map.insert(r.env.clone(), buf);
    }
    Ok(map)
}

fn load_secret_bytes(from: &str, search_root: &Path) -> Result<Vec<u8>, SecretError> {
    if let Some(name) = from.strip_prefix("env:") {
        let val = std::env::var(name)
            .map_err(|_| SecretError::Unavailable(format!("host env var '{name}' not set")))?;
        return Ok(val.into_bytes());
    }
    if let Some(path) = from.strip_prefix("file:") {
        let p = Path::new(path);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            search_root.join(p)
        };
        return fs::read(&full).map_err(|e| {
            SecretError::Unavailable(format!("cannot read secret file {}: {e}", full.display()))
        });
    }
    if let Some(text) = from.strip_prefix("value:") {
        return Ok(text.as_bytes().to_vec());
    }
    // Also try plain env name for convenience
    if !from.contains(':') {
        let val = std::env::var(from)
            .map_err(|_| SecretError::Unavailable(format!("host env var '{from}' not set")))?;
        return Ok(val.into_bytes());
    }
    Err(SecretError::Unsupported(from.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_policy::SecretRef;
    use std::env;

    #[test]
    fn resolve_from_value() {
        let refs = vec![SecretRef {
            env: "TOKEN".into(),
            from: "value:abc123".into(),
        }];
        let map = resolve_secrets(&refs, Path::new(".")).unwrap();
        let pairs = map.to_env_pairs().unwrap();
        assert_eq!(pairs, vec![("TOKEN".into(), "abc123".into())]);
    }

    #[test]
    fn resolve_from_env() {
        env::set_var("SSBX_TEST_SECRET", "from-env");
        let refs = vec![SecretRef {
            env: "INJECTED".into(),
            from: "env:SSBX_TEST_SECRET".into(),
        }];
        let map = resolve_secrets(&refs, Path::new(".")).unwrap();
        let pairs = map.to_env_pairs().unwrap();
        assert_eq!(pairs[0].1, "from-env");
        env::remove_var("SSBX_TEST_SECRET");
    }
}
