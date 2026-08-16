//! Persistent sandbox instance store under ~/.config/simple-sandbox.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sandbox_policy::{MechanismKind, SandboxPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::ensure_dir;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("sandbox not found: {0}")]
    NotFound(String),
    #[error("sandbox already exists: {0}")]
    AlreadyExists(String),
}

/// On-disk record for a sandbox instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRecord {
    pub id: String,
    pub name: String,
    pub mechanism: MechanismKind,
    pub runtime_id: String,
    pub policy_hash: String,
    pub workdir: PathBuf,
    pub created_at: DateTime<Utc>,
    pub proxy_port: Option<u16>,
    pub log_path: Option<PathBuf>,
    pub ephemeral: bool,
}

/// Index file listing sandboxes + last used.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SandboxState {
    pub last_used: Option<String>,
    pub sandboxes: Vec<SandboxRecord>,
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StateError> {
        let root = root.into();
        ensure_dir(&root)?;
        ensure_dir(&root.join("sandboxes"))?;
        ensure_dir(&root.join("logs"))?;
        ensure_dir(&root.join("policies"))?;
        let store = Self { root };
        if !store.index_path().exists() {
            store.save_index(&SandboxState::default())?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    pub fn load_index(&self) -> Result<SandboxState, StateError> {
        let data = fs::read_to_string(self.index_path())?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn save_index(&self, state: &SandboxState) -> Result<(), StateError> {
        let data = serde_json::to_string_pretty(state)?;
        fs::write(self.index_path(), data)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SandboxRecord>, StateError> {
        Ok(self.load_index()?.sandboxes)
    }

    pub fn get(&self, name: &str) -> Result<SandboxRecord, StateError> {
        self.load_index()?
            .sandboxes
            .into_iter()
            .find(|s| s.name == name || s.id == name)
            .ok_or_else(|| StateError::NotFound(name.to_string()))
    }

    pub fn get_or_last(&self, name: Option<&str>) -> Result<SandboxRecord, StateError> {
        let state = self.load_index()?;
        if let Some(n) = name {
            return state
                .sandboxes
                .into_iter()
                .find(|s| s.name == n || s.id == n)
                .ok_or_else(|| StateError::NotFound(n.to_string()));
        }
        if let Some(last) = &state.last_used {
            if let Some(rec) = state
                .sandboxes
                .iter()
                .find(|s| &s.name == last || &s.id == last)
            {
                return Ok(rec.clone());
            }
        }
        state
            .sandboxes
            .last()
            .cloned()
            .ok_or_else(|| StateError::NotFound("(no sandboxes)".into()))
    }

    pub fn insert(&self, mut record: SandboxRecord) -> Result<SandboxRecord, StateError> {
        let mut state = self.load_index()?;
        if state.sandboxes.iter().any(|s| s.name == record.name) {
            return Err(StateError::AlreadyExists(record.name));
        }
        if record.id.is_empty() {
            record.id = Uuid::new_v4().to_string();
        }
        // Persist policy copy
        let policy_path = self
            .root
            .join("policies")
            .join(format!("{}.yaml", record.name));
        // policy yaml is written by caller via save_policy

        state.last_used = Some(record.name.clone());
        state.sandboxes.push(record.clone());
        self.save_index(&state)?;
        let _ = policy_path;
        Ok(record)
    }

    pub fn save_policy(&self, name: &str, policy: &SandboxPolicy) -> Result<PathBuf, StateError> {
        let path = self.root.join("policies").join(format!("{name}.yaml"));
        fs::write(
            &path,
            policy
                .to_yaml()
                .map_err(|e| StateError::Io(std::io::Error::other(e.to_string())))?,
        )?;
        Ok(path)
    }

    pub fn load_policy(&self, name: &str) -> Result<SandboxPolicy, StateError> {
        let path = self.root.join("policies").join(format!("{name}.yaml"));
        let text = fs::read_to_string(path)?;
        SandboxPolicy::parse_yaml(&text)
            .map_err(|e| StateError::Io(std::io::Error::other(e.to_string())))
    }

    pub fn update_policy(&self, name: &str, policy: &SandboxPolicy) -> Result<(), StateError> {
        let hash = policy
            .content_hash()
            .map_err(|e| StateError::Io(std::io::Error::other(e.to_string())))?;
        self.save_policy(name, policy)?;
        let mut state = self.load_index()?;
        let rec = state
            .sandboxes
            .iter_mut()
            .find(|s| s.name == name)
            .ok_or_else(|| StateError::NotFound(name.to_string()))?;
        rec.policy_hash = hash;
        state.last_used = Some(name.to_string());
        self.save_index(&state)?;
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<SandboxRecord, StateError> {
        let mut state = self.load_index()?;
        let idx = state
            .sandboxes
            .iter()
            .position(|s| s.name == name || s.id == name)
            .ok_or_else(|| StateError::NotFound(name.to_string()))?;
        let rec = state.sandboxes.remove(idx);
        if state.last_used.as_deref() == Some(&rec.name) {
            state.last_used = state.sandboxes.last().map(|s| s.name.clone());
        }
        self.save_index(&state)?;
        let _ = fs::remove_file(
            self.root
                .join("policies")
                .join(format!("{}.yaml", rec.name)),
        );
        Ok(rec)
    }

    pub fn touch_last_used(&self, name: &str) -> Result<(), StateError> {
        let mut state = self.load_index()?;
        state.last_used = Some(name.to_string());
        self.save_index(&state)
    }

    pub fn log_path_for(&self, name: &str) -> PathBuf {
        self.root.join("logs").join(format!("{name}.log"))
    }

    pub fn new_record(
        name: &str,
        mechanism: MechanismKind,
        runtime_id: &str,
        policy: &SandboxPolicy,
        workdir: &Path,
        ephemeral: bool,
        proxy_port: Option<u16>,
    ) -> Result<SandboxRecord, StateError> {
        Ok(SandboxRecord {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            mechanism,
            runtime_id: runtime_id.to_string(),
            policy_hash: policy
                .content_hash()
                .map_err(|e| StateError::Io(std::io::Error::other(e.to_string())))?,
            workdir: workdir.to_path_buf(),
            created_at: Utc::now(),
            proxy_port,
            log_path: None,
            ephemeral,
        })
    }
}
