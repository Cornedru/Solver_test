use crate::solver::task::TurnstileTask;
use crate::solver::user_fingerprint::Fingerprint;
use anyhow::{anyhow, Context, Result};
use rand::{rng, Rng};
use std::sync::Arc;
use tokio::fs;

pub(crate) mod challenge;
pub mod entries;
pub mod keys;
mod performance;
pub mod task;
mod task_client;
pub mod user_fingerprint;
mod utils;
pub mod vm_parser;
mod timezone;

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub branch: String,
    pub version: String,
}

pub struct TurnstileSolver {
    fingerprints: Arc<Vec<Fingerprint>>,
}

impl TurnstileSolver {
    pub async fn new() -> Result<Self> {
        let path = "workspace/cloudflare_test.json";
        let fp_str = fs::read(path)
            .await
            .with_context(|| format!("Failed to read fingerprint file at {}", path))?;

        let raw_values: Vec<serde_json::Value> = serde_json::from_slice(&fp_str)
            .context("Failed to parse fingerprints JSON")?;

        let mut fps = Vec::with_capacity(raw_values.len());
        // Correction Warning: suppression de .enumerate() car 'i' était inutilisé
        for v in raw_values {
            if let Ok(fp) = serde_json::from_value::<Fingerprint>(v) {
                fps.push(fp);
            }
        }

        if fps.is_empty() {
            return Err(anyhow!("No valid fingerprints found in {}", path));
        }

        Ok(Self {
            fingerprints: Arc::new(fps),
        })
    }

    pub async fn create_task(
        &self,
        site_key: impl Into<String>,
        href: impl Into<String>,
        action: Option<String>,
        c_data: Option<String>,
    ) -> Result<TurnstileTask> {
        // Correction Error: Suppression du '?' car get_fingerprint ne retourne pas un Result
        let fingerprint = self.get_fingerprint();
        let site_key = site_key.into();

        let task = TurnstileTask::new(
            site_key,
            href.into(),
            action,
            c_data,
            None,
            fingerprint,
        )?;

        Ok(task)
    }

    fn get_fingerprint(&self) -> &Fingerprint {
        let idx = rng().random_range(0..self.fingerprints.len());
        &self.fingerprints[idx]
    }
}