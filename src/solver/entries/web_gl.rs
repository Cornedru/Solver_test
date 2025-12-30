use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct WebGLEntry {
    pub masked_gpu_info_key: String,
    pub gpu_masked_vendor_key: String,
    pub gpu_masked_renderer_key: String,
    pub unmasked_gpu_info_key: String,
    pub gpu_unmasked_vendor_key: String,
    pub gpu_unmasked_renderer_key: String,
    pub no_navigator_gpu_data_key: String,
    pub prefix_key: String,
    pub suffix_key: String,
    pub encrypted_content_key: String,
}

#[async_trait]
impl FingerprintEntryBase for WebGLEntry {
    fn parse(
        quick_idx_map: &FxHashMap<String, usize>,
        strings: &[String],
        _: &[VMEntryValue],
    ) -> Result<Self>
    where
        Self: Sized,
    {
        // 1. Extraction des clés basées sur des offsets connus (inchangé car fiable pour les constantes)
        let masked_gpu_info_key = get_string_at_offset(quick_idx_map, strings, "getParameter", -2)?;
        let gpu_masked_vendor_key = get_string_at_offset(quick_idx_map, strings, "getParameter", -1)?;
        let gpu_masked_renderer_key = get_string_at_offset(quick_idx_map, strings, "getParameter", 2)?;
        
        // Point d'ancrage principal
        let unmasked_gpu_info_key = get_string_at_offset(quick_idx_map, strings, "WEBGL_debug_renderer_info", 1)?;
        let anchor_idx = *quick_idx_map.get(&unmasked_gpu_info_key)
            .ok_or_else(|| anyhow!("Anchor key not found in map"))?;

        let gpu_unmasked_vendor_key = get_string_at_offset(quick_idx_map, strings, "WEBGL_debug_renderer_info", 2)?;
        let gpu_unmasked_renderer_key = get_string_at_offset(quick_idx_map, strings, "UNMASKED_VENDOR_WEBGL", 1)?;

        let prefix_key = get_string_at_offset(quick_idx_map, strings, "substring", -1)?;
        let suffix_key = get_string_at_offset(quick_idx_map, strings, "substring", 1)?;
        let no_navigator_gpu_data_key = get_string_at_offset(quick_idx_map, strings, "info", -1)?;

        // 2. Logique améliorée pour encrypted_content_key
        // Au lieu de scanner tout le tableau pour length 5/6, on cherche dans un cluster autour de l'ancre.
        // La clé de résultat est généralement stockée peu après les définitions de constantes WebGL.
        let search_range = 10; // Fenêtre de recherche
        let start_scan = anchor_idx.saturating_sub(5);
        let end_scan = (anchor_idx + search_range).min(strings.len());
        
        // Liste d'exclusion : les clés qu'on connait déjà
        let known_keys = [
            &masked_gpu_info_key, &gpu_masked_vendor_key, &gpu_masked_renderer_key,
            &unmasked_gpu_info_key, &gpu_unmasked_vendor_key, &gpu_unmasked_renderer_key,
            &prefix_key, &suffix_key, &no_navigator_gpu_data_key,
            "getParameter", "WEBGL_debug_renderer_info", "UNMASKED_VENDOR_WEBGL"
        ];

        let encrypted_content_key = strings[start_scan..end_scan]
            .iter()
            .find(|k| {
                let len = k.len();
                // Critères :
                // 1. Longueur typique d'une clé obfusquée (courte, 2-6 chars)
                // 2. N'est pas une des clés déjà résolues ou mots-clés
                // 3. Ne commence pas par des caractères spéciaux évidents (optionnel)
                (len >= 2 && len <= 6) && !known_keys.contains(&k.as_str())
            })
            .map(|s| s.to_string())
            .or_else(|| {
                // Fallback : si la proximité échoue, on scanne avec exclusion stricte
                strings.iter().find(|k| {
                    let len = k.len();
                    (len == 5 || len == 6) && !known_keys.contains(&k.as_str())
                }).map(|s| s.to_string())
            })
            .context("Could not identify encrypted content key via clustering or fallback")?;

        Ok(Self {
            masked_gpu_info_key,
            gpu_masked_vendor_key,
            gpu_masked_renderer_key,
            unmasked_gpu_info_key,
            gpu_unmasked_vendor_key,
            gpu_unmasked_renderer_key,
            prefix_key,
            suffix_key,
            encrypted_content_key,
            no_navigator_gpu_data_key,
        })
    }

    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize> {
        let fingerprint = &task.fingerprint;

        let mut gpu_info_object: Map<String, Value> = serde_json::Map::new();

        let mut masked_info_object: Map<String, Value> = serde_json::Map::new();
        masked_info_object.insert(
            self.gpu_masked_vendor_key.clone(),
            fingerprint.webgl.masked_vendor.clone().into(),
        );
        masked_info_object.insert(
            self.gpu_masked_renderer_key.clone(),
            fingerprint.webgl.masked_renderer.clone().into(),
        );
        gpu_info_object.insert(self.masked_gpu_info_key.clone(), masked_info_object.into());

        let mut unmasked_info_object: Map<String, Value> = serde_json::Map::new();
        unmasked_info_object.insert(
            self.gpu_unmasked_vendor_key.clone(),
            task.fingerprint.webgl.unmasked_vendor.clone().into(),
        );
        unmasked_info_object.insert(
            self.gpu_unmasked_renderer_key.clone(),
            task.fingerprint.webgl.unmasked_renderer.clone().into(),
        );
        gpu_info_object.insert(
            self.unmasked_gpu_info_key.clone(),
            unmasked_info_object.into(),
        );
        
        let mapped_gpu_data = task.fingerprint.webgl.navigator_gpu_data
            .as_ref()
            .map(|v| Value::Object(v.clone()))
            .unwrap_or_else(|| Value::String(self.no_navigator_gpu_data_key.clone()));

        // Construction du payload crypté
        let payload = json!([
            format!("{}{}{}", self.prefix_key, task.fingerprint.webgl.webgl_first_hash, self.suffix_key),
            format!("{}{}{}", self.prefix_key, task.fingerprint.webgl.webgl_second_hash, self.suffix_key),
            gpu_info_object,
            mapped_gpu_data,
        ]);

        let encrypted = task.encryption.encrypt(payload);

        map.insert(self.encrypted_content_key.clone(), encrypted.into());

        Ok(rng().random_range(160..=280))
    }
}