use anyhow::{anyhow, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, ObjectPropertyKind};
use oxc_ast_visit::{Visit, walk::walk_object_expression};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;

#[derive(Debug, Default, Clone)]
pub struct CloudflareChallengeOptions {
    pub c_type: String,
    pub cv_id: String,
    pub c_arg: String,
    pub zone: String,
    pub api_v_id: String,
    pub widget_id: String,
    pub site_key: String,
    pub api_mode: String,
    pub api_size: String,
    pub api_rcv: String,
    pub reset_src: String,
    pub c_ray: String,
    pub ch: String,
    pub md: String,
    pub time: String,
    pub iss_ua: String,
    pub ip: String,
    pub turnstile_u: String,
}

struct CloudflareChallengeOptionsVisitor {
    candidates: Vec<String>,
    options: CloudflareChallengeOptions,
    found_target: bool,
}

impl<'a> Visit<'a> for CloudflareChallengeOptionsVisitor {
    fn visit_object_expression(&mut self, expr: &oxc_ast::ast::ObjectExpression<'a>) {
        let mut is_target = false;
        // Identification de l'objet cible
        for prop in &expr.properties {
            if let ObjectPropertyKind::ObjectProperty(p) = prop {
                if let Expression::StringLiteral(val) = &p.value {
                    let v = val.value.as_str();
                    if (v.starts_with("0x4") && v.len() > 20) || v.contains("challenges.cloudflare.com") {
                        is_target = true;
                        break;
                    }
                }
            }
        }

        if is_target {
            self.found_target = true;
            for prop in &expr.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                    if let Expression::StringLiteral(val) = &p.value {
                        self.candidates.push(val.value.as_str().to_string());
                    }
                }
            }
        }
        walk_object_expression(self, expr);
    }
}

impl CloudflareChallengeOptions {
    pub fn from_html(html: &str) -> Result<Self> {
        let mut opts = if let Ok(options) = Self::parse_with_ast(html) {
             options
        } else {
            Self::parse_with_regex(html)?
        };

        eprintln!("✅ Final Options:");
        eprintln!("   SiteKey: {}", opts.site_key);
        eprintln!("   c_arg (len): {}", opts.c_arg.len());
        eprintln!("   api_rcv (len): {}", opts.api_rcv.len());
        eprintln!("   ch: {}", opts.ch);
        eprintln!("   cRay: {}", opts.c_ray);

        if opts.c_arg.is_empty() { return Err(anyhow!("Missing c_arg (payload)")); }
        if opts.ch.is_empty() { return Err(anyhow!("Missing ch (challenge hash)")); }

        Ok(opts)
    }

    fn parse_with_ast(html: &str) -> Result<Self> {
        let keyword = "_cf_chl_opt";
        let key_idx = html.find(keyword).ok_or_else(|| anyhow!("Marker '{}' not found", keyword))?;
        let script_end = html[key_idx..].find("</script>").map(|i| key_idx + i).unwrap_or(html.len());
        let script_start_tag_idx = html[..key_idx].rfind("<script").unwrap_or(0);
        let script_content_start = html[script_start_tag_idx..key_idx].find('>').map(|i| script_start_tag_idx + i + 1).unwrap_or(script_start_tag_idx); 
        let source_code = &html[script_content_start..script_end];

        let allocator = Allocator::default();
        let source_type = SourceType::default(); 
        let ret = Parser::new(&allocator, source_code, source_type).parse();

        if ret.program.body.is_empty() { return Err(anyhow!("Failed to parse script AST")); }

        let mut visitor = CloudflareChallengeOptionsVisitor {
            candidates: Vec::new(),
            options: CloudflareChallengeOptions::default(),
            found_target: false,
        };
        visitor.visit_program(&ret.program);

        if !visitor.found_target { return Err(anyhow!("Config object not found in AST")); }

        let mut opts = visitor.options;
        let candidates = visitor.candidates;

        // 1. Payload (c_arg)
        if let Some(payload) = candidates.iter().max_by_key(|s| s.len()) {
            if payload.len() > 500 {
                opts.c_arg = payload.clone();
            }
        }

        // 2. Signature de Version
        let version_sig = if !opts.c_arg.is_empty() {
            let re = Regex::new(r"-\d+-\d+(\.\d+)+-").unwrap();
            re.find(&opts.c_arg).map(|m| m.as_str().to_string())
        } else {
            None
        };

        // 3. Filtrage Candidats
        let mut relevant_candidates: Vec<String> = if let Some(sig) = &version_sig {
            eprintln!("🔍 Detected version signature: {}", sig);
            candidates.iter()
                .filter(|s| s.contains(sig) && **s != opts.c_arg)
                .cloned()
                .collect()
        } else {
            candidates.iter()
                .filter(|s| **s != opts.c_arg)
                .cloned()
                .collect()
        };
        
        // Trier par longueur croissante (Court -> Long)
        relevant_candidates.sort_by_key(|s| s.len());

        eprintln!("🔍 Relevant candidates (same version): {}", relevant_candidates.len());

        // 4. Attribution & Sanitization Spécifique
        if relevant_candidates.len() >= 2 {
            let raw_ch = relevant_candidates[0].clone(); // Le plus court
            let raw_rcv = relevant_candidates.last().unwrap().clone(); // Le plus long

            // -- TRAITEMENT CH --
            // On garde le PREFIX (avant le premier tiret)
            if let Some(idx) = raw_ch.find('-') {
                opts.ch = raw_ch[..idx].to_string();
            } else {
                opts.ch = raw_ch;
            }
            eprintln!("🧹 CH extracted: {}", opts.ch);

            // -- TRAITEMENT API_RCV --
            // On garde le SUFFIX (après la signature de version)
            if let Some(sig) = &version_sig {
                if let Some(pos) = raw_rcv.find(sig) {
                    // On prend ce qu'il y a APRES la signature
                    let start_idx = pos + sig.len();
                    if start_idx < raw_rcv.len() {
                        opts.api_rcv = raw_rcv[start_idx..].to_string();
                    }
                }
            }
            // Fallback si pas de signature (ou format inconnu)
            if opts.api_rcv.is_empty() {
                 // On essaie de prendre après le dernier tiret ? Non risqué.
                 // On prend tout sauf le préfixe s'il y a des tirets
                 let parts: Vec<&str> = raw_rcv.split('-').collect();
                 if parts.len() > 3 {
                     // Reconstruction approximative pour les formats inconnus
                     // Mais pour 1.2.1.1, le code ci-dessus (sig) devrait marcher.
                     opts.api_rcv = parts.last().unwrap().to_string();
                 } else {
                     opts.api_rcv = raw_rcv;
                 }
            }
            eprintln!("🧹 API_RCV extracted (len={}): {:.30}...", opts.api_rcv.len(), opts.api_rcv);

        } else if relevant_candidates.len() == 1 {
            // Fallback 1 candidat (rare)
            opts.ch = relevant_candidates[0].clone();
            if let Some(idx) = opts.ch.find('-') { opts.ch.truncate(idx); }
        }

        // Champs statiques
        for v in &candidates {
            if v.starts_with("0x4") && v.len() < 35 { opts.site_key = v.clone(); }
            else if v.len() == 16 && v.chars().all(|c| c.is_ascii_hexdigit()) { opts.c_ray = v.clone(); }
            else if v.contains("cloudflare.com") { opts.zone = v.clone(); }
            else if v.len() == 5 && v.chars().all(|c| c.is_ascii_alphanumeric()) { opts.widget_id = v.clone(); }
            else if matches!(v.as_str(), "managed" | "non-interactive" | "invisible") { opts.api_mode = v.clone(); }
        }

        opts.turnstile_u = Self::extract_turnstile_u(html).unwrap_or_default();
        Ok(opts)
    }

    fn parse_with_regex(html: &str) -> Result<Self> {
        let mut options = CloudflareChallengeOptions::default();
        let ch_regex = Regex::new(r#"['"](\.[a-zA-Z0-9_-]{30,})['"]"#).unwrap();
        if let Some(cap) = ch_regex.captures(html) { if let Some(m) = cap.get(1) { options.ch = m.as_str().to_string(); } }
        let carg_regex = Regex::new(r#"['"]([a-zA-Z0-9_\-.]{500,})['"]"#).unwrap();
        if let Some(cap) = carg_regex.captures(html) { if let Some(m) = cap.get(1) { options.c_arg = m.as_str().to_string(); } }
        Ok(options)
    }

    fn extract_turnstile_u(html: &str) -> Option<String> {
        let parts: Vec<&str> = html.split("chlTimeoutMs").collect();
        if parts.len() > 1 { return Some("".to_string()); }
        None
    }

    pub fn extract_from_orchestrate(_orchestrate_text: &str) -> Result<(String, String)> {
        Ok((String::new(), String::new()))
    }
}