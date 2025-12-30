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
        // Phase 1: Identify if this is the target object (contains SiteKey or Zone)
        let mut is_target = false;
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
            // Phase 2: Collect all string values preserving order
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
        if let Ok(options) = Self::parse_with_ast(html) {
            // Validation: We need at least site_key and c_arg
            if !options.site_key.is_empty() && !options.c_arg.is_empty() {
                return Ok(options);
            }
            eprintln!("⚠️ AST parsing incomplete (missing critical fields), trying regex fallback...");
        }
        
        Self::parse_with_regex(html)
    }

    fn parse_with_ast(html: &str) -> Result<Self> {
        let keyword = "_cf_chl_opt";
        let key_idx = html
            .find(keyword)
            .ok_or_else(|| anyhow!("Marker '{}' not found", keyword))?;

        let script_end = html[key_idx..]
            .find("</script>")
            .map(|i| key_idx + i)
            .unwrap_or(html.len());

        let script_start_tag_idx = html[..key_idx]
            .rfind("<script")
            .unwrap_or(0);

        let script_content_start = html[script_start_tag_idx..key_idx]
            .find('>')
            .map(|i| script_start_tag_idx + i + 1)
            .unwrap_or(script_start_tag_idx); 

        let source_code = &html[script_content_start..script_end];

        let allocator = Allocator::default();
        let source_type = SourceType::default(); 
        let ret = Parser::new(&allocator, source_code, source_type).parse();

        if ret.program.body.is_empty() {
            return Err(anyhow!("Failed to parse script AST"));
        }

        let mut visitor = CloudflareChallengeOptionsVisitor {
            candidates: Vec::new(),
            options: CloudflareChallengeOptions::default(),
            found_target: false,
        };
        
        visitor.visit_program(&ret.program);

        if !visitor.found_target {
            return Err(anyhow!("Config object not found in AST"));
        }

        // --- INTELLIGENT FIELD MAPPING ---
        let mut opts = visitor.options;
        let candidates = visitor.candidates;

        // 1. Extract Payload (c_arg) - The longest string
        if let Some(payload) = candidates.iter().max_by_key(|s| s.len()) {
            if payload.len() > 100 {
                opts.c_arg = payload.clone();
            }
        }

        // 2. Extract Version Signature from Payload
        // Pattern: -TIMESTAMP-VERSION- (e.g., "-1767074958-1.2.1.1-")
        let version_sig = if !opts.c_arg.is_empty() {
            let re = Regex::new(r"-\d+-\d+(\.\d+)+-").unwrap();
            re.find(&opts.c_arg).map(|m| m.as_str().to_string())
        } else {
            None
        };

        if let Some(sig) = &version_sig {
            eprintln!("🔍 Detected version signature in payload: {}", sig);
        }

        // 3. Map other fields
        for v in &candidates {
            // Skip the payload itself
            if *v == opts.c_arg { continue; }

            // SiteKey
            if v.starts_with("0x4") && v.len() < 35 {
                opts.site_key = v.clone();
            } 
            // cRay
            else if v.len() == 16 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                opts.c_ray = v.clone();
            }
            // Zone
            else if v.contains("cloudflare.com") {
                opts.zone = v.clone();
            }
            // Widget ID
            else if v.len() == 5 && v.chars().all(|c| c.is_ascii_alphanumeric()) {
                opts.widget_id = v.clone();
            }
            // Mode
            else if matches!(v.as_str(), "managed" | "non-interactive" | "invisible") {
                opts.api_mode = v.clone();
            }
            // Challenge Hash (ch) - CRITICAL FIX
            // Look for the string that contains the SAME version signature as the payload.
            // AND ensure we take the FIRST match (don't overwrite if we already have one),
            // because subsequent matches might be fallback/secondary tokens.
            else if let Some(sig) = &version_sig {
                if opts.ch.is_empty() && v.contains(sig) && v.len() > 50 {
                    opts.ch = v.clone();
                    eprintln!("✅ Found matching ch for version {}: {}", sig, v);
                }
            }
        }

        // 4. Fallback for ch if no signature matched (or payload parsing failed)
        if opts.ch.is_empty() {
            for v in &candidates {
                if *v == opts.c_arg { continue; }
                if v.len() > 50 && v.len() < 500 && !v.starts_with('0') { // Avoid api_rcv if possible
                     // Only take it if it looks like a hash (contains dashes/dots)
                     if v.contains('-') || v.contains('.') {
                         opts.ch = v.clone();
                         break; // Take the first reasonable candidate
                     }
                }
            }
        }

        // 5. Sanitization (Strip metadata from ch)
        // CHANGED: Only split on the first dash (start of timestamp). 
        // Do NOT split on dot, as some hashes contain dots (e.g. QrCm8).
        if !opts.ch.is_empty() {
             let clean_ch = if let Some(idx) = opts.ch.find('-') {
                 opts.ch[..idx].to_string()
             } else {
                 opts.ch.clone()
             };
             eprintln!("🧹 Sanitized ch: {} -> {}", opts.ch, clean_ch);
             opts.ch = clean_ch;
        }

        opts.turnstile_u = Self::extract_turnstile_u(html).unwrap_or_default();

        Ok(opts)
    }

    fn parse_with_regex(html: &str) -> Result<Self> {
        let mut options = CloudflareChallengeOptions::default();
        
        let ch_regex = Regex::new(r#"['"](\.[a-zA-Z0-9_-]{30,})['"]"#).unwrap();
        if let Some(cap) = ch_regex.captures(html) {
            if let Some(m) = cap.get(1) {
                options.ch = m.as_str().to_string();
            }
        }
        
        let carg_regex = Regex::new(r#"['"]([a-zA-Z0-9_\-.]{500,})['"]"#).unwrap();
        if let Some(cap) = carg_regex.captures(html) {
             if let Some(m) = cap.get(1) {
                options.c_arg = m.as_str().to_string();
            }
        }
        
        Ok(options)
    }

    fn extract_turnstile_u(html: &str) -> Option<String> {
        let parts: Vec<&str> = html.split("chlTimeoutMs").collect();
        if parts.len() > 1 {
             return Some("".to_string()); 
        }
        None
    }

    /// Extract fields from the orchestrate API response
    pub fn extract_from_orchestrate(orchestrate_text: &str) -> Result<(String, String)> {
        eprintln!("\n=== Analyzing Orchestrate Response ===");
        eprintln!("Response length: {} bytes", orchestrate_text.len());
        
        let preview = if orchestrate_text.len() > 300 {
            &orchestrate_text[..300]
        } else {
            orchestrate_text
        };
        eprintln!("Preview: {}", preview);
        
        let mut ch = String::new();
        let mut url = String::new();

        // Look for window._cf_chl_opt.cH assignment
        let opt_ch_pattern = Regex::new(r#"window\._cf_chl_opt\.cH\s*=\s*["']([a-zA-Z0-9_-]{20,})["']"#).ok();
        if let Some(re) = opt_ch_pattern {
            if let Some(cap) = re.captures(orchestrate_text) {
                if let Some(m) = cap.get(1) {
                    ch = m.as_str().to_string();
                    eprintln!("✅ Found ch in window._cf_chl_opt.cH: {}", ch);
                }
            }
        }

        // Look for URL patterns
        let url_patterns = vec![
            r#"/flow/ov1[^/]*/[a-f0-9]{16}/([a-zA-Z0-9_-]{20,})"#,
            r#"["']url["']\s*:\s*["']([^"']+)["']"#,
        ];

        for pattern in &url_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(orchestrate_text) {
                    if let Some(m) = cap.get(1) {
                        let captured = m.as_str().to_string();
                        if pattern.contains("url") {
                            url = captured;
                            eprintln!("✅ Found URL: {}", url);
                        } else if ch.is_empty() {
                            ch = captured;
                            eprintln!("✅ Found ch in URL pattern: {}", ch);
                        }
                        break;
                    }
                }
            }
        }

        eprintln!("=== Orchestrate Parsing Results ===");
        eprintln!("ch: {}", if ch.is_empty() { "NOT FOUND (normal - should be in initial HTML)" } else { &ch });
        eprintln!("url: {}", if url.is_empty() { "NOT FOUND" } else { &url });
        eprintln!("===================================\n");

        Ok((ch, url))
    }
}