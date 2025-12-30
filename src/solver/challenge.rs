use anyhow::{anyhow, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, ObjectPropertyKind, PropertyKey};
use oxc_parser::{Parser, ParserReturn};
use oxc_span::SourceType;

#[derive(Debug, Default)]
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

impl CloudflareChallengeOptions {
    pub fn from_html(html: &str) -> Result<Self> {
        let start_marker = "window._cf_chl_opt={";
        // On cherche le début de l'objet mais on capture un bloc plus large pour garantir un JS valide
        let start_idx = html
            .find(start_marker)
            .ok_or_else(|| anyhow!("Failed to find challenge data start"))?;
        
        // Extraction approximative du script pour le parser (jusqu'à la fin de la balise ou une longueur raisonnable)
        let script_slice = &html[start_idx..];
        let end_idx = script_slice.find("</script>").unwrap_or(script_slice.len());
        let source_code = &script_slice[..end_idx];

        let allocator = Allocator::default();
        let source_type = SourceType::default().with_module(false).with_typescript(false);
        
        let ParserReturn { program, errors, .. } = Parser::new(&allocator, source_code, source_type).parse();

        if !errors.is_empty() {
             // Fallback ou erreur si le parsing échoue drastiquement, 
             // mais oxc est résilient. On log ou on fail.
             // Ici on continue car on cherche juste une assignation spécifique.
        }

        let mut options = CloudflareChallengeOptions::default();
        let mut found = false;

        // Traversée de l'AST pour trouver l'assignation window._cf_chl_opt = { ... }
        for stmt in program.body {
            if let oxc_ast::ast::Statement::ExpressionStatement(expr_stmt) = stmt {
                if let Expression::AssignmentExpression(assign_expr) = &expr_stmt.expression {
                    // Vérification sommaire de la partie gauche (window._cf_chl_opt)
                    // Pour simplifier/optimiser, on assume que c'est le premier gros objet assigné dans ce snippet
                    // ou on vérifie strictement si nécessaire.
                    
                    if let Expression::ObjectExpression(obj_expr) = &assign_expr.right {
                        found = true;
                        for prop in &obj_expr.properties {
                            if let ObjectPropertyKind::ObjectProperty(p) = prop {
                                if let PropertyKey::StaticIdentifier(key) = &p.key {
                                    if let Expression::StringLiteral(val) = &p.value {
                                        let val_str = val.value.as_str().to_string();
                                        match key.name.as_str() {
                                            "cType" => options.c_type = val_str,
                                            "cvId" => options.cv_id = val_str,
                                            "cFPWv" => options.c_arg = val_str,
                                            "cZone" => options.zone = val_str,
                                            "chlApivId" => options.api_v_id = val_str,
                                            "chlApiWidgetId" => options.widget_id = val_str,
                                            "chlApiSitekey" => options.site_key = val_str,
                                            "chlApiMode" => options.api_mode = val_str,
                                            "chlApiSize" => options.api_size = val_str,
                                            "chlApiRcV" => options.api_rcv = val_str,
                                            "cRay" => options.c_ray = val_str,
                                            "cH" => options.ch = val_str,
                                            "md" => options.md = val_str,
                                            "cITimeS" => options.time = val_str,
                                            "chlIssUA" => options.iss_ua = val_str,
                                            "chlIp" => options.ip = val_str,
                                            "chlApiResetSrc" => options.reset_src = val_str,
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !found {
            return Err(anyhow!("Could not locate _cf_chl_opt object in AST"));
        }

        // turnstile_u est souvent en dehors de l'objet principal ou calculé dynamiquement
        // On garde une extraction légère pour ce champ spécifique s'il n'est pas dans l'AST
        options.turnstile_u = Self::extract_turnstile_u(html).unwrap_or_default();

        Ok(options)
    }

    fn extract_turnstile_u(html: &str) -> Option<String> {
        html.split("chlTimeoutMs:")
            .nth(1)?
            .split(',')
            .nth(1)?
            .split(['\'', '"'])
            .nth(1)
            .map(String::from)
    }
}