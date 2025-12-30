use oxc_ast::ast::{CallExpression, Expression, StringLiteral};
use oxc_ast_visit::walk::walk_call_expression;
use oxc_ast_visit::Visit;

#[derive(Default, Debug)]
pub struct ScriptVisitor {
    pub initial_vm: Option<String>,
    pub main_vm: Option<String>,
    pub compressor_charset: Option<String>,
    pub init_argument: Option<String>,
}

impl<'a> Visit<'a> for ScriptVisitor {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        // On vérifie que c'est bien un appel de fonction standard
        if !it.callee.is_identifier_reference() {
            walk_call_expression(self, it);
            return;
        }

        // RELAXED: On accepte les fonctions avec plus d'un argument (ex: decrypt(str, key))
        if it.arguments.is_empty() {
            walk_call_expression(self, it);
            return;
        }

        let first_arg = it.arguments.get(0).unwrap();

        // On vérifie que le premier argument est une String Literal
        if !first_arg.is_expression() || !first_arg.as_expression().unwrap().is_string_literal() {
            walk_call_expression(self, it);
            return;
        }

        let first_arg_str = match first_arg.as_expression().unwrap() {
            Expression::StringLiteral(str) => str.value.as_str(),
            _ => return, // Safety: on ignore si ce n'est pas une string simple
        };

        // HEURISTIQUE DE TAILLE :
        // Le bytecode initial fait généralement entre 300 et 800 caractères.
        // Le main bytecode fait plus de 1000 caractères.
        
        let len = first_arg_str.len();

        if len > 300 {
            if len >= 1000 {
                // C'est probablement le Main VM Payload
                self.main_vm = Some(first_arg_str.to_string());
            } else if self.initial_vm.is_none() {
                // C'est probablement l'Initial VM Payload (anciennement atob)
                // On prend le premier candidat valide qu'on trouve.
                // On ne vérifie PLUS le nom de la fonction (callee) car il change souvent.
                self.initial_vm = Some(first_arg_str.to_string());
            }
        }

        walk_call_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &StringLiteral<'a>) {
        // Détection du charset du compresseur LZ (inchangée)
        if it.value.len() == 65 && it.value.contains("$") && it.value.contains("-") && it.value.contains("+") {
            self.compressor_charset = Some(it.value.to_string());
        }
        
        // Détection de l'argument d'init (inchangée)
        if it.value.len() > 20
            && it.value.starts_with("/")
            && it.value.ends_with("/")
            && it.value.split(":").count() == 3
            && !it.value.contains("/b/")
        {
            self.init_argument = Some(it.value.to_string());
        }
    }
}