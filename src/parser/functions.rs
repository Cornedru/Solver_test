use oxc_ast::ast::{
    ArrayExpressionElement, AssignmentExpression, AssignmentTarget, Expression, Function,
    VariableDeclaration,
};
use oxc_ast_visit::{
    walk::{walk_assignment_expression, walk_function, walk_variable_declaration},
    Visit,
};
use oxc_semantic::ScopeFlags;
use rustc_hash::FxHashMap;

#[derive(Default)]
pub struct FindFunctions<'a> {
    last_function_name: &'a str,
    is_big_function: bool, 
    pub key: u16,
    pub constants: u16,
    pub function_with_opcodes: &'a str, 
    pub functions: FxHashMap<&'a str, u16>,
    pub variables: FxHashMap<&'a str, f64>,
}

impl<'a> FindFunctions<'a> {
    fn resolve_expr(&self, expr: &Expression) -> Option<f64> {
        match expr {
            Expression::NumericLiteral(lit) => Some(lit.value),
            Expression::StringLiteral(lit) => lit.value.parse::<f64>().ok(),
            Expression::Identifier(ident) => self.variables.get(ident.name.as_str()).copied(),
            Expression::ParenthesizedExpression(paren) => self.resolve_expr(&paren.expression),
            Expression::SequenceExpression(seq) => seq.expressions.last().and_then(|e| self.resolve_expr(e)),
            Expression::UnaryExpression(unary) => {
                let val = self.resolve_expr(&unary.argument)?;
                match unary.operator.as_str() {
                    "-" => Some(-val), "+" => Some(val), "~" => Some((!(val as i64)) as f64),
                    "!" => Some(if val == 0.0 { 1.0 } else { 0.0 }), _ => None,
                }
            },
            Expression::BinaryExpression(bin) => {
                let left = self.resolve_expr(&bin.left);
                let right = self.resolve_expr(&bin.right);
                match (left, right) {
                    (Some(l), Some(r)) => match bin.operator.as_str() {
                        "+" => Some(l + r), "-" => Some(l - r), "*" => Some(l * r), "/" => Some(l / r),
                        "%" => Some(l % r), "&" => Some((l as i64 & r as i64) as f64), "|" => Some((l as i64 | r as i64) as f64),
                        "^" => Some((l as i64 ^ r as i64) as f64), "<<" => Some(((l as i64) << (r as i64)) as f64),
                        ">>" => Some(((l as i64) >> (r as i64)) as f64), _ => None,
                    },
                    _ => None 
                }
            },
            Expression::LogicalExpression(logic) => {
                let left = self.resolve_expr(&logic.left);
                let right = self.resolve_expr(&logic.right);
                match logic.operator.as_str() {
                    "||" => if let Some(l) = left { if l != 0.0 && !l.is_nan() { Some(l) } else { right } } else { right },
                    "&&" => if let Some(l) = left { if l == 0.0 || l.is_nan() { Some(l) } else { right } } else { None },
                    "??" => if left.is_some() { left } else { right }, _ => None
                }
            },
            Expression::ConditionalExpression(cond) => {
                let test = self.resolve_expr(&cond.test);
                if let Some(t) = test {
                    if t != 0.0 && !t.is_nan() { self.resolve_expr(&cond.consequent) } else { self.resolve_expr(&cond.alternate) }
                } else { None }
            }
            _ => None,
        }
    }

    fn resolve_index(&self, expr: &Expression) -> Option<u16> {
        if let Some(val) = self.resolve_expr(expr) { return Some(val as u16); }
        if let Expression::BinaryExpression(bin) = expr {
            let left = self.resolve_expr(&bin.left);
            let right = self.resolve_expr(&bin.right);
            match (left, right) {
                (Some(val), None) | (None, Some(val)) => return Some(val as u16),
                _ => {}
            }
        }
        None
    }

    fn extract_function_name(&self, expr: &Expression<'a>) -> Option<&'a str> {
        match expr {
            Expression::Identifier(ident) => Some(ident.name.as_str()),
            Expression::CallExpression(call) => {
                if !call.arguments.is_empty() {
                    if let Some(arg) = call.arguments.first() {
                         if let Expression::Identifier(ident) = arg.as_expression().unwrap() {
                             return Some(ident.name.as_str());
                         }
                    }
                }
                None
            },
            Expression::SequenceExpression(seq) => seq.expressions.last().and_then(|e| self.extract_function_name(e)),
            Expression::ParenthesizedExpression(paren) => self.extract_function_name(&paren.expression),
            _ => None
        }
    }
}

impl<'a> Visit<'a> for FindFunctions<'a> {
    fn visit_function(&mut self, node: &Function<'a>, flags: ScopeFlags) {
        // Logique "Silver Bullet" : Anonyme ou pas, si > 50 lignes, c'est VM_ENTRY
        let mut name = node.id.as_ref().map(|id| id.name.as_str()).unwrap_or("");
        
        if let Some(body) = &node.body {
            if body.statements.len() > 50 {
                self.is_big_function = true;
                name = "VM_ENTRY"; 
                // eprintln!("[INFO] VM Detected (>50 lines), forcing name 'VM_ENTRY'");
            } else {
                self.is_big_function = false;
            }
        } else {
            self.is_big_function = false;
        }

        self.last_function_name = name;
        if self.is_big_function { self.function_with_opcodes = name; }

        walk_function(self, node, flags);
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
        for declarator in &decl.declarations {
            if let Some(init) = &declarator.init {
                if let oxc_ast::ast::BindingPatternKind::BindingIdentifier(ident) = &declarator.id.kind {
                    if let Some(val) = self.resolve_expr(init) {
                        self.variables.insert(ident.name.as_str(), val);
                    }
                }
            }
        }
        walk_variable_declaration(self, decl);
    }

    fn visit_assignment_expression(&mut self, node: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(ident) = &node.left {
            if let Some(val) = self.resolve_expr(&node.right) {
                self.variables.insert(ident.name.as_str(), val);
            }
        }

        if self.is_big_function {
            if let AssignmentTarget::ComputedMemberExpression(member_expr) = &node.left {
                let resolved_idx = self.resolve_index(&member_expr.expression);

                if let Some(value) = resolved_idx {
                    if let Some(name) = self.extract_function_name(&node.right) {
                        self.functions.insert(name.into(), value);
                    } else if let Expression::ArrayExpression(array_expr) = &node.right {
                        self.constants = value;
                        if array_expr.elements.len() > 3 {
                            if let ArrayExpressionElement::NumericLiteral(num_lit) = &array_expr.elements[3] {
                                self.key = num_lit.value as u16;
                            }
                        }
                    } else {
                        // MAPPING ORPHELIN -> VM_ENTRY
                        if !self.function_with_opcodes.is_empty() {
                            self.functions.insert(self.function_with_opcodes, value);
                        }
                    }
                }
            }
        }
        walk_assignment_expression(self, node);
    }
}