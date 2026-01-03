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
use regex::Regex;

#[derive(Default)]
pub struct FindFunctions<'a> {
    last_function_name: &'a str,
    is_big_function: bool, 
    pub key: u16,
    pub constants: u16,
    pub function_with_opcodes: &'a str, 
    pub functions: FxHashMap<&'a str, u16>,
    pub variables: FxHashMap<&'a str, f64>,

    // NEW: store candidate raw bits found on RHS for a given resolved index
    pub index_bits: FxHashMap<u16, Vec<u16>>,
}

impl<'a> FindFunctions<'a> {
    // NEW getter used by disassembler fallback
    pub fn get_bits_for_index(&self, idx: u16) -> Option<&Vec<u16>> {
        self.index_bits.get(&idx)
    }

    fn resolve_expr(&self, expr: &Expression<'a>) -> Option<f64> {
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

    fn resolve_index(&self, expr: &Expression<'a>) -> Option<u16> {
        if let Some(val) = self.resolve_expr(expr) { return Some(val as u16); }
        if let Expression::BinaryExpression(bin) = expr {
            let left = self.resolve_expr(&bin.left);
            let right = self.resolve_expr(&bin.right);
            match (left, right) {
                (Some(val), None) | (None, Some(val)) => return Some(val as u16),
                _ => {}
            }
        }
        self.extract_numeric_literal(expr).map(|v| v as u16)
    }

    fn extract_numeric_literal(&self, expr: &Expression<'a>) -> Option<u64> {
        match expr {
            Expression::NumericLiteral(n) => Some(n.value as u64),
            Expression::StringLiteral(s) => s.value.parse::<u64>().ok(),
            Expression::ParenthesizedExpression(p) => self.extract_numeric_literal(&p.expression),
            Expression::UnaryExpression(u) => self.extract_numeric_literal(&u.argument),
            Expression::BinaryExpression(b) => {
                self.extract_numeric_literal(&b.left)
                    .or_else(|| self.extract_numeric_literal(&b.right))
            }
            Expression::SequenceExpression(seq) => seq.expressions.iter().rev().find_map(|e| self.extract_numeric_literal(e)),
            Expression::CallExpression(call) => {
                call.arguments.iter().find_map(|arg| arg.as_expression().and_then(|e| self.extract_numeric_literal(e)))
            },
            _ => {
                match expr {
                    Expression::ComputedMemberExpression(cm) => {
                        self.extract_numeric_literal(&cm.expression).or_else(|| self.extract_numeric_literal(&cm.object))
                    }
                    Expression::StaticMemberExpression(sm) => self.extract_numeric_literal(&sm.object),
                    _ => None
                }
            }
        }
    }

    fn extract_function_name(&self, expr: &Expression<'a>) -> Option<&'a str> {
        match expr {
            Expression::Identifier(ident) => Some(ident.name.as_str()),
            Expression::CallExpression(call) => {
                match &call.callee {
                    Expression::Identifier(ident) => Some(ident.name.as_str()),
                    Expression::StaticMemberExpression(mem) => {
                        if let Expression::Identifier(obj_ident) = &mem.object {
                            Some(obj_ident.name.as_str())
                        } else { None }
                    }
                    Expression::ComputedMemberExpression(mem) => {
                        if let Expression::Identifier(obj_ident) = &mem.object {
                            Some(obj_ident.name.as_str())
                        } else { None }
                    }
                    _ => None
                }
            },
            Expression::StaticMemberExpression(mem) => {
                if let Expression::Identifier(obj_ident) = &mem.object {
                    Some(obj_ident.name.as_str())
                } else { None }
            },
            Expression::ComputedMemberExpression(mem) => {
                if let Expression::Identifier(obj_ident) = &mem.object {
                    Some(obj_ident.name.as_str())
                } else { None }
            },
            _ => None
        }
    }
}

impl<'a> Visit<'a> for FindFunctions<'a> {
    fn visit_function(&mut self, node: &Function<'a>, flags: ScopeFlags) {
        let mut name = node.id.as_ref().map(|id| id.name.as_str()).unwrap_or("");
        
        if let Some(body) = &node.body {
            if body.statements.len() > 50 {
                self.is_big_function = true;
                name = "VM_ENTRY"; 
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

        let mut resolved_idx: Option<u16> = None;

        match &node.left {
            AssignmentTarget::ComputedMemberExpression(member_expr) => {
                resolved_idx = self.resolve_index(&member_expr.expression);
            }
            AssignmentTarget::StaticMemberExpression(static_expr) => {
                let property_name = static_expr.property.name.as_str();
                if let Ok(n) = property_name.parse::<u16>() {
                    resolved_idx = Some(n);
                } else {
                    let re = Regex::new(r"\d+").unwrap();
                    if let Some(cap) = re.captures(property_name) {
                        if let Ok(n) = cap.get(0).unwrap().as_str().parse::<u16>() {
                            resolved_idx = Some(n);
                        }
                    }
                }
            }
            _ => {}
        }

        if let Some(value) = resolved_idx {
            // store candidate raw bits when RHS is ArrayExpression (common VM opcode patterns)
            if let Expression::ArrayExpression(array_expr) = &node.right {
                let mut bits: Vec<u16> = Vec::new();
                for el in &array_expr.elements {
                    if let Some(expr) = el.as_expression() {
                        match expr {
                            Expression::NumericLiteral(n) => bits.push(n.value as u16),
                            Expression::StringLiteral(s) => {
                                if let Ok(v) = s.value.parse::<u16>() { bits.push(v); }
                            }
                            Expression::UnaryExpression(u) => {
                                if let Expression::NumericLiteral(nlit) = &u.argument {
                                    bits.push(nlit.value as u16);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                if !bits.is_empty() {
                    eprintln!("[FindFunctions] captured raw bits for index {} len={}", value, bits.len());
                    self.index_bits.insert(value, bits);
                }
            }

            // existing mapping logic (unchanged)...
            if value == 195 || value == 127 {
                eprintln!("[FindFunctions] SKIP mapping: resolved index {} looks like a key/marker (skip)", value);
            } else if value as usize > 1000 {
                eprintln!("[FindFunctions] SKIP mapping: resolved index {} too large (likely parse error)", value);
            } else {
                if let Some(name) = self.extract_function_name(&node.right) {
                    eprintln!("[FindFunctions] mapping function '{}' -> {}", name, value);
                    self.functions.insert(name, value);
                } else if let Expression::ArrayExpression(array_expr) = &node.right {
                    eprintln!("[FindFunctions] found array expression at index {}, constants={}", value, array_expr.elements.len());
                    self.constants = value;
                    if array_expr.elements.len() > 3 {
                        if let Some(expr) = array_expr.elements[3].as_expression() {
                            if let Expression::NumericLiteral(num_lit) = expr {
                                self.key = num_lit.value as u16;
                                eprintln!("[FindFunctions] extracted key = {}", self.key);
                            }
                        }
                    }
                } else {
                    if !self.function_with_opcodes.is_empty() {
                        eprintln!("[FindFunctions] orphan mapping -> {} = {}", self.function_with_opcodes, value);
                        self.functions.insert(self.function_with_opcodes, value);
                    } else {
                        eprintln!("[FindFunctions] orphan assignment but no VM_ENTRY known");
                    }
                }
            }
        }

        walk_assignment_expression(self, node);
    }
}