use oxc_allocator::Vec as Vec2;
use oxc_ast::ast::{
    AssignmentExpression, AssignmentTarget, Expression,
    Function, Statement,
};
use oxc_ast_visit::{
    walk::{
        walk_assignment_expression, walk_expression, walk_function,
        walk_statement, walk_statements,
    },
    Visit,
};
use oxc_semantic::ScopeFlags;
use rustc_hash::FxHashMap;

use strum::{EnumIter, IntoEnumIterator, ToString};

use super::utils::{AssigmentExtractor, BinaryBitExtractor, BitExtractor, TestExtractor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultOpcode {
    pub bits: Vec<u16>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct WithTestOpcode {
    pub test_bits: Vec<u16>,
    pub bits: Vec<u16>,
}

#[derive(Debug, EnumIter, Clone, PartialEq, Eq)]
pub enum LiteralType {
    Null,
    NaN,
    Infinity,
    True,
    False,
    Float,
    Integer,
    String,
    NextValue,
    CopyState,
    Array,
    Regexp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLiteralTest {
    pub bits: Vec<u16>,
    pub type_: LiteralType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLiteralOpcode {
    pub bits: Vec<u16>,
    pub tests: FxHashMap<u16, NewLiteralTest>,
}

#[derive(Debug, EnumIter, Clone, Hash, PartialEq, Eq)]
pub enum UnaryOperator {
    TypeOf,
    Minus,
    Plus,
    LogicalNot,
    BitwiseNot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnaryOpcode {
    pub bits: Vec<u16>,
    pub operator: UnaryOperator,
}

impl UnaryOperator {
    pub fn get_operator(&self) -> &'static str {
        match self {
            UnaryOperator::BitwiseNot => "~",
            UnaryOperator::LogicalNot => "!",
            UnaryOperator::Minus => "-",
            UnaryOperator::Plus => "+",
            UnaryOperator::TypeOf => "typeof",
        }
    }
}

#[derive(Debug, EnumIter, Clone, Hash, PartialEq, Eq)]
pub enum BinaryOperator {
    Addition,
    Subtraction,
    Multiplication,
    Division,
    Modulo,
    LogicalAnd,
    LogicalOr,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
    UnsignedRightShift,
    Equals,
    EqualsStrict,
    GreaterThan,
    GreaterThanOrEqual,
    InstanceOf,
    In,
}

impl BinaryOperator {
    pub fn get_operator(&self) -> &'static str {
        match self {
            BinaryOperator::Addition => "+",
            BinaryOperator::Subtraction => "-",
            BinaryOperator::Multiplication => "*",
            BinaryOperator::Division => "/",
            BinaryOperator::Modulo => "%",
            BinaryOperator::LogicalAnd => "&&",
            BinaryOperator::LogicalOr => "||",
            BinaryOperator::BitwiseAnd => "&",
            BinaryOperator::BitwiseOr => "|",
            BinaryOperator::BitwiseXor => "^",
            BinaryOperator::LeftShift => "<<",
            BinaryOperator::RightShift => ">>",
            BinaryOperator::UnsignedRightShift => ">>>",
            BinaryOperator::Equals => "==",
            BinaryOperator::EqualsStrict => "===",
            BinaryOperator::GreaterThan => ">",
            BinaryOperator::GreaterThanOrEqual => ">=",
            BinaryOperator::InstanceOf => "instanceof",
            BinaryOperator::In => "in",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryOpcode {
    pub bits: Vec<u16>,
    pub operator: BinaryOperator,
    pub swap: bool,
}

#[derive(Debug, EnumIter, Clone, PartialEq, Eq)]
pub enum HeapType {
    Set,
    Get,
    Init,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureTest {
    pub bits: Vec<u16>,
    pub closure_type: HeapType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureOpcode {
    pub bits: Vec<u16>,
    pub closures: FxHashMap<u16, ClosureTest>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToString)]
pub enum Opcode {
    ArrayPush(DefaultOpcode),
    Throw(DefaultOpcode),
    Bind(DefaultOpcode),
    RegisterVMFunction(DefaultOpcode),
    Binary(BinaryOpcode),
    Unary(UnaryOpcode),
    NewLiteral(NewLiteralOpcode),
    NewObject(DefaultOpcode),
    Pop(DefaultOpcode),
    SetProperty(DefaultOpcode),
    GetProperty(DefaultOpcode),
    SplicePop(DefaultOpcode),
    CallFuncNoContext(DefaultOpcode),
    SwapRegister(DefaultOpcode),
    NewArray(DefaultOpcode),
    Jump(DefaultOpcode),
    JumpIf(DefaultOpcode),
    Move(DefaultOpcode),
    Call(DefaultOpcode),
    Heap(ClosureOpcode),
}

pub struct OpcodeParser<'a> {
    constants: u16,
    functions: FxHashMap<&'a str, u16>,

    pub opcodes: FxHashMap<u16, Opcode>,
    pub create_function_ident: &'a str,
    pub window_register: u16,
}

impl<'a> OpcodeParser<'a> {
    pub fn new(constants: u16, functions: FxHashMap<&'a str, u16>) -> Self {
        OpcodeParser {
            constants,
            functions,
            opcodes: FxHashMap::default(),
            create_function_ident: "",
            window_register: 0,
        }
    }

    fn extract_bits_for_default_opcode(&self, statements: &Vec2<Statement<'a>>) -> DefaultOpcode {
        let mut bit_extractor = BitExtractor::new(self.constants);
        walk_statements(&mut bit_extractor, statements);
        DefaultOpcode {
            bits: bit_extractor.bits,
        }
    }

    fn handle_unary_opcodes(
        &mut self,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BitExtractor,
    ) {
        for operator in UnaryOperator::iter() {
            if tests_visitor.tests.is_empty() { break; }
            let test = tests_visitor.tests.remove(0);
            let bits = bits_extractor.bits.drain(0..2).as_slice().to_vec();
            self.opcodes
                .insert(test, Opcode::Unary(UnaryOpcode { bits, operator }));
        }
    }

    fn handle_literal_opcodes(
        &mut self,
        opcode_register: u16,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BitExtractor,
    ) {
        let bits = bits_extractor.bits.drain(0..2).as_slice().to_vec();
        let mut tests = FxHashMap::default();

        for type_ in LiteralType::iter() {
            if tests_visitor.tests.is_empty() { break; }
            let test = tests_visitor.tests.remove(0);
            let bits = match type_ {
                LiteralType::Integer
                | LiteralType::String
                | LiteralType::CopyState
                | LiteralType::Array => {
                    vec![bits_extractor.bits.remove(0)]
                }
                LiteralType::Regexp => bits_extractor.bits.clone(),
                _ => vec![],
            };

            tests.insert(test, NewLiteralTest { bits, type_ });
        }

        self.opcodes.insert(
            opcode_register,
            Opcode::NewLiteral(NewLiteralOpcode { bits, tests }),
        );
    }

    fn handle_binary_opcodes(
        &mut self,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BinaryBitExtractor,
    ) {
        for operator in BinaryOperator::iter() {
            if tests_visitor.tests.is_empty() { break; }
            let test = tests_visitor.tests.remove(0);
            let drain_len = 3.min(bits_extractor.bits.len());
            let bits = bits_extractor.bits.drain(0..drain_len).as_slice().to_vec();
            
            let swap = if !bits_extractor.swaps.is_empty() {
                bits_extractor.swaps.remove(0)
            } else {
                false
            };

            self.opcodes.insert(
                test,
                Opcode::Binary(BinaryOpcode {
                    bits,
                    operator,
                    swap,
                }),
            );
        }
    }

    fn handle_heap_opcodes(
        &mut self,
        opcode_register: u16,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BitExtractor,
    ) {
        let bits = if !bits_extractor.bits.is_empty() { bits_extractor.bits.remove(0) } else { 0 };
        let mut closures = FxHashMap::default();

        for closure in HeapType::iter() {
            if tests_visitor.tests.is_empty() { break; }
            let test = tests_visitor.tests.remove(0);
            let closure_bits = match closure {
                HeapType::Init => vec![],
                _ => if !bits_extractor.bits.is_empty() { vec![bits_extractor.bits.remove(0)] } else { vec![] },
            };

            closures.insert(
                test,
                ClosureTest {
                    bits: closure_bits,
                    closure_type: closure,
                },
            );
        }

        self.opcodes.insert(
            opcode_register,
            Opcode::Heap(ClosureOpcode {
                bits: vec![bits],
                closures,
            }),
        );
    }

    fn process_by_test_count(
        &mut self,
        opcode_register: u16,
        tests_visitor: &mut TestExtractor,
        bits_extractor: &mut BitExtractor,
        binary_bits_extractor: &mut BinaryBitExtractor,
    ) {
        let test_count = tests_visitor.tests.len();
        
        let unary_count = UnaryOperator::iter().count();
        let literal_count = LiteralType::iter().count();
        let binary_count = BinaryOperator::iter().count();
        let heap_count = HeapType::iter().count();

        if test_count == unary_count {
            self.handle_unary_opcodes(tests_visitor, bits_extractor);
        } else if test_count == literal_count {
            self.handle_literal_opcodes(opcode_register, tests_visitor, bits_extractor);
        } else if test_count == binary_count || test_count == binary_count - 1 {
            self.handle_binary_opcodes(tests_visitor, binary_bits_extractor);
        } else if test_count == heap_count {
            self.handle_heap_opcodes(opcode_register, tests_visitor, bits_extractor);
        }
    }
}

impl<'a> Visit<'a> for OpcodeParser<'a> {
    fn visit_assignment_expression(&mut self, assign_expr: &AssignmentExpression<'a>) {
        if let (
            AssignmentTarget::AssignmentTargetIdentifier(ident),
            Expression::CallExpression(_),
        ) = (&assign_expr.left, &assign_expr.right)
        {
            if let Some(opcode_register) = self.functions.remove(ident.name.as_str()) {
                self.window_register = opcode_register;
            }
        }

        walk_assignment_expression(self, assign_expr);
    }

    fn visit_function(&mut self, node: &Function<'a>, flags: ScopeFlags) {
        let body = match &node.body {
            Some(body) => body,
            None => { walk_function(self, node, flags); return; }
        };

        // GESTION NOMS DE FONCTIONS & ANONYMES
        let name_opt = node.id.as_ref().map(|id| id.name.as_str());
        
        // Si la fonction est énorme, on la traite comme "VM_ENTRY", qu'elle ait un nom ou non.
        let lookup_name = if body.statements.len() > 50 {
            Some("VM_ENTRY")
        } else {
            name_opt
        };

        let name = match lookup_name {
            Some(n) => n,
            None => { 
                walk_function(self, node, flags);
                return; 
            }
        };

        if body.statements.is_empty() {
            walk_function(self, node, flags);
            return;
        }

        if let Statement::ReturnStatement(stmt) = &body.statements.last().unwrap() {
            if let Some(Expression::ComputedMemberExpression(member_expr)) = &stmt.argument {
                if body.statements.len() >= 2 {
                    if let Statement::ExpressionStatement(expr) =
                        &body.statements[body.statements.len() - 2]
                    {
                        if matches!(member_expr.object, Expression::StaticMemberExpression(_))
                            && matches!(member_expr.expression, Expression::BinaryExpression(_))
                            && matches!(expr.expression, Expression::AssignmentExpression(_))
                        {
                            self.create_function_ident = name;
                        }
                    }
                }
            }
        }

        if let Some(opcode_register) = self.functions.remove(name) {
            
            // Si c'est la VM (>50 statements), on force l'opcode SetProperty
            if body.statements.len() > 50 {
                self.opcodes.insert(opcode_register, Opcode::SetProperty(DefaultOpcode { bits: vec![] }));
                walk_function(self, node, flags);
                return;
            }

            // Normal processing for standard opcodes
            if body.statements.len() >= 2 {
                match &body.statements[body.statements.len() - 2] {
                    Statement::ExpressionStatement(expr) => {
                        if let Expression::ConditionalExpression(_) = &expr.expression {
                            let mut assigments_visitor = AssigmentExtractor::new();
                            assigments_visitor.visit_function_body(node.body.as_ref().unwrap());
                            let mut tests_visitor = TestExtractor::default();
                            walk_expression(&mut tests_visitor, &expr.expression);
                            let mut bits_extractor = BitExtractor::new(self.constants);
                            walk_expression(&mut bits_extractor, &expr.expression);
                            let mut binary_bits_extractor = BinaryBitExtractor::new(
                                self.constants,
                                assigments_visitor.identifiers,
                            );
                            walk_expression(&mut binary_bits_extractor, &expr.expression);

                            self.process_by_test_count(
                                opcode_register,
                                &mut tests_visitor,
                                &mut bits_extractor,
                                &mut binary_bits_extractor,
                            );
                        } else if let Expression::AssignmentExpression(assign_expr) =
                            &expr.expression
                        {
                            if let (
                                AssignmentTarget::ComputedMemberExpression(_),
                                Expression::ComputedMemberExpression(_),
                            ) = (&assign_expr.left, &assign_expr.right)
                            {
                                let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                self.opcodes
                                    .insert(opcode_register, Opcode::SwapRegister(opcode));
                            }
                        }
                    }
                    Statement::IfStatement(_) => {
                         let mut assigments_visitor = AssigmentExtractor::new();
                        assigments_visitor.visit_function_body(node.body.as_ref().unwrap());

                        let mut tests_visitor = TestExtractor::default();
                        walk_statement(
                            &mut tests_visitor,
                            &body.statements[body.statements.len() - 2],
                        );

                        let mut bits_extractor = BitExtractor::new(self.constants);
                        walk_statements(&mut bits_extractor, &body.statements);

                        let mut binary_bits_extractor =
                            BinaryBitExtractor::new(self.constants, assigments_visitor.identifiers);
                        walk_statements(&mut binary_bits_extractor, &body.statements);

                        self.process_by_test_count(
                            opcode_register,
                            &mut tests_visitor,
                            &mut bits_extractor,
                            &mut binary_bits_extractor,
                        );
                    }
                    _ => {}
                }
            }

            match body.statements.last().unwrap() {
                Statement::ExpressionStatement(expr) => match &expr.expression {
                    Expression::AssignmentExpression(assign_expr) => match &assign_expr.left {
                        AssignmentTarget::ComputedMemberExpression(member_expr) => {
                            match &assign_expr.right {
                                Expression::CallExpression(call_expr) => {
                                    if !call_expr.arguments.is_empty() && !call_expr.arguments[0].is_member_expression() {
                                        let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                        self.opcodes.insert(opcode_register, Opcode::SplicePop(opcode));
                                    }
                                    if let Expression::ComputedMemberExpression(computed_expr) = &call_expr.callee {
                                        if let Expression::StringLiteral(str_lit) = &computed_expr.expression {
                                            if str_lit.value == "push" {
                                                let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                                self.opcodes.insert(opcode_register, Opcode::ArrayPush(opcode));
                                            }
                                        }
                                    }
                                    if let Expression::ComputedMemberExpression(computed_expr) = &call_expr.callee {
                                        if let (Expression::Identifier(ident), Expression::StringLiteral(str_lit)) = (&computed_expr.object, &computed_expr.expression) {
                                            match str_lit.value.as_str() {
                                                "bind" => {
                                                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                                    match ident.name.len() {
                                                        1 => self.opcodes.insert(opcode_register, Opcode::Bind(opcode)),
                                                        2 => self.opcodes.insert(opcode_register, Opcode::RegisterVMFunction(opcode)),
                                                        _ => None
                                                    };
                                                },
                                                "pop" => {
                                                     let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                                     self.opcodes.insert(opcode_register, Opcode::Pop(opcode));
                                                },
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                Expression::ObjectExpression(_) => {
                                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes.insert(opcode_register, Opcode::NewObject(opcode));
                                }
                                Expression::ComputedMemberExpression(member_expr_right) => {
                                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                    match member_expr_right.object {
                                        Expression::Identifier(_) => { self.opcodes.insert(opcode_register, Opcode::GetProperty(opcode)); },
                                        Expression::StaticMemberExpression(_) => { self.opcodes.insert(opcode_register, Opcode::SetProperty(opcode)); },
                                        _ => {
                                            self.opcodes.insert(opcode_register, Opcode::SetProperty(opcode));
                                        }
                                    }
                                }
                                Expression::NewExpression(_) => {
                                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes.insert(opcode_register, Opcode::CallFuncNoContext(opcode));
                                }
                                Expression::ArrayExpression(_) => {
                                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes.insert(opcode_register, Opcode::NewArray(opcode));
                                }
                                Expression::Identifier(_) => {
                                    if let Expression::NumericLiteral(_) = &member_expr.expression {
                                        let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                        self.opcodes.insert(opcode_register, Opcode::Jump(opcode));
                                    } else {
                                        let mut is_move = false;
                                        if body.statements.len() >= 2 {
                                            if let Statement::ExpressionStatement(expr_stmt) = &body.statements[body.statements.len() - 2] {
                                                 if let Expression::AssignmentExpression(ae) = &expr_stmt.expression {
                                                     if let AssignmentTarget::AssignmentTargetIdentifier(_) = &ae.left {
                                                         is_move = true;
                                                     }
                                                 }
                                            }
                                        }
                                        if is_move {
                                            let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                            self.opcodes.insert(opcode_register, Opcode::Move(opcode));
                                        } else {
                                            let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                            self.opcodes.insert(opcode_register, Opcode::SetProperty(opcode));
                                        }
                                    }
                                }
                                Expression::ConditionalExpression(_) => {
                                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                    self.opcodes.insert(opcode_register, Opcode::Call(opcode));
                                }
                                _ => {
                                     let opcode = self.extract_bits_for_default_opcode(&body.statements);
                                     self.opcodes.insert(opcode_register, Opcode::SetProperty(opcode));
                                }
                            }
                        }
                        _ => {}
                    },
                    Expression::LogicalExpression(_) => {
                        let opcode = self.extract_bits_for_default_opcode(&body.statements);
                        self.opcodes.insert(opcode_register, Opcode::JumpIf(opcode));
                    }
                    _ => {}
                },
                Statement::IfStatement(_) => {}
                Statement::ThrowStatement(_) => {
                    let opcode = self.extract_bits_for_default_opcode(&body.statements);
                    self.opcodes.insert(opcode_register, Opcode::Throw(opcode));
                }
                _ => {}
            }
        }

        walk_function(self, node, flags);
    }
}

/// Normalize raw "bits" captured from AST to remove known markers/keys
/// Retourne un nouveau Vec<u8> et logge si la normalisation a changé la taille.
pub fn normalize_bits(raw: &[u16]) -> Vec<u16> {
    eprintln!("[magic_bits::normalize_bits] entry raw.len={}", raw.len());
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while i < raw.len() {
        // Remove repeating marker pair 195,188 sequences only
        if i + 1 < raw.len() && raw[i] == 195 && raw[i + 1] == 188 {
            // consume consecutive (195,188) pairs
            while i + 1 < raw.len() && raw[i] == 195 && raw[i + 1] == 188 {
                i += 2;
            }
            continue;
        }
        // Remove isolated 127 (separator) but keep isolated 195
        if raw[i] == 127 {
            i += 1;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
    if out.len() != raw.len() {
        eprintln!(
            "[magic_bits::normalize_bits] normalized.len={} (raw.len={})",
            out.len(),
            raw.len()
        );
    } else {
        eprintln!("[magic_bits::normalize_bits] no change after normalize");
    }
    out
}