use oxc_allocator::Allocator;
use oxc_ast::{
    ast::{AssignmentExpression, BinaryExpression, Expression, ForStatement},
    AstBuilder,
};
use oxc_ast_visit::{
    walk_mut::{
        walk_assignment_expression, walk_binary_expression, walk_expression, walk_for_statement,
    },
    VisitMut,
};

pub struct GetKeyOperations<'a> {
    ast: AstBuilder<'a>,
    pub key_expr: Option<Expression<'a>>,
}

impl<'a> GetKeyOperations<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            key_expr: None,
        }
    }
}

impl<'a> VisitMut<'a> for GetKeyOperations<'a> {
    fn visit_expression(&mut self, node: &mut Expression<'a>) {
        if let Expression::BinaryExpression(bin_expr) = node {
            // On cherche l'opération "KEY & 255"
            if bin_expr.operator.as_str() == "&" {
                if let Expression::NumericLiteral(num) = &bin_expr.right {
                    // Cloudflare utilise parfois des flottants comme 255.63, donc on cast en int
                    if (num.value as u32) == 255 {
                        self.key_expr = Some(self.ast.move_expression(node));
                    }
                }
            }
        }
        walk_expression(self, node);
    }
}

#[derive(Default, Debug)]
pub struct KeyOperations {
    pub add: u32,
    pub multiply: u32,
}

pub struct FindOffset<'a> {
    ast: AstBuilder<'a>,
    in_for: bool,
    pub key_expr: Option<Expression<'a>>,
    pub offset: i16,
}

impl<'a> FindOffset<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            in_for: false,
            key_expr: None,
            offset: 0,
        }
    }
}

impl<'a> VisitMut<'a> for FindOffset<'a> {
    fn visit_for_statement(&mut self, node: &mut ForStatement<'a>) {
        self.in_for = true;
        walk_for_statement(self, node);
        self.in_for = false;
    }

    fn visit_assignment_expression(&mut self, node: &mut AssignmentExpression<'a>) {
        // Nouvelle logique de détection plus robuste
        // On ne cherche plus "array[3] =", on cherche n'importe quelle assignation dans la boucle
        // qui implique une opération "& 255" (masquage d'octet).
        if self.in_for {
             if let Expression::BinaryExpression(bin_expr) = &mut node.right {
                 if bin_expr.operator.as_str() == "&" {
                     if let Expression::NumericLiteral(num) = &bin_expr.right {
                         if (num.value as u32) == 255 {
                             // C'est notre expression de clé !
                             self.key_expr = Some(self.ast.move_expression(&mut node.right));
                         }
                     }
                 }
             }
        }

        walk_assignment_expression(self, node);
    }

    fn visit_binary_expression(&mut self, node: &mut BinaryExpression<'a>) {
        // Recherche de l'offset (ex: "valeur + fonction()") ou XOR
        // Dans les versions récentes, c'est souvent un XOR (^) plutôt qu'un +
        let op = node.operator.as_str();
        
        if op == "+" || op == "^" {
            let (lit, call_expr) = match (&node.left, &node.right) {
                (Expression::NumericLiteral(num_lit), Expression::CallExpression(call_expr)) => {
                    (num_lit.value as i64, Some(call_expr))
                }
                (Expression::CallExpression(call_expr), Expression::NumericLiteral(num_lit)) => {
                    (num_lit.value as i64, Some(call_expr))
                }
                _ => (0, None),
            };

            if let Some(_) = call_expr {
                // On a trouvé une constante associée à un appel de fonction
                // C'est probablement notre offset.
                if lit != 0 {
                    self.offset = lit as i16;
                    return;
                }
            }
        }

        walk_binary_expression(self, node);
    }
}