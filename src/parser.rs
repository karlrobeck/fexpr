use crate::scanner::Token;

#[derive(Debug)]
pub struct Expr {
    left: Token,
    op: String,
    right: Token,
}

#[derive(Debug)]
pub struct ExprGroup {
    items: Vec<Expr>,
    join: String,
}
