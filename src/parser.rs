use crate::scanner::{JoinOp, Scanner, SignOp, Token};

#[derive(Debug, Default, Clone)]
pub struct Expr {
    left: Token,
    op: SignOp,
    right: Token,
}

impl Expr {
    pub fn is_zero(self) -> bool {
        self.op == SignOp::None && self.left == Token::None && self.right == Token::None
    }
}

#[derive(Debug)]
pub struct ExprGroup {
    pub join: JoinOp,
    pub item: ExprGroupItem,
}

#[derive(Debug)]
pub enum ExprGroupItem {
    Expr(Expr),
    ExprGroups(ExprGroups),
}

#[derive(Debug)]
pub struct ExprGroups {
    pub expr_groups: Vec<ExprGroup>,
}

impl ExprGroups {
    fn new() -> Self {
        Self {
            expr_groups: Vec::new(),
        }
    }

    pub fn get(&self) -> &Vec<ExprGroup> {
        &self.expr_groups
    }

    fn push(&mut self, value: ExprGroup) {
        self.expr_groups.push(value)
    }

    fn len(&self) -> usize {
        self.expr_groups.len()
    }
}

#[derive(PartialEq)]
enum Step {
    BeforeSign,
    Sign,
    AfterSign,
    Join,
}

pub fn parse(text: &str) -> Result<ExprGroups, anyhow::Error> {
    let mut result = ExprGroups {
        expr_groups: vec![],
    };
    let mut scanner = Scanner::new(text.as_bytes().into(), 3);
    let mut step = Step::BeforeSign;
    let mut join = JoinOp::And;
    let mut expr = Expr::default();

    loop {
        let token = scanner.scan()?;

        if matches!(token, Token::EOF(_)) {
            break;
        }

        if matches!(token, Token::Whitespace(_)) || matches!(token, Token::Comment(_)) {
            continue;
        }

        if matches!(token, Token::Group(_)) {
            let group_result = parse(token.literal())?;

            // append only if non-empty group
            if group_result.len() > 0 {
                result.push(ExprGroup {
                    join,
                    item: ExprGroupItem::ExprGroups(group_result),
                })
            }

            step = Step::Join;
            continue;
        }

        match step {
            Step::BeforeSign => {
                if !matches!(token, Token::Identifier(_))
                    && !matches!(token, Token::Text(_))
                    && !matches!(token, Token::Number(_))
                {
                    return Err(anyhow::anyhow!(format!(
                        "Expected left operand (identifier, text or number), got {} ({})",
                        token.literal(),
                        token.kind()
                    )));
                }

                expr = Expr {
                    left: token,
                    ..Default::default()
                };

                step = Step::Sign
            }
            Step::Sign => {
                if !matches!(token, Token::Sign(_)) {
                    return Err(anyhow::anyhow!(format!(
                        "Expected a sign operator, got {} ({})",
                        token.literal(),
                        token.kind()
                    )));
                }

                expr.op = match SignOp::from_str(token.literal()) {
                    Some(op) => op,
                    None => {
                        return Err(anyhow::anyhow!(format!(
                            "Expected a sign operator, got {} ({})",
                            token.literal(),
                            token.kind()
                        )));
                    }
                };

                step = Step::AfterSign;
            }
            Step::AfterSign => {
                if !matches!(token, Token::Identifier(_))
                    && !matches!(token, Token::Text(_))
                    && !matches!(token, Token::Number(_))
                {
                    return Err(anyhow::anyhow!(format!(
                        "Expected right operand (identifier, text or number), got {} ({})",
                        token.literal(),
                        token.kind(),
                    )));
                }

                expr.right = token;
                result.push(ExprGroup {
                    join,
                    item: ExprGroupItem::Expr(expr.clone()),
                });

                step = Step::Join;
            }
            Step::Join => {
                if !matches!(token, Token::Join(_)) {
                    return Err(anyhow::anyhow!(format!(
                        "Expected && or ||, got {} ({})",
                        token.literal(),
                        token.kind()
                    )));
                }

                join = match JoinOp::from_str(token.literal()) {
                    Some(join) => join,
                    None => {
                        return Err(anyhow::anyhow!(format!(
                            "Expected && or ||, got {} ({})",
                            token.literal(),
                            token.kind()
                        )));
                    }
                };

                step = Step::BeforeSign;
            }
        }
    }

    if step != Step::Join {
        if result.len() == 0 && expr.is_zero() {
            return Err(anyhow::anyhow!("Empty filter expression".to_owned()));
        }

        return Err(anyhow::anyhow!(
            "Invalid or incomplete filter expression".to_owned(),
        ));
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(r"> 1", true)]
    #[case(r"a >", true)]
    #[case(r"a > >", true)]
    #[case(r"a > %", true)]
    #[case(r"a ! 1", true)]
    #[case(r"a - 1", true)]
    #[case(r"a + 1", true)]
    #[case(r"1 - 1", true)]
    #[case(r"1 + 1", true)]
    #[case(r"> a 1", true)]
    #[case(r"a || 1", true)]
    #[case(r"a && 1", true)]
    #[case(r"test > 1 &&", true)]
    #[case(r"|| test = 1", true)]
    #[case(r"test = 1 && ||", true)]
    #[case(r"test = 1 && a", true)]
    #[case(r#"test = 1 && "a""#, true)]
    #[case(r"test = 1 a", true)]
    #[case(r#"test = 1 "a""#, true)]
    #[case(r"test = 1@test", true)]
    #[case(r"test = .@test", true)]
    #[case(r#"test = "demo'"#, true)]
    #[case(r#"test = 'demo""#, true)]
    #[case(r#"test = 'demo'""#, true)]
    #[case(r"test = 'demo''", true)]
    #[case(r#"test = "demo"'"#, true)]
    #[case(r#"test = "demo"""#, true)]
    #[case(r#"test = ""demo""#, true)]
    #[case(r"test = ''demo''", true)]
    #[case(r"test = `demo`", true)]
    #[case(r"test = / demo", true)]
    #[case(r"test = // demo", true)]
    #[case(r"// demo", true)]
    #[case(r"test = 123 // demo", false)]
    #[case("test = // demo\n123", false)]
    #[case(
        r"
            a = 123 &&
            // demo
            b = 456
        ",
        false
    )]
    #[case(r"1=12", false)]
    #[case(r"   1    =    12    ", false)]
    #[case(r#""demo" != test"#, false)]
    #[case(r"a~1", false)]
    #[case(r"a !~ 1", false)]
    #[case(r"test>12", false)]
    #[case(r"test > 12", false)]
    #[case(r#"test >="test""#, false)]
    #[case(r"test<@demo.test2", false)]
    #[case(r#"1<="test""#, false)]
    #[case(r#"1<="te'st""#, false)]
    #[case(r#"demo='te\'st'"#, false)]
    #[case(r#"demo="te\'st""#, false)]
    #[case(r#"demo="te\"st""#, false)]
    #[case(r"(a=1", true)]
    #[case(r"a=1)", true)]
    #[case(r"((a=1)", true)]
    #[case(r"{a=1}", true)]
    #[case(r"[a=1]", true)]
    #[case(r"((a=1 || a=2) && c=1))", true)]
    #[case(r"()", true)]
    #[case(r"(a=1)", false)]
    #[case(r#"(a="test(")"#, false)]
    #[case(r#"(a="test)")"#, false)]
    #[case(r"((a=1))", false)]
    #[case(r"a=1 || 2!=3", false)]
    #[case(r"a=1 && 2!=3", false)]
    #[case(r#"a=1 && 2!=3 || "b"=a"#, false)]
    #[case(r#"(a=1 && 2!=3) || "b"=a"#, false)]
    #[case(r"((a=1 || a=2) && (c=1))", false)]
    #[case(r#"(a='"')"#, false)]
    #[case(r"(a='\'')", false)]
    #[case(r#"(a="'")"#, false)]
    #[case(r#"(a="\"")"#, false)]
    pub fn test_parser(#[case] text: &str, #[case] expected_error: bool) {
        match parse(text) {
            Ok(_) => assert!(!expected_error),
            Err(_) => assert!(expected_error),
        }
    }
}
