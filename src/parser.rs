use crate::scanner::{JoinOp, Scanner, SignOp, Token};

#[derive(Debug, Default, Clone)]
pub struct Expr {
    left: Token,
    op: SignOp,
    right: Token,
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{} {} {}}}", self.left, self.op, self.right)
    }
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

impl std::fmt::Display for ExprGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{} {}}}", self.join, self.item)
    }
}

#[derive(Debug)]
pub enum ExprGroupItem {
    Expr(Expr),
    ExprGroups(ExprGroups),
}

impl std::fmt::Display for ExprGroupItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprGroupItem::Expr(expr) => write!(f, "{expr}",),
            ExprGroupItem::ExprGroups(expr_groups) => write!(f, "{expr_groups}",),
        }
    }
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

impl std::fmt::Display for ExprGroups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (i, expr_group) in self.expr_groups.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{{{} {}}}", expr_group.join, expr_group.item)?;
        }
        write!(f, "]")?;
        Ok(())
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
    let mut result = ExprGroups::new();
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
    #[case(r"> 1", true, r"[]")]
    #[case(r"a >", true, r"[]")]
    #[case(r"a > >", true, r"[]")]
    #[case(r"a > %", true, r"[]")]
    #[case(r"a ! 1", true, r"[]")]
    #[case(r"a - 1", true, r"[]")]
    #[case(r"a + 1", true, r"[]")]
    #[case(r"1 - 1", true, r"[]")]
    #[case(r"1 + 1", true, r"[]")]
    #[case(r"> a 1", true, r"[]")]
    #[case(r"a || 1", true, r"[]")]
    #[case(r"a && 1", true, r"[]")]
    #[case(r"test > 1 &&", true, r"[]")]
    #[case(r"|| test = 1", true, r"[]")]
    #[case(r"test = 1 && ||", true, r"[]")]
    #[case(r"test = 1 && a", true, r"[]")]
    #[case(r#"test = 1 && "a""#, true, r"[]")]
    #[case(r"test = 1 a", true, r"[]")]
    #[case(r#"test = 1 "a""#, true, r"[]")]
    #[case(r"test = 1@test", true, r"[]")]
    #[case(r"test = .@test", true, r"[]")]
    #[case(r#"test = "demo'"#, true, r"[]")]
    #[case(r#"test = 'demo""#, true, r"[]")]
    #[case(r#"test = 'demo'""#, true, r"[]")]
    #[case(r"test = 'demo''", true, r"[]")]
    #[case(r#"test = "demo"'"#, true, r"[]")]
    #[case(r#"test = "demo"""#, true, r"[]")]
    #[case(r#"test = ""demo""#, true, r"[]")]
    #[case(r"test = ''demo''", true, r"[]")]
    #[case(r"test = `demo`", true, r"[]")]
    #[case(r"test = / demo", true, r"[]")]
    #[case(r"test = // demo", true, r"[]")]
    #[case(r"// demo", true, r"[]")]
    #[case(
        r"test = 123 // demo",
        false,
        r"[{&& {{identifier test} = {number 123}}}]"
    )]
    #[case(
        "test = // demo\n123",
        false,
        r"[{&& {{identifier test} = {number 123}}}]"
    )]
    #[case(
        r"
            a = 123 &&
            // demo
            b = 456
        ",
        false,
        r"[{&& {{identifier a} = {number 123}}} {&& {{identifier b} = {number 456}}}]"
    )]
    #[case(r"1=12", false, r"[{&& {{number 1} = {number 12}}}]")]
    #[case(r"   1    =    12    ", false, r"[{&& {{number 1} = {number 12}}}]")]
    #[case(
        r#""demo" != test"#,
        false,
        r"[{&& {{text demo} != {identifier test}}}]"
    )]
    #[case(r"a~1", false, r"[{&& {{identifier a} ~ {number 1}}}]")]
    #[case(r"a !~ 1", false, r"[{&& {{identifier a} !~ {number 1}}}]")]
    #[case(r"test>12", false, r"[{&& {{identifier test} > {number 12}}}]")]
    #[case(r"test > 12", false, r"[{&& {{identifier test} > {number 12}}}]")]
    #[case(
        r#"test >="test""#,
        false,
        r"[{&& {{identifier test} >= {text test}}}]"
    )]
    #[case(
        r"test<@demo.test2",
        false,
        r"[{&& {{identifier test} < {identifier @demo.test2}}}]"
    )]
    #[case(r#"1<="test""#, false, r"[{&& {{number 1} <= {text test}}}]")]
    #[case(r#"1<="te'st""#, false, r"[{&& {{number 1} <= {text te'st}}}]")]
    #[case(
        r#"demo='te\'st'"#,
        false,
        r"[{&& {{identifier demo} = {text te'st}}}]"
    )]
    #[case(
        r#"demo="te\'st""#,
        false,
        r"[{&& {{identifier demo} = {text te\'st}}}]"
    )]
    #[case(
        r#"demo="te\"st""#,
        false,
        r#"[{&& {{identifier demo} = {text te"st}}}]"#
    )]
    #[case(r"(a=1", true, r"[]")]
    #[case(r"a=1)", true, r"[]")]
    #[case(r"((a=1)", true, r"[]")]
    #[case(r"{a=1}", true, r"[]")]
    #[case(r"[a=1]", true, r"[]")]
    #[case(r"((a=1 || a=2) && c=1))", true, r"[]")]
    #[case(r"()", true, r"[]")]
    #[case(r"(a=1)", false, r"[{&& [{&& {{identifier a} = {number 1}}}]}]")]
    #[case(
        r#"(a="test(")"#,
        false,
        r"[{&& [{&& {{identifier a} = {text test(}}}]}]"
    )]
    #[case(
        r#"(a="test)")"#,
        false,
        r"[{&& [{&& {{identifier a} = {text test)}}}]}]"
    )]
    #[case(
        r"((a=1))",
        false,
        r"[{&& [{&& [{&& {{identifier a} = {number 1}}}]}]}]"
    )]
    #[case(
        r"a=1 || 2!=3",
        false,
        r"[{&& {{identifier a} = {number 1}}} {|| {{number 2} != {number 3}}}]"
    )]
    #[case(
        r"a=1 && 2!=3",
        false,
        r"[{&& {{identifier a} = {number 1}}} {&& {{number 2} != {number 3}}}]"
    )]
    #[case(r#"a=1 && 2!=3 || "b"=a"#, false, r"[{&& {{identifier a} = {number 1}}} {&& {{number 2} != {number 3}}} {|| {{text b} = {identifier a}}}]")]
    #[case(r#"(a=1 && 2!=3) || "b"=a"#, false, r"[{&& [{&& {{identifier a} = {number 1}}} {&& {{number 2} != {number 3}}}]} {|| {{text b} = {identifier a}}}]")]
    #[case(r"((a=1 || a=2) && (c=1))", false, r"[{&& [{&& [{&& {{identifier a} = {number 1}}} {|| {{identifier a} = {number 2}}}]} {&& [{&& {{identifier c} = {number 1}}}]}]}]")]
    #[case(r#"(a='"')"#, false, r#"[{&& [{&& {{identifier a} = {text "}}}]}]"#)]
    #[case(r"(a='\'')", false, r"[{&& [{&& {{identifier a} = {text '}}}]}]")]
    #[case(r#"(a="'")"#, false, r"[{&& [{&& {{identifier a} = {text '}}}]}]")]
    #[case(r#"(a="\"")"#, false, r#"[{&& [{&& {{identifier a} = {text "}}}]}]"#)]
    pub fn test_parser(
        #[case] text: &str,
        #[case] expected_error: bool,
        #[case] expected_print: &str,
    ) {
        let value = match parse(text) {
            Ok(value) => {
                assert!(!expected_error);
                value
            }
            Err(_) => {
                assert!(expected_error);
                return;
            }
        };

        let token_print = value.to_string();

        assert!(
            token_print == expected_print,
            "Expected {}, got {}",
            expected_print,
            token_print
        )
    }
}
