type JoinOp = &'static str;
type SignOp = &'static str;
type TokenType = &'static str;

const EOF: char = '\0';

const JoinAnd: JoinOp = "&&";
const JoinOr: JoinOp = "||";

const SignEq: SignOp = "=";
const SignNeq: SignOp = "!=";
const SignLike: SignOp = "~";
const SignNlike: SignOp = "!~";
const SignLt: SignOp = "<";
const SignLte: SignOp = "<=";
const SignGt: SignOp = ">";
const SignGte: SignOp = ">=";

// array/any operators
const SignAnyEq: SignOp = "?=";
const SignAnyNeq: SignOp = "?!=";
const SignAnyLike: SignOp = "?~";
const SignAnyNlike: SignOp = "?!~";
const SignAnyLt: SignOp = "?<";
const SignAnyLte: SignOp = "?<=";
const SignAnyGt: SignOp = "?>";
const SignAnyGte: SignOp = "?>=";

const TokenUnexpected: TokenType = "unexpected";
const TokenEOF: TokenType = "eof";
const TokenWS: TokenType = "whitespace";
const TokenJoin: TokenType = "join";
const TokenSign: TokenType = "sign";
const TokenIdentifier: TokenType = "identifier";
const TokenFunction: TokenType = "function";
const TokenNumber: TokenType = "number";
const TokenText: TokenType = "text";
const TokenGroup: TokenType = "group";
const TokenComment: TokenType = "comment";

#[derive(Debug)]
pub struct Token {
    pub meta: Option<Box<dyn std::any::Any>>,
    pub r#type: TokenType,
    pub literal: String,
}

#[derive(Debug, Clone)]
pub struct Scanner {
    data: Vec<u8>,
    pos: i64,
    max_function_depth: i16,
}

impl Scanner {
    pub fn new(data: Vec<u8>, max_function_depth: i16) -> Self {
        Self {
            data,
            max_function_depth,
            pos: 0,
        }
    }

    fn unread(&mut self) {
        if self.pos > 0 {
            self.pos -= 1;
        }
    }

    fn read(&mut self) -> char {
        if self.pos >= self.data.len() as i64 {
            return EOF;
        }

        let character = self.data[self.pos as usize] as char;
        self.pos += 1;

        return character;
    }

    pub fn scan(&mut self) -> Result<Token, anyhow::Error> {
        let character = self.read();

        if character == EOF {
            return Ok(Token {
                r#type: TokenEOF,
                literal: "".into(),
                meta: None,
            });
        }

        if is_whitespace_rune(character) {
            self.unread();
            return self.scan_whitespace();
        }

        if is_group_start_rune(character) {
            self.unread();
            return self.scan_group();
        }

        if is_identifier_start_rune(character) {
            self.unread();
            return self.scan_identifier(self.max_function_depth);
        }

        if is_number_start_rune(character) {
            self.unread();
            return self.scan_number();
        }

        if is_text_start_rune(character) {
            self.unread();
            return self.scan_text(false);
        }

        if is_sign_start_rune(character) {
            self.unread();
            return self.scan_sign();
        }

        if is_join_start_rune(character) {
            self.unread();
            return self.scan_join();
        }

        if is_comment_start_rune(character) {
            self.unread();
            return self.scan_comment();
        }

        return Err(anyhow::anyhow!("unexpected character {:?}", character));
    }
}

impl Scanner {
    fn scan_whitespace(&mut self) -> Result<Token, anyhow::Error> {
        let mut buffer = vec![];

        loop {
            let character = self.read();

            if character == EOF {
                break;
            }

            // todo isWhitespaceRune
            if character != ' ' && character != '\t' && character != '\n' {
                self.unread();
                break;
            }

            buffer.push(character);
        }

        return Ok(Token {
            r#type: TokenWS,
            literal: buffer.into_iter().collect(),
            meta: None,
        });
    }

    fn scan_number(&mut self) -> Result<Token, anyhow::Error> {
        let mut buffer = vec![];

        let mut had_dot = false;

        loop {
            let character = self.read();

            if character == EOF {
                break;
            }

            if !is_digit_rune(character) &&
			// minus sign but not at the beginning
			(character != '-' || buffer.len() != 0) &&
			// dot but there was already another dot
			(character != '.' || had_dot)
            {
                self.unread();
                break;
            }

            buffer.push(character);

            if character == '.' {
                had_dot = true;
            }
        }

        let total = buffer.len();
        let literal: String = buffer.into_iter().collect();

        if (total == 1 && literal.chars().nth(0) == Some('-'))
            || literal.chars().nth(0) == Some('.')
            || literal.chars().nth(total - 1) == Some('.')
        {
            return Err(anyhow::anyhow!("invalid number {:?}", literal));
        }

        return Ok(Token {
            meta: None,
            r#type: TokenNumber,
            literal,
        });
    }

    fn scan_text(&mut self, preserve_quotes: bool) -> Result<Token, anyhow::Error> {
        let mut buffer = vec![];

        // read the first rune to determine the quotes type
        let first_character = self.read();
        buffer.push(first_character);
        let mut prev_character = '\0';
        let mut has_matching_quotes = false;

        // Read every subsequent text rune into the buffer.
        // EOF and matching unescaped ending quote will cause the loop to exit.
        loop {
            let character = self.read();

            if character == EOF {
                break;
            }

            // write the text rune
            buffer.push(character);

            // unescaped matching quote, aka. the end
            if character == first_character && prev_character != '\\' {
                has_matching_quotes = true;
                break;
            }

            prev_character = character;
        }

        let mut literal: String = buffer.into_iter().collect();

        if !has_matching_quotes {
            return Err(anyhow::anyhow!("invalid quoted text {:?}", literal));
        }

        if !preserve_quotes {
            // unquote
            let literal_chars: Vec<char> = literal.chars().collect();

            literal = literal_chars[1..literal.len() - 1].iter().collect();

            let first_character_str = first_character.to_string();

            literal = literal.replace(
                &("\\".to_owned() + &first_character_str),
                &first_character_str,
            );
        }

        return Ok(Token {
            r#type: TokenText,
            literal,
            meta: None,
        });
    }

    fn scan_comment(&mut self) -> Result<Token, anyhow::Error> {
        let mut buffer = vec![];

        // Read the first 2 characters without writing them to the buffer.
        if !is_comment_start_rune(self.read()) || !is_comment_start_rune(self.read()) {
            return Err(anyhow::anyhow!("invalid comment"));
        }

        // Read every subsequent comment text rune into the buffer.
        // \n and EOF will cause the loop to exit.
        loop {
            let character = self.read();

            if character == EOF || character == '\n' {
                break;
            }

            buffer.push(character);
        }

        let literal: String = buffer.into_iter().collect();

        return Ok(Token {
            r#type: TokenComment,
            literal: literal.trim().to_string(),
            meta: None,
        });
    }

    fn scan_identifier(&mut self, func_depth: i16) -> Result<Token, anyhow::Error> {
        let mut buffer = vec![];

        // read the first rune in case it is a special start identifier character
        buffer.push(self.read());

        // Read every subsequent identifier rune into the buffer.
        // Non-ident runes and EOF will cause the loop to exit.
        loop {
            let character = self.read();

            if character == EOF {
                break;
            }

            // func
            if character == '(' {
                let literal: String = buffer.into_iter().collect();
                let func_name = literal.clone();
                if func_depth <= 0 {
                    return Err(anyhow::anyhow!(
                        "max nested function arguments reached (max: {})",
                        self.max_function_depth
                    ));
                }
                if !is_valid_identifier(&func_name) {
                    return Err(anyhow::anyhow!("invalid function name {:?}", func_name));
                }

                self.unread();

                return self.scan_function_args(func_name, func_depth);
            }

            // not an identifier character
            if !is_letter_rune(character)
                && !is_digit_rune(character)
                && !is_identifier_combine_rune(character)
                && character != '_'
            {
                self.unread();
                break;
            }

            // write the identifier rune
            buffer.push(character);
        }

        let literal: String = buffer.into_iter().collect();

        if !is_valid_identifier(&literal) {
            return Err(anyhow::anyhow!("invalid identifier {:?}", literal));
        }

        return Ok(Token {
            r#type: TokenIdentifier,
            literal,
            meta: None,
        });
    }

    fn scan_sign(&mut self) -> Result<Token, anyhow::Error> {
        let mut buffer = vec![];

        // Read every subsequent sign rune into the buffer.
        // Non-sign runes and EOF will cause the loop to exit.
        loop {
            let character = self.read();

            if character == EOF {
                break;
            }

            if !is_sign_start_rune(character) {
                self.unread();
                break;
            }

            // write the sign rune
            buffer.push(character);
        }

        let literal: String = buffer.into_iter().collect();

        if !is_sign_operator(&literal) {
            return Err(anyhow::anyhow!("invalid sign operator {:?}", literal));
        }

        return Ok(Token {
            r#type: TokenSign,
            literal,
            meta: None,
        });
    }

    fn scan_join(&mut self) -> Result<Token, anyhow::Error> {
        let mut buffer = vec![];

        // Read every subsequent join operator rune into the buffer.
        // Non-join runes and EOF will cause the loop to exit.
        loop {
            let ch = self.read();

            if ch == EOF {
                break;
            }

            if !is_join_start_rune(ch) {
                self.unread();
                break;
            }

            // write the join operator rune
            buffer.push(ch);
        }

        let literal: String = buffer.into_iter().collect();

        if !is_join_operator(&literal) {
            return Err(anyhow::anyhow!("invalid join operator {:?}", literal));
        }

        return Ok(Token {
            r#type: TokenJoin,
            literal,
            meta: None,
        });
    }

    fn scan_group(&mut self) -> Result<Token, anyhow::Error> {
        let mut buffer = vec![];

        // read the first group bracket without writing it to the buffer
        let first_character = self.read();
        let mut open_groups = 1;

        // Read every subsequent text rune into the buffer.
        // EOF and matching unescaped ending quote will cause the loop to exit.
        loop {
            let character = self.read();

            if character == EOF {
                break;
            }
            if is_group_start_rune(character) {
                // nested group
                open_groups += 1;
                buffer.push(character);
            } else if is_text_start_rune(character) {
                self.unread();
                let t = self.scan_text(true); // with quotes to preserve the exact text start/end runes
                match t {
                    Ok(token) => {
                        buffer.extend(token.literal.chars());
                    }
                    Err(err) => {
                        // write the errored literal as it is
                        let literal: String = buffer.into_iter().collect();
                        return Err(anyhow::anyhow!("{}, {}", literal, err));
                    }
                }
            } else if character == ')' {
                open_groups -= 1;
                if open_groups <= 0 {
                    break;
                }
                buffer.push(character);
            } else {
                buffer.push(character);
            }
        }

        let literal: String = buffer.into_iter().collect();

        if !is_group_start_rune(first_character) || open_groups > 0 {
            return Err(anyhow::anyhow!(
                "invalid formatted group - missing {} closing bracket(s)",
                open_groups
            ));
        }

        return Ok(Token {
            r#type: TokenGroup,
            literal,
            meta: None,
        });
    }

    fn scan_function_args(
        &mut self,
        func_name: String,
        func_depth: i16,
    ) -> Result<Token, anyhow::Error> {
        let mut args: Vec<Token> = vec![];

        let mut expect_comma = false;
        let mut is_comma;
        let mut is_closed = false;

        let ch = self.read();
        if ch != '(' {
            return Err(anyhow::anyhow!(
                "invalid or incomplete function call {:?}",
                func_name
            ));
        }

        // Read every subsequent rune until ')' or EOF has been reached.
        loop {
            let ch = self.read();

            if ch == EOF {
                break;
            }

            if ch == ')' {
                is_closed = true;
                break;
            }

            // skip whitespaces
            if is_whitespace_rune(ch) {
                let t = self.scan_whitespace();
                match t {
                    Ok(_) => {}
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "failed to scan whitespaces in function {:?}: {:?}",
                            func_name,
                            err
                        ));
                    }
                }
                continue;
            }

            // skip comments
            if is_comment_start_rune(ch) {
                self.unread();
                let t = self.scan_comment();
                match t {
                    Ok(_) => {}
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "failed to scan comment in function {:?}: {:?}",
                            func_name,
                            err
                        ));
                    }
                }
                continue;
            }

            is_comma = ch == ',';

            if expect_comma && !is_comma {
                return Err(anyhow::anyhow!(
                    "expected comma after the last argument in function {:?}",
                    func_name
                ));
            }

            if !expect_comma && is_comma {
                return Err(anyhow::anyhow!(
                    "unexpected comma in function {:?}",
                    func_name
                ));
            }

            expect_comma = false; // reset

            if is_comma {
                continue;
            }

            if is_identifier_start_rune(ch) {
                self.unread();
                let t = self.scan_identifier(func_depth - 1);
                match t {
                    Ok(token) => {
                        args.push(token);
                        expect_comma = true;
                    }
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "invalid identifier argument in function {:?}: {:?}",
                            func_name,
                            err
                        ));
                    }
                }
            } else if is_number_start_rune(ch) {
                self.unread();
                let t = self.scan_number();
                match t {
                    Ok(token) => {
                        args.push(token);
                        expect_comma = true;
                    }
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "invalid number argument in function {:?}: {:?}",
                            func_name,
                            err
                        ));
                    }
                }
            } else if is_text_start_rune(ch) {
                self.unread();
                let t = self.scan_text(false);
                match t {
                    Ok(token) => {
                        args.push(token);
                        expect_comma = true;
                    }
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "invalid text argument in function {:?}: {:?}",
                            func_name,
                            err
                        ));
                    }
                }
            } else {
                return Err(anyhow::anyhow!(
                    "unsupported argument character in function {:?}",
                    func_name
                ));
            }
        }

        if !is_closed {
            return Err(anyhow::anyhow!(
                "invalid or incomplete function {:?} (expected ')')",
                func_name
            ));
        }

        return Ok(Token {
            r#type: TokenFunction,
            literal: func_name,
            meta: Some(Box::new(args)),
        });
    }
}

fn is_whitespace_rune(ch: char) -> bool {
    ch == ' ' || ch == '\t' || ch == '\n'
}

fn is_letter_rune(ch: char) -> bool {
    (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

fn is_digit_rune(ch: char) -> bool {
    ch >= '0' && ch <= '9'
}

fn is_text_start_rune(ch: char) -> bool {
    ch == '\'' || ch == '"'
}

fn is_number_start_rune(ch: char) -> bool {
    ch == '-' || is_digit_rune(ch)
}

fn is_sign_start_rune(ch: char) -> bool {
    ch == '=' || ch == '?' || ch == '!' || ch == '>' || ch == '<' || ch == '~'
}

fn is_join_start_rune(ch: char) -> bool {
    ch == '&' || ch == '|'
}

fn is_group_start_rune(ch: char) -> bool {
    ch == '('
}

fn is_comment_start_rune(ch: char) -> bool {
    ch == '/'
}

fn is_identifier_start_rune(ch: char) -> bool {
    is_letter_rune(ch) || is_identifier_special_start_rune(ch)
}

fn is_identifier_special_start_rune(ch: char) -> bool {
    ch == '@' || ch == '_' || ch == '#'
}

fn is_identifier_combine_rune(ch: char) -> bool {
    ch == '.' || ch == ':'
}

fn is_sign_operator(literal: &str) -> bool {
    match literal {
        SignEq | SignNeq | SignLt | SignLte | SignGt | SignGte | SignLike | SignNlike
        | SignAnyEq | SignAnyNeq | SignAnyLike | SignAnyNlike | SignAnyLt | SignAnyLte
        | SignAnyGt | SignAnyGte => true,
        _ => false,
    }
}

fn is_join_operator(literal: &str) -> bool {
    match literal {
        JoinAnd | JoinOr => true,
        _ => false,
    }
}

fn is_valid_identifier(literal: &str) -> bool {
    let length = literal.len();

    if length > 0 {
        !is_identifier_combine_rune(literal.chars().nth(length - 1).unwrap())
            && (length != 1 || !is_identifier_special_start_rune(literal.chars().nth(0).unwrap()))
    } else {
        false
    }
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("   ",vec![
        (false,Token{meta:None,r#type:TokenWS,literal:"   ".into()}),
    ])]
    #[case("test 123",vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"test".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenNumber,literal:"123".into()}),
    ])]
    // Identifiers
    #[case("test",vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"test".into()}),
    ])]
    #[case("@",vec![
        (true,Token{meta:None,r#type:TokenIdentifier,literal:"@".into()}),
    ])]
    #[case("test:",vec![
        (true,Token{meta:None,r#type:TokenIdentifier,literal:"test:".into()}),
    ])]
    #[case("test.",vec![
        (true,Token{meta:None,r#type:TokenIdentifier,literal:"test.".into()}),
    ])]
    #[case("@test.123:c",vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"@test.123:c".into()}),
    ])]
    #[case("_test_a.123",vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"_test_a.123".into()}),
    ])]
    #[case("#test.123:456",vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"#test.123:456".into()}),
    ])]
    #[case(".test.123",vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:".".into()}),
    ])]
    #[case(":test.123",vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:":".into()}),
    ])]
    #[case("test#@",vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"test".into()}),
    ])]
    #[case("test'",vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"test".into()}),
    ])]
    #[case("test\"d",vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"test".into()}),
    ])]
    // Numbers
    #[case("123",vec![
        (false,Token{meta:None,r#type:TokenNumber,literal:"123".into()}),
    ])]
    #[case("-123",vec![
        (false,Token{meta:None,r#type:TokenNumber,literal:"-123".into()}),
    ])]
    #[case("-123.456",vec![
        (false,Token{meta:None,r#type:TokenNumber,literal:"-123.456".into()}),
    ])]
    #[case("123.456",vec![
        (false,Token{meta:None,r#type:TokenNumber,literal:"123.456".into()}),
    ])]
    #[case("12.34.56",vec![
        (false,Token{meta:None,r#type:TokenNumber,literal:"12.34".into()}),
        (true,Token{meta:None,r#type:TokenUnexpected,literal:".".into()}),
        (false,Token{meta:None,r#type:TokenNumber,literal:"56".into()}),
    ])]
    #[case(".123",vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:".".into()}),
        (false,Token{meta:None,r#type:TokenNumber,literal:"123".into()}),
    ])]
    #[case("- 123",vec![
        (true,Token{meta:None,r#type:TokenNumber,literal:"-".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenNumber,literal:"123".into()}),
    ])]
    #[case("12-3",vec![
        (false,Token{meta:None,r#type:TokenNumber,literal:"12".into()}),
        (false,Token{meta:None,r#type:TokenNumber,literal:"-3".into()}),
    ])]
    #[case("123.abc",vec![
        (true,Token{meta:None,r#type:TokenNumber,literal:"123.".into()}),
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"abc".into()}),
    ])]
    #[case("&&||",vec![
        (true,Token{meta:None,r#type:TokenJoin,literal:"&&||".into()}),
    ])]
    // Text
    #[case("\"\"",vec![
        (false,Token{meta:None,r#type:TokenText,literal:"".into()}),
    ])]
    #[case(r"''",vec![
        (false,Token{meta:None,r#type:TokenText,literal:"".into()}),
    ])]
    #[case(r"'test'",vec![
        (false,Token{meta:None,r#type:TokenText,literal:"test".into()}),
    ])]
    #[case(r"'te\'st'",vec![
        (false,Token{meta:None,r#type:TokenText,literal:"te'st".into()}),
    ])]
    #[case(r#"'te"st'"#,vec![
        (false,Token{meta:None,r#type:TokenText,literal:"te\"st".into()}),
    ])]
    #[case(r#"'te"st'"#,vec![
        (false,Token{meta:None,r#type:TokenText,literal:"te\"st".into()}),
    ])]
    #[case(r#""tes@#,;!@#%^'\"t""#,vec![
        (false,Token{meta:None,r#type:TokenText,literal:r#"tes@#,;!@#%^'"t"#.into()}),
    ])]
    #[case(r#"'tes@#,;!@#%^\'"t'"#,vec![
        (false,Token{meta:None,r#type:TokenText,literal:r#"tes@#,;!@#%^'"t"#.into()}),
    ])]
    #[case(r#""test"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:r#""#.into()}),
    ])]
    #[case(r#""test"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:r#""#.into()}),
    ])]
    #[case(r#"'АБЦ"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:r#""#.into()}),
    ])]
    // join types
    #[case(r#"&&||"#,vec![
        (true,Token{meta:None,r#type:TokenJoin,literal:"&&||".into()}),
    ])]
    #[case(r#"&& ||"#,vec![
        (false,Token{meta:None,r#type:TokenJoin,literal:"&&".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenJoin,literal:"||".into()}),
    ])]
    #[case(r#"'||test&&'&&123"#,vec![
        (false,Token{meta:None,r#type:TokenText,literal:"||test&&".into()}),
        (false,Token{meta:None,r#type:TokenJoin,literal:"&&".into()}),
        (false,Token{meta:None,r#type:TokenNumber,literal:"123".into()}),
    ])]
    // expression signs
    #[case(r#"=!="#,vec![
        (true,Token{meta:None,r#type:TokenSign,literal:"=!=".into()}),
        ])]
    #[case(r#"= != ~ !~ > >= < <= ?= ?!= ?~ ?!~ ?> ?>= ?< ?<="#,vec![
        (false,Token{meta:None,r#type:TokenSign,literal:"=".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"!=".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"~".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"!~".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:">".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:">=".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"<".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"<=".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"?=".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"?!=".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"?~".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"?!~".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"?>".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"?>=".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"?<".into()}),
        (false,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenSign,literal:"?<=".into()}),
    ])]
    // comments
    #[case(r#"/ test"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:"/".into()}),
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"test".into()}),
    ])]
    #[case(r#"/ / test"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:"/".into()}),
        (true,Token{meta:None,r#type:TokenWS,literal:" ".into()}),
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"test".into()}),
    ])]
    #[case(r#"//"#,vec![
        (false,Token{meta:None,r#type:TokenComment,literal:"".into()}),
    ])]
    #[case(r#"//test"#,vec![
        (false,Token{meta:None,r#type:TokenComment,literal:"test".into()}),
    ])]
    #[case(r#"// test"#,vec![
        (false,Token{meta:None,r#type:TokenComment,literal:"test".into()}),
    ])]
    #[case(r#"//   test1 //test2  "#,vec![
        (false,Token{meta:None,r#type:TokenComment,literal:"test1 //test2".into()}),
    ])]
    #[case(r#"///test"#,vec![
        (false,Token{meta:None,r#type:TokenComment,literal:"/test".into()}),
    ])]
    // function calls
    #[case(r#"test()"#,vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"test".into()}),
    ])]
    #[case(r#"test(a, b"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:"(".into()}),
    ])]
    #[case(r#"@test:abc()"#,vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"@test:abc".into()}),
    ])]
    #[case(r#"test(  a  )"#,vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"test".into()}),
    ])]
    #[case(r#"test(a, b)"#,vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"test".into()}),
    ])]
    #[case(r#"test(a, b,  )"#,vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"test".into()}),
    ])]
    #[case(r#"test(a,,)"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:"(".into()}),
    ])]
    #[case(r#"test(a,,,b)"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:"(".into()}),
    ])]
    #[case(r#"test(   @test.a.b:test  , 123, "ab)c", 'd,ce')"#,vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"test".into()}),
    ])]
    #[case(r#"test(a //test)"#,vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:"(".into()}),
    ])]
    #[case("test(a //test\n)",vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"test".into()}),
    ])]
    #[case("test(a, //test\n, b)",vec![
        (true,Token{meta:None,r#type:TokenUnexpected,literal:"(".into()}),
    ])]
    #[case("test(a, //test\n b)",vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"test".into()}),
    ])]
    #[case(r#"test(a, test(test(b), c), d)"#,vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"test".into()}),
    ])]
    // max funcs depth
    #[case(r#"a(b(c(1)))"#,vec![
        (false,Token{meta:None,r#type:TokenFunction,literal:"a".into()}),
    ])]
    #[case(r#"a(b(c(d(1))))"#,vec![
        (true,Token{meta:None,r#type:TokenFunction,literal:"a".into()}),
    ])]
    // groups
    #[case(r#"a)"#,vec![
        (false,Token{meta:None,r#type:TokenIdentifier,literal:"a".into()}),
    ])]
    #[case(r#"(a b c"#,vec![
        (true,Token{meta:None,r#type:TokenGroup,literal:"a b c".into()}),
    ])]
    #[case(r#"(a b c)"#,vec![
        (false,Token{meta:None,r#type:TokenGroup,literal:"a b c".into()}),
    ])]
    #[case(r#"((a b c))"#,vec![
        (false,Token{meta:None,r#type:TokenGroup,literal:"(a b c)".into()}),
    ])]
    #[case(r#"((a )b c))"#,vec![
        (false,Token{meta:None,r#type:TokenGroup,literal:"(a )b c".into()}),
    ])]
    #[case(r#"("ab)("c)"#,vec![
        (false,Token{meta:None,r#type:TokenGroup,literal:r#""ab)("c"#.into()}),
    ])]
    #[case(r#"("ab)(c)"#,vec![
        (true,Token{meta:None,r#type:TokenGroup,literal:r#""ab)(c"#.into()}),
    ])]
    #[case(r#"( func(1, 2, 3, func(4)) a b c )"#,vec![
        (false,Token{meta:None,r#type:TokenGroup,literal:" func(1, 2, 3, func(4)) a b c ".into()}),
    ])]
    #[rstest]
    pub fn test_scanner(#[case] text: &str, #[case] expects: Vec<(bool, Token)>) {
        let mut scanner = Scanner::new(text.into(), 3);
        for expect in expects {
            let token = scanner.scan();
            assert_eq!(token.is_err(), expect.0, "case {}", text);
            if !token.is_err() {
                let token = token.unwrap();
                assert_eq!(token.r#type, expect.1.r#type, "case {}", text);
                assert_eq!(token.literal, expect.1.literal, "case {}", text);
            }
        }
    }
}
