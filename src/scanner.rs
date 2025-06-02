use crate::error;

const EOF: char = '\0';

#[derive(Debug, PartialEq,Clone,Copy)]
pub enum JoinOp {
    And,
    Or,
}

impl JoinOp {
    pub fn from_str(str: &str) -> Option<Self> {
        match str {
            "&&" => Some(Self::And),
            "||" => Some(Self::Or),
            _ => None,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::And => "&&",
            Self::Or => "||",
        }
    }
}

impl std::fmt::Display for JoinOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, PartialEq, Default,Clone)]
pub enum SignOp {
    #[default]
    None,
    Eq,
    Neq,
    Like,
    Nlike,
    Lt,
    Lte,
    Gt,
    Gte,
    AnyEq,
    AnyNeq,
    AnyLike,
    AnyNlike,
    AnyLt,
    AnyLte,
    AnyGt,
    AnyGte,
}

impl SignOp {
    pub fn from_str(str: &str) -> Option<Self> {
        match str {
            "=" => Some(Self::Eq),
            "!=" => Some(Self::Neq),
            "~" => Some(Self::Like),
            "!~" => Some(Self::Nlike),
            "<" => Some(Self::Lt),
            "<=" => Some(Self::Lte),
            ">" => Some(Self::Gt),
            ">=" => Some(Self::Gte),
            "?=" => Some(Self::AnyEq),
            "?!=" => Some(Self::AnyNeq),
            "?~" => Some(Self::AnyLike),
            "?!~" => Some(Self::AnyNlike),
            "?<" => Some(Self::AnyLt),
            "?<=" => Some(Self::AnyLte),
            "?>" => Some(Self::AnyGt),
            "?>=" => Some(Self::AnyGte),
            _ => None,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::None => "",
            Self::Eq => "=",
            Self::Neq => "!=",
            Self::Like => "~",
            Self::Nlike => "!~",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::AnyEq => "?=",
            Self::AnyNeq => "?!=",
            Self::AnyLike => "?~",
            Self::AnyNlike => "?!~",
            Self::AnyLt => "?<",
            Self::AnyLte => "?<=",
            Self::AnyGt => "?>",
            Self::AnyGte => "?>=",
        }
    }
}

impl std::fmt::Display for SignOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, PartialEq, Default, Clone)]
pub enum Token {
    // token kind constants
    #[default]
    None,
    EOF(String),
    Whitespace(String),
    Join(String),
    Sign(String),
    Identifier(String),
    Number(String),
    Text(String),
    Group(String),
    Comment(String),
    Function {
        name: String,
        args: Vec<Token>,
    },
}

impl Token {
    pub fn kind(&self) -> &str {
        match self {
            Self::None => "",
            Self::EOF(_) => "eof",
            Self::Whitespace(_) => "whitespace",
            Self::Join(_) => "join",
            Self::Sign(_) => "sign",
            Self::Identifier(_) => "identifier", // variable, column name, placeholder, etc.
            Self::Number(_) => "number",
            Self::Text(_) => "text",   // ' or " quoted string
            Self::Group(_) => "group", // groupped/nested tokens
            Self::Comment(_) => "comment",
            Self::Function { .. } => "function",
        }
    }

    pub fn literal(&self) -> &str {
        match self {
            Self::None => "",
            Self::EOF(value) => value,
            Self::Whitespace(value) => value,
            Self::Join(value) => value,
            Self::Sign(value) => value,
            Self::Identifier(value) => value,
            Self::Number(value) => value,
            Self::Text(value) => value,
            Self::Group(value) => value,
            Self::Comment(value) => value,
            Self::Function { name, .. } => name,
        }
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{} {}}}", self.kind(), self.literal())
    }
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

    pub fn scan(&mut self) -> Result<Token, error::FexprError> {
        let character = self.read();

        if character == EOF {
            return Ok(Token::EOF(character.to_string()));
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

        return Err(error::FexprError::TokenUnexpected(character.to_string()));
    }
}

impl Scanner {
    fn scan_whitespace(&mut self) -> Result<Token, error::FexprError> {
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

        return Ok(Token::Whitespace(buffer.into_iter().collect()));
    }

    fn scan_number(&mut self) -> Result<Token, error::FexprError> {
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
            return Err(error::FexprError::InvalidNumber(literal.to_string()));
        }

        return Ok(Token::Number(literal));
    }

    fn scan_text(&mut self, preserve_quotes: bool) -> Result<Token, error::FexprError> {
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
            return Err(error::FexprError::InvalidQuoteText(literal.to_string()));
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

        return Ok(Token::Text(literal));
    }

    fn scan_comment(&mut self) -> Result<Token, error::FexprError> {
        let mut buffer = vec![];

        // Read the first 2 characters without writing them to the buffer.
        if !is_comment_start_rune(self.read()) || !is_comment_start_rune(self.read()) {
            return Err(error::FexprError::InvalidComment("invalid comment".to_string()));
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

        return Ok(Token::Comment(literal));
    }

    fn scan_identifier(&mut self, func_depth: i16) -> Result<Token, error::FexprError> {
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
                    return Err(error::FexprError::MaxFunctionDepthExceeded(self.max_function_depth));
                }
                if !is_valid_identifier(&func_name) {
                    return Err(error::FexprError::InvalidFunctionName(func_name));
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
            return Err(error::FexprError::InvalidIdentifier(literal));
        }

        return Ok(Token::Identifier(literal));
    }

    fn scan_sign(&mut self) -> Result<Token, error::FexprError> {
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
            return Err(error::FexprError::InvalidSignOperator(literal));
        }

        return Ok(Token::Sign(literal));
    }

    fn scan_join(&mut self) -> Result<Token, error::FexprError> {
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
            return Err(error::FexprError::InvalidJoinOperator(literal));
        }

        return Ok(Token::Join(literal));
    }

    fn scan_group(&mut self) -> Result<Token, error::FexprError> {
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
                        if let Token::Text(literal) = token {
                            buffer.extend(literal.chars());
                        }
                    }
                    Err(err) => return Err(err)
                    
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
            return Err(error::FexprError::UnterminatedGroup);
        }

        return Ok(Token::Group(literal));
    }

    fn scan_function_args(
        &mut self,
        func_name: String,
        func_depth: i16,
    ) -> Result<Token, error::FexprError> {
        let mut args: Vec<Token> = vec![];

        let mut expect_comma = false;
        let mut is_comma;
        let mut is_closed = false;

        let ch = self.read();
        if ch != '(' {
            return Err(error::FexprError::InvalidFunctionArguments);
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
                        return Err(err);
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
                        return Err(err);
                    }
                }
                continue;
            }

            is_comma = ch == ',';

            if expect_comma && !is_comma {
                return Err(error::FexprError::ExpectedComma(
                    func_name
                ));
            }

            if !expect_comma && is_comma {
                return Err(error::FexprError::UnexpectedComma(
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
                        return Err(err);
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
                        return Err(err);
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
                        return Err(err);
                    }
                }
            } else {
                return Err(error::FexprError::InvalidFunctionArguments);
            }
        }

        if !is_closed {
            return Err(error::FexprError::InvalidFunctionArguments);
        }

        return Ok(Token::Function {
            name: func_name,
            args,
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
    SignOp::from_str(literal).is_some()
}

fn is_join_operator(literal: &str) -> bool {
    JoinOp::from_str(literal).is_some()
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
        (false,Token::Whitespace("   ".into())),
    ])]
    #[case("test 123",vec![
        (false,Token::Identifier("test".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Number("123".into())),
    ])]
    // Identifiers
    #[case("test",vec![
        (false,Token::Identifier("test".into())),
    ])]
    #[case("@",vec![
        (true,Token::Identifier("@".into())),
    ])]
    #[case("test:",vec![
        (true,Token::Identifier("test:".into())),
    ])]
    #[case("test.",vec![
        (true,Token::Identifier("test.".into())),
    ])]
    #[case("@test.123:c",vec![
        (false,Token::Identifier("@test.123:c".into())),
    ])]
    #[case("_test_a.123",vec![
        (false,Token::Identifier("_test_a.123".into())),
    ])]
    #[case("#test.123:456",vec![
        (false,Token::Identifier("#test.123:456".into())),
    ])]
    #[case(".test.123",vec![
        (true,Token::None),
        (false,Token::Identifier("test.123".into())),
    ])]
    #[case(":test.123",vec![
        (true,Token::None),
        (false,Token::Identifier("test.123".into())),
    ])]
    #[case("test#@",vec![
        (false,Token::Identifier("test".into())),
        (true,Token::None),
        (true,Token::None),
    ])]
    #[case("test'",vec![
        (false,Token::Identifier("test".into())),
        (true,Token::Identifier("'".into())),
    ])]
    #[case("test\"d",vec![
        (false,Token::Identifier("test".into())),
        (true,Token::None),
    ])]
    // Numbers
    #[case("123",vec![
        (false,Token::Number("123".into())),
    ])]
    #[case("-123",vec![
        (false,Token::Number("-123".into())),
    ])]
    #[case("-123.456",vec![
        (false,Token::Number("-123.456".into())),
    ])]
    #[case("123.456",vec![
        (false,Token::Number("123.456".into())),
    ])]
    #[case("12.34.56",vec![
        (false,Token::Number("12.34".into()),),
        (true,Token::None),
        (false,Token::Number("56".into())),
    ])]
    #[case(".123",vec![
        (true,Token::None),
        (false,Token::Number("123".into()))
    ])]
    #[case("- 123",vec![
        (true,Token::Sign("-".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Number("123".into())),
    ])]
    #[case("12-3",vec![
        (false,Token::Number("12".into())),
        (false,Token::Number("-3".into())),
    ])]
    #[case("123.abc",vec![
        (true,Token::None),
        (false,Token::Identifier("abc".into()))
    ])]
    // Text
    #[case("\"\"",vec![
        (false,Token::Text("".into())),
    ])]
    #[case(r"''",vec![
        (false,Token::Text("".into())),
    ])]
    #[case(r"'test'",vec![
        (false,Token::Text("test".into())),
    ])]
    #[case(r"'te\'st'",vec![
        (false,Token::Text("te'st".into())),
    ])]
    #[case(r#"'te"st'"#,vec![
        (false,Token::Text("te\"st".into())),
    ])]
    #[case(r#"'te"st'"#,vec![
        (false,Token::Text("te\"st".into())),
    ])]
    #[case(r#""tes@#,;!@#%^'\"t""#,vec![
        (false,Token::Text(r#"tes@#,;!@#%^'"t"#.into())),
    ])]
    #[case(r#"'tes@#,;!@#%^\'"t'"#,vec![
        (false,Token::Text(r#"tes@#,;!@#%^'"t"#.into())),
    ])]
    #[case(r#""test"#,vec![
        (true,Token::Text("test".into())),
    ])]
    #[case(r#""test"#,vec![
        (true,Token::Text("test".into())),
    ])]
    #[case(r#"'АБЦ"#,vec![
        (true,Token::Text("АБЦ".into())),
    ])]
    // join types
    #[case(r#"&&||"#,vec![
        (true,Token::None),
    ])]
    #[case(r#"&& ||"#,vec![
        (false,Token::Join("&&".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Join("||".into())),
    ])]
    #[case(r#"'||test&&'&&123"#,vec![
        (false,Token::Text("||test&&".into())),
        (false,Token::Join("&&".into())),
        (false,Token::Number("123".into())),
    ])]
    // // expression signs
    #[case(r#"=!="#,vec![
        (true,Token::None),
    ])]
    #[case(r#"= != ~ !~ > >= < <= ?= ?!= ?~ ?!~ ?> ?>= ?< ?<="#,vec![
        (false,Token::Sign("=".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("!=".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("~".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("!~".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign(">".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign(">=".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("<".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("<=".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("?=".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("?!=".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("?~".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("?!~".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("?>".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("?>=".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("?<".into())),
        (false,Token::Whitespace(" ".into())),
        (false,Token::Sign("?<=".into())),
    ])]
    // // comments
    #[case(r#"/ test"#,vec![
        (true,Token::None),
        (false,Token::Identifier("test".into())),
    ])]
    #[case(r#"/ / test"#,vec![
        (true,Token::None),
        (true,Token::None),
        (false,Token::Identifier("test".into())),
    ])]
    #[case(r#"//"#,vec![
        (false,Token::Comment("".into())),
    ])]
    #[case(r#"//test"#,vec![
        (false,Token::Comment("test".into())),
    ])]
    #[case(r#"// test"#,vec![
        (false,Token::Comment(" test".into())),
    ])]
    #[case(r#"//   test1 //test2  "#,vec![
        (false,Token::Comment("   test1 //test2  ".into())),
    ])]
    #[case(r#"///test"#,vec![
        (false,Token::Comment("/test".into())),
    ])]
    // // function calls
    #[case(r#"test()"#,vec![
        (false,Token::Function{name:"test".into(),args:vec![]}),
    ])]
    #[case(r#"test(a, b"#,vec![
        (true,Token::None),
    ])]
    #[case(r#"@test:abc()"#,vec![
        (false,Token::Function{name:"@test:abc".into(),args:vec![]}),
    ])]
    #[case(r#"test(  a  )"#,vec![
        (
            false,
            Token::Function{
            name:"test".into(),
            args:vec![Token::Identifier("a".into())]
        }),
    ])]
    #[case(r#"test(a, b)"#,vec![
        (false,Token::Function{ 
            name:"test".into(),
            args:vec![
                Token::Identifier("a".into()),
                Token::Identifier("b".into())
            ] 
        }),
    ])]
    #[case(r#"test(a, b,  )"#,vec![
        (false,Token::Function {
            name:"test".into(),
            args:vec![
                Token::Identifier("a".into()),
                Token::Identifier("b".into())
            ]
        }),
    ])]
    #[case(r#"test(a,,)"#,vec![
        (true,Token::None),
        (true,Token::None),
    ])]
    #[case(r#"test(a,,,b)"#,vec![
        (true,Token::None),
        (true,Token::None),
    ])]
    #[case(r#"test(   @test.a.b:test  , 123, "ab)c", 'd,ce')"#,vec![
        (false,Token::Function{
            name:"test".into(),
            args:vec![
                Token::Identifier("@test.a.b:test".into()),
                Token::Number("123".into()),
                Token::Text("ab)c".into()),
                Token::Text("d,ce".into()),
            ]
        }),
    ])]
    #[case(r#"test(a //test)"#,vec![
        (true,Token::None),
    ])]
    #[case("test(a //test\n)",vec![
        (false,Token::Function {
            name:"test".into(),
            args:vec![Token::Identifier("a".into())]
        }),
    ])]
    #[case("test(a, //test\n, b)",vec![
        (true,Token::None),
    ])]
    #[case("test(a, //test\n b)",vec![
        (false,Token::Function{
            name:"test".into(),
            args:vec![
                Token::Identifier("a".into()),
                Token::Identifier("b".into()),
            ]
        }),
    ])]
    #[case(r#"test(a, test(test(b), c), d)"#,vec![
        (false,Token::Function {
            name:"test".into(),
            args:vec![
                Token::Identifier("a".into()),
                Token::Function {
                    name:"test".into(),
                    args:vec![
                        Token::Function {
                            name:"test".into(),
                            args:vec![
                                Token::Identifier("b".into())
                            ]
                        },
                        Token::Identifier("c".into())
                    ]
                },
                Token::Identifier("d".into())
            ]
        }),
    ])]
    // max funcs depth
    #[case(r#"a(b(c(1)))"#,vec![
        (false,Token::Function {
            name:"a".into(),
            args:vec![
                Token::Function {
                    name:"b".into(),
                    args:vec![
                        Token::Function {
                            name:"c".into(),
                            args:vec![
                                Token::Number("1".into())
                            ]
                        }
                    ]
                }
            ]
        }),
    ])]
    #[case(r#"a(b(c(d(1))))"#,vec![
        (true,Token::None),
    ])]
    // groups
    #[case(r#"a)"#,vec![
        (false,Token::Identifier("a".into())),
        (true,Token::None),
    ])]
    #[case(r#"(a b c"#,vec![
        (true,Token::Group("a b c".into())),
    ])]
    #[case(r#"(a b c)"#,vec![
        (false,Token::Group("a b c".into())),
    ])]
    #[case(r#"((a b c))"#,vec![
        (false,Token::Group("(a b c)".into())),
    ])]
    #[case(r#"((a )b c))"#,vec![
        (false,Token::Group("(a )b c".into())),
    ])]
    #[case(r#"("ab)("c)"#,vec![
        (false,Token::Group("\"ab)(\"c".into())),
    ])]
    #[case(r#"("ab)(c)"#,vec![
        (true,Token::Group("\"ab)(c".into())),
    ])]
    #[case(r#"( func(1, 2, 3, func(4)) a b c )"#,vec![
        (false,Token::Group(" func(1, 2, 3, func(4)) a b c ".into())),
    ])]
    #[rstest]
    pub fn test_scanner(#[case] text: &str, #[case] expects: Vec<(bool, Token)>) {
        let mut scanner = Scanner::new(text.into(), 3);
        for expect in expects {
            let token = scanner.scan();
            assert_eq!(token.is_err(), expect.0, "case {}", text);
            if !token.is_err() {
                let token = token.unwrap();
                assert_eq!(token, expect.1, "case {}", text);
            }
        }
    }
}
