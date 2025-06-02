use thiserror::Error;

#[derive(Error, Debug)]
pub enum FexprError {
    #[error("Unexpected character {0}")]
    TokenUnexpected(String),
    #[error("Invalid number {0}")]
    InvalidNumber(String),
    #[error("Invalid quoted text {0}")]
    InvalidQuoteText(String),
    #[error("Invalid comment {0}")]
    InvalidComment(String),
    #[error("Invalid identifier {0}")]
    InvalidIdentifier(String),
    #[error("Invalid sign operator {0}")]
    InvalidSignOperator(String),
    #[error("Invalid join operator {0}")]
    InvalidJoinOperator(String),
    #[error("Unterminated group")]
    UnterminatedGroup,
    #[error("Max function depth exceeded {0}")]
    MaxFunctionDepthExceeded(i16),
    #[error("Invalid function arguments")]
    InvalidFunctionArguments,
    #[error("Invalid function name {0}")]
    InvalidFunctionName(String),
    #[error("Expected comma in function arguments {0}")]
    ExpectedComma(String),
    #[error("Unexpected comma in function arguments {0}")]
    UnexpectedComma(String),
    #[error("Expected left operand (identifier, text or number), got {0} ({1})")]
    ExpectedLeftOperand(String, String),
    #[error("Expected a sign operator, got {0} ({1})")]
    ExpectedSignOperator(String, String),
    #[error("Expected right operand (identifier, text or number), got {0} ({1})")]
    ExpectedRightOperand(String, String),
    #[error("Expected && or ||, got {0} ({1})")]
    ExpectedJoinOperator(String, String),
    #[error("Empty filter expression")]
    EmptyFilterExpression,
    #[error("Invalid or incomplete filter expression")]
    InvalidOrIncompleteFilterExpression,
}
