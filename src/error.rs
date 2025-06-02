use thiserror::Error;

#[derive(Error, Debug)]
pub enum FexprError {
    #[error("unexpected character {0}")]
    TokenUnexpected(String),
    #[error("invalid number {0}")]
    InvalidNumber(String),
    #[error("invalid quoted text {0}")]
    InvalidQuoteText(String),
    #[error("invalid comment {0}")]
    InvalidComment(String),
    #[error("invalid identifier {0}")]
    InvalidIdentifier(String),
    #[error("invalid sign operator {0}")]
    InvalidSignOperator(String),
    #[error("invalid join operator {0}")]
    InvalidJoinOperator(String),
    #[error("unterminated group")]
    UnterminatedGroup,
    #[error("max function depth exceeded {0}")]
    MaxFunctionDepthExceeded(i16),
    #[error("invalid function arguments")]
    InvalidFunctionArguments,
    #[error("invalid function name {0}")]
    InvalidFunctionName(String),
    #[error("expected comma in function arguments {0}")]
    ExpectedComma(String),
    #[error("unexpected comma in function arguments {0}")]
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
