fexpr
================================================================================

**fexpr** is a filter query language parser that generates easy to work with AST structure so that you can create safely SQL, Elasticsearch, etc. queries from user input.

Or in other words, transform the string `"id > 1"` into the struct `[{&& {{identifier id} > {number 1}}}]`.

Supports parenthesis and various conditional expression operators (see [Grammar](https://github.com/karlrobeck/fexpr#grammar)).


## Example usage

```
cargo install github.com/karlrobeck/fexpr
```

```rust
use fexpr;

fn main() {
    // [{&& {{identifier id} = {number 123}}} {&& {{identifier status} = {text active}}}]
    let result = fexpr::parse("id=123 && status='active'").unwrap();
}
```

> Note that each parsed expression statement contains a join/union operator (`&&` or `||`) so that the result can be consumed on small chunks without having to rely on the group/nesting context.

> See the repository documentation for more details and examples.


## Grammar

**fexpr** grammar resembles the SQL `WHERE` expression syntax. It recognizes several token types (identifiers, numbers, quoted text, expression operators, whitespaces, etc.).

> You could find all supported tokens in [`scanner.rs`](https://github.com/karlrobeck/fexpr/blob/master/src/scanner.rs).

#### Operators

- **`=`**  Equal operator (eg. `a=b`)
- **`!=`** NOT Equal operator (eg. `a!=b`)
- **`>`**  Greater than operator (eg. `a>b`)
- **`>=`** Greater than or equal operator (eg. `a>=b`)
- **`<`**  Less than or equal operator (eg. `a<b`)
- **`<=`** Less than or equal operator (eg. `a<=b`)
- **`~`**  Like/Contains operator (eg. `a~b`)
- **`!~`** NOT Like/Contains operator (eg. `a!~b`)
- **`?=`**  Array/Any equal operator (eg. `a?=b`)
- **`?!=`** Array/Any NOT Equal operator (eg. `a?!=b`)
- **`?>`**  Array/Any Greater than operator (eg. `a?>b`)
- **`?>=`** Array/Any Greater than or equal operator (eg. `a?>=b`)
- **`?<`**  Array/Any Less than or equal operator (eg. `a?<b`)
- **`?<=`** Array/Any Less than or equal operator (eg. `a?<=b`)
- **`?~`**  Array/Any Like/Contains operator (eg. `a?~b`)
- **`?!~`** Array/Any NOT Like/Contains operator (eg. `a?!~b`)
- **`&&`** AND join operator (eg. `a=b && c=d`)
- **`||`** OR join operator (eg. `a=b || c=d`)
- **`()`** Parenthesis (eg. `(a=1 && b=2) || (a=3 && b=4)`)

#### Numbers
Number tokens are any integer or decimal numbers.

_Example_: `123`, `10.50`, `-14`.

#### Quoted text

Text tokens are any literals that are wrapped by `'` or `"` quotes.

_Example_: `'Lorem ipsum dolor 123!'`, `"escaped \"word\""`, `"mixed 'quotes' are fine"`.

#### Identifiers

Identifier tokens are literals that start with a letter, `_`, `@` or `#` and could contain further any number of letters, digits, `.` (usually used as a separator) or `:` (usually used as modifier) characters.

_Example_: `id`, `a.b.c`, `field123`, `@request.method`, `author.name:length`.

#### Functions
Function tokens are similar to the identifiers but in addition accept a list of arguments enclosed in parenthesis `()`.
The function arguments must be separated by comma (_a single trailing comma is also allowed_) and each argument can be an identifier, quoted text, number or another nested function (_you can configure the maximum number of nested functions when using the scanner_).


_Example_: `test()`, `test(a.b, 123, "abc")`, `@a.b.c:test(true)`, `a(b(c(1, 2)))`.

#### Comments

Comment tokens are any single line text literals starting with `//`.
Similar to whitespaces, comments are ignored by `fexpr.Parse()`.

_Example_: `// test`.


## Using only the scanner

The tokenizer (aka. `fexpr::scanner::Scanner`) could be used without the parser's state machine so that you can write your own custom tokens processing:

```rust
use fexpr::scanner::{Scanner, Token};

fn main() {
    let mut scanner = Scanner::new("id > 123".as_bytes().to_vec(), 3);

    // scan single token at a time until EOF or error is reached
    loop {
        let token = scanner.scan().unwrap();
        
        if let Token::EOF(_) = token {
            break;
        }
        
        println!("{}", token);
    }
}

// Output:
// {identifier id}
// {whitespace  }
// {sign >}
// {whitespace  }
// {number 123}
```