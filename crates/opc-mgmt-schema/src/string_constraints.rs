//! Bounded whole-value matching for the supported XSD regular-expression grammar.
//!
//! This parses XSD syntax before invoking the regex engine. Rust-specific flags,
//! assertions, lazy quantifiers and set operators cannot alter YANG semantics.
//! XML name escapes and Unicode block names are explicitly unsupported; Unicode
//! general categories use the regex dependency's Unicode tables.

use regex::{Regex, RegexBuilder};
use std::fmt;

/// Maximum UTF-8 bytes in one source pattern.
pub const MAX_PATTERN_BYTES: usize = 4096;
/// Maximum parenthesis or character-class nesting in a source pattern.
pub const MAX_PATTERN_DEPTH: usize = 64;
/// Maximum compiled automaton size and lazy-DFA cache size, each in bytes.
pub const MAX_PATTERN_COMPILED_BYTES: usize = 1_048_576;

/// A schema-only diagnostic that never includes a pattern or candidate value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternError {
    /// The pattern exceeds a source, nesting, repetition or automaton bound.
    Limit,
    /// The source is not a supported well-formed XSD regular expression.
    Syntax,
    /// XML name escapes and Unicode block escapes are outside this profile.
    UnsupportedEscape,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit => "XSD pattern exceeds the supported resource bound",
            Self::Syntax => "invalid XSD regular expression",
            Self::UnsupportedEscape => "unsupported XSD XML-name or Unicode-block escape",
        })
    }
}

impl std::error::Error for PatternError {}

/// A compiled whole-value YANG pattern. Generated code stores this in a
/// `OnceLock`, so matching never reparses or recompiles an accepted pattern.
#[derive(Debug)]
pub struct CompiledYangPattern(Regex);

impl CompiledYangPattern {
    /// Compile a bounded XSD expression, rejecting unsupported syntax before
    /// passing the translated expression to the engine.
    pub fn compile(source: &str) -> Result<Self, PatternError> {
        if source.len() > MAX_PATTERN_BYTES {
            return Err(PatternError::Limit);
        }
        let mut parser = Parser {
            chars: source.chars().collect(),
            position: 0,
        };
        let expression = parser.expression(0)?;
        if parser.peek().is_some() {
            return Err(PatternError::Syntax);
        }
        bounded_regex_builder(&expression)
            .build()
            .map(Self)
            .map_err(|_| PatternError::Limit)
    }

    /// Whether the complete string matches the expression.
    pub fn is_match(&self, value: &str) -> bool {
        self.0.is_match(value)
    }
}

fn bounded_regex_builder(expression: &str) -> RegexBuilder {
    let mut builder = RegexBuilder::new(&format!(r"\A(?:{expression})\z"));
    builder
        .size_limit(MAX_PATTERN_COMPILED_BYTES)
        .dfa_size_limit(MAX_PATTERN_COMPILED_BYTES)
        .nest_limit((MAX_PATTERN_DEPTH * 4) as u32);
    builder
}

struct Parser {
    chars: Vec<char>,
    position: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }
    fn next(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.position += 1;
        Some(ch)
    }
    fn consume(&mut self, expected: char) -> Result<(), PatternError> {
        if self.next() == Some(expected) {
            Ok(())
        } else {
            Err(PatternError::Syntax)
        }
    }
    fn depth(depth: usize) -> Result<(), PatternError> {
        if depth > MAX_PATTERN_DEPTH {
            Err(PatternError::Limit)
        } else {
            Ok(())
        }
    }

    fn expression(&mut self, depth: usize) -> Result<String, PatternError> {
        Self::depth(depth)?;
        let mut out = String::new();
        while let Some(ch) = self.peek() {
            match ch {
                ')' => break,
                '|' => {
                    self.next();
                    out.push('|');
                    continue;
                }
                _ => {}
            }
            let atom = match self.next().ok_or(PatternError::Syntax)? {
                '(' => {
                    let inner = self.expression(depth + 1)?;
                    self.consume(')')?;
                    format!("(?:{inner})")
                }
                '[' => self.class(depth + 1)?,
                '\\' => self.escape()?.0,
                '.' => r"[^\n\r]".into(),
                '?' | '*' | '+' | '{' | '}' | ']' => return Err(PatternError::Syntax),
                c => literal(c),
            };
            out.push_str(&atom);
            match self.peek() {
                Some('?' | '*' | '+') => out.push(self.next().ok_or(PatternError::Syntax)?),
                Some('{') => {
                    self.next();
                    let min = self.number()?;
                    let max = if self.peek() == Some(',') {
                        self.next();
                        if self.peek() == Some('}') {
                            None
                        } else {
                            Some(self.number()?)
                        }
                    } else {
                        Some(min)
                    };
                    self.consume('}')?;
                    if max.is_some_and(|max| max < min) {
                        return Err(PatternError::Syntax);
                    }
                    match max {
                        Some(max) => out.push_str(&format!("{{{min},{max}}}")),
                        None => out.push_str(&format!("{{{min},}}")),
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    fn number(&mut self) -> Result<u32, PatternError> {
        let start = self.position;
        let mut n = 0u32;
        while let Some(c @ '0'..='9') = self.peek() {
            self.next();
            n = n
                .checked_mul(10)
                .and_then(|n| n.checked_add(c as u32 - '0' as u32))
                .ok_or(PatternError::Limit)?;
            if n > 1_000_000 {
                return Err(PatternError::Limit);
            }
        }
        if self.position == start {
            Err(PatternError::Syntax)
        } else {
            Ok(n)
        }
    }

    // The opening '[' has already been consumed. Wrapping the base group
    // separately preserves the order of negation and XSD class subtraction.
    fn class(&mut self, depth: usize) -> Result<String, PatternError> {
        Self::depth(depth)?;
        let mut group = String::new();
        if self.peek() == Some('^') {
            self.next();
            group.push('^');
        }
        let mut count = 0;
        loop {
            if self.peek() == Some(']') {
                self.next();
                return if count > 0 {
                    Ok(format!("[{group}]"))
                } else {
                    Err(PatternError::Syntax)
                };
            }
            if count > 0
                && self.peek() == Some('-')
                && self.chars.get(self.position + 1) == Some(&'[')
            {
                self.position += 2;
                let sub = self.class(depth + 1)?;
                self.consume(']')?;
                return Ok(format!("[[{group}]--{sub}]"));
            }
            let (item, scalar) = self.class_item(count == 0)?;
            group.push_str(&item);
            count += 1;
            if self.peek() == Some('-')
                && !matches!(self.chars.get(self.position + 1), Some('[' | ']'))
            {
                self.next();
                let (end, end_scalar) = self.class_item(false)?;
                match (scalar, end_scalar) {
                    (Some(a), Some(b)) if a <= b => {
                        group.push('-');
                        group.push_str(&end);
                    }
                    _ => return Err(PatternError::Syntax),
                }
            }
        }
    }

    fn class_item(&mut self, first: bool) -> Result<(String, Option<char>), PatternError> {
        match self.next().ok_or(PatternError::Syntax)? {
            '\\' => self.escape(),
            '[' | ']' => Err(PatternError::Syntax),
            '-' if !first && self.peek() != Some(']') => Err(PatternError::Syntax),
            c => Ok((literal(c), Some(c))),
        }
    }

    fn escape(&mut self) -> Result<(String, Option<char>), PatternError> {
        let ch = self.next().ok_or(PatternError::Syntax)?;
        let text = match ch {
            'n' => return Ok((literal('\n'), Some('\n'))),
            'r' => return Ok((literal('\r'), Some('\r'))),
            't' => return Ok((literal('\t'), Some('\t'))),
            '\\' | '|' | '.' | '?' | '*' | '+' | '(' | ')' | '{' | '}' | '-' | '[' | ']' | '^' => {
                return Ok((literal(ch), Some(ch)))
            }
            's' => r"[ \t\n\r]".into(),
            'S' => r"[^ \t\n\r]".into(),
            'd' => r"\p{Nd}".into(),
            'D' => r"\P{Nd}".into(),
            'w' => r"[^\p{P}\p{Z}\p{C}]".into(),
            'W' => r"[\p{P}\p{Z}\p{C}]".into(),
            'i' | 'I' | 'c' | 'C' => return Err(PatternError::UnsupportedEscape),
            'p' | 'P' => {
                self.consume('{')?;
                let mut category = String::new();
                loop {
                    match self.next().ok_or(PatternError::Syntax)? {
                        '}' => break,
                        c => category.push(c),
                    }
                }
                if category.starts_with("Is") {
                    return Err(PatternError::UnsupportedEscape);
                }
                if !matches!(
                    category.as_str(),
                    "L" | "Lu"
                        | "Ll"
                        | "Lt"
                        | "Lm"
                        | "Lo"
                        | "M"
                        | "Mn"
                        | "Mc"
                        | "Me"
                        | "N"
                        | "Nd"
                        | "Nl"
                        | "No"
                        | "P"
                        | "Pc"
                        | "Pd"
                        | "Ps"
                        | "Pe"
                        | "Pi"
                        | "Pf"
                        | "Po"
                        | "Z"
                        | "Zs"
                        | "Zl"
                        | "Zp"
                        | "S"
                        | "Sm"
                        | "Sc"
                        | "Sk"
                        | "So"
                        | "C"
                        | "Cc"
                        | "Cf"
                        | "Co"
                        | "Cs"
                        | "Cn"
                ) {
                    return Err(PatternError::Syntax);
                }
                format!("\\{ch}{{{category}}}")
            }
            _ => return Err(PatternError::Syntax),
        };
        Ok((text, None))
    }
}

fn literal(ch: char) -> String {
    format!(r"\x{{{:x}}}", ch as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xsd_operators_and_literal_anchors_are_exact() {
        for (pattern, yes, no) in [
            ("[0-9]{3}", "123", "x123"),
            ("^[$]$", "^$$", "$"),
            ("(ab|cd){1,2}x?", "cdabx", "abcdab"),
            ("[a-z-[aeiou]]+", "bcdf", "be"),
            ("[^a-[b]]", "c", "b"),
            (r"\s", "\t", "\u{a0}"),
            (r"\w+", "é+", "_"),
            (r"\p{L}+", "é界", "1"),
            (".", "a", "\r"),
            ("[a&&b]+", "&", "c"),
        ] {
            let compiled = CompiledYangPattern::compile(pattern).unwrap();
            assert!(compiled.is_match(yes), "{pattern}");
            assert!(!compiled.is_match(no), "{pattern}");
        }
    }

    #[test]
    fn other_dialects_malformed_expressions_and_limits_fail_closed() {
        for pattern in [
            r"\bword\b",
            "(?i)a",
            "a+?",
            "a{,2}",
            "[z-a]",
            "[]",
            "[a-[b]c]",
            r"\x41",
            "[",
            "(",
            "a**",
            r"\p{Greek}",
        ] {
            assert_eq!(
                CompiledYangPattern::compile(pattern).unwrap_err(),
                PatternError::Syntax,
                "{pattern}"
            );
        }
        for pattern in [r"\i\c*", r"\p{IsBasicLatin}"] {
            assert_eq!(
                CompiledYangPattern::compile(pattern).unwrap_err(),
                PatternError::UnsupportedEscape
            );
        }
        for pattern in [
            "a".repeat(MAX_PATTERN_BYTES + 1),
            "(".repeat(MAX_PATTERN_DEPTH + 1),
            "a{1000001}".into(),
            r"\p{L}{1000000}".into(),
        ] {
            assert_eq!(
                CompiledYangPattern::compile(&pattern).unwrap_err(),
                PatternError::Limit
            );
        }
    }

    #[test]
    fn parser_rejects_trailing_input_reversed_quantifiers_and_interior_dashes() {
        for (valid, invalid) in [("a", "a)"), ("a{1,2}", "a{2,1}"), ("[a-c]", "[a-b-c]")] {
            CompiledYangPattern::compile(valid).unwrap();
            assert_eq!(
                CompiledYangPattern::compile(invalid).unwrap_err(),
                PatternError::Syntax
            );
        }
    }

    #[test]
    fn repetition_bound_is_checked_before_regex_compilation() {
        for (source, expected) in [
            ("1000000", Ok(1_000_000)),
            ("1000001", Err(PatternError::Limit)),
        ] {
            let mut parser = Parser {
                chars: source.chars().collect(),
                position: 0,
            };
            assert_eq!(parser.number(), expected);
        }
    }

    #[test]
    fn source_and_nesting_limits_have_accepted_boundary_cases() {
        CompiledYangPattern::compile(&"a".repeat(MAX_PATTERN_BYTES)).unwrap();
        assert_eq!(
            CompiledYangPattern::compile(&"a".repeat(MAX_PATTERN_BYTES + 1)).unwrap_err(),
            PatternError::Limit
        );
        let nested = |depth| format!("{}a{}", "(".repeat(depth), ")".repeat(depth));
        CompiledYangPattern::compile(&nested(MAX_PATTERN_DEPTH)).unwrap();
        assert_eq!(
            CompiledYangPattern::compile(&nested(MAX_PATTERN_DEPTH + 1)).unwrap_err(),
            PatternError::Limit
        );
    }

    #[test]
    fn compiled_size_limit_rejects_before_the_engine_default_limit() {
        let source = "a{50000}";
        RegexBuilder::new(source)
            .size_limit(MAX_PATTERN_COMPILED_BYTES * 2)
            .build()
            .unwrap();
        assert_eq!(
            CompiledYangPattern::compile(source).unwrap_err(),
            PatternError::Limit
        );
    }

    #[test]
    fn matching_cache_uses_the_configured_bound_instead_of_the_engine_default() {
        // Matching has identical semantics at either cache size. Inspect the
        // actual builder configuration because allocator/RSS timing would not
        // reliably distinguish this resource contract. The engine is locked.
        let configured = format!("{:?}", bounded_regex_builder("a"));
        let engine_default = format!("{:?}", RegexBuilder::new("a"));
        let expected = format!("hybrid_cache_capacity: Some({MAX_PATTERN_COMPILED_BYTES})");
        assert!(configured.contains(&expected), "{configured}");
        assert!(!engine_default.contains(&expected), "{engine_default}");
    }
}
