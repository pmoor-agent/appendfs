use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::clock::{format_duration, parse_duration};
use crate::remote::config::ConfiguredRemote;

/// Context passed to [`PruneExpr::evaluate`] during local log eviction checks.
#[derive(Debug)]
pub struct PruneContext<'a> {
    /// Age since the log file was sealed.
    pub age: Duration,
    /// Set of remote store names that have confirmed identical size and MD5/ETag.
    pub confirmed_remotes: &'a HashSet<&'a str>,
    /// All configured remote stores for this volume.
    pub stores: &'a [ConfiguredRemote],
}

impl<'a> PruneContext<'a> {
    pub fn new(age: Duration, confirmed_remotes: &'a HashSet<&'a str>, stores: &'a [ConfiguredRemote]) -> Self {
        Self {
            age,
            confirmed_remotes,
            stores,
        }
    }
}

/// Abstract syntax tree representing a local cache pruning / retention expression rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PruneExpr {
    /// Specific named remote has confirmed the object.
    Remote(String),
    /// Log age since seal is at least the specified duration (e.g. `older_than(7d)`).
    OlderThan(Duration),
    /// At least $k$ confirmed remotes are readable (`mode.is_readable()`).
    Readable(usize),
    /// At least $k$ of the sub-expressions must be satisfied.
    AtLeast(usize, Vec<PruneExpr>),
    /// All sub-expressions must be satisfied (`&&` / `and` / `allof`).
    All(Vec<PruneExpr>),
    /// At least one sub-expression must be satisfied (`||` / `or` / `oneof`).
    Any(Vec<PruneExpr>),
}

impl Default for PruneExpr {
    fn default() -> Self {
        Self::default_rule()
    }
}

impl PruneExpr {
    /// Returns the default pruning rule: "older_than(30d) && readable(1)".
    pub fn default_rule() -> Self {
        Self::parse("older_than(30d) && readable(1)").expect("valid default rule")
    }

    /// Returns an immediate eviction rule requiring at least `k` readable remote confirmations.
    pub fn immediate_readable(k: usize) -> Self {
        Self::All(vec![Self::OlderThan(Duration::ZERO), Self::Readable(k)])
    }

    /// Parses a string representation into a [`PruneExpr`].
    pub fn parse(input: &str) -> Result<Self, String> {
        let tokens = tokenize(input)?;
        let mut parser = Parser::new(tokens);
        let expr = parser.parse_expr()?;
        parser.expect_end()?;
        Ok(expr)
    }

    /// Evaluates whether this pruning rule is satisfied for the candidate log file.
    pub fn evaluate(&self, ctx: &PruneContext<'_>) -> bool {
        match self {
            PruneExpr::Remote(name) => ctx.confirmed_remotes.contains(name.as_str()),
            PruneExpr::OlderThan(dur) => ctx.age >= *dur,
            PruneExpr::Readable(k) => {
                let readable_count = ctx
                    .stores
                    .iter()
                    .filter(|s| s.mode.is_readable() && ctx.confirmed_remotes.contains(s.name.as_str()))
                    .count();
                readable_count >= *k
            }
            PruneExpr::AtLeast(k, exprs) => {
                let matched = exprs.iter().filter(|e| e.evaluate(ctx)).count();
                matched >= *k
            }
            PruneExpr::All(exprs) => exprs.iter().all(|e| e.evaluate(ctx)),
            PruneExpr::Any(exprs) => exprs.iter().any(|e| e.evaluate(ctx)),
        }
    }

    /// Validates safety invariants for this pruning expression against the configured stores:
    /// 1. All referenced remotes must exist in `stores`.
    /// 2. Eviction must not be permitted with 0 remote confirmations.
    /// 3. Eviction must not be permitted when only write-only remotes have confirmed the object
    ///    (preventing total data unavailability once local files are deleted).
    pub fn validate_safety(&self, stores: &[ConfiguredRemote]) -> Result<(), String> {
        if stores.is_empty() {
            return Ok(());
        }

        // 1. Verify all named remotes exist
        let configured_names: HashSet<&str> = stores.iter().map(|s| s.name.as_str()).collect();
        let mut referenced_names = Vec::new();
        self.collect_remote_names(&mut referenced_names);
        for name in referenced_names {
            if !configured_names.contains(name.as_str()) {
                return Err(format!(
                    "prune_rule references unknown remote '{}'. Configured remotes: {:?}",
                    name,
                    configured_names.iter().collect::<Vec<_>>()
                ));
            }
        }

        // 2. Invariant Check: Rule must not allow eviction when 0 remotes have confirmed the object
        let empty_confirmed = HashSet::new();
        let empty_ctx = PruneContext::new(Duration::MAX, &empty_confirmed, stores);
        if self.evaluate(&empty_ctx) {
            return Err(
                "prune_rule can be satisfied without any remote confirmations; at least one remote confirmation is required to prevent data loss".to_string(),
            );
        }

        // 3. Invariant Check: Rule must not allow eviction when ONLY write-only remotes have confirmed the object
        let write_only_confirmed: HashSet<&str> = stores
            .iter()
            .filter(|s| !s.mode.is_readable())
            .map(|s| s.name.as_str())
            .collect();
        if !write_only_confirmed.is_empty() {
            let write_only_ctx = PruneContext::new(Duration::MAX, &write_only_confirmed, stores);
            if self.evaluate(&write_only_ctx) {
                return Err(
                    "prune_rule can be satisfied solely by write-only (archival) remotes without any readable remote confirmed; at least one readable remote must be confirmed before local eviction is permitted".to_string(),
                );
            }
        }

        Ok(())
    }

    fn collect_remote_names(&self, out: &mut Vec<String>) {
        match self {
            PruneExpr::Remote(name) => out.push(name.clone()),
            PruneExpr::OlderThan(_) | PruneExpr::Readable(_) => {}
            PruneExpr::AtLeast(_, exprs) | PruneExpr::All(exprs) | PruneExpr::Any(exprs) => {
                for e in exprs {
                    e.collect_remote_names(out);
                }
            }
        }
    }
}

impl fmt::Display for PruneExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PruneExpr::Remote(name) => write!(f, "{}", name),
            PruneExpr::OlderThan(dur) => write!(f, "older_than({})", format_duration(*dur)),
            PruneExpr::Readable(k) => write!(f, "readable({})", k),
            PruneExpr::AtLeast(k, exprs) => {
                write!(f, "at_least({}, ", k)?;
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", e)?;
                }
                write!(f, ")")
            }
            PruneExpr::All(exprs) => {
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        write!(f, " && ")?;
                    }
                    let needs_parens = matches!(e, PruneExpr::Any(_));
                    if needs_parens {
                        write!(f, "({})", e)?;
                    } else {
                        write!(f, "{}", e)?;
                    }
                }
                Ok(())
            }
            PruneExpr::Any(exprs) => {
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        write!(f, " || ")?;
                    }
                    write!(f, "{}", e)?;
                }
                Ok(())
            }
        }
    }
}

impl<'de> Deserialize<'de> for PruneExpr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PruneExpr::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for PruneExpr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// ============================================================================
// Tokenizer & Parser
// ============================================================================

#[derive(Debug, PartialEq, Clone)]
enum Token {
    Word(String),
    And,
    Or,
    LParen,
    RParen,
    Comma,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }

        if c == '(' {
            chars.next();
            tokens.push(Token::LParen);
            continue;
        }
        if c == ')' {
            chars.next();
            tokens.push(Token::RParen);
            continue;
        }
        if c == ',' {
            chars.next();
            tokens.push(Token::Comma);
            continue;
        }

        if c == '&' {
            chars.next();
            if chars.next() == Some('&') {
                tokens.push(Token::And);
                continue;
            } else {
                return Err("expected '&&' after '&'".to_string());
            }
        }

        if c == '|' {
            chars.next();
            if chars.next() == Some('|') {
                tokens.push(Token::Or);
                continue;
            } else {
                return Err("expected '||' after '|'".to_string());
            }
        }

        // Quoted string literal
        if c == '"' || c == '\'' {
            let quote = c;
            chars.next();
            let mut word = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == quote {
                    closed = true;
                    break;
                }
                word.push(ch);
            }
            if !closed {
                return Err(format!("unclosed quote starting with {}", quote));
            }
            tokens.push(Token::Word(word));
            continue;
        }

        // Identifier or word token
        if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
            let mut word = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
                    word.push(ch);
                    chars.next();
                } else {
                    break;
                }
            }

            match word.to_lowercase().as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                _ => tokens.push(Token::Word(word)),
            }
            continue;
        }

        return Err(format!("unexpected character '{}' in prune rule", c));
    }

    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn expect_end(&self) -> Result<(), String> {
        if self.pos < self.tokens.len() {
            Err(format!("unexpected trailing token: {:?}", self.tokens[self.pos]))
        } else {
            Ok(())
        }
    }

    fn parse_expr(&mut self) -> Result<PruneExpr, String> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<PruneExpr, String> {
        let mut left = self.parse_and()?;

        while let Some(Token::Or) = self.peek() {
            self.next(); // consume Or
            let right = self.parse_and()?;
            left = match left {
                PruneExpr::Any(mut list) => {
                    list.push(right);
                    PruneExpr::Any(list)
                }
                other => PruneExpr::Any(vec![other, right]),
            };
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<PruneExpr, String> {
        let mut left = self.parse_primary()?;

        while let Some(Token::And) = self.peek() {
            self.next(); // consume And
            let right = self.parse_primary()?;
            left = match left {
                PruneExpr::All(mut list) => {
                    list.push(right);
                    PruneExpr::All(list)
                }
                other => PruneExpr::All(vec![other, right]),
            };
        }

        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<PruneExpr, String> {
        match self.peek() {
            Some(Token::LParen) => {
                self.next(); // consume LParen
                let expr = self.parse_expr()?;
                match self.next() {
                    Some(Token::RParen) => Ok(expr),
                    other => Err(format!("expected ')' but found {:?}", other)),
                }
            }
            Some(Token::Word(_)) => {
                let Some(Token::Word(word)) = self.next() else {
                    unreachable!()
                };

                // Check for function call
                if let Some(Token::LParen) = self.peek() {
                    self.next(); // consume LParen
                    self.parse_function_call(&word)
                } else {
                    // Bare identifier
                    if word.eq_ignore_ascii_case("readable") {
                        Ok(PruneExpr::Readable(1))
                    } else {
                        Ok(PruneExpr::Remote(word))
                    }
                }
            }
            other => Err(format!("expected expression, found {:?}", other)),
        }
    }

    fn parse_function_call(&mut self, func_name: &str) -> Result<PruneExpr, String> {
        match func_name.to_lowercase().as_str() {
            "older_than" => {
                let arg = match self.next() {
                    Some(Token::Word(w)) => w,
                    other => return Err(format!("expected duration in older_than(...), found {:?}", other)),
                };
                match self.next() {
                    Some(Token::RParen) => {}
                    other => return Err(format!("expected ')' closing older_than, found {:?}", other)),
                }
                let dur = parse_duration(&arg).map_err(|e| format!("invalid duration in older_than: {}", e))?;
                Ok(PruneExpr::OlderThan(dur))
            }
            "readable" => {
                let k = match self.next() {
                    Some(Token::Word(w)) => w
                        .parse::<usize>()
                        .map_err(|_| format!("invalid integer count in readable({}): '{}'", w, w))?,
                    other => return Err(format!("expected integer count in readable(...), found {:?}", other)),
                };
                match self.next() {
                    Some(Token::RParen) => {}
                    other => return Err(format!("expected ')' closing readable, found {:?}", other)),
                }
                Ok(PruneExpr::Readable(k))
            }
            "oneof" | "any" => {
                let args = self.parse_comma_expressions()?;
                match self.next() {
                    Some(Token::RParen) => {}
                    other => return Err(format!("expected ')' closing {}, found {:?}", func_name, other)),
                }
                if args.is_empty() {
                    return Err(format!("{} requires at least one argument", func_name));
                }
                Ok(PruneExpr::Any(args))
            }
            "allof" | "all" => {
                let args = self.parse_comma_expressions()?;
                match self.next() {
                    Some(Token::RParen) => {}
                    other => return Err(format!("expected ')' closing {}, found {:?}", func_name, other)),
                }
                if args.is_empty() {
                    return Err(format!("{} requires at least one argument", func_name));
                }
                Ok(PruneExpr::All(args))
            }
            "at_least" => {
                let k_str = match self.next() {
                    Some(Token::Word(w)) => w,
                    other => return Err(format!("expected count k in at_least(k, ...), found {:?}", other)),
                };
                let k = k_str
                    .parse::<usize>()
                    .map_err(|_| format!("invalid count in at_least: '{}'", k_str))?;

                match self.next() {
                    Some(Token::Comma) => {}
                    other => return Err(format!("expected ',' after count in at_least, found {:?}", other)),
                }

                let args = self.parse_comma_expressions()?;
                match self.next() {
                    Some(Token::RParen) => {}
                    other => return Err(format!("expected ')' closing at_least, found {:?}", other)),
                }
                if args.is_empty() {
                    return Err("at_least requires at least one target expression".to_string());
                }
                Ok(PruneExpr::AtLeast(k, args))
            }
            other => Err(format!("unknown function '{}'", other)),
        }
    }

    fn parse_comma_expressions(&mut self) -> Result<Vec<PruneExpr>, String> {
        let mut list = Vec::new();
        if let Some(Token::RParen) = self.peek() {
            return Ok(list);
        }

        loop {
            let expr = self.parse_expr()?;
            list.push(expr);

            if let Some(Token::Comma) = self.peek() {
                self.next(); // consume Comma
            } else {
                break;
            }
        }

        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::config::RemoteMode;
    use std::sync::Arc;

    #[test]
    fn test_parse_simple_and_composite() {
        let expr = PruneExpr::parse("older_than(7d) && oneof(nfsremote) && oneof(glacier, gcs)").unwrap();
        assert_eq!(
            expr,
            PruneExpr::All(vec![
                PruneExpr::OlderThan(Duration::from_secs(7 * 86400)),
                PruneExpr::Any(vec![PruneExpr::Remote("nfsremote".to_string())]),
                PruneExpr::Any(vec![
                    PruneExpr::Remote("glacier".to_string()),
                    PruneExpr::Remote("gcs".to_string()),
                ]),
            ])
        );
    }

    #[test]
    fn test_parse_precedence_and_grouping() {
        let expr = PruneExpr::parse("(older_than(2d) && nfs && glacier) || (older_than(30d) && glacier)").unwrap();
        assert_eq!(
            expr,
            PruneExpr::Any(vec![
                PruneExpr::All(vec![
                    PruneExpr::OlderThan(Duration::from_secs(2 * 86400)),
                    PruneExpr::Remote("nfs".to_string()),
                    PruneExpr::Remote("glacier".to_string()),
                ]),
                PruneExpr::All(vec![
                    PruneExpr::OlderThan(Duration::from_secs(30 * 86400)),
                    PruneExpr::Remote("glacier".to_string()),
                ]),
            ])
        );
    }

    #[test]
    fn test_parse_at_least_and_readable() {
        let expr = PruneExpr::parse("at_least(2, s3, r2, gcs) && readable(1)").unwrap();
        assert_eq!(
            expr,
            PruneExpr::All(vec![
                PruneExpr::AtLeast(
                    2,
                    vec![
                        PruneExpr::Remote("s3".to_string()),
                        PruneExpr::Remote("r2".to_string()),
                        PruneExpr::Remote("gcs".to_string()),
                    ]
                ),
                PruneExpr::Readable(1),
            ])
        );

        let bare_readable = PruneExpr::parse("older_than(30d) && readable").unwrap();
        assert_eq!(
            bare_readable,
            PruneExpr::All(vec![
                PruneExpr::OlderThan(Duration::from_secs(30 * 86400)),
                PruneExpr::Readable(1),
            ])
        );
    }

    #[test]
    fn test_display_roundtrip() {
        let inputs = [
            "older_than(7d) && readable(1)",
            "nfsremote && (glacier || gcs)",
            "at_least(2, s3, r2) && glacier",
            "(older_than(2d) && nfs && glacier) || (older_than(30d) && glacier)",
        ];

        for input in inputs {
            let parsed = PruneExpr::parse(input).unwrap();
            let display_str = parsed.to_string();
            let roundtripped = PruneExpr::parse(&display_str).unwrap();
            assert_eq!(parsed, roundtripped, "Mismatch on roundtrip for input: {}", input);
        }
    }

    #[test]
    fn test_evaluate_tiered_lifecycle() {
        let mock_store: Arc<dyn crate::remote::RemoteStore> = Arc::new(crate::remote::mock::MockRemoteStore::new());
        let stores = vec![
            ConfiguredRemote {
                name: "nfs".to_string(),
                store: mock_store.clone(),
                mode: RemoteMode::ReadWrite,
                replicate_ancestors: false,
                upload_partial_logs: true,
            },
            ConfiguredRemote {
                name: "glacier".to_string(),
                store: mock_store.clone(),
                mode: RemoteMode::WriteOnly,
                replicate_ancestors: false,
                upload_partial_logs: false,
            },
            ConfiguredRemote {
                name: "gcs".to_string(),
                store: mock_store.clone(),
                mode: RemoteMode::ReadOnly,
                replicate_ancestors: false,
                upload_partial_logs: false,
            },
        ];

        let rule = PruneExpr::parse("older_than(7d) && oneof(nfs) && oneof(glacier, gcs)").unwrap();

        // 1. Age < 7d: false even if all confirmed
        let mut confirmed = HashSet::from(["nfs", "glacier", "gcs"]);
        let ctx_young = PruneContext::new(Duration::from_secs(6 * 86400), &confirmed, &stores);
        assert!(!rule.evaluate(&ctx_young));

        // 2. Age >= 7d but missing glacier/gcs: false
        confirmed = HashSet::from(["nfs"]);
        let ctx_no_archive = PruneContext::new(Duration::from_secs(8 * 86400), &confirmed, &stores);
        assert!(!rule.evaluate(&ctx_no_archive));

        // 3. Age >= 7d but missing nfs (only glacier confirmed): false
        confirmed = HashSet::from(["glacier"]);
        let ctx_only_glacier = PruneContext::new(Duration::from_secs(8 * 86400), &confirmed, &stores);
        assert!(!rule.evaluate(&ctx_only_glacier));

        // 4. Age >= 7d and nfs + glacier confirmed: true!
        confirmed = HashSet::from(["nfs", "glacier"]);
        let ctx_satisfied = PruneContext::new(Duration::from_secs(8 * 86400), &confirmed, &stores);
        assert!(rule.evaluate(&ctx_satisfied));
    }

    #[test]
    fn test_safety_validation_catches_unsafe_rules() {
        let mock_store: Arc<dyn crate::remote::RemoteStore> = Arc::new(crate::remote::mock::MockRemoteStore::new());
        let stores = vec![
            ConfiguredRemote {
                name: "nfs".to_string(),
                store: mock_store.clone(),
                mode: RemoteMode::ReadWrite,
                replicate_ancestors: false,
                upload_partial_logs: true,
            },
            ConfiguredRemote {
                name: "glacier".to_string(),
                store: mock_store.clone(),
                mode: RemoteMode::WriteOnly,
                replicate_ancestors: false,
                upload_partial_logs: false,
            },
        ];

        // Safe rule: requires nfs (readable) AND glacier (write-only)
        let safe_rule = PruneExpr::parse("older_than(7d) && nfs && glacier").unwrap();
        assert!(safe_rule.validate_safety(&stores).is_ok());

        // Unsafe rule 1: allows eviction when ONLY glacier (write-only) confirmed!
        let unsafe_rule1 = PruneExpr::parse("older_than(7d) && glacier").unwrap();
        assert!(
            unsafe_rule1.validate_safety(&stores).is_err(),
            "Rule allowing eviction on write-only remote alone must be rejected"
        );

        // Unsafe rule 2: OR branch allows solely glacier
        let unsafe_rule2 = PruneExpr::parse("older_than(7d) && (nfs || glacier)").unwrap();
        assert!(
            unsafe_rule2.validate_safety(&stores).is_err(),
            "Rule with branch allowing solely write-only remote must be rejected"
        );

        // Unsafe rule 3: zero remote confirmations (bare older_than)
        let unsafe_rule3 = PruneExpr::parse("older_than(7d)").unwrap();
        assert!(
            unsafe_rule3.validate_safety(&stores).is_err(),
            "Rule with 0 remote confirmations must be rejected"
        );

        // Unsafe rule 4: unknown remote name
        let unsafe_rule4 = PruneExpr::parse("older_than(7d) && non_existent_remote").unwrap();
        assert!(
            unsafe_rule4.validate_safety(&stores).is_err(),
            "Rule referencing non-existent remote must be rejected"
        );
    }
}
