//! The license-expression reading of sbomqs v2.1.2.
//!
//! sbomqs passes every license string through `LookupExpression`
//! (`pkg/licenses/license.go`), which parses it with go-spdx v2.7.0
//! (`spdxexp.ExtractLicenses`, `spdxexp/{scan,parse,extracts,node}.go`).
//! This module ports that reading; the SPDX license and exception ids are
//! the `spdx` crate's.
//!
//! * An empty value, or the whole value `NONE` or `NOASSERTION` (any case),
//!   is no license.
//! * A value that is exactly a deprecated `+` id of the SPDX list (such as
//!   `GPL-2.0+`) is kept as that id.
//! * Otherwise the value must be a valid SPDX expression whose every
//!   license and exception id is on the SPDX list (matched without regard
//!   to case, with go-spdx's `-only`, `-or-later` and `+` normalization).
//!   When it is not, the whole value is one custom license, looked up
//!   nowhere ([`Term::Custom`]).
//! * A valid expression yields its distinct terms ([`Term::Parsed`]): a
//!   license id, with `+` when it has one and is not an `-or-later` id,
//!   followed by ` WITH <exception>` when it has one; `LicenseRef-…`; or
//!   `DocumentRef-…:LicenseRef-…`. sbomqs then looks each term up in its
//!   SPDX list, then in its AboutCode data, so `MIT+` and
//!   `Apache-2.0 WITH LLVM-exception` are not SPDX-listed terms.
//! * An expression with more than 20 ` AND ` / ` OR ` operators is first split
//!   at its top-level ` AND `s, each clause read on its own, and a clause
//!   that does not parse kept whole as a term (`extractLicensesSafe`).

use std::collections::HashMap;
use std::sync::LazyLock;

/// One license sbomqs derives from a license string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Term {
    /// A term of a valid expression, which sbomqs looks up by name.
    Parsed(String),
    /// A string that is no valid expression: one custom license
    /// (`CreateCustomLicense`), looked up nowhere.
    Custom(String),
}

/// Ids the `spdx` crate lists but go-spdx does not treat as licenses.
const NOT_LICENSES: &[&str] = &["NOASSERTION", "NONE"];

/// SPDX license and exception ids by lowercase name, the case-insensitive
/// lookups of go-spdx's `IsActiveLicense`, `IsDeprecatedLicense` and
/// `IsException`, each yielding the canonical id.
struct IdIndex {
    active: HashMap<String, &'static str>,
    deprecated: HashMap<String, &'static str>,
    exceptions: HashMap<String, &'static str>,
}

static ID_INDEX: LazyLock<IdIndex> = LazyLock::new(|| {
    let mut active = HashMap::new();
    let mut deprecated = HashMap::new();
    for license in spdx::identifiers::LICENSES {
        if NOT_LICENSES.contains(&license.name) {
            continue;
        }
        let map = if license.flags & spdx::flags::IS_DEPRECATED != 0 {
            &mut deprecated
        } else {
            &mut active
        };
        map.insert(license.name.to_ascii_lowercase(), license.name);
    }
    let exceptions = spdx::identifiers::EXCEPTIONS
        .iter()
        .map(|e| (e.name.to_ascii_lowercase(), e.name))
        .collect();
    IdIndex {
        active,
        deprecated,
        exceptions,
    }
});

/// SPDX licenses by exact id, deprecated ones included: sbomqs'
/// `LookupSpdxLicense` (a map keyed by `licenseId`).
static LISTED: LazyLock<HashMap<&'static str, &'static spdx::License>> = LazyLock::new(|| {
    spdx::identifiers::LICENSES
        .iter()
        .filter(|l| !NOT_LICENSES.contains(&l.name))
        .map(|l| (l.name, l))
        .collect()
});

/// The SPDX-listed license an exact term names, if any.
pub(super) fn listed_license(term: &str) -> Option<&'static spdx::License> {
    LISTED.get(term).copied()
}

/// The licenses sbomqs' `LookupExpression` derives from `expression`.
pub(super) fn lookup_expression(expression: &str) -> Vec<Term> {
    if expression.is_empty()
        || expression.eq_ignore_ascii_case("none")
        || expression.eq_ignore_ascii_case("noassertion")
    {
        return Vec::new();
    }
    // A deprecated `+` id survives as authored: go-spdx would rewrite it
    // to its `-or-later` successor.
    if listed_license(expression)
        .is_some_and(|l| l.flags & spdx::flags::IS_DEPRECATED != 0 && l.name.ends_with('+'))
    {
        return vec![Term::Parsed(expression.to_string())];
    }
    match extract_licenses_safe(expression) {
        Some(terms) => terms.into_iter().map(Term::Parsed).collect(),
        None => vec![Term::Custom(expression.to_string())],
    }
}

/// Above this many operators sbomqs splits at top-level ANDs first.
const MAX_DIRECT_EXTRACT_OPERATORS: usize = 20;

/// sbomqs `extractLicensesSafe`: `None` when the expression does not parse
/// (and was not split).
fn extract_licenses_safe(expression: &str) -> Option<Vec<String>> {
    let operators = expression.matches(" AND ").count() + expression.matches(" OR ").count();
    if operators <= MAX_DIRECT_EXTRACT_OPERATORS {
        return extract_licenses(expression);
    }
    let mut all = Vec::new();
    for clause in split_top_level_and(expression) {
        let clause = clause.trim();
        match extract_licenses(clause) {
            Some(terms) => {
                for term in terms {
                    push_distinct(&mut all, term);
                }
            }
            None => push_distinct(&mut all, clause.to_string()),
        }
    }
    Some(all)
}

fn push_distinct(all: &mut Vec<String>, term: String) {
    if !all.contains(&term) {
        all.push(term);
    }
}

/// sbomqs `splitTopLevelAND`: split at ` AND ` outside parentheses.
fn split_top_level_and(expression: &str) -> Vec<&str> {
    let bytes = expression.as_bytes();
    let mut parts = Vec::new();
    let mut depth: i64 = 0;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b' ' if depth == 0 && bytes[i..].starts_with(b" AND ") => {
                parts.push(&expression[start..i]);
                start = i + 5;
                i += 4;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&expression[start..]);
    parts
}

/// go-spdx `ExtractLicenses`: the distinct terms of a valid expression,
/// `None` when it does not scan or parse.
fn extract_licenses(expression: &str) -> Option<Vec<String>> {
    let tokens = scan(expression)?;
    let mut parser = Parser {
        tokens: &tokens,
        index: 0,
    };
    let node = parser.parse_tokens()?;
    let mut terms = Vec::new();
    collect_terms(&node, &mut terms);
    Some(terms)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Operator(&'static str),
    DocumentRef(String),
    LicenseRef(String),
    License(&'static str),
    Exception(&'static str),
}

/// go-spdx `scan`: `None` on the first token it cannot read.
fn scan(expression: &str) -> Option<Vec<Token>> {
    const OPERATORS: [&str; 7] = ["WITH", "AND", "OR", "(", ")", ":", "+"];
    let mut text = expression.to_string();
    let mut index = 0;
    let mut tokens = Vec::new();
    loop {
        // Only spaces separate tokens; a tab or a newline is an error.
        while text.as_bytes().get(index) == Some(&b' ') {
            index += 1;
        }
        if index >= text.len() {
            break;
        }
        let rest = &text[index..];
        if let Some(op) = OPERATORS.iter().find(|op| rest.starts_with(**op)) {
            if *op == "+" && index > 0 && text.as_bytes()[index - 1] == b' ' {
                return None; // "unexpected space before +"
            }
            index += op.len();
            tokens.push(Token::Operator(op));
            continue;
        }
        if let Some(after) = rest.strip_prefix("DocumentRef-") {
            let id = read_id(after)?;
            index += "DocumentRef-".len() + id.len();
            tokens.push(Token::DocumentRef(id.to_string()));
            continue;
        }
        if let Some(after) = rest.strip_prefix("LicenseRef-") {
            let id = read_id(after)?;
            index += "LicenseRef-".len() + id.len();
            tokens.push(Token::LicenseRef(id.to_string()));
            continue;
        }
        let id = read_id(rest)?.to_string();
        index += id.len();
        let token = normalize_license(&id, &mut text, &mut index)?;
        tokens.push(token);
    }
    Some(tokens)
}

/// go-spdx `readID`: `[A-Za-z0-9-.]+` at the start, `None` when empty.
fn read_id(text: &str) -> Option<&str> {
    let end = text
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
        .unwrap_or(text.len());
    (end > 0).then(|| &text[..end])
}

/// go-spdx `licenseLookup`: an active license, then an exception.
fn license_lookup(id: &str) -> Option<Token> {
    let lower = id.to_ascii_lowercase();
    ID_INDEX
        .active
        .get(&lower)
        .copied()
        .map(Token::License)
        .or_else(|| {
            ID_INDEX
                .exceptions
                .get(&lower)
                .copied()
                .map(Token::Exception)
        })
}

/// go-spdx `normalizeLicense`, which may rewrite the rest of the
/// expression (its `-or-later` branch). `index` points just past `id`.
fn normalize_license(id: &str, text: &mut String, index: &mut usize) -> Option<Token> {
    if let Some(token) = license_lookup(id) {
        return Some(token);
    }
    if let Some(base) = id.strip_suffix("-only")
        && let Some(token) = license_lookup(base)
    {
        return Some(token);
    }
    if text.as_bytes().get(*index) == Some(&b'+')
        && let Some(token) = license_lookup(&format!("{id}-or-later"))
    {
        *index += 1;
        return Some(token);
    }
    if let Some(base) = id.strip_suffix("-or-later")
        && let Some(token) = license_lookup(base)
    {
        // Verbatim go-spdx: replace `-or-later` with a `+` operator and
        // drop the character after it.
        let cut = *index - "-or-later".len();
        let mut rewritten = format!("{}+", &text[..cut]);
        if *index < text.len() {
            rewritten.push_str(text.get(*index + 1..).unwrap_or(""));
        }
        *text = rewritten;
        *index = cut;
        return Some(token);
    }
    ID_INDEX
        .deprecated
        .get(&id.to_ascii_lowercase())
        .copied()
        .map(Token::License)
}

/// A parsed expression node.
enum Node {
    Expression(Box<Node>, Box<Node>),
    License {
        id: &'static str,
        plus: bool,
        exception: Option<&'static str>,
    },
    Reference {
        document: Option<String>,
        license: String,
    },
}

/// go-spdx's recursive-descent parser over the scanned tokens.
struct Parser<'a> {
    tokens: &'a [Token],
    index: usize,
}

impl Parser<'_> {
    fn has_more(&self) -> bool {
        self.index < self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn operator(&mut self, op: &str) -> bool {
        if matches!(self.peek(), Some(Token::Operator(found)) if *found == op) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    /// `parseTokens`: an expression that uses every token.
    fn parse_tokens(&mut self) -> Option<Node> {
        if self.tokens.is_empty() {
            return None;
        }
        let node = self.parse_expression()?;
        (!self.has_more()).then_some(node)
    }

    fn parse_expression(&mut self) -> Option<Node> {
        let left = self.parse_and()?;
        if !self.has_more() || !self.operator("OR") {
            return Some(left);
        }
        if !self.has_more() {
            return None;
        }
        let right = self.parse_expression()?;
        Some(Node::Expression(Box::new(left), Box::new(right)))
    }

    fn parse_and(&mut self) -> Option<Node> {
        let left = self.parse_atom()?;
        if !self.has_more() || !self.operator("AND") {
            return Some(left);
        }
        if !self.has_more() {
            return None;
        }
        let right = self.parse_and()?;
        Some(Node::Expression(Box::new(left), Box::new(right)))
    }

    fn parse_atom(&mut self) -> Option<Node> {
        if self.operator("(") {
            let expression = self.parse_expression()?;
            return self.operator(")").then_some(expression);
        }
        match self.peek()?.clone() {
            Token::DocumentRef(document) => {
                self.index += 1;
                if !self.operator(":") {
                    return None;
                }
                let Some(Token::LicenseRef(license)) = self.peek().cloned() else {
                    return None;
                };
                self.index += 1;
                Some(Node::Reference {
                    document: Some(document),
                    license,
                })
            }
            Token::LicenseRef(license) => {
                self.index += 1;
                Some(Node::Reference {
                    document: None,
                    license,
                })
            }
            Token::License(id) => {
                self.index += 1;
                let mut plus = id.ends_with("-or-later");
                if self.has_more() && self.operator("+") {
                    plus = true;
                }
                let mut exception = None;
                if self.has_more() && self.operator("WITH") {
                    let Some(Token::Exception(name)) = self.peek().cloned() else {
                        return None;
                    };
                    self.index += 1;
                    exception = Some(name);
                }
                Some(Node::License {
                    id,
                    plus,
                    exception,
                })
            }
            Token::Operator(_) | Token::Exception(_) => None,
        }
    }
}

/// go-spdx `collectExtractedLicenses` with `reconstructedLicenseString`:
/// the distinct terms in reading order.
fn collect_terms(node: &Node, terms: &mut Vec<String>) {
    match node {
        Node::Expression(left, right) => {
            collect_terms(left, terms);
            collect_terms(right, terms);
        }
        Node::License {
            id,
            plus,
            exception,
        } => {
            let mut term = (*id).to_string();
            if *plus && !id.to_ascii_lowercase().ends_with("-or-later") {
                term.push('+');
            }
            if let Some(exception) = exception {
                term.push_str(" WITH ");
                term.push_str(exception);
            }
            push_distinct(terms, term);
        }
        Node::Reference { document, license } => {
            let mut term = format!("LicenseRef-{license}");
            if let Some(document) = document {
                term = format!("DocumentRef-{document}:{term}");
            }
            push_distinct(terms, term);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(terms: &[&str]) -> Vec<Term> {
        terms
            .iter()
            .map(|t| Term::Parsed((*t).to_string()))
            .collect()
    }

    #[test]
    fn sentinels_and_empty_values_are_no_license() {
        for value in ["", "NONE", "none", "NOASSERTION", "NoAssertion"] {
            assert!(lookup_expression(value).is_empty(), "{value}");
        }
    }

    #[test]
    fn valid_expressions_yield_distinct_terms() {
        assert_eq!(lookup_expression("MIT"), parsed(&["MIT"]));
        assert_eq!(
            lookup_expression("(MIT AND BSD-3-Clause) OR Apache-2.0"),
            parsed(&["MIT", "BSD-3-Clause", "Apache-2.0"])
        );
        // ExtractLicenses collects a set.
        assert_eq!(lookup_expression("MIT OR MIT"), parsed(&["MIT"]));
        // Ids match without regard to case and come back canonical.
        assert_eq!(lookup_expression("mit"), parsed(&["MIT"]));
        assert_eq!(
            lookup_expression("LicenseRef-foo AND DocumentRef-ext:LicenseRef-bar"),
            parsed(&["LicenseRef-foo", "DocumentRef-ext:LicenseRef-bar"])
        );
    }

    #[test]
    fn exceptions_and_plus_stay_on_the_term() {
        assert_eq!(
            lookup_expression("Apache-2.0 WITH LLVM-exception"),
            parsed(&["Apache-2.0 WITH LLVM-exception"])
        );
        assert_eq!(lookup_expression("MIT+"), parsed(&["MIT+"]));
        // `+` on an id with an -or-later successor becomes that successor.
        assert_eq!(
            lookup_expression("LGPL-2.1+ OR MIT"),
            parsed(&["LGPL-2.1-or-later", "MIT"])
        );
        // -only falls back to the bare id when the -only form is unknown.
        assert_eq!(
            lookup_expression("Apache-2.0-only"),
            parsed(&["Apache-2.0"])
        );
        // A whole-value deprecated `+` id is kept as authored.
        assert_eq!(lookup_expression("GPL-2.0+"), parsed(&["GPL-2.0+"]));
    }

    #[test]
    fn invalid_values_are_one_custom_license() {
        for value in [
            "MIT OR FooBar",
            "Apache License 2.0",
            "MIT Apache-2.0",
            "MIT AND",
            "(MIT",
            "MIT\tOR Apache-2.0",
            "MIT WITH",
            "mit or apache-2.0",
            "https://spdx.org/licenses/CC0-1.0",
        ] {
            assert_eq!(
                lookup_expression(value),
                vec![Term::Custom(value.to_string())],
                "{value}"
            );
        }
    }

    #[test]
    fn long_expressions_split_at_top_level_and() {
        let mut clauses: Vec<String> = (0..21).map(|_| "MIT".to_string()).collect();
        clauses.push("(Apache-2.0 OR BSD-3-Clause)".to_string());
        clauses.push("Unknown Thing".to_string());
        let expression = clauses.join(" AND ");
        assert_eq!(
            lookup_expression(&expression),
            parsed(&["MIT", "Apache-2.0", "BSD-3-Clause", "Unknown Thing"])
        );
    }
}
