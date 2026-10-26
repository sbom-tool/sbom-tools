//! Minimal JSON Schema validator for the schemas the tests check output
//! against: the draft 2020-12 schemas under `schemas/`, the vendored OSCAL
//! schema (draft-07) under `tests/fixtures/schemas/oscal/` and the vendored
//! SARIF 2.1.0 schema (draft-04) under `tests/fixtures/schemas/sarif/`.
//!
//! Implements exactly the keywords and `format`s those schemas use and panics
//! on any other, so a schema edit can never be silently ignored by the tests.
//! A full validator crate was not added: `jsonschema` and `boon` both pull in
//! `borrow-or-share` (MIT-0), a license `deny.toml` does not allow.
//!
//! Where the drafts differ, the schema's `$schema` decides: draft-04 and
//! draft-07 ignore every keyword next to a `$ref`, later drafts apply them.
//! `pattern` is read the way JSON Schema defines it, as an ECMA-262 regular
//! expression, not as `regex` crate syntax (see [`ecma_to_rust`]); `format`
//! is asserted.

#![allow(dead_code)]

use serde_json::{Map, Value};

/// Keywords that only annotate (no assertion), plus `$defs` and the
/// `definitions` of draft-04 and draft-07, which hold `$ref` targets and are
/// not applied by themselves. `contentEncoding` is an annotation in draft-07
/// (§8.3 leaves decoding to the application). `id` is draft-04's spelling of
/// `$id`; only local `$ref`s are resolved, so neither changes the outcome.
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$id",
    "id",
    "$comment",
    "title",
    "description",
    "default",
    "$defs",
    "definitions",
    "contentEncoding",
];

/// ECMA-262 `\s`: the WhiteSpace and LineTerminator code points, as the body
/// of a `regex` character class.
const ECMA_WHITESPACE: &str = r"\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}";

/// ECMA-262 line terminators, the code points `.` does not match.
const ECMA_LINE_TERMINATORS: &str = r"\n\r\x{2028}\x{2029}";

/// Validate `instance` against `schema`, returning every failure as
/// `<instance path>: <reason>`.
pub fn validate(schema: &Value, instance: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    check(schema, schema, instance, "", &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// A copy of `schema` that rejects undeclared fields: `additionalProperties:
/// false` is injected into every object schema that has `properties`.
pub fn strict_copy(schema: &Value) -> Value {
    let mut strict = schema.clone();
    make_strict(&mut strict);
    strict
}

fn make_strict(schema: &mut Value) {
    let Value::Object(map) = schema else {
        return;
    };
    if map.contains_key("properties") {
        map.entry("additionalProperties")
            .or_insert(Value::Bool(false));
    }
    for keyword in ["items", "additionalProperties"] {
        if let Some(sub) = map.get_mut(keyword) {
            make_strict(sub);
        }
    }
    for keyword in ["properties", "$defs"] {
        if let Some(Value::Object(subs)) = map.get_mut(keyword) {
            for sub in subs.values_mut() {
                make_strict(sub);
            }
        }
    }
}

fn check(root: &Value, schema: &Value, instance: &Value, path: &str, errors: &mut Vec<String>) {
    let map = match schema {
        Value::Bool(true) => return,
        Value::Bool(false) => {
            errors.push(format!("{path}: no value is allowed here"));
            return;
        }
        Value::Object(map) => map,
        other => panic!("schema at {path} is not an object or boolean: {other}"),
    };
    if let Some(reference) = map.get("$ref")
        && refs_replace_siblings(root)
    {
        check(root, resolve(root, reference), instance, path, errors);
        return;
    }
    for (keyword, value) in map {
        match keyword.as_str() {
            k if ANNOTATIONS.contains(&k) => {}
            "$ref" => {
                let target = resolve(root, value);
                check(root, target, instance, path, errors);
            }
            "allOf" => {
                for sub in value.as_array().expect("allOf is an array") {
                    check(root, sub, instance, path, errors);
                }
            }
            "anyOf" => {
                let options = value.as_array().expect("anyOf is an array");
                let mut rejections = Vec::new();
                for option in options {
                    let mut option_errors = Vec::new();
                    check(root, option, instance, path, &mut option_errors);
                    if option_errors.is_empty() {
                        rejections.clear();
                        break;
                    }
                    rejections.push(option_errors);
                }
                if !rejections.is_empty() {
                    errors.push(format!(
                        "{path}: matches none of the {} anyOf alternatives",
                        options.len()
                    ));
                    for (i, option_errors) in rejections.iter().enumerate() {
                        errors.extend(option_errors.iter().map(|e| format!("  [{i}] {e}")));
                    }
                }
            }
            "oneOf" => {
                let options = value.as_array().expect("oneOf is an array");
                let mut rejections = Vec::new();
                let mut matched = 0usize;
                for option in options {
                    let mut option_errors = Vec::new();
                    check(root, option, instance, path, &mut option_errors);
                    if option_errors.is_empty() {
                        matched += 1;
                    } else {
                        rejections.push(option_errors);
                    }
                }
                match matched {
                    1 => {}
                    0 => {
                        errors.push(format!(
                            "{path}: matches none of the {} oneOf alternatives",
                            options.len()
                        ));
                        for (i, option_errors) in rejections.iter().enumerate() {
                            errors.extend(option_errors.iter().map(|e| format!("  [{i}] {e}")));
                        }
                    }
                    n => errors.push(format!(
                        "{path}: matches {n} of the oneOf alternatives, not exactly one"
                    )),
                }
            }
            "format" => {
                if let Value::String(s) = instance {
                    let format = value.as_str().expect("format is a string");
                    if !matches_format(format, s) {
                        errors.push(format!("{path}: {s:?} is not a valid {format}"));
                    }
                }
            }
            "type" => check_type(value, instance, path, errors),
            "const" => {
                if instance != value {
                    errors.push(format!("{path}: expected {value}, got {instance}"));
                }
            }
            "enum" => {
                let options = value.as_array().expect("enum is an array");
                if !options.contains(instance) {
                    errors.push(format!("{path}: {instance} is not one of {value}"));
                }
            }
            "properties" => {
                if let Value::Object(fields) = instance {
                    let declared = value.as_object().expect("properties is an object");
                    for (name, sub) in declared {
                        if let Some(field) = fields.get(name) {
                            check(root, sub, field, &format!("{path}/{name}"), errors);
                        }
                    }
                }
            }
            "required" => {
                if let Value::Object(fields) = instance {
                    for name in value.as_array().expect("required is an array") {
                        let name = name.as_str().expect("required names are strings");
                        if !fields.contains_key(name) {
                            errors.push(format!("{path}: missing required field `{name}`"));
                        }
                    }
                }
            }
            "additionalProperties" => {
                if let Value::Object(fields) = instance {
                    let empty = Map::new();
                    let declared = map
                        .get("properties")
                        .and_then(Value::as_object)
                        .unwrap_or(&empty);
                    for (name, field) in fields {
                        if !declared.contains_key(name) {
                            let field_path = format!("{path}/{name}");
                            if value == &Value::Bool(false) {
                                errors.push(format!("{field_path}: undeclared field"));
                            } else {
                                check(root, value, field, &field_path, errors);
                            }
                        }
                    }
                }
            }
            "items" => {
                if let Value::Array(items) = instance {
                    for (i, item) in items.iter().enumerate() {
                        check(root, value, item, &format!("{path}/{i}"), errors);
                    }
                }
            }
            "minItems" => {
                if let Value::Array(items) = instance {
                    let min = value.as_u64().expect("minItems is an integer");
                    if (items.len() as u64) < min {
                        errors.push(format!("{path}: fewer than {min} items"));
                    }
                }
            }
            "uniqueItems" => {
                if let Value::Array(items) = instance
                    && value.as_bool().expect("uniqueItems is a boolean")
                {
                    for (i, item) in items.iter().enumerate() {
                        if let Some(j) = items[..i].iter().position(|earlier| earlier == item) {
                            errors.push(format!("{path}: items {j} and {i} are equal"));
                        }
                    }
                }
            }
            "minimum" | "maximum" => {
                if let Some(n) = instance.as_f64() {
                    let bound = value.as_f64().expect("bound is a number");
                    let ok = if keyword == "minimum" {
                        n >= bound
                    } else {
                        n <= bound
                    };
                    if !ok {
                        errors.push(format!("{path}: {n} violates {keyword} {bound}"));
                    }
                }
            }
            "minLength" => {
                if let Value::String(s) = instance {
                    let min = value.as_u64().expect("minLength is an integer");
                    if (s.chars().count() as u64) < min {
                        errors.push(format!("{path}: shorter than {min} characters"));
                    }
                }
            }
            "pattern" => {
                if let Value::String(s) = instance {
                    let pattern = value.as_str().expect("pattern is a string");
                    if !matches_pattern(pattern, s) {
                        errors.push(format!("{path}: {s:?} does not match {pattern}"));
                    }
                }
            }
            other => panic!("unsupported JSON Schema keyword `{other}` at {path}"),
        }
    }
}

/// `pattern` semantics: an unanchored ECMA-262 search, with each regex
/// compiled once.
fn matches_pattern(pattern: &str, s: &str) -> bool {
    thread_local! {
        static COMPILED: std::cell::RefCell<std::collections::HashMap<String, regex::Regex>> =
            std::cell::RefCell::default();
    }
    COMPILED.with(|compiled| {
        compiled
            .borrow_mut()
            .entry(pattern.to_string())
            .or_insert_with(|| {
                regex::Regex::new(&ecma_to_rust(pattern))
                    .unwrap_or_else(|e| panic!("bad pattern {pattern}: {e}"))
            })
            .is_match(s)
    })
}

/// Rewrite an ECMA-262 pattern (JSON Schema's dialect, read with Unicode
/// semantics, as the OSCAL schema's `\p{L}` requires) as `regex` crate
/// syntax. The two agree on everything the schemas use except:
///
/// - `.` excludes all four ECMA line terminators, not only `\n`;
/// - `\s` and `\S` use ECMA's whitespace set (U+FEFF in, U+0085 out);
/// - `\d`, `\w` and their negations are ASCII-only;
/// - inside a class, `[`, `&` and `~` are literals (in `regex` they open a
///   nested class or a set operation).
///
/// Constructs whose meaning differs and that no schema uses (`[]`, `[^]`,
/// `--` in a class, a negated escape inside a class) panic rather than
/// mistranslate; lookaround and backreferences fail to compile, which panics
/// too.
pub fn ecma_to_rust(pattern: &str) -> String {
    let unsupported = |what: &str| -> ! { panic!("unsupported in pattern {pattern:?}: {what}") };
    let mut out = String::with_capacity(pattern.len() * 2);
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let escaped = chars
                    .next()
                    .unwrap_or_else(|| unsupported("a trailing backslash"));
                match (escaped, in_class) {
                    ('d', false) => out.push_str("[0-9]"),
                    ('D', false) => out.push_str("[^0-9]"),
                    ('w', false) => out.push_str("[A-Za-z0-9_]"),
                    ('W', false) => out.push_str("[^A-Za-z0-9_]"),
                    ('s', false) => out.push_str(&format!("[{ECMA_WHITESPACE}]")),
                    ('S', false) => out.push_str(&format!("[^{ECMA_WHITESPACE}]")),
                    ('d', true) => out.push_str("0-9"),
                    ('w', true) => out.push_str("A-Za-z0-9_"),
                    ('s', true) => out.push_str(ECMA_WHITESPACE),
                    ('D' | 'W' | 'S', true) => unsupported("a negated escape inside a class"),
                    (other, _) => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    out.push('^');
                    chars.next();
                }
                if chars.peek() == Some(&']') {
                    unsupported("an empty class `[]` or `[^]`");
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(']');
            }
            '[' | '&' | '~' if in_class => {
                out.push('\\');
                out.push(c);
            }
            '-' if in_class && chars.peek() == Some(&'-') => unsupported("`--` inside a class"),
            '.' if !in_class => out.push_str(&format!("[^{ECMA_LINE_TERMINATORS}]")),
            _ => out.push(c),
        }
    }
    out
}

/// `format` as an assertion, for the formats the schemas use. Draft-07 makes
/// format validation optional; asserting it is the stricter reading, and the
/// one validators such as ajv with ajv-formats apply.
fn matches_format(format: &str, s: &str) -> bool {
    match format {
        // RFC 3339 §5.6 date-time.
        "date-time" => chrono::DateTime::parse_from_rfc3339(s).is_ok(),
        // RFC 3986 URI: a scheme, then only URI characters.
        "uri" => uri_scheme(s).is_some_and(is_uri_scheme) && is_uri_text(s),
        // RFC 3986 URI-reference: a URI, or a relative reference whose first
        // segment has no colon.
        "uri-reference" => is_uri_text(s) && uri_scheme(s).is_none_or(is_uri_scheme),
        // RFC 6531 mailbox, loosely: text, an `@`, text, no whitespace.
        "email" => {
            s.split_once('@')
                .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
                && !s.chars().any(char::is_whitespace)
        }
        other => panic!("unsupported JSON Schema format `{other}`"),
    }
}

/// The text before the first `:` when that colon comes before any `/`, `?`
/// or `#` (the only place a scheme can end), else `None`.
fn uri_scheme(s: &str) -> Option<&str> {
    let end = s.find([':', '/', '?', '#'])?;
    s[end..].starts_with(':').then(|| &s[..end])
}

/// RFC 3986 `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn is_uri_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Only RFC 3986 characters (unreserved, reserved, `%XX` escapes), with at
/// most one `#`.
fn is_uri_text(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hex = |j: usize| bytes.get(j).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(i + 1) && hex(i + 2)) {
                return false;
            }
            i += 3;
            continue;
        }
        let allowed = b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=".contains(&b);
        if !allowed {
            return false;
        }
        i += 1;
    }
    s.matches('#').count() <= 1
}

/// Whether the root schema is draft-04 or draft-07, where a `$ref` makes
/// every keyword beside it ignored (draft 2019-09 and later apply them
/// alongside).
fn refs_replace_siblings(root: &Value) -> bool {
    root.get("$schema")
        .and_then(Value::as_str)
        .is_some_and(|uri| uri.contains("draft-04") || uri.contains("draft-07"))
}

fn resolve<'a>(root: &'a Value, reference: &Value) -> &'a Value {
    let reference = reference.as_str().expect("$ref is a string");
    let pointer = reference
        .strip_prefix('#')
        .unwrap_or_else(|| panic!("only local $ref is supported: {reference}"));
    root.pointer(pointer)
        .unwrap_or_else(|| panic!("unresolved $ref {reference}"))
}

fn check_type(expected: &Value, instance: &Value, path: &str, errors: &mut Vec<String>) {
    let names: Vec<&str> = match expected {
        Value::String(name) => vec![name.as_str()],
        Value::Array(names) => names
            .iter()
            .map(|n| n.as_str().expect("type names are strings"))
            .collect(),
        other => panic!("bad type keyword at {path}: {other}"),
    };
    let matches = |name: &str| match name {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        "number" => instance.is_number(),
        "integer" => {
            instance.is_i64()
                || instance.is_u64()
                || instance.as_f64().is_some_and(|f| f.fract() == 0.0)
        }
        other => panic!("unknown type `{other}` at {path}"),
    };
    if !names.iter().any(|name| matches(name)) {
        errors.push(format!("{path}: {instance} is not of type {expected}"));
    }
}
