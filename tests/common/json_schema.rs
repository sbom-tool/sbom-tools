//! Minimal JSON Schema (draft 2020-12) validator for the schemas under
//! `schemas/`.
//!
//! Implements exactly the keywords those schemas use and panics on any other
//! keyword, so a schema edit can never be silently ignored by the tests. A
//! full validator crate was not added: `jsonschema` and `boon` both pull in
//! `borrow-or-share` (MIT-0), a license `deny.toml` does not allow.

#![allow(dead_code)]

use serde_json::{Map, Value};

/// Keywords that only annotate (no assertion), plus `$defs`, which holds
/// `$ref` targets and is not applied by itself.
const ANNOTATIONS: &[&str] = &[
    "$schema",
    "$id",
    "$comment",
    "title",
    "description",
    "$defs",
];

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
    for (keyword, value) in map {
        match keyword.as_str() {
            k if ANNOTATIONS.contains(&k) => {}
            "$ref" => {
                let target = resolve(root, value);
                check(root, target, instance, path, errors);
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

/// `pattern` semantics: an unanchored search, with each regex compiled once.
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
                regex::Regex::new(pattern).unwrap_or_else(|e| panic!("bad pattern {pattern}: {e}"))
            })
            .is_match(s)
    })
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
