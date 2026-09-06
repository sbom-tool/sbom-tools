use std::path::{Component, Path};

use super::pipeline_receipt::ReceiptError;

/// Validate a manifest path is a non-empty, UTF-8, relative path without traversal.
pub(crate) fn validate_relative_path(value: &str, label: &str) -> Result<(), ReceiptError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || value.starts_with("//")
        || (value.len() >= 2 && value.as_bytes()[1] == b':')
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ReceiptError::Contract(format!(
            "{label} must be a safe relative path"
        )));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir))
    {
        return Err(ReceiptError::Contract(format!(
            "{label} must not contain '.' components"
        )));
    }
    Ok(())
}
