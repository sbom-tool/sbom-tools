//! JSON serialization for pipeline receipts.
use super::pipeline_receipt::{PipelineShardReceipt, ReceiptError, validate_receipt};
use std::{fs, fs::OpenOptions, io::Write, path::Path};

pub fn write_receipt(path: &Path, receipt: &PipelineShardReceipt) -> Result<(), ReceiptError> {
    validate_receipt(receipt)?;
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|source| ReceiptError::Json {
        path: path.into(),
        source,
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| ReceiptError::Io {
            path: path.into(),
            source,
        })?;
    file.write_all(&bytes).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })
}

pub fn read_receipt(path: &Path) -> Result<PipelineShardReceipt, ReceiptError> {
    let bytes = fs::read(path).map_err(|source| ReceiptError::Io {
        path: path.into(),
        source,
    })?;
    // Two-phase parse keeps the documented exit split intact: bytes that are
    // not JSON are an operational error (Json -> exit 3), while readable JSON
    // that violates the receipt shape is a gate verdict (Contract -> exit 1).
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|source| ReceiptError::Json {
            path: path.into(),
            source,
        })?;
    let receipt: PipelineShardReceipt = serde_json::from_value(value)
        .map_err(|source| ReceiptError::Contract(source.to_string()))?;
    validate_receipt(&receipt)?;
    Ok(receipt)
}

pub fn check_receipt(path: &Path) -> Result<(), ReceiptError> {
    read_receipt(path).map(|_| ())
}
