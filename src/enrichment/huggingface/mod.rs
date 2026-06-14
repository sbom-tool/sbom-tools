//! HuggingFace Hub model-info enrichment.
//!
//! ML components from real-world generators typically arrive with sparse model
//! cards and no weight hashes. This source resolves a `MachineLearningModel`
//! component to its HuggingFace model id (via a `pkg:huggingface/...` PURL or a
//! `huggingface.co` model-card URL) and injects only **high-confidence** fields
//! from `GET /api/models/{id}?blobs=true`:
//!
//! - `siblings[].lfs.sha256` → component hashes (feeds integrity scoring /
//!   AI-010 and `verify --model-dir`),
//! - `pipeline_tag`           → `MlModelInfo.task`,
//! - `lastModified`           → a staleness signal,
//! - `license`                → declared license, only when none is declared.
//!
//! It deliberately does NOT scrape the freeform `cardData` YAML and does not
//! infer quantization (the API does not reliably expose it).
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::enrichment::huggingface::{HuggingFaceClient, HuggingFaceConfig};
//!
//! let mut client = HuggingFaceClient::with_defaults();
//! // client.enrich_components(&mut components)?;
//! ```

mod api;
mod client;

pub use api::{HfLfs, HfModelInfo, HfSibling};
pub use client::{
    HUGGINGFACE_API_URL, HuggingFaceClient, HuggingFaceConfig, HuggingFaceEnrichmentStats,
    resolve_model_id,
};
