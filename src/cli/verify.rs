//! CLI handler for the `verify` command.
//!
//! Provides file hash verification and component hash auditing.

use std::path::PathBuf;

use anyhow::Result;

use crate::parsers::parse_sbom;
use crate::pipeline::exit_codes;
use crate::reports::escape::sanitize_path;
use crate::verification::{
    ModelVerifyResult, audit_component_hashes, verify_file_hash, verify_model_dir,
};

/// Verify action to perform
#[derive(Debug, Clone, clap::Subcommand)]
pub enum VerifyAction {
    /// Verify file integrity against a hash value
    Hash {
        /// SBOM file to verify
        file: PathBuf,
        /// Expected hash (sha256:<hex>, sha512:<hex>, or bare hex)
        #[arg(long)]
        expected: Option<String>,
        /// Read expected hash from a file (e.g., sbom.json.sha256)
        #[arg(long, conflicts_with = "expected")]
        hash_file: Option<PathBuf>,
    },
    /// Audit component hashes within an SBOM
    AuditHashes {
        /// SBOM file to audit
        file: PathBuf,
        /// Output format (table or json)
        #[arg(
            short = 'f',
            long = "output",
            alias = "format",
            default_value = "table"
        )]
        format: String,
    },
    /// Verify ML-model weight files against the hashes recorded in an SBOM
    ModelWeights {
        /// SBOM file describing the model(s)
        file: PathBuf,
        /// Directory holding the weight files (supports the HuggingFace cache
        /// snapshot layout where blobs are named by their SHA-256)
        #[arg(long = "model-dir")]
        model_dir: PathBuf,
        /// Output format (table or json)
        #[arg(
            short = 'f',
            long = "output",
            alias = "format",
            default_value = "table"
        )]
        format: String,
    },
    /// Validate a versioned pipeline shard receipt
    Receipt {
        /// Receipt JSON file (pipeline-shard-receipt/v1)
        file: PathBuf,
        /// Output format (table or json)
        #[arg(
            short = 'f',
            long = "output",
            alias = "format",
            default_value = "table"
        )]
        format: String,
    },
    /// Aggregate receipts from a JSON file or directory using a strict policy JSON file.
    ReceiptAggregate {
        /// Receipt JSON file, or a directory whose *.json files are all receipts
        receipts: PathBuf,
        /// Aggregate policy JSON file (aggregate-policy/v1)
        #[arg(long)]
        policy: PathBuf,
        /// Output format (table or json)
        #[arg(
            short = 'f',
            long = "output",
            alias = "format",
            default_value = "table"
        )]
        format: String,
    },
    /// Generate an unsigned receipt from a strict, digest-free JSON descriptor.
    ReceiptGenerate {
        /// Descriptor JSON file (pipeline-shard-receipt-input/v1); relative
        /// source_root/artifact_root paths resolve against the working directory
        #[arg(long)]
        input: PathBuf,
        /// Path for the new receipt; an existing file is never overwritten
        #[arg(long)]
        output: PathBuf,
    },
}

/// Run the verify command.
pub fn run_verify(action: VerifyAction, quiet: bool) -> Result<i32> {
    match action {
        VerifyAction::Hash {
            file,
            expected,
            hash_file,
        } => {
            let expected_hash = if let Some(e) = expected {
                e
            } else if let Some(hf) = hash_file {
                crate::verification::read_hash_file(&hf)?
            } else {
                // Try to find a sidecar hash file
                let sha_path = file.with_extension(
                    file.extension()
                        .map(|e| format!("{}.sha256", e.to_string_lossy()))
                        .unwrap_or_else(|| "sha256".to_string()),
                );
                if sha_path.exists() {
                    if !quiet {
                        eprintln!("Using sidecar hash file: {}", sanitize_path(&sha_path));
                    }
                    crate::verification::read_hash_file(&sha_path)?
                } else {
                    anyhow::bail!(
                        "no hash provided. Use --expected <hash> or --hash-file <path>, \
                         or place a .sha256 sidecar file alongside the SBOM"
                    );
                }
            };

            let result = verify_file_hash(&file, &expected_hash)?;

            if !quiet {
                println!("{result}");
            }

            if result.verified {
                Ok(exit_codes::SUCCESS)
            } else {
                // A failed verification is a VERDICT, not an operational
                // error — exit 1 so scripts can distinguish "hash mismatch"
                // from "could not verify" (exit 3).
                Ok(exit_codes::CHANGES_DETECTED)
            }
        }
        VerifyAction::AuditHashes { file, format } => {
            let sbom = parse_sbom(&file)?;
            let report = audit_component_hashes(&sbom);

            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Component Hash Audit");
                println!("====================");
                println!(
                    "Total: {}  Strong: {}  Weak-only: {}  Missing: {}",
                    report.total_components,
                    report.strong_count,
                    report.weak_only_count,
                    report.missing_count
                );
                println!("Pass rate: {:.1}%\n", report.pass_rate());

                if report.weak_only_count > 0 || report.missing_count > 0 {
                    println!("Issues:");
                    for comp in &report.components {
                        match comp.result {
                            crate::verification::HashAuditResult::WeakOnly => {
                                println!(
                                    "  WEAK   {} {} ({})",
                                    comp.name,
                                    comp.version.as_deref().unwrap_or(""),
                                    comp.algorithms.join(", ")
                                );
                            }
                            crate::verification::HashAuditResult::Missing => {
                                println!(
                                    "  MISSING {} {}",
                                    comp.name,
                                    comp.version.as_deref().unwrap_or("")
                                );
                            }
                            crate::verification::HashAuditResult::Strong => {}
                        }
                    }
                }
            }

            if report.missing_count > 0 || report.weak_only_count > 0 {
                Ok(exit_codes::CHANGES_DETECTED) // non-zero for CI gating
            } else {
                Ok(exit_codes::SUCCESS)
            }
        }
        VerifyAction::ModelWeights {
            file,
            model_dir,
            format,
        } => {
            let sbom = parse_sbom(&file)?;
            let report = verify_model_dir(&sbom, &model_dir);

            // A verification pass over zero models is vacuous — exiting 0
            // would let CI believe weights were verified when nothing was.
            if report.total_models == 0 {
                anyhow::bail!("SBOM contains no model components; nothing to verify");
            }

            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Model Weight Verification");
                println!("=========================");
                println!("Model dir: {}", report.model_dir);
                println!(
                    "Models: {}  Verified: {}  Mismatch: {}  Missing: {}  No-hash: {}",
                    report.total_models,
                    report.verified_count,
                    report.mismatch_count,
                    report.missing_count,
                    report.no_hash_count,
                );

                for comp in &report.components {
                    // A verified component is reported succinctly; everything
                    // else (the actionable cases) gets its located file/hash.
                    match comp.result {
                        ModelVerifyResult::Verified => {
                            println!(
                                "  {} {} {} -> {}",
                                comp.result.label(),
                                comp.name,
                                comp.version.as_deref().unwrap_or(""),
                                comp.file.as_deref().unwrap_or("?"),
                            );
                        }
                        _ => {
                            println!(
                                "  {} {} {}{}",
                                comp.result.label(),
                                comp.name,
                                comp.version.as_deref().unwrap_or(""),
                                comp.hash
                                    .as_deref()
                                    .map(|h| format!(" ({h})"))
                                    .unwrap_or_default(),
                            );
                        }
                    }
                }
            }

            if report.has_failures() {
                // Verdict, not operational error: exit 1 (see verify hash).
                Ok(exit_codes::CHANGES_DETECTED)
            } else {
                Ok(exit_codes::SUCCESS)
            }
        }
        VerifyAction::Receipt { file, format } => {
            let json = format == "json";
            let verdict = contract_verdict(crate::verification::check_receipt(&file))?;
            if json {
                let value = serde_json::json!({
                    "file": file.display().to_string(),
                    "valid": verdict.is_ok(),
                    "error": verdict.as_ref().err(),
                });
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            match verdict {
                Ok(()) => {
                    if !quiet && !json {
                        println!("Receipt valid: {}", sanitize_path(&file));
                    }
                    Ok(exit_codes::SUCCESS)
                }
                Err(message) => {
                    eprintln!("receipt verification failed: {message}");
                    Ok(exit_codes::CHANGES_DETECTED)
                }
            }
        }
        VerifyAction::ReceiptAggregate {
            receipts,
            policy,
            format,
        } => {
            let json = format == "json";
            let verdict = aggregate_receipt_files(&receipts, &policy)?;
            if json {
                let value = match &verdict {
                    Ok(summary) => serde_json::json!({
                        "valid": true,
                        "receipt_count": summary.receipt_count,
                        "artifact_count": summary.artifact_count,
                        "error": null,
                    }),
                    Err(message) => serde_json::json!({
                        "valid": false,
                        "receipt_count": null,
                        "artifact_count": null,
                        "error": message,
                    }),
                };
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            match verdict {
                Ok(_) => {
                    if !quiet && !json {
                        println!("Receipts valid");
                    }
                    Ok(exit_codes::SUCCESS)
                }
                Err(message) => {
                    eprintln!("receipt aggregation failed: {message}");
                    Ok(exit_codes::CHANGES_DETECTED)
                }
            }
        }
        VerifyAction::ReceiptGenerate { input, output } => {
            let verdict = contract_verdict(
                crate::verification::read_contract_json::<
                    crate::verification::ReceiptGenerationInput,
                >(&input)
                .and_then(crate::verification::generate_receipt_from_descriptor)
                .and_then(|receipt| crate::verification::write_receipt(&output, &receipt)),
            )?;
            match verdict {
                Ok(()) => {
                    if !quiet {
                        println!("Receipt generated: {}", sanitize_path(&output));
                    }
                    Ok(exit_codes::SUCCESS)
                }
                Err(message) => {
                    eprintln!("receipt generation failed: {message}");
                    Ok(exit_codes::CHANGES_DETECTED)
                }
            }
        }
    }
}

/// Split a receipt result into the exit contract: a `Contract` violation is a
/// verdict (`Ok(Err(message))`, exit 1); I/O and malformed JSON stay
/// operational errors (`Err`, exit 3).
fn contract_verdict<T>(
    result: Result<T, crate::verification::ReceiptError>,
) -> Result<std::result::Result<T, String>> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(crate::verification::ReceiptError::Contract(message)) => Ok(Err(message)),
        Err(error) => Err(error.into()),
    }
}

/// Load the policy and every receipt, then aggregate. Policy and receipt
/// contract violations are verdicts; unreadable or malformed files are
/// operational errors.
fn aggregate_receipt_files(
    receipts: &std::path::Path,
    policy: &std::path::Path,
) -> Result<std::result::Result<crate::verification::AggregateVerification, String>> {
    let policy = match contract_verdict(crate::verification::read_contract_json::<
        crate::verification::AggregatePolicy,
    >(policy))?
    {
        Ok(policy) => policy,
        Err(message) => return Ok(Err(message)),
    };
    let mut loaded = Vec::new();
    for path in receipt_paths(receipts)? {
        match contract_verdict(crate::verification::read_receipt(&path))? {
            Ok(receipt) => loaded.push(receipt),
            Err(message) => return Ok(Err(message)),
        }
    }
    contract_verdict(crate::verification::aggregate_receipts(&loaded, &policy))
}

fn receipt_paths(path: &std::path::Path) -> Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        anyhow::bail!(
            "receipt input is not a file or directory: {}",
            path.display()
        );
    }
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|ext| ext == "json")
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    if paths.is_empty() {
        anyhow::bail!(
            "receipt directory contains no JSON files: {}",
            path.display()
        );
    }
    Ok(paths)
}
