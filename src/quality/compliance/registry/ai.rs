//! The rules of the AI readiness profiles: EU AI Act Annex IV and the
//! BSI/G7 SBOM-for-AI Minimum Elements.

use super::*;

/// Mistyped-ML remediation, shared by the EU AI Act and BSI/G7 SBOM-for-AI
/// applicability guards.
const REMEDIATION_UNTYPED_ML: &str = "Components with pkg:huggingface PURLs or model-card references look like ML models; leaving them untyped hides them from every AI-BOM readiness check. Type them as machine-learning models and attach the AI metadata.";

/// BSI/G7 SBOM-for-AI Models-cluster remediation.
const REMEDIATION_BSIAI_MODELS: &str = "Declare the BSI/G7 SBOM-for-AI Models minimum elements for each MachineLearningModel component: name, version, a unique identifier (PURL/CPE/SWHID/SWID), a model-weight hash using a NIST-approved algorithm (SHA-256+), a model card, the architecture, training datasets, limitations, and a license.";

/// BSI/G7 SBOM-for-AI Datasets-cluster remediation.
const REMEDIATION_BSIAI_DATASETS: &str = "Declare the BSI/G7 SBOM-for-AI Datasets minimum elements for each Data component: name, a unique identifier, a hash value, a license, a sensitivity classification, and provenance / intended use.";

/// BSI/G7 SBOM-for-AI document/metadata/system/infra/security remediation.
const REMEDIATION_BSIAI_GENERAL: &str = "Declare the BSI/G7 SBOM-for-AI minimum elements: document author, data-format name + version, timestamp, generation tool, and signature; the primary AI system, its producer, and its data-flow/usage; runtime/framework infrastructure links; and AI-specific security controls / exploitability references where they can be expressed.";

/// The declared [`RuleMeta`] of `rule_id` when it is a rule of this
/// family; `None` otherwise.
pub(super) fn declared_rule_meta(rule_id: &str) -> Option<RuleMeta> {
    use StandardKind as K;
    let meta = match rule_id {
        // ---- EU AI Act Annex IV technical-documentation readiness --------
        // The per-element checks below shared one SARIF rule per Annex IV
        // paragraph (SBOM-AIACT-ANNEX-IV-1, -2C, -2D, -2G, -3) until v0.4.0.
        "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1-DESCRIPTION",
            name: "AiActModelDescription",
            short_description: "EU AI Act Annex IV §1: General description of the AI model (description, architecture or model card)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: "Add a general description of the AI model: a description, its architecture family or name, or a model-card reference.",
            advice: Some(&ADVICE_AI_DESCRIPTION),
        },
        "SBOM-AIACT-ANNEX-IV-1-PURPOSE" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-1-PURPOSE",
            name: "AiActIntendedPurpose",
            short_description: "EU AI Act Annex IV §1: Intended purpose and use-cases of the AI model",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §1")],
            remediation: "Document the intended purpose / use-cases of the AI model.",
            advice: Some(&ADVICE_AI_PURPOSE),
        },
        "SBOM-AIACT-ANNEX-IV-2D-DATASETS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D-DATASETS",
            name: "AiActTrainingDatasets",
            short_description: "EU AI Act Annex IV §2(d): Training datasets referenced",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Reference the training datasets used.",
            advice: Some(&ADVICE_AI_DATASETS),
        },
        "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D-SENSITIVITY",
            name: "AiActDatasetSensitivity",
            short_description: "EU AI Act Annex IV §2(d): Sensitivity classification of each dataset",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Declare a sensitivity classification for each dataset (e.g. 'none', 'pii', 'personal').",
            advice: Some(&ADVICE_AI_SENSITIVITY),
        },
        "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2D-PERSONAL-DATA",
            name: "AiActPersonalData",
            short_description: "EU AI Act Annex IV §2(d): Training data involving personal data (GDPR lawful basis and safeguards)",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(d)")],
            remediation: "Where training data involves personal data, document the GDPR lawful basis and data-protection measures alongside the SBOM (AI Act and GDPR apply in parallel).",
            advice: None,
        },
        "SBOM-AIACT-ANNEX-IV-2G-METRICS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2G-METRICS",
            name: "AiActValidationMetrics",
            short_description: "EU AI Act Annex IV §2(g): Validation and testing metrics (accuracy, robustness)",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV §2(g)")],
            remediation: "Record validation/testing metrics (accuracy, robustness).",
            advice: Some(&ADVICE_AI_METRICS),
        },
        // Energy / computational-resources disclosure lives in Annex IV
        // §2(c) ("the computational resources used to develop, train, test
        // and validate the AI system"), NOT §2(g), which covers validation
        // and testing procedures/metrics. Explicit energy reporting is the
        // GPAI technical documentation (Annex XI).
        "SBOM-AIACT-ANNEX-IV-2C-ENERGY" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-2C-ENERGY",
            name: "AiActComputationalResources",
            short_description: "EU AI Act Annex IV §2(c): Computational resources and training-energy disclosure",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §2(c)")],
            remediation: "Disclose computational resources / training energy.",
            advice: Some(&ADVICE_AI_ENERGY),
        },
        "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS" => RuleMeta {
            sarif_id: "SBOM-AIACT-ANNEX-IV-3-LIMITATIONS",
            name: "AiActLimitations",
            short_description: "EU AI Act Annex IV §3: Foreseeable limitations and risks of the model",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::EuAiAct, "Annex IV §3")],
            remediation: "State the foreseeable limitations and risks of the model, including ethical and fairness considerations.",
            advice: Some(&ADVICE_AI_LIMITATIONS),
        },
        "SBOM-AIACT-UNTYPED-ML" => RuleMeta {
            sarif_id: "SBOM-AIACT-UNTYPED-ML",
            name: "AiActUntypedMlContent",
            short_description: "EU AI Act readiness: ML content detected but not typed machine-learning-model",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV: applicability")],
            remediation: REMEDIATION_UNTYPED_ML,
            advice: Some(&ADVICE_UNTYPED_ML),
        },
        // Generic bucket for EU-AI-Act-run findings whose check site has no
        // specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-AIACT-GENERAL" => RuleMeta {
            sarif_id: "SBOM-AIACT-GENERAL",
            name: "AiActGeneralRequirement",
            short_description: "EU AI Act Annex IV: general documentation-readiness requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::EuAiAct, "Annex IV")],
            remediation: "Catch-all for EU AI Act Annex IV findings that have no dedicated rule (no check emits it; the SARIF writer files unmapped findings here). Document the element the finding's requirement names: each model's description and intended purpose, its training datasets and their sensitivity, validation metrics, computational resources, and limitations.",
            advice: None,
        },
        // ---- BSI/G7 SBOM-for-AI Minimum Elements readiness ---------------
        // The element-level checks below shared one SARIF rule per cluster
        // (SBOM-BSIAI-META, -SYS, -MODEL, -DATASET, -INFRA, -SEC) until
        // v0.4.0.
        "SBOM-BSIAI-UNTYPED-ML" => RuleMeta {
            sarif_id: "SBOM-BSIAI-UNTYPED-ML",
            name: "BsiSbomForAiUntypedMlContent",
            short_description: "BSI/G7 SBOM-for-AI readiness: ML content detected but not typed machine-learning-model",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Applicability")],
            remediation: REMEDIATION_UNTYPED_ML,
            advice: Some(&ADVICE_UNTYPED_ML),
        },
        // Metadata cluster
        "SBOM-BSIAI-META-AUTHOR" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-AUTHOR",
            name: "BsiSbomForAiAuthor",
            short_description: "BSI/G7 SBOM-for-AI Metadata: SBOM author",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Author")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_CREATORS),
        },
        "SBOM-BSIAI-META-FORMAT" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-FORMAT",
            name: "BsiSbomForAiDataFormat",
            short_description: "BSI/G7 SBOM-for-AI Metadata: Data-format name and version",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Data format name + version")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        "SBOM-BSIAI-META-TIMESTAMP" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-TIMESTAMP",
            name: "BsiSbomForAiTimestamp",
            short_description: "BSI/G7 SBOM-for-AI Metadata: SBOM timestamp",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Metadata / Timestamp")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_TIMESTAMP),
        },
        "SBOM-BSIAI-META-TOOL" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-TOOL",
            name: "BsiSbomForAiGenerationTool",
            short_description: "BSI/G7 SBOM-for-AI Metadata: Generation tool",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Metadata / Generation tool")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_TOOL),
        },
        "SBOM-BSIAI-META-SIGNATURE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-META-SIGNATURE",
            name: "BsiSbomForAiSignature",
            short_description: "BSI/G7 SBOM-for-AI Metadata: SBOM signature",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Metadata / Signature")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_SIGNATURE),
        },
        // System-Level cluster
        "SBOM-BSIAI-SYS-PRIMARY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS-PRIMARY",
            name: "BsiSbomForAiPrimarySystem",
            short_description: "BSI/G7 SBOM-for-AI System-Level: Primary AI system identified",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "System-Level / Primary AI system")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_PRIMARY),
        },
        "SBOM-BSIAI-SYS-PRODUCER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS-PRODUCER",
            name: "BsiSbomForAiProducer",
            short_description: "BSI/G7 SBOM-for-AI System-Level: Producer of the AI system",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "System-Level / Producer")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_PRODUCER),
        },
        "SBOM-BSIAI-SYS-DATAFLOW" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SYS-DATAFLOW",
            name: "BsiSbomForAiDataFlow",
            short_description: "BSI/G7 SBOM-for-AI System-Level: Data flow and usage of the AI system",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "System-Level / Data flow & usage")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        // Models cluster
        "SBOM-BSIAI-MODEL-NAME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-NAME",
            name: "BsiSbomForAiModelName",
            short_description: "BSI/G7 SBOM-for-AI Models: Model name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model name")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-BSIAI-MODEL-VERSION" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-VERSION",
            name: "BsiSbomForAiModelVersion",
            short_description: "BSI/G7 SBOM-for-AI Models: Model version",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model version")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_VERSION),
        },
        "SBOM-BSIAI-MODEL-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-IDENTIFIER",
            name: "BsiSbomForAiModelIdentifier",
            short_description: "BSI/G7 SBOM-for-AI Models: Unique model identifier (PURL, CPE, SWHID or SWID)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model identifier")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-BSIAI-MODEL-HASH" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-HASH",
            name: "BsiSbomForAiModelHash",
            short_description: "BSI/G7 SBOM-for-AI Models: Model-weight hash value",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Model hash value")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-BSIAI-MODEL-HASH-ALGO" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-HASH-ALGO",
            name: "BsiSbomForAiModelHashAlgorithm",
            short_description: "BSI/G7 SBOM-for-AI Models: Model-weight hash uses a NIST-approved algorithm (SHA-256 or stronger)",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Models / Hash algorithm")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-BSIAI-MODEL-CARD" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-CARD",
            name: "BsiSbomForAiModelCard",
            short_description: "BSI/G7 SBOM-for-AI Models: Model card",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Model card")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_AI_MODEL_CARD),
        },
        "SBOM-BSIAI-MODEL-ARCHITECTURE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-ARCHITECTURE",
            name: "BsiSbomForAiModelArchitecture",
            short_description: "BSI/G7 SBOM-for-AI Models: Model architecture",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Architecture")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_AI_ARCHITECTURE),
        },
        "SBOM-BSIAI-MODEL-DATASETS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-DATASETS",
            name: "BsiSbomForAiModelDatasets",
            short_description: "BSI/G7 SBOM-for-AI Models: Training datasets referenced",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Training datasets")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_AI_TRAINING_DATASETS),
        },
        "SBOM-BSIAI-MODEL-LIMITATIONS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-LIMITATIONS",
            name: "BsiSbomForAiModelLimitations",
            short_description: "BSI/G7 SBOM-for-AI Models: Model limitations",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Limitations")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_AI_LIMITATION),
        },
        "SBOM-BSIAI-MODEL-LICENSE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-MODEL-LICENSE",
            name: "BsiSbomForAiModelLicense",
            short_description: "BSI/G7 SBOM-for-AI Models: Model license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Models / Model license")],
            remediation: REMEDIATION_BSIAI_MODELS,
            advice: Some(&ADVICE_LICENSE),
        },
        // Datasets cluster
        "SBOM-BSIAI-DATASET-NAME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-NAME",
            name: "BsiSbomForAiDatasetName",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Dataset name",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset name")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_NAME),
        },
        "SBOM-BSIAI-DATASET-IDENTIFIER" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-IDENTIFIER",
            name: "BsiSbomForAiDatasetIdentifier",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Unique dataset identifier",
            default_severity: ViolationSeverity::Error,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset identifier")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_IDENTIFIER),
        },
        "SBOM-BSIAI-DATASET-HASH" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-HASH",
            name: "BsiSbomForAiDatasetHash",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Dataset hash value",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset hash value")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_HASH),
        },
        "SBOM-BSIAI-DATASET-LICENSE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-LICENSE",
            name: "BsiSbomForAiDatasetLicense",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Dataset license",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Dataset license")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_LICENSE),
        },
        "SBOM-BSIAI-DATASET-SENSITIVITY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-SENSITIVITY",
            name: "BsiSbomForAiDatasetSensitivity",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Sensitivity classification",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Sensitivity classification")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_AI_SENSITIVITY),
        },
        "SBOM-BSIAI-DATASET-PROVENANCE" => RuleMeta {
            sarif_id: "SBOM-BSIAI-DATASET-PROVENANCE",
            name: "BsiSbomForAiDatasetProvenance",
            short_description: "BSI/G7 SBOM-for-AI Datasets: Provenance and intended use",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Datasets / Provenance & intended use")],
            remediation: REMEDIATION_BSIAI_DATASETS,
            advice: Some(&ADVICE_DATASET_PROVENANCE),
        },
        // Infrastructure cluster
        "SBOM-BSIAI-INFRA-RUNTIME" => RuleMeta {
            sarif_id: "SBOM-BSIAI-INFRA-RUNTIME",
            name: "BsiSbomForAiRuntime",
            short_description: "BSI/G7 SBOM-for-AI Infrastructure: Runtime and framework dependency links",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Infrastructure / Runtime & framework")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: Some(&ADVICE_DEPENDENCIES),
        },
        // Security cluster
        "SBOM-BSIAI-SEC-CONTROLS" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SEC-CONTROLS",
            name: "BsiSbomForAiSecurityControls",
            short_description: "BSI/G7 SBOM-for-AI Security: AI-specific security controls",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Security / AI security controls")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        "SBOM-BSIAI-SEC-EXPLOITABILITY" => RuleMeta {
            sarif_id: "SBOM-BSIAI-SEC-EXPLOITABILITY",
            name: "BsiSbomForAiExploitability",
            short_description: "BSI/G7 SBOM-for-AI Security: Exploitability reference",
            default_severity: ViolationSeverity::Info,
            refs: &[(K::BsiSbomForAi, "Security / Exploitability reference")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        // Generic bucket for BSI/G7-SBOM-for-AI-run findings whose check site
        // has no specific registry mapping (SARIF fallback re-bucketing).
        "SBOM-BSIAI-GENERAL" => RuleMeta {
            sarif_id: "SBOM-BSIAI-GENERAL",
            name: "BsiSbomForAiGeneralRequirement",
            short_description: "BSI/G7 SBOM-for-AI: general minimum-elements requirement",
            default_severity: ViolationSeverity::Warning,
            refs: &[(K::BsiSbomForAi, "Minimum Elements")],
            remediation: REMEDIATION_BSIAI_GENERAL,
            advice: None,
        },
        _ => return None,
    };
    Some(meta)
}
