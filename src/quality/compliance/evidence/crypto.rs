//! Cryptographic facts, which CNSA 2.0 and NIST PQC read: the component a
//! crypto reference names, what algorithm a component names, and what it
//! declares beside that identity. A crypto reference is a bom-ref (a
//! certificate's signature algorithm, a cipher suite's algorithms, an IKEv2
//! transform's algorithm, a protocol's crypto references), and it names the
//! component whose format id it is.
//!
//! A level classifies only some components: the algorithm assets, and the
//! components the references it judges name. So each component's
//! classification is derived the first time a check reads it, and kept:
//! the two crypto levels of a run classify each component once between
//! them. The verdicts, which need the deadline calendar, stay in the
//! checker (`crypto.rs`), which also defines the classification.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::super::crypto::{Declared, classical_bits_of, classify_crypto_component};
use super::{ComponentIx, ComponentView, SbomEvidence};
use crate::model::{AlgorithmClassification, CryptoProperties, NormalizedSbom};

/// The crypto facts of an SBOM.
pub(crate) struct CryptoFacts<'a> {
    /// Each bom-ref to the component whose format id it is. Where several
    /// components share one, the one the inventory lists last wins, as in
    /// `NormalizedSbomIndex`; an empty format id names nothing.
    bom_refs: HashMap<&'a str, ComponentIx>,
    /// Per component: the algorithm it names, derived on first read.
    algorithms: Box<[OnceLock<AlgorithmClassification>]>,
    /// Per component: what it declares beside that algorithm, derived on
    /// first read.
    declared: Box<[OnceLock<Declared>]>,
}

impl<'a> CryptoFacts<'a> {
    pub(super) fn collect(sbom: &'a NormalizedSbom) -> Self {
        let mut bom_refs = HashMap::with_capacity(sbom.components.len());
        // All components: a crypto reference may name a component of any
        // type, as the SBOM's own index resolves it.
        for (ix, component) in sbom.components.values().enumerate() {
            let format_id = component.identifiers.format_id.as_str();
            if !format_id.is_empty() {
                bom_refs.insert(format_id, ComponentIx(ix));
            }
        }
        let count = sbom.components.len();
        Self {
            bom_refs,
            algorithms: (0..count).map(|_| OnceLock::new()).collect(),
            declared: (0..count).map(|_| OnceLock::new()).collect(),
        }
    }
}

impl<'a> SbomEvidence<'a> {
    /// The component a crypto reference names: the one whose format id
    /// `bom_ref` is (see [`CryptoFacts`]), or `None`.
    pub(crate) fn resolve_bom_ref(&self, bom_ref: &str) -> Option<ComponentView<'_, 'a>> {
        self.crypto()
            .bom_refs
            .get(bom_ref)
            .map(|&ix| self.component(ix))
    }
}

impl<'e, 'a> ComponentView<'e, 'a> {
    /// The component's crypto properties, as read: what the CNSA 2.0 and
    /// NIST PQC checks judge of a cryptographic asset.
    pub(crate) fn crypto_properties(&self) -> Option<&'a CryptoProperties> {
        self.component.crypto_properties.as_ref()
    }

    /// The algorithm the component names: its algorithm properties, OID and
    /// name, classified as the crypto checks classify a crypto asset or the
    /// target of a crypto reference (see `crypto::classify_crypto_component`).
    pub(crate) fn algorithm(&self) -> &'e AlgorithmClassification {
        self.ev.crypto().algorithms[self.ix.0]
            .get_or_init(|| classify_crypto_component(self.component))
    }

    /// What the component declares beside its algorithm's identity: its
    /// primitive, classical security level and elliptic curve, and a
    /// 112-bit digest its identity names (see `crypto::Declared`).
    pub(crate) fn algorithm_declared(&self) -> &'e Declared {
        self.ev.crypto().declared[self.ix.0].get_or_init(|| Declared::of(self.component))
    }

    /// The component's declared classical security level, in bits.
    pub(crate) fn classical_bits(&self) -> Option<u32> {
        classical_bits_of(self.component)
    }
}
