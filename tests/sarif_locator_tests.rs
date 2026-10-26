//! The SBOM locator against the real parsers: on every SBOM fixture, every
//! component whose id the document states (its CycloneDX `bom-ref`, SPDX
//! `SPDXID` or SPDX 3.0 `spdxId`) is found, on the line that states it.

#[path = "common/sbom_fixtures.rs"]
mod sbom_fixtures;

use sbom_tools::reports::SbomLocator;

/// The 1-based line of the first occurrence of `needle` in `text`.
fn line_of_text(text: &str, needle: &str) -> Option<u32> {
    let offset = text.find(needle)?;
    let breaks = text[..offset]
        .bytes()
        .enumerate()
        .filter(|&(i, b)| b == b'\n' || (b == b'\r' && text.as_bytes().get(i + 1) != Some(&b'\n')))
        .count();
    u32::try_from(breaks + 1).ok()
}

#[test]
fn every_stated_component_id_is_found_on_every_fixture() {
    let fixtures = sbom_fixtures::fixtures();
    assert!(fixtures.len() > 100, "the SBOM fixtures were not found");
    let mut missing = Vec::new();
    let mut found_total = 0usize;
    for fixture in &fixtures {
        let locator = SbomLocator::scan(&fixture.raw);
        for (i, component) in fixture.sbom.components.values().enumerate() {
            let id = &component.identifiers.format_id;
            // A component without a stated id falls back to its name.
            if id.is_empty() || *id == component.name {
                continue;
            }
            match locator.line_of(id) {
                Some(line) => {
                    found_total += 1;
                    assert!(line >= 1, "{}: {id}", fixture.rel);
                    // The id is written on that line (unescaped ids only:
                    // an escaped one is spelled differently in the text).
                    // A text search per id is quadratic, so only the first
                    // components of a fixture are cross-checked.
                    if i < 64
                        && let Some(text_line) = line_of_text(&fixture.raw, id)
                    {
                        assert!(
                            text_line <= line,
                            "{}: {id} is reported on line {line}, but the text first \
                             spells it on line {text_line}",
                            fixture.rel
                        );
                    }
                }
                None => missing.push(format!("{}: {id}", fixture.rel)),
            }
        }
    }
    assert!(found_total > 500, "only {found_total} ids were found");
    assert!(
        missing.is_empty(),
        "{} stated component ids not found:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

/// Every fixture that has CycloneDX `metadata` or SPDX creation information
/// has a document line. (Two minimal CycloneDX XML fixtures have neither;
/// their document-level findings point at line 1.)
#[test]
fn every_fixture_has_a_document_line() {
    let markers = [
        "\"metadata\"",
        "<metadata",
        "creationInfo",
        "CreationInfo",
        "Creator:",
        "Created:",
    ];
    let missing: Vec<String> = sbom_fixtures::fixtures()
        .iter()
        .filter(|f| markers.iter().any(|m| f.raw.contains(m)))
        .filter(|f| SbomLocator::scan(&f.raw).document_line().is_none())
        .map(|f| f.rel.clone())
        .collect();
    assert!(
        missing.is_empty(),
        "fixtures without a document line:\n{}",
        missing.join("\n")
    );
}
