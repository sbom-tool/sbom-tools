//! Source lines of the elements of an SBOM document.
//!
//! The parsers read straight into the normalized model and keep no source
//! positions, so SARIF output finds them again with one linear pass over the
//! bytes that were already read for parsing:
//!
//! - **JSON** (CycloneDX, SPDX 2.x, SPDX 3.0): an escape-aware byte scan
//!   that tracks the line number. When an object key equals `bom-ref`
//!   (CycloneDX), `SPDXID` (SPDX 2.x), or `spdxId` or `@id` (SPDX 3.0), the
//!   string value that follows is recorded with its line. The line of the
//!   root `metadata` key (CycloneDX) or of the first `creationInfo`
//!   (SPDX) is the document's line; the `bom-ref` of `metadata.component`
//!   is the primary component's.
//! - **XML** (CycloneDX, SPDX RDF/XML): a `quick_xml` reader records each
//!   `bom-ref` attribute (and the fragment of each `rdf:about`) at its byte
//!   offset, turned into a line through a newline index with binary search.
//! - **Tag-value** (SPDX 2.x): the line of each `SPDXID:` tag, skipping the
//!   inside of multi-line `<text>` values the way the parser does.
//!
//! An id that appears more than once keeps its first line. Lines are counted
//! from 1, ending at LF, CRLF or a lone CR. A minified one-line JSON
//! document puts every element on line 1.

use std::collections::HashMap;

/// The line of each element id of an SBOM document (CycloneDX `bom-ref`,
/// SPDX `SPDXID` / `spdxId` / `@id`), plus the lines that stand for the
/// document and its primary component.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SbomLocator {
    ids: HashMap<String, u32>,
    document_line: Option<u32>,
    primary_line: Option<u32>,
}

impl SbomLocator {
    /// Scan `content`, the text of an SBOM document. The syntax is taken
    /// from its first character: `{` or `[` is JSON, `<` is XML, anything
    /// else is SPDX tag-value. Never fails: text it cannot read yields fewer
    /// lines.
    #[must_use]
    pub fn scan(content: &str) -> Self {
        let first = content
            .trim_start_matches('\u{feff}')
            .trim_start()
            .chars()
            .next();
        match first {
            Some('{' | '[') => scan_json(content.as_bytes()),
            Some('<') => scan_xml(content),
            _ => scan_tag_value(content),
        }
    }

    /// The line of the element whose `bom-ref` / `SPDXID` / `spdxId` /
    /// `@id` is `id`: its first occurrence.
    #[must_use]
    pub fn line_of(&self, id: &str) -> Option<u32> {
        self.ids.get(id).copied()
    }

    /// The line that stands for the document: the CycloneDX `metadata`, the
    /// SPDX `creationInfo` (tag-value: the first creation-information tag).
    #[must_use]
    pub const fn document_line(&self) -> Option<u32> {
        self.document_line
    }

    /// The line of the CycloneDX `metadata.component`: its `bom-ref`, else
    /// where the component starts.
    #[must_use]
    pub const fn primary_line(&self) -> Option<u32> {
        self.primary_line
    }

    /// The number of distinct element ids found.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether no element id was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    fn record(&mut self, id: String, line: u32) {
        self.ids.entry(id).or_insert(line);
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// What an object key is, as far as the scan cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    /// `bom-ref`, `SPDXID`, `spdxId` or `@id`: its string value is an id.
    Id,
    Metadata,
    Component,
    CreationInfo,
    /// `type` or `@type`: an SPDX 3.0 `CreationInfo` node marks the document.
    Type,
    Other,
}

/// The container a value of interest opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    /// The root object's `metadata` (CycloneDX).
    Metadata,
    /// `metadata.component` (CycloneDX).
    MetadataComponent,
    Other,
}

struct Frame {
    object: bool,
    tag: Tag,
}

fn classify_key(raw: &[u8], literal: &[u8]) -> Key {
    let classify = |key: &[u8]| match key {
        b"bom-ref" | b"SPDXID" | b"spdxId" | b"@id" => Key::Id,
        b"metadata" => Key::Metadata,
        b"component" => Key::Component,
        b"creationInfo" => Key::CreationInfo,
        b"type" | b"@type" => Key::Type,
        _ => Key::Other,
    };
    if raw.contains(&b'\\') {
        // An escaped key (`"bom-ref"`) means the same as its decoded
        // spelling.
        decode_string(literal).map_or(Key::Other, |key| classify(key.as_bytes()))
    } else {
        classify(raw)
    }
}

/// Decode a JSON string literal (quotes included) exactly as the parser
/// did.
fn decode_string(literal: &[u8]) -> Option<String> {
    serde_json::from_slice(literal).ok()
}

/// The index of the closing quote of the string literal opening at `start`.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn scan_json(bytes: &[u8]) -> SbomLocator {
    let mut found = SbomLocator::default();
    let mut metadata_component_line: Option<u32> = None;
    let mut line: u32 = 1;
    let mut stack: Vec<Frame> = Vec::with_capacity(16);
    // In the innermost object, whether the next string is a key.
    let mut at_key = false;
    // The key just read, waiting for its value.
    let mut pending: Option<(Key, u32)> = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => line += 1,
            b'\r' => {
                if bytes.get(i + 1) != Some(&b'\n') {
                    line += 1;
                }
            }
            open @ (b'{' | b'[') => {
                let tag = match (pending.take(), stack.len(), stack.last().map(|f| f.tag)) {
                    (Some((Key::Metadata, _)), 1, _) => Tag::Metadata,
                    (Some((Key::Component, _)), 2, Some(Tag::Metadata)) => Tag::MetadataComponent,
                    _ => Tag::Other,
                };
                let object = open == b'{';
                stack.push(Frame { object, tag });
                at_key = object;
            }
            b'}' | b']' => {
                stack.pop();
                pending = None;
                at_key = false;
            }
            b',' => {
                pending = None;
                at_key = stack.last().is_some_and(|f| f.object);
            }
            b':' => at_key = false,
            b'"' => {
                let end = string_end(bytes, i);
                let raw = &bytes[i + 1..end.min(bytes.len())];
                let literal = &bytes[i..(end + 1).min(bytes.len())];
                if at_key {
                    let key = classify_key(raw, literal);
                    match key {
                        Key::Metadata if stack.len() == 1 => {
                            found.document_line.get_or_insert(line);
                        }
                        Key::CreationInfo => {
                            found.document_line.get_or_insert(line);
                        }
                        Key::Component
                            if stack.len() == 2
                                && stack.last().is_some_and(|f| f.tag == Tag::Metadata) =>
                        {
                            metadata_component_line.get_or_insert(line);
                        }
                        _ => {}
                    }
                    pending = Some((key, line));
                    at_key = false;
                } else {
                    match pending.take() {
                        Some((Key::Id, _)) => {
                            if let Some(id) = decode_string(literal) {
                                let in_primary = stack.len() == 3
                                    && stack
                                        .last()
                                        .is_some_and(|f| f.tag == Tag::MetadataComponent);
                                if in_primary {
                                    found.primary_line.get_or_insert(line);
                                }
                                found.record(id, line);
                            }
                        }
                        Some((Key::Type, _))
                            if raw == b"CreationInfo" || raw == b"spdx:Core/CreationInfo" =>
                        {
                            found.document_line.get_or_insert(line);
                        }
                        _ => {}
                    }
                }
                // Valid JSON strings hold no raw line breaks, so the scan can
                // jump over the literal without counting lines in it.
                i = end;
            }
            b' ' | b'\t' => {}
            // A number, `true`, `false` or `null` is a value too.
            _ => pending = None,
        }
        i += 1;
    }
    if found.primary_line.is_none() {
        found.primary_line = metadata_component_line;
    }
    found
}

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------

/// Byte offsets of the line terminators of a text, for offset → line.
struct LineIndex {
    breaks: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let bytes = text.as_bytes();
        let breaks = bytes
            .iter()
            .enumerate()
            .filter(|&(i, &b)| b == b'\n' || (b == b'\r' && bytes.get(i + 1) != Some(&b'\n')))
            .map(|(i, _)| i)
            .collect();
        Self { breaks }
    }

    /// The 1-based line of byte `offset`.
    fn line(&self, offset: usize) -> u32 {
        let line = self.breaks.partition_point(|&b| b < offset) + 1;
        u32::try_from(line).unwrap_or(u32::MAX)
    }
}

fn scan_xml(text: &str) -> SbomLocator {
    use quick_xml::events::Event;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Context {
        Metadata,
        MetadataComponent,
        Other,
    }

    let mut found = SbomLocator::default();
    let lines = LineIndex::new(text);
    let base = text.as_ptr() as usize;
    let mut reader = quick_xml::Reader::from_str(text);
    let mut stack: Vec<Context> = Vec::with_capacity(16);
    loop {
        let start = usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
        let (element, opens) = match reader.read_event() {
            Ok(Event::Start(e)) => (e, true),
            Ok(Event::Empty(e)) => (e, false),
            Ok(Event::End(_)) => {
                stack.pop();
                continue;
            }
            Ok(Event::Eof) | Err(_) => break,
            Ok(_) => continue,
        };
        let local = element.local_name();
        let local = local.as_ref();
        let context = match (stack.len(), stack.last(), local) {
            (1, _, "metadata") => {
                found.document_line.get_or_insert(lines.line(start));
                Context::Metadata
            }
            (2, Some(Context::Metadata), "component") => Context::MetadataComponent,
            _ => {
                if local == "CreationInfo" || local == "creationInfo" {
                    found.document_line.get_or_insert(lines.line(start));
                }
                Context::Other
            }
        };
        let mut primary_line = None;
        let mut attributes = element.attributes();
        attributes.with_checks(false);
        for attr in attributes.flatten() {
            let key = attr.key.local_name();
            let is_bom_ref = attr.key.as_ref() == "bom-ref";
            let is_about = matches!(key.as_ref(), "about" | "ID");
            if !is_bom_ref && !is_about {
                continue;
            }
            // Borrowed values point into `text`: the attribute's own line,
            // even when an element spreads its attributes over lines.
            let offset = match &attr.value {
                std::borrow::Cow::Borrowed(value) => {
                    (value.as_ptr() as usize).checked_sub(base).unwrap_or(start)
                }
                std::borrow::Cow::Owned(_) => start,
            };
            let line = lines.line(offset);
            if is_bom_ref {
                let raw = attr.value.to_string();
                if let Ok(value) = attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    && value != raw
                {
                    found.record(value.into_owned(), line);
                }
                found.record(raw, line);
                if context == Context::MetadataComponent {
                    primary_line.get_or_insert(line);
                }
            } else {
                // The SPDX RDF/XML parser takes a package's SPDXID from the
                // fragment of its rdf:about URI (or the last path segment).
                let uri = attr.value.as_ref();
                let id = uri
                    .rfind('#')
                    .or_else(|| uri.rfind('/'))
                    .map_or(uri, |i| &uri[i + 1..]);
                if !id.is_empty() {
                    found.record(id.to_string(), line);
                }
            }
        }
        if context == Context::MetadataComponent {
            let line = primary_line.unwrap_or_else(|| lines.line(start));
            found.primary_line.get_or_insert(line);
        }
        if opens {
            stack.push(context);
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Tag-value
// ---------------------------------------------------------------------------

/// The lines of `text`, ending at LF, CRLF or a lone CR, with their
/// 1-based numbers.
fn numbered_lines(text: &str) -> impl Iterator<Item = (u32, &str)> {
    let mut rest = text;
    let mut number: u32 = 0;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        number = number.saturating_add(1);
        let end = rest.find(['\n', '\r']).unwrap_or(rest.len());
        let line = &rest[..end];
        let skip = match rest.as_bytes().get(end) {
            Some(b'\r') if rest.as_bytes().get(end + 1) == Some(&b'\n') => 2,
            Some(_) => 1,
            None => 0,
        };
        rest = &rest[end + skip..];
        Some((number, line))
    })
}

fn scan_tag_value(text: &str) -> SbomLocator {
    let mut found = SbomLocator::default();
    let mut in_text_block = false;
    for (number, line) in numbered_lines(text) {
        if in_text_block {
            if line.contains("</text>") {
                in_text_block = false;
            }
            continue;
        }
        let Some((tag, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        // A free-form value can span lines inside <text>…</text>; the
        // parser does not read tags inside it, so neither does the scan.
        if let Some(after) = value.strip_prefix("<text>")
            && !after.contains("</text>")
        {
            in_text_block = true;
        }
        match tag.trim() {
            "SPDXID" if !value.is_empty() => found.record(value.to_string(), number),
            "Creator" | "Created" | "CreatorComment" | "LicenseListVersion" => {
                found.document_line.get_or_insert(number);
            }
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_cyclonedx_json() {
        let doc = r#"{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2026-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "bom-ref": "app",
      "name": "app"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "name": "lodash"
    },
    {
      "type": "library",
      "name": "left-pad",
      "bom-ref": "left-pad",
      "components": [ { "bom-ref": "nested", "name": "nested" } ]
    }
  ]
}"#;
        let found = SbomLocator::scan(doc);
        assert_eq!(found.document_line(), Some(4));
        assert_eq!(found.primary_line(), Some(8));
        assert_eq!(found.line_of("app"), Some(8));
        assert_eq!(found.line_of("pkg:npm/lodash@4.17.21"), Some(15));
        assert_eq!(found.line_of("left-pad"), Some(21));
        assert_eq!(found.line_of("nested"), Some(22));
        assert_eq!(found.line_of("lodash"), None, "a name is not an id");
        assert_eq!(found.len(), 4);
    }

    #[test]
    fn minified_json_puts_every_element_on_line_one() {
        let doc = r#"{"bomFormat":"CycloneDX","metadata":{"component":{"bom-ref":"app"}},"components":[{"bom-ref":"a"},{"bom-ref":"b"}]}"#;
        let found = SbomLocator::scan(doc);
        for id in ["app", "a", "b"] {
            assert_eq!(found.line_of(id), Some(1), "{id}");
        }
        assert_eq!(found.document_line(), Some(1));
        assert_eq!(found.primary_line(), Some(1));
    }

    #[test]
    fn escaped_ids_and_keys_decode_like_the_parser() {
        let doc = "{\n\"components\": [\n{\"bom-ref\": \"a\\\"b\\\\c\\u00e9\\/d\"},\n{\"bom\\u002dref\": \"escaped-key\"},\n{\"name\": \"x\\\"bom-ref\\\": {[,:\", \"bom-ref\": \"after-tricky-string\"}\n]\n}";
        let found = SbomLocator::scan(doc);
        assert_eq!(found.line_of("a\"b\\cé/d"), Some(3));
        assert_eq!(found.line_of("escaped-key"), Some(4));
        assert_eq!(
            found.line_of("after-tricky-string"),
            Some(5),
            "a string holding quotes, brackets and the key itself is skipped whole"
        );
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn duplicate_ids_keep_their_first_line() {
        let doc = "{\"components\": [\n{\"bom-ref\": \"dup\"},\n{\"bom-ref\": \"dup\"}\n]}";
        assert_eq!(SbomLocator::scan(doc).line_of("dup"), Some(2));
    }

    #[test]
    fn non_string_values_after_an_id_key_are_not_ids() {
        let doc = "{\"components\": [{\"bom-ref\": 7, \"name\": \"seven\"}, {\"bom-ref\": null}]}";
        let found = SbomLocator::scan(doc);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn crlf_and_lone_cr_end_lines() {
        let doc = "{\r\n\"components\": [\r{\"bom-ref\": \"a\"},\r\n{\"bom-ref\": \"b\"}]}";
        let found = SbomLocator::scan(doc);
        assert_eq!(found.line_of("a"), Some(3));
        assert_eq!(found.line_of("b"), Some(4));
    }

    #[test]
    fn utf8_bom_and_leading_whitespace_are_skipped() {
        let doc = "\u{feff}\n  {\"metadata\": {}, \"components\": [{\"bom-ref\": \"a\"}]}";
        let found = SbomLocator::scan(doc);
        assert_eq!(found.line_of("a"), Some(2));
        assert_eq!(found.document_line(), Some(2));
    }

    #[test]
    fn metadata_counts_only_at_the_root() {
        let doc = "{\n\"components\": [{\"metadata\": {\"component\": {\"bom-ref\": \"x\"}}}],\n\"metadata\": {}\n}";
        let found = SbomLocator::scan(doc);
        assert_eq!(found.document_line(), Some(3));
        assert_eq!(found.primary_line(), None);
        assert_eq!(found.line_of("x"), Some(2));
    }

    #[test]
    fn primary_without_a_bom_ref_points_at_its_component_key() {
        let doc = "{\n\"metadata\": {\n\"component\": {\n\"name\": \"app\"\n}\n}\n}";
        assert_eq!(SbomLocator::scan(doc).primary_line(), Some(3));
    }

    #[test]
    fn spdx2_json() {
        let doc = r#"{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    { "SPDXID": "SPDXRef-Package-a", "name": "a" }
  ]
}"#;
        let found = SbomLocator::scan(doc);
        assert_eq!(found.line_of("SPDXRef-DOCUMENT"), Some(3));
        assert_eq!(found.line_of("SPDXRef-Package-a"), Some(8));
        assert_eq!(found.document_line(), Some(4));
    }

    #[test]
    fn spdx3_json_ld_graph() {
        let doc = r#"{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo"
    },
    {
      "type": "software_Package",
      "spdxId": "urn:spdx:pkg:a",
      "creationInfo": "_:creationinfo"
    }
  ]
}"#;
        let found = SbomLocator::scan(doc);
        assert_eq!(found.document_line(), Some(5));
        assert_eq!(found.line_of("urn:spdx:pkg:a"), Some(10));
        assert_eq!(found.line_of("_:creationinfo"), Some(6));
    }

    #[test]
    fn cyclonedx_xml() {
        let doc = r#"<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <metadata>
    <component type="application" bom-ref="app">
      <name>app</name>
    </component>
  </metadata>
  <components>
    <component type="library"
               bom-ref="pkg:npm/a&amp;b@1">
      <name>a</name>
    </component>
    <component type="library" bom-ref="b"/>
  </components>
</bom>"#;
        let found = SbomLocator::scan(doc);
        assert_eq!(found.document_line(), Some(3));
        assert_eq!(found.primary_line(), Some(4));
        assert_eq!(found.line_of("app"), Some(4));
        assert_eq!(
            found.line_of("pkg:npm/a&b@1"),
            Some(10),
            "the attribute's own line, unescaped"
        );
        assert_eq!(found.line_of("b"), Some(13));
    }

    #[test]
    fn spdx_rdf_xml_takes_the_about_fragment() {
        let doc = r#"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:spdx="http://spdx.org/rdf/terms#">
  <spdx:SpdxDocument rdf:about="https://example.com/doc#SPDXRef-DOCUMENT">
    <spdx:creationInfo>
      <spdx:CreationInfo/>
    </spdx:creationInfo>
    <spdx:describesPackage>
      <spdx:Package rdf:about="https://example.com/doc#SPDXRef-Package-a"/>
    </spdx:describesPackage>
  </spdx:SpdxDocument>
</rdf:RDF>"#;
        let found = SbomLocator::scan(doc);
        assert_eq!(found.line_of("SPDXRef-DOCUMENT"), Some(3));
        assert_eq!(found.line_of("SPDXRef-Package-a"), Some(8));
        assert_eq!(found.document_line(), Some(4));
    }

    #[test]
    fn spdx_tag_value() {
        let doc = "SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nCreator: Tool: x\nCreated: 2026-01-01T00:00:00Z\n\nPackageName: a\nSPDXID: SPDXRef-Package-a\nPackageComment: <text>first\nSPDXID: SPDXRef-inside-text\n</text>\nPackageName: b\n  SPDXID:   SPDXRef-Package-b  \n";
        let found = SbomLocator::scan(doc);
        assert_eq!(found.line_of("SPDXRef-DOCUMENT"), Some(2));
        assert_eq!(found.document_line(), Some(3));
        assert_eq!(found.line_of("SPDXRef-Package-a"), Some(7));
        assert_eq!(
            found.line_of("SPDXRef-inside-text"),
            None,
            "a tag inside a <text> block is text"
        );
        assert_eq!(found.line_of("SPDXRef-Package-b"), Some(12));
    }

    #[test]
    fn unreadable_text_yields_nothing() {
        for doc in [
            "",
            "{",
            "{\"bom-ref\": \"unterminated",
            "{\"components\": [{\"bom-ref\": \"x\\",
            "<bom",
            "<bom bom-ref=\"unterminated",
            "not an sbom",
        ] {
            let found = SbomLocator::scan(doc);
            assert!(found.is_empty(), "{doc}: {found:?}");
            assert!(found.document_line().is_none(), "{doc}");
            assert!(found.primary_line().is_none(), "{doc}");
        }
    }

    #[test]
    fn crlf_between_a_key_and_its_value() {
        let doc = "{\"components\": [{\"bom-ref\":\r\n \"a\"}]}";
        assert_eq!(SbomLocator::scan(doc).line_of("a"), Some(2));
    }

    #[test]
    fn line_index_binary_search() {
        let index = LineIndex::new("a\nb\r\nc\rd");
        assert_eq!(index.line(0), 1);
        assert_eq!(index.line(2), 2);
        assert_eq!(index.line(5), 3);
        assert_eq!(index.line(7), 4);
    }
}
