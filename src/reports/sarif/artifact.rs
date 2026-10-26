//! The SBOM file a SARIF run's results point into.
//!
//! GitHub code scanning drops a result that has no physical location, and
//! resolves a relative artifact URI against the repository root. A run
//! therefore names the SBOM by its path relative to a source root — the
//! repository the SBOM lives in, or `--sarif-base` — under the `SRCROOT` URI
//! base id, and every result gives the line of the component it is about.

use super::locator::SbomLocator;
use crate::model::NormalizedSbom;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

/// The URI base id of artifact URIs relative to the source root.
pub const SARIF_SRCROOT: &str = "SRCROOT";

/// The command-line token that reads the SBOM from standard input.
const STDIN_TOKEN: &str = "-";

/// Where an SBOM file is, as a SARIF `artifactLocation`: a URI relative to
/// the `SRCROOT` base, or an absolute one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SarifArtifactLocation {
    uri: String,
    uri_base_id: Option<String>,
}

impl SarifArtifactLocation {
    /// A location relative to the `SRCROOT` base. `uri` must already be a
    /// relative URI reference (`/`-separated, percent-encoded), such as
    /// `sboms/app.cdx.json`.
    #[must_use]
    pub fn relative(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            uri_base_id: Some(SARIF_SRCROOT.to_string()),
        }
    }

    /// A location with no base: `uri` is an absolute URI (`file:///…`), or
    /// `-` for an SBOM read from standard input.
    #[must_use]
    pub fn absolute(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            uri_base_id: None,
        }
    }

    /// The location of the SBOM file at `path`, relative to `base` when one
    /// is given and to the repository the file is in otherwise.
    ///
    /// The repository is the nearest ancestor directory of the file that
    /// holds a `.git` entry (a directory, or a file in a worktree or
    /// submodule); with none, the current directory is the base. Paths are
    /// resolved first, symlinks included, since code scanning cannot show a
    /// result on a symlink. A file outside the base gets an absolute
    /// `file://` URI. `-` (standard input) has no file and stays `-`.
    ///
    /// # Errors
    ///
    /// When `path` or `base` cannot be resolved (does not exist).
    pub fn for_sbom_path(path: &Path, base: Option<&Path>) -> std::io::Result<Self> {
        if path.as_os_str() == STDIN_TOKEN {
            return Ok(Self::absolute(STDIN_TOKEN));
        }
        let file = std::fs::canonicalize(path)?;
        let base = match base {
            Some(base) => Some(std::fs::canonicalize(base)?),
            None => repository_root(&file).or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|dir| std::fs::canonicalize(dir).ok())
            }),
        };
        let relative = base
            .as_deref()
            .and_then(|base| file.strip_prefix(base).ok())
            .filter(|relative| !relative.as_os_str().is_empty());
        Ok(match relative {
            Some(relative) => Self::relative(encode_relative_path(relative)),
            None => Self::absolute(file_uri(&file)),
        })
    }

    /// The URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// `SRCROOT` for a URI relative to the source root, `None` otherwise.
    #[must_use]
    pub fn uri_base_id(&self) -> Option<&str> {
        self.uri_base_id.as_deref()
    }
}

/// The nearest ancestor directory of `file` that holds a `.git` entry.
fn repository_root(file: &Path) -> Option<PathBuf> {
    file.ancestors()
        .skip(1)
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

/// RFC 3986 `pchar` minus `:` (which would read as a scheme in the first
/// segment of a relative reference): kept as is in a path segment.
fn is_segment_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=@".contains(&b)
}

fn push_segment(out: &mut String, segment: &str) {
    use std::fmt::Write as _;
    for b in segment.bytes() {
        if is_segment_char(b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

/// `relative` as a relative URI reference: its segments percent-encoded and
/// joined by `/`.
fn encode_relative_path(relative: &Path) -> String {
    let mut out = String::new();
    for part in relative.components() {
        let Component::Normal(segment) = part else {
            continue;
        };
        if !out.is_empty() {
            out.push('/');
        }
        push_segment(&mut out, &segment.to_string_lossy());
    }
    out
}

/// `file` (absolute, resolved) as a `file://` URI.
fn file_uri(file: &Path) -> String {
    let mut out = String::from("file://");
    for part in file.components() {
        match part {
            Component::Prefix(prefix) => {
                // A Windows drive (`C:`, `\\?\C:`) becomes `/C:`.
                let text = prefix.as_os_str().to_string_lossy();
                let drive = text.trim_start_matches(r"\\?\");
                out.push('/');
                out.push_str(drive);
            }
            Component::Normal(segment) => {
                out.push('/');
                push_segment(&mut out, &segment.to_string_lossy());
            }
            Component::RootDir | Component::CurDir | Component::ParentDir => {}
        }
    }
    if out == "file://" {
        out.push('/');
    }
    out
}

/// Where one component of the SBOM is.
#[derive(Debug, Clone)]
struct ComponentSite {
    /// The line of its `bom-ref` / `SPDXID` / `spdxId`, when the text
    /// states one.
    line: Option<u32>,
    /// Its purl, else its format id: the result's logical location.
    logical_name: String,
}

/// The SBOM file the results of a SARIF run point into: its location, the
/// line that stands for the document, and the line of each component,
/// found by [`SbomLocator`] in the text that was parsed.
#[derive(Debug, Clone)]
pub struct SarifArtifact {
    location: SarifArtifactLocation,
    document_line: u32,
    components: HashMap<String, ComponentSite>,
}

impl SarifArtifact {
    /// Locate the components of `sbom` in `content`, the text it was parsed
    /// from.
    #[must_use]
    pub fn new(location: SarifArtifactLocation, sbom: &NormalizedSbom, content: &str) -> Self {
        Self::from_locator(location, sbom, &SbomLocator::scan(content))
    }

    /// Locate the components of `sbom` with a locator that already scanned
    /// its text.
    #[must_use]
    pub fn from_locator(
        location: SarifArtifactLocation,
        sbom: &NormalizedSbom,
        locator: &SbomLocator,
    ) -> Self {
        let primary = sbom.primary_component_id.as_ref();
        let components = sbom
            .components
            .iter()
            .map(|(id, component)| {
                let line = locator
                    .line_of(&component.identifiers.format_id)
                    .or_else(|| {
                        (Some(id) == primary)
                            .then(|| locator.primary_line())
                            .flatten()
                    });
                let logical_name = component
                    .identifiers
                    .purl
                    .clone()
                    .filter(|purl| !purl.is_empty())
                    .unwrap_or_else(|| component.identifiers.format_id.clone());
                (id.value().to_string(), ComponentSite { line, logical_name })
            })
            .collect();
        Self {
            location,
            document_line: locator.document_line().unwrap_or(1),
            components,
        }
    }

    /// Where the SBOM file is.
    #[must_use]
    pub const fn location(&self) -> &SarifArtifactLocation {
        &self.location
    }

    /// The line results about the whole document point at: the CycloneDX
    /// `metadata` or the SPDX creation information, else line 1.
    #[must_use]
    pub const fn document_line(&self) -> u32 {
        self.document_line
    }

    /// The line of the component whose canonical id is `component_id`, when
    /// the text states its id.
    #[must_use]
    pub fn component_line(&self, component_id: &str) -> Option<u32> {
        self.components.get(component_id).and_then(|site| site.line)
    }

    /// The logical name (purl, else format id) of the component whose
    /// canonical id is `component_id`.
    pub(super) fn logical_name(&self, component_id: &str) -> Option<&str> {
        self.components
            .get(component_id)
            .map(|site| site.logical_name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_are_percent_encoded_uri_references() {
        assert_eq!(
            encode_relative_path(Path::new("sboms/app 1/a:b#c%d.cdx.json")),
            "sboms/app%201/a%3Ab%23c%25d.cdx.json"
        );
        assert_eq!(
            encode_relative_path(Path::new("ünïcode/x.json")),
            "%C3%BCn%C3%AFcode/x.json"
        );
    }

    #[cfg(unix)]
    #[test]
    fn absolute_paths_become_file_uris() {
        assert_eq!(
            file_uri(Path::new("/tmp/my sbom.json")),
            "file:///tmp/my%20sbom.json"
        );
        assert_eq!(file_uri(Path::new("/")), "file:///");
    }

    #[test]
    fn stdin_has_no_file() {
        let location =
            SarifArtifactLocation::for_sbom_path(Path::new("-"), None).expect("stdin location");
        assert_eq!(location.uri(), "-");
        assert_eq!(location.uri_base_id(), None);
    }

    #[test]
    fn a_path_under_the_base_is_relative_to_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let nested = dir.path().join("sboms");
        std::fs::create_dir_all(&nested).expect("mkdir");
        let file = nested.join("app.cdx.json");
        std::fs::write(&file, "{}").expect("write");
        let location =
            SarifArtifactLocation::for_sbom_path(&file, Some(dir.path())).expect("location");
        assert_eq!(location.uri(), "sboms/app.cdx.json");
        assert_eq!(location.uri_base_id(), Some(SARIF_SRCROOT));

        let elsewhere = tempfile::tempdir().expect("temp dir");
        let outside =
            SarifArtifactLocation::for_sbom_path(&file, Some(elsewhere.path())).expect("location");
        assert!(outside.uri().starts_with("file://"), "{}", outside.uri());
        assert!(outside.uri().ends_with("/sboms/app.cdx.json"));
        assert_eq!(outside.uri_base_id(), None);
    }

    #[test]
    fn the_repository_root_is_the_default_base() {
        let repo = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir(repo.path().join(".git")).expect("mkdir .git");
        let dir = repo.path().join("a").join("b");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("bom.json");
        std::fs::write(&file, "{}").expect("write");
        let location = SarifArtifactLocation::for_sbom_path(&file, None).expect("location");
        assert_eq!(location.uri(), "a/b/bom.json");
        // A `.git` file (worktree, submodule) marks a repository too.
        let worktree = repo.path().join("a");
        std::fs::write(worktree.join(".git"), "gitdir: ../.git/worktrees/a").expect("write");
        let location = SarifArtifactLocation::for_sbom_path(&file, None).expect("location");
        assert_eq!(location.uri(), "b/bom.json");
    }

    #[test]
    fn a_missing_file_or_base_is_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(
            SarifArtifactLocation::for_sbom_path(&dir.path().join("missing.json"), None).is_err()
        );
        let file = dir.path().join("bom.json");
        std::fs::write(&file, "{}").expect("write");
        assert!(
            SarifArtifactLocation::for_sbom_path(&file, Some(&dir.path().join("nope"))).is_err()
        );
    }

    #[test]
    fn components_resolve_to_their_lines_and_logical_names() {
        let content = "{\n\"bomFormat\": \"CycloneDX\",\n\"specVersion\": \"1.6\",\n\"metadata\": {\n\"component\": {\"type\": \"application\", \"name\": \"app\"}\n},\n\"components\": [\n{\"type\": \"library\", \"bom-ref\": \"ref-a\", \"name\": \"a\", \"purl\": \"pkg:npm/a@1\"},\n{\"type\": \"library\", \"bom-ref\": \"ref-b\", \"name\": \"b\"}\n]\n}";
        let sbom = crate::parsers::parse_sbom_str(content).expect("parses");
        let artifact =
            SarifArtifact::new(SarifArtifactLocation::relative("bom.json"), &sbom, content);
        assert_eq!(artifact.document_line(), 4);
        let mut by_name = std::collections::HashMap::new();
        for (id, component) in &sbom.components {
            by_name.insert(component.name.clone(), id.value().to_string());
        }
        let a = &by_name["a"];
        assert_eq!(artifact.component_line(a), Some(8));
        assert_eq!(artifact.logical_name(a), Some("pkg:npm/a@1"));
        let b = &by_name["b"];
        assert_eq!(artifact.component_line(b), Some(9));
        assert_eq!(artifact.logical_name(b), Some("ref-b"));
        // The primary component has no bom-ref: its metadata.component line.
        let app = &by_name["app"];
        assert_eq!(artifact.component_line(app), Some(5));
        assert_eq!(artifact.component_line("not-a-component"), None);
    }
}
