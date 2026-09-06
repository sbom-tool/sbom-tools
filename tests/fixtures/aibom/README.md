# AI-BOM test dataset

Real-world AI-BOMs produced by **third-party** generators, kept verbatim as a
regression corpus for the AI/ML surface of sbom-tools (parsing, AI-readiness
scoring, `bsi-ai` / `ai-act` compliance profiles).

Unlike the hand-written fixtures in `tests/fixtures/cyclonedx/`, nothing here is
authored to make a check pass. These files exercise how other tools actually
emit AI-BOMs in the wild, so drift in our parser or scoring is caught against
documents we do not control.

Run the corpus with:

```bash
./scripts/test-aibom.sh
```

## Provenance

| File | Upstream | Generator |
|------|----------|-----------|
| `Llama-3.2-1B-Instruct.cdx.json` | [manifest-cyber/aibom `examples/Llama-3.2-1B-Instruct.json`](https://github.com/manifest-cyber/aibom/blob/main/examples/Llama-3.2-1B-Instruct.json) | Manifest Cyber `aibom-gen` 0.1.0-alpha.10 |
| `Qwen2.5-7B-Instruct.cdx.json` | [manifest-cyber/aibom `examples/Qwen2.5-7B-Instruct.json`](https://github.com/manifest-cyber/aibom/blob/main/examples/Qwen2.5-7B-Instruct.json) | Manifest Cyber `aibom-gen` 0.1.0-alpha.10 |

Both files were retrieved from upstream commit `bc2cc7a8839ac495c39ff0b982d226b17a079822`
(2026-07-16) and are unmodified apart from the `.cdx.json` extension, which
matches this repo's fixture naming. The upstream repository is Apache-2.0.

## What these two documents cover

CycloneDX 1.5, HuggingFace-sourced, 3 top-level components each
(1 `machine-learning-model` + 2 `library`), with the model carrying **nested**
sub-components:

- weight and config files as nested `type: file` components, each with a hash —
  the flattened component count is therefore much higher than the top-level
  count (36 for Llama, 59 for Qwen);
- training/eval datasets as nested `type: data` components (21 for Llama, 45 for Qwen)
  rather than `modelCard.modelParameters.datasets`;
- a `model-card` external reference pointing back at the HuggingFace repo.

That nesting is the point of including them: it is a spec-legal shape that our
own fixtures did not previously exercise.

## Expected results

`tests/aibom_corpus_tests.rs` pins how sbom-tools reads these files today so
that drift is a deliberate decision:

| File | Flattened components | Nested `type: data` | AI-001 | AI-002 | AI-003 |
|------|---------------------:|--------------------:|:------:|:------:|:------:|
| `Llama-3.2-1B-Instruct.cdx.json` | 36 | 21 | pass | pass | **fail** |
| `Qwen2.5-7B-Instruct.cdx.json`   | 59 | 45 | pass | pass | **fail** |

AI-003 ("Training datasets referenced") fails on both **by policy**. The
Manifest generator declares datasets as bare nested `type: data` components
carrying only `properties` (`usage: training`, `source`, …) and no `data[]`
block. sbom-tools accepts two shapes as training-dataset evidence:

1. `modelCard.modelParameters.datasets` (CycloneDX) / `trainedOn` (SPDX 3.0);
2. dataset components nested under the model **with** a `data[]` block
   (`Component::dataset` evidence).

A bare `type: data` component is not dataset evidence — the same rule the
`bsi-ai` / `ai-act` profiles apply, because CycloneDX `data` also covers
configuration bundles. If Manifest starts emitting `data[]` blocks or
`modelParameters.datasets`, AI-003 will pass and the pinned test must be
updated on purpose.

## Adding to the dataset

Drop a `.cdx.json` / `.cdx.xml` / `.spdx.json` file in this directory, add a row
to the provenance table above with the upstream URL and commit, and confirm the
source license permits redistribution. `scripts/test-aibom.sh` picks up new
files automatically.
