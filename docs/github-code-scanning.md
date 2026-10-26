# GitHub code scanning

sbom-tools writes SARIF that GitHub code scanning shows as alerts on the SBOM
file itself: one alert per finding, on the line of the component it is about,
kept across edits that move or reformat the file. This page covers uploading
it and keeping its alerts stable. The SARIF format itself is described in the
[README](../README.md#sarif-and-code-scanning) and, field by field, in
[compliance-output.md](compliance-output.md#sarif).

## Upload from a workflow

`validate` exits `1` when a standard finds errors, so run it, upload the SARIF,
and only then fail the job:

```yaml
name: SBOM compliance

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # upload SARIF
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Install sbom-tools
        run: cargo install sbom-tools --version 0.4.0 --locked

      - name: Validate
        id: validate
        run: |
          set +e
          sbom-tools validate sbom.cdx.json --standard cra,ntia -o sarif -O sbom.sarif
          echo "exit-code=$?" >> "$GITHUB_OUTPUT"

      - name: Upload to code scanning
        if: hashFiles('sbom.sarif') != ''
        uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with:
          sarif_file: sbom.sarif

      - name: Fail on findings
        if: steps.validate.outputs.exit-code != '0'
        env:
          EXIT_CODE: ${{ steps.validate.outputs.exit-code }}
        run: exit "$EXIT_CODE"
```

- **Permissions:** the upload needs `security-events: write`. On a private repository, code scanning also needs GitHub Code Security.
- **Gates:** add `--fail-on-warning` to fail on warnings too. Exit code `3` means a usage or operational error, such as a mistyped standard or an unreadable file. It writes no SARIF, which is why the upload step checks that the file exists. The README lists [every exit code](../README.md#exit-codes).
- **Installing:** `sbom-tools-action` installs and verifies a release binary for you, and passes the SARIF flags through as inputs.

## Categories

GitHub keeps one set of alerts per category, and each upload replaces the set
in its category. sbom-tools names the category itself, in
`runs[].automationDetails.id`:

| Command | Category |
|---|---|
| `validate --standard cra,ntia` | `sbom-tools/cra+ntia/` (standards sorted, joined by `+`) |
| `quality --profile security` | `sbom-tools/quality/security/` |
| `diff` | `sbom-tools/diff/` |
| `view` | `sbom-tools/view/` |

Because the SARIF names its category, `upload-sarif` ignores its own `category`
input. To change the category, pass `--sarif-category` to sbom-tools.

When one workflow checks several SBOMs against the same standards, give each
its own category. Otherwise each upload would replace the other's alerts, and
`upload-sarif` refuses two uploads with the same category in one job:

```sh
sbom-tools validate services/api/sbom.cdx.json --standard cra \
  -o sarif -O api.sarif --sarif-category sbom-tools/cra/api
sbom-tools validate services/web/sbom.cdx.json --standard cra \
  -o sarif -O web.sarif --sarif-category sbom-tools/cra/web
```

Keep a category stable over time. Renaming it opens a new set of alerts, and
the old category's alerts stay open until that category is deleted in the
repository's code scanning settings.

## Where alerts point

- **The file:** each result names the SBOM by its path relative to the
  repository root. That is the nearest directory above the SBOM that holds a
  `.git`, or the directory given with `--sarif-base`.
  - Code scanning can show an alert only on a file in the analysed commit. So
    validate the SBOM where it is checked in, not a copy in a temporary
    directory.
  - An SBOM outside the base is named by an absolute `file://` URI, with a
    warning on stderr, and code scanning cannot place its alerts.
- **The line:** each result points at the line of the component's `bom-ref`,
  `SPDXID`, `spdxId` or `@id`. A finding about the whole document points at the
  CycloneDX `metadata` or the SPDX creation information.
  - A component whose id the file does not state points at line 1.
  - A minified SBOM is one line, so all its alerts are on line 1. They are still
    kept apart by their fingerprints.
- **Monorepos:** an SBOM generated in a subdirectory still resolves to its path
  from the repository root. Use `--sarif-base` only when the checkout root is
  not the repository root.

## Alerts that survive edits

Each result's `partialFingerprints` come from the finding's identity: the
standard, the rule and the component (see
[finding identity](compliance-output.md#finding-identity)). They never come from
its line or wording. Moving, reformatting or regenerating the SBOM therefore
keeps an alert open under the same number, and an alert you dismiss stays
dismissed. When the SBOM is fixed, the alert closes as fixed on the next upload.

## Pull requests

- **`validate` on the PR's SBOM:** code scanning compares the PR's results with
  the base branch's and shows only the new alerts on the PR. That needs an
  upload from a run on the base branch too, which is why the workflow above
  also runs on pushes to `main`.
- **`diff -o sarif` between the base and the PR SBOM:** results point into the
  new SBOM only. A removed component points at the new SBOM's document line,
  and the old SBOM's own compliance findings are not results. `diff -o json`
  keeps both sides.

## Limits

- **Results:** a run holds at most 25,000 results, the most GitHub accepts.
  GitHub shows only the 5,000 most severe. A run that would hold more keeps the
  most severe, and says how many it left out on stderr and in
  `invocations[0].toolExecutionNotifications`. `--sarif-max-results` changes
  the cap; `0` removes it, for other SARIF consumers.
- **File size:** GitHub accepts SARIF files of up to 10 MB gzipped. Even
  uncapped, 50,003 results (a 50,000-component SBOM failing NTIA on every
  component) come to about 4.3 MB gzipped.
- **Passed checks:** these are not results, so they raise no alert.
  `--sarif-include-passes` adds them as `kind: "pass"` results at level `none`.
  Code scanning's handling of non-failing results is not documented, so leave
  them out of uploads.
- **TUI exports:** the TUI's SARIF export carries no physical locations, so code
  scanning drops its results. Use the CLI.

## Upgrading from sbom-tools 0.3

Code scanning showed no alerts from sbom-tools 0.3: its results had no
locations, so GitHub dropped them. The first upload from 0.4 opens one alert per
finding.

If your workflow passed a `category` to `upload-sarif`, that input no longer
applies. Pass the same value with `--sarif-category`, or accept the new default
category.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The upload succeeds but no alerts appear | The SBOM is not in the analysed commit, or is outside the base (`file://` URI) | Validate the checked-in file; check `--sarif-base` |
| `only one run ... per job per tool/category` | Two uploads share a category | Give each a different `--sarif-category` |
| Alerts from another SBOM close | Two SBOMs share a category, so each upload replaces the other's alerts | Give each SBOM its own `--sarif-category` |
| The upload is rejected for too many results | A run over 25,000 results, from `--sarif-max-results 0` or a cap above 25,000 | Use the default cap |
| All alerts are on line 1 | The SBOM is minified, or its components have no `bom-ref` | Pretty-print the SBOM, or give components ids |
| Many new alerts after upgrading from 0.3 | Expected once: 0.3's results had no locations, so code scanning showed none | Triage them once; later uploads keep the same alerts |
