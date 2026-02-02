//! Property-based tests for core model types.
//!
//! Ensures core types handle arbitrary input without panicking,
//! and that key invariants hold across random inputs.

use proptest::prelude::*;
use sbom_tools::model::{LicenseExpression, LicenseFamily};

proptest! {
    // 1000 cases (higher than parser tests) because type invariant checks
    // are fast and benefit from broader input coverage.
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn license_expression_doesnt_panic(s in "\\PC{0,200}") {
        let expr = LicenseExpression::new(s);
        let _ = expr.is_permissive();
        let _ = expr.is_copyleft();
        let _ = expr.family();
        let _ = expr.to_string();
        let _ = expr.is_valid_spdx;
    }

    #[test]
    fn license_family_consistency(s in "\\PC{1,100}") {
        let expr = LicenseExpression::new(s);
        let family = expr.family();
        // If family says Permissive, is_permissive should agree (for valid SPDX)
        if expr.is_valid_spdx {
            match family {
                LicenseFamily::Permissive | LicenseFamily::PublicDomain => {
                    prop_assert!(expr.is_permissive(), "Family {:?} but is_permissive() returned false for {:?}", family, expr);
                }
                LicenseFamily::Copyleft => {
                    prop_assert!(expr.is_copyleft());
                }
                _ => {}
            }
        }
    }

    #[test]
    fn spdx_id_roundtrip(id in "(MIT|Apache-2\\.0|GPL-2\\.0-only|BSD-3-Clause|ISC|Unlicense|MPL-2\\.0)") {
        let expr = LicenseExpression::from_spdx_id(&id);
        prop_assert!(expr.is_valid_spdx, "Known SPDX ID '{}' should be valid", id);
    }

    #[test]
    fn or_expression_most_permissive(
        left in "(MIT|Apache-2\\.0|BSD-3-Clause)",
        right in "(GPL-2\\.0-only|AGPL-3\\.0-only)",
    ) {
        // OR expression: licensee can choose the most permissive option
        let expr = LicenseExpression::new(format!("{} OR {}", left, right));
        prop_assert!(expr.is_valid_spdx);
        prop_assert!(expr.is_permissive(), "OR with permissive branch should be permissive");
        prop_assert_eq!(expr.family(), LicenseFamily::Permissive);
    }

    #[test]
    fn and_expression_most_restrictive(
        left in "(MIT|Apache-2\\.0|BSD-3-Clause)",
        right in "(GPL-2\\.0-only|AGPL-3\\.0-only)",
    ) {
        // AND expression: all requirements must be met
        let expr = LicenseExpression::new(format!("{} AND {}", left, right));
        prop_assert!(expr.is_valid_spdx);
        prop_assert!(expr.is_copyleft(), "AND with copyleft branch should be copyleft");
        prop_assert_eq!(expr.family(), LicenseFamily::Copyleft);
    }

    #[test]
    fn noassertion_is_not_valid(prefix in "\\PC{0,20}") {
        let expr = LicenseExpression::new(format!("{}NOASSERTION{}", prefix, prefix));
        prop_assert!(!expr.is_valid_spdx);
    }

    #[test]
    fn empty_expression_is_not_valid(_dummy in Just(())) {
        let expr = LicenseExpression::new(String::new());
        prop_assert!(!expr.is_valid_spdx);
        prop_assert!(!expr.is_permissive());
        prop_assert!(!expr.is_copyleft());
    }
}
