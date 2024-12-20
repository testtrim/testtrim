// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};

use crate::{
    coverage::full_coverage_data::FullCoverageData,
    platform::{TestPlatform, TestReason},
    sys_trace::trace::UnifiedSocketAddr,
};

pub struct NetworkDependency {
    pub socket: UnifiedSocketAddr,
}

pub fn compute_tests_from_network_accesses<TP>(
    coverage_data: &FullCoverageData<TP::TI, TP::CI>,
    all_test_identifiers: &HashSet<TP::TI>,
) -> HashMap<TP::TI, HashSet<TestReason<TP::CI>>>
where
    TP: TestPlatform,
{
    let mut test_cases: HashMap<TP::TI, HashSet<TestReason<TP::CI>>> = HashMap::new();

    for (ci, tests) in coverage_data.coverage_identifier_to_test_map() {
        if let Ok(_network_dependency) = TryInto::<NetworkDependency>::try_into(ci.clone()) {
            for test in tests {
                if all_test_identifiers.contains(test) {
                    test_cases
                        .entry(test.clone())
                        .or_default()
                        .insert(TestReason::CoverageIdentifier(ci.clone()));
                }
            }
        }
    }

    test_cases
}
