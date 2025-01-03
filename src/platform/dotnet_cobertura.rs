// SPDX-FileCopyrightText: 2024 Mathieu Fenniak <mathieu@fenniak.net>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Coverage {
    // #[serde(rename = "@line-rate", default)]
    // line_rate: f64,
    // #[serde(rename = "@branch-rate", default)]
    // branch_rate: f64,
    // #[serde(rename = "@version", default)]
    // version: String,
    // #[serde(rename = "@timestamp", default)]
    // timestamp: String,
    // #[serde(rename = "@lines-covered", default)]
    // lines_covered: u32,
    // #[serde(rename = "@lines-valid", default)]
    // lines_valid: u32,
    // #[serde(rename = "@branches-covered", default)]
    // branches_covered: u32,
    // #[serde(rename = "@branches-valid", default)]
    // branches_valid: u32,
    // #[serde(default)]
    // sources: Sources,
    #[serde(default)]
    pub packages: Packages,
}

// #[derive(Debug, Deserialize, Default)]
// struct Sources {
//     #[serde(rename = "source", default)]
//     source: Vec<String>,
// }

#[derive(Debug, Deserialize, Default)]
pub struct Packages {
    #[serde(rename = "package", default)]
    pub package: Vec<Package>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Package {
    #[serde(rename = "@name", default)]
    pub name: String,
    // TODO: external dependency tracking
    // #[serde(rename = "@line-rate", default)]
    // pub line_rate: f64,
    // #[serde(rename = "@branch-rate", default)]
    // branch_rate: f64,
    // #[serde(rename = "@complexity", default)]
    // complexity: u32,
    #[serde(rename = "classes", default)]
    pub classes: Classes,
}

#[derive(Debug, Deserialize, Default)]
pub struct Classes {
    #[serde(rename = "class", default)]
    pub class: Vec<Class>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Class {
    // Note: class with the same "name" can appear multiple times with different "filename" if it is a `partial` class.
    #[serde(rename = "@name", default)]
    pub name: String,
    #[serde(rename = "@filename", default)]
    pub filename: String,
    #[serde(rename = "@line-rate", default)]
    pub line_rate: f64,
    // #[serde(rename = "@branch-rate", default)]
    // branch_rate: f64,
    // #[serde(rename = "@complexity", default)]
    // complexity: u32,
    // #[serde(rename = "methods", default)]
    // methods: Methods,
}

// #[derive(Debug, Deserialize, Default)]
// struct Methods {
//     #[serde(rename = "method", default)]
//     method: Vec<Method>,
// }

// #[derive(Debug, Deserialize, Default)]
// struct Method {
//     #[serde(rename = "name", default)]
//     name: String,
//     #[serde(rename = "signature", default)]
//     signature: String,
//     #[serde(rename = "line-rate", default)]
//     line_rate: f64,
//     #[serde(rename = "branch-rate", default)]
//     branch_rate: f64,
//     #[serde(rename = "complexity", default)]
//     complexity: u32,
//     #[serde(rename = "lines", default)]
//     lines: Lines,
// }

// #[derive(Debug, Deserialize, Default)]
// struct Lines {
//     #[serde(rename = "line", default)]
//     line: Vec<Line>,
// }

// #[derive(Debug, Deserialize)]
// struct Line {
//     #[serde(rename = "number", default)]
//     number: u32,
//     #[serde(rename = "hits", default)]
//     hits: u32,
//     #[serde(rename = "branch", default)]
//     branch: String, // can be converted to bool with custom deserialization if necessary
// }

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::platform::dotnet_cobertura::Coverage;

    #[test]
    fn parse_cobertura() -> Result<()> {
        let cobertura = include_str!("../../tests/test_data/coverage.cobertura.xml");
        let coverage: Coverage = quick_xml::de::from_str(cobertura)?;

        println!("coverage: {coverage:?}");
        // assert_eq!(coverage.line_rate, 0.21109999999999998);
        assert_eq!(coverage.packages.package.len(), 17);

        let pkg = &coverage.packages.package[0];
        assert_eq!(pkg.name, "Microsoft.VisualStudio.TestPlatform.ObjectModel");
        // assert!((pkg.line_rate - 0.3411).abs() < 0.01, "line_rate == 0.3411"); // TODO: external dependency tracking

        let pkg = &coverage.packages.package[12];
        assert_eq!(pkg.name, "MathFunctions");
        // assert!((pkg.line_rate - 0.9565).abs() < 0.01, "line_rate == 0.9565"); // TODO: external dependency tracking

        assert_eq!(pkg.classes.class.len(), 2);

        let cls = &pkg.classes.class[0];
        assert_eq!(cls.name, "MathFunctions.BasicOps");
        assert_eq!(
            cls.filename,
            "home/mfenniak/Dev/testtrim-test-projects/dotnet-coverage-specimen/MathFunctions/BasicOps.cs"
        );
        assert!((cls.line_rate - 1.0).abs() < 0.01, "line_rate == 1.0");

        Ok(())
    }
}
