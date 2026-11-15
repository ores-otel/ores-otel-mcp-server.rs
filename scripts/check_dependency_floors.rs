//! Fail-closed, std-only guard for known vulnerable Cargo.lock dependency floors.
//!
//! This is defense in depth, NOT a substitute for cargo audit --deny warnings.
//! CI first runs cargo metadata --locked to validate the complete Cargo format
//! and dependency graph; this guard then checks every locked copy of a crate.

use std::{
    collections::BTreeSet,
    env, fs,
    path::Path,
    process::ExitCode,
};

const MAX_LOCK_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u64, u64, u64);

impl Version {
    fn parse(input: &str) -> Result<Self, String> {
        let parts = input.split('.').collect::<Vec<_>>();
        if parts.len() != 3
            || parts.iter().any(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| byte.is_ascii_digit())
                    || (part.len() > 1 && part.starts_with('0'))
            })
        {
            return Err(format!("non-stable or malformed version {input:?}"));
        }
        let numbers = parts
            .iter()
            .map(|part| part.parse::<u64>().map_err(|_| "version integer overflow".to_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(numbers[0], numbers[1], numbers[2]))
    }
}

#[derive(Default)]
struct Package {
    name: Option<String>,
    version: Option<String>,
}

fn toml_literal(line: &str, key: &str) -> Result<String, String> {
    let value = line
        .strip_prefix(key)
        .ok_or_else(|| format!("missing {key} field"))?
        .trim();
    let quoted = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(|| format!("{key} must be a quoted literal"))?;
    if quoted.is_empty() || quoted.contains(['"', '\\', '\n', '\r']) {
        return Err(format!("{key} must be a nonempty plain literal"));
    }
    Ok(quoted.to_owned())
}

fn finish_package(
    current: Option<Package>,
    packages: &mut Vec<(String, String)>,
) -> Result<(), String> {
    if let Some(package) = current {
        let name = package
            .name
            .ok_or_else(|| "package missing name".to_owned())?;
        let version = package
            .version
            .ok_or_else(|| format!("{name}: package missing version"))?;
        packages.push((name, version));
    }
    Ok(())
}

/// Parses only machine-generated Cargo.lock package identities.
/// Cargo metadata --locked must run before this check in CI to establish
/// the full TOML and dependency graph validity.
fn package_identities(lock: &str) -> Result<Vec<(String, String)>, String> {
    if lock.len() > MAX_LOCK_BYTES {
        return Err("Cargo.lock exceeds 32 MiB scan limit".to_owned());
    }
    let mut packages = Vec::new();
    let mut current: Option<Package> = None;
    let mut saw_table = false;
    for (i, raw) in lock.lines().enumerate() {
        let line = raw.trim();
        if line == "[[package]]" {
            finish_package(current.take(), &mut packages)?;
            current = Some(Package::default());
            saw_table = true;
        } else if line.starts_with('[') && line.ends_with(']') {
            finish_package(current.take(), &mut packages)?;
        } else if let Some(package) = current.as_mut() {
            if line.starts_with("name =") {
                if package.name.replace(toml_literal(line, "name =")?).is_some() {
                    return Err(format!("line {}: duplicate package.name", i + 1));
                }
            } else if line.starts_with("version =") {
                if package
                    .version
                    .replace(toml_literal(line, "version =")?)
                    .is_some()
                {
                    return Err(format!("line {}: duplicate package.version", i + 1));
                }
            }
        }
    }
    finish_package(current, &mut packages)?;
    if !saw_table || packages.is_empty() {
        return Err("Cargo.lock must contain [[package]] records".to_owned());
    }
    let mut seen = BTreeSet::new();
    for (name, version) in &packages {
        if !seen.insert((name.as_str(), version.as_str())) {
            return Err(format!("duplicate package identity: {name}@{version}"));
        }
    }
    Ok(packages)
}

fn floor_errors(packages: &[(String, String)]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut found_rmcp = false;
    for (name, version) in packages {
        if name == "rmcp" {
            found_rmcp = true;
        }
        let relevant = matches!(
            name.as_str(),
            "rmcp" | "quinn-proto" | "quinn-udp" | "rustls"
                | "rustls-webpki" | "webpki-roots" | "pin-utils" | "tokio"
        );
        if !relevant {
            continue;
        }
        let parsed = match Version::parse(version) {
            Ok(value) => value,
            Err(message) => {
                errors.push(format!("{name}@{version}: {message}"));
                continue;
            }
        };
        let floor = match name.as_str() {
            "rmcp" => Some(Version(3, 9, 0)),
            "quinn-proto" => Some(Version(0, 11, 19)),
            "rustls" => Some(Version(0, 23, 46)),
            "rustls-webpki" => Some(Version(0, 103, 16)),
            _ => None,
        };
        if let Some(required) = floor {
            if parsed < required {
                errors.push(format!(
                    "{name}@{version}: requires >= {}.{}.{} (all copies)",
                    required.0, required.1, required.2
                ));
            }
        }
        match name.as_str() {
            "quinn-udp"
                if parsed < Version(0, 5, 16)
                    || (Version(0, 6, 0) <= parsed && parsed < Version(0, 6, 3)) =>
            {
                errors.push(format!(
                    "quinn-udp@{version}: requires >=0.5.16,<0.6.0 or >=0.6.3"
                ));
            }
            "webpki-roots" if parsed.0 == 1 && parsed < Version(1, 0, 10) => {
                errors.push(format!("webpki-roots@{version}: requires >=1.0.10 on 1.x"));
            }
            "pin-utils" => {
                errors.push(format!("pin-utils@{version}: unmaintained; remove dependency"));
            }
            "tokio" if parsed <= Version(1, 47, 1) => {
                errors.push(format!("tokio@{version}: affected I/O safety baseline; re-audit"));
            }
            _ => {}
        }
    }
    if !found_rmcp {
        errors.push("missing rmcp package: check lock completeness".to_owned());
    }
    errors
}

fn scan(lock: &str) -> Result<Vec<String>, String> {
    Ok(floor_errors(&package_identities(lock)?))
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _executable = args.next();
    let Some(path) = args.next() else {
        eprintln!("usage: check_dependency_floors <Cargo.lock>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: check_dependency_floors <Cargo.lock>");
        return ExitCode::from(2);
    }
    let path = Path::new(&path);
    let bytes = match fs::read(path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("[security-floor] cannot read Cargo.lock: {error}");
            return ExitCode::from(2);
        }
    };
    let lock = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("[security-floor] Cargo.lock is not UTF-8");
            return ExitCode::from(2);
        }
    };
    match scan(&lock) {
        Ok(errors) if errors.is_empty() => {
            println!("[security-floor] known floors clear; cargo audit --deny warnings required");
            ExitCode::SUCCESS
        }
        Ok(errors) => {
            for error in &errors {
                eprintln!("[security-floor] FAIL: {error}");
            }
            eprintln!("[security-floor] {} dependency violations", errors.len());
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("[security-floor] malformed lockfile: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &[(&str, &str)] = &[
        ("rmcp", "3.9.0"),
        ("quinn-proto", "0.11.19"),
        ("quinn-udp", "0.5.16"),
        ("rustls", "0.23.46"),
        ("rustls-webpki", "0.103.16"),
        ("webpki-roots", "1.0.10"),
        ("tokio", "1.47.2"),
    ];

    fn fixture(packages: &[(&str, &str)]) -> String {
        let mut text = String::from("version = 4\n\n");
        for (name, version) in packages {
            text.push_str(&format!(
                "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n\n"
            ));
        }
        text
    }

    #[test]
    fn accepts_fixed_floors() {
        assert!(scan(&fixture(CLEAN)).unwrap().is_empty());
    }

    #[test]
    fn rejects_multiple_old_rmcp_versions_even_when_fixed_version_exists() {
        let mut rows = CLEAN.to_vec();
        rows.extend([("rmcp", "2.2.0"), ("rmcp", "3.1.4")]);
        let violations = scan(&fixture(&rows)).unwrap();
        assert_eq!(violations.iter().filter(|v| v.contains("requires >= 3.9.0")).count(), 2);
    }

    #[test]
    fn rejects_all_eight_known_vulnerable_crate_families() {
        let rows = [
            ("rmcp", "2.2.0"),
            ("quinn-proto", "0.11.17"),
            ("quinn-udp", "0.5.15"),
            ("rustls", "0.23.45"),
            ("rustls-webpki", "0.103.15"),
            ("webpki-roots", "1.0.9"),
            ("pin-utils", "0.1.0"),
            ("tokio", "1.47.1"),
        ];
        assert_eq!(scan(&fixture(&rows)).unwrap().len(), rows.len());
    }

    #[test]
    fn rejects_quinn_udp_patch_gap() {
        for value in ["0.5.15", "0.6.0", "0.6.1", "0.6.2"] {
            assert!(!scan(&fixture(&[("rmcp", "3.9.0"), ("quinn-udp", value)])).unwrap().is_empty());
        }
        for value in ["0.5.16", "0.6.3"] {
            assert!(scan(&fixture(&[("rmcp", "3.9.0"), ("quinn-udp", value)])).unwrap().is_empty());
        }
    }

    #[test]
    fn rejects_missing_rmcp() {
        assert!(scan(&fixture(&[("tokio", "1.47.2")]))
            .unwrap()
            .iter()
            .any(|message| message.contains("missing rmcp")));
    }

    #[test]
    fn rejects_missing_or_malformed_package_records() {
        for text in ["", "version = 4\n", "[[package]]\nname = \"rmcp\"", "[[package]]\nversion = \"3.9.0\""] {
            assert!(scan(text).is_err(), "accepted malformed {text:?}");
        }
    }

    #[test]
    fn rejects_prerelease_and_numeric_overflow() {
        for version in ["3.9.0-beta.1", "3.9.0+build", "3.9", "3.9.0.1", "3.9.18446744073709551616"] {
            assert!(!scan(&fixture(&[("rmcp", version)])).unwrap().is_empty());
        }
    }

    #[test]
    fn rejects_duplicate_package_identity() {
        let mut rows = CLEAN.to_vec();
        rows.push(("rmcp", "3.9.0"));
        assert!(scan(&fixture(&rows)).is_err());
    }

    #[test]
    fn rejects_duplicate_package_fields() {
        let text = "[[package]]\nname = \"rmcp\"\nname = \"rmcp\"\nversion = \"3.9.0\"\n";
        assert!(scan(text).is_err());
    }

    #[test]
    fn allows_old_zero_x_root_store_branch() {
        assert!(scan(&fixture(&[("rmcp", "3.9.0"), ("webpki-roots", "0.26.11")]))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rejects_oversized_lockfile() {
        assert!(scan(&" ".repeat(MAX_LOCK_BYTES + 1)).is_err());
    }
}
