"""Mutation-style regression tests for the fail-closed Cargo.lock security gate."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from check_dependency_floors import find_violations, parse_version

def lock(*packages):
    return ("version = 4\n\n" + "\n".join(
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        for name, version in packages
    )).encode()

CLEAN = (
    ("rmcp", "3.9.0"),
    ("quinn-proto", "0.11.19"),
    ("quinn-udp", "0.5.16"),
    ("rustls", "0.23.46"),
    ("rustls-webpki", "0.103.16"),
    ("webpki-roots", "1.0.10"),
    ("tokio", "1.47.2"),
)

class DependencyFloorTests(unittest.TestCase):
    def test_clean_floors(self):
        self.assertEqual([], find_violations(lock(*CLEAN)))

    def test_parallel_legacy_rmcp_versions_rejected(self):
        problems = find_violations(lock(*CLEAN, ("rmcp", "2.2.0"), ("rmcp", "3.1.4")))
        self.assertEqual(2, sum("requires >= 3.9.0" in p for p in problems))

    def test_each_known_vulnerable_entry_rejected(self):
        old = (
            ("rmcp", "2.2.0"),
            ("quinn-proto", "0.11.17"),
            ("quinn-udp", "0.5.15"),
            ("rustls", "0.23.45"),
            ("rustls-webpki", "0.103.15"),
            ("webpki-roots", "1.0.9"),
            ("pin-utils", "0.1.0"),
            ("tokio", "1.47.1"),
        )
        self.assertEqual(8, len(find_violations(lock(*old))))

    def test_quinn_udp_vulnerable_gap(self):
        for version in ("0.5.15", "0.6.0", "0.6.1", "0.6.2"):
            with self.subTest(version=version):
                self.assertTrue(find_violations(lock(("rmcp", "3.9.0"), ("quinn-udp", version))))
        for version in ("0.5.16", "0.6.3"):
            with self.subTest(version=version):
                self.assertEqual([], find_violations(lock(("rmcp", "3.9.0"), ("quinn-udp", version))))

    def test_missing_rmcp_fails_closed(self):
        self.assertTrue(any("missing rmcp" in p for p in find_violations(lock(("tokio", "1.47.2")))))

    def test_invalid_lockfile_fails_closed(self):
        for candidate in (b"not toml = [", b"", b"version = 4\n", b"\xff"):
            self.assertTrue(find_violations(candidate))

    def test_prerelease_needs_explicit_review(self):
        self.assertTrue(find_violations(lock(("rmcp", "3.9.0-beta.1"))))
        with self.assertRaises(ValueError):
            parse_version("3.9.0-beta.1")

    def test_duplicate_identity_fails_closed(self):
        self.assertTrue(any("duplicate" in x for x in find_violations(lock(*CLEAN, ("rmcp", "3.9.0")))))

if __name__ == "__main__":
    unittest.main()
