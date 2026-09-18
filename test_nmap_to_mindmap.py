"""Regression tests for the dependency-free Nmap MindMap core."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

from nmap_to_mindmap import (
    _address_from_scan_header,
    inject_nmap_into_mindmap,
    inject_ports,
    parse_nmap_output,
)


PROJECT_DIR = Path(__file__).resolve().parent


class NmapMindMapCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.workdir = Path(self._temporary_directory.name)
        self.scan = self.workdir / "scan.txt"
        self.source = self.workdir / "source.mm"
        self.output = self.workdir / "enriched.mm"
        shutil.copy2(PROJECT_DIR / "tcp_scan", self.scan)
        shutil.copy2(PROJECT_DIR / "23 IPs Firewall - PT.mm", self.source)

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def test_parser_reads_sample_scan(self) -> None:
        result = parse_nmap_output(self.scan)

        self.assertEqual(len(result), 8)
        self.assertEqual(sum(len(ports) for ports in result.values()), 25)
        self.assertEqual(result["1.6.66.18"][1], {
            "port": "80",
            "proto": "tcp",
            "state": "open",
            "service": "http",
        })

    def test_address_parser_accepts_hostname_ipv4_and_ipv6_headers(self) -> None:
        self.assertEqual(
            _address_from_scan_header("gateway.example (203.0.113.10)"), "203.0.113.10"
        )
        self.assertEqual(_address_from_scan_header("2001:db8::10"), "2001:db8::10")
        self.assertIsNone(_address_from_scan_header("host-name-only.example"))

    def test_new_output_preserves_source_and_injects_test_cases(self) -> None:
        original_source = self.source.read_bytes()

        summary = inject_nmap_into_mindmap(self.scan, self.source, self.output)

        self.assertTrue(summary.changed)
        self.assertEqual(summary.scanned_hosts, 8)
        self.assertEqual(summary.scanned_ports, 25)
        self.assertEqual(summary.matched_hosts, 8)
        self.assertEqual(summary.ports_added, 25)
        self.assertIsNone(summary.backup_path)
        self.assertEqual(self.source.read_bytes(), original_source)
        self.assertTrue(self.output.is_file())

        tree = ET.parse(self.output)
        host = next(node for node in tree.getroot().iter("node") if node.get("TEXT") == "1.6.66.18")
        port = next(node for node in host if node.get("TEXT") == "80/tcp - open - http")
        self.assertTrue(
            any(node.get("TEXT") == "Test Cases" for node in port if node.tag == "node")
        )

    def test_existing_output_is_backed_up_and_reprocessing_is_idempotent(self) -> None:
        first = inject_nmap_into_mindmap(self.scan, self.source, self.output)
        self.assertTrue(first.changed)
        prior_output = self.output.read_bytes()

        second = inject_nmap_into_mindmap(self.scan, self.source, self.output)
        self.assertTrue(second.changed)
        self.assertIsNotNone(second.backup_path)
        assert second.backup_path is not None
        self.assertEqual(second.backup_path.read_bytes(), prior_output)

        rerun = inject_nmap_into_mindmap(self.scan, self.output, self.output)
        self.assertFalse(rerun.changed)
        self.assertEqual(rerun.matched_hosts, 8)

    def test_unmatched_map_is_a_safe_no_op(self) -> None:
        tree = ET.ElementTree(ET.fromstring('<map><node TEXT="198.51.100.99" /></map>'))
        result = inject_ports(
            tree,
            {"203.0.113.20": [{"port": "80", "proto": "tcp", "state": "open", "service": "http"}]},
        )

        self.assertEqual(result, (0, 0, 0, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
