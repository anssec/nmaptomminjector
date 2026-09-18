#!/usr/bin/env python3
"""Core logic and command-line interface for Nmap MindMap Injector.

The module is deliberately dependency-free. ``nmap_mindmap_gui.py`` imports
these functions for the desktop application, while this file remains usable
from a terminal:

    python nmap_to_mindmap.py scan.txt assessment.mm --output enriched.mm

When launched without command-line arguments it opens the GUI, making the
source convenient to double-click during development. The portable Windows
release is built from ``nmap_mindmap_gui.py`` and does not require Python on
the recipient's computer.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional
from xml.etree import ElementTree as ET


APP_NAME = "Nmap MindMap Injector"


# Keep the database next to the source during development. PyInstaller sees
# this regular import and bundles it into the portable executable.
try:
    from vapt_db import VAPT_DB, VAPT_DB_UDP
    DB_LOADED = True
except ImportError:
    VAPT_DB: dict[int, list] = {}
    VAPT_DB_UDP: dict[int, list] = {}
    DB_LOADED = False


STATE_COLOR = {
    "open": "#00aa00",
    "filtered": "#ff8800",
    "closed": "#cc0000",
    "open|filtered": "#007799",
    "closed|filtered": "#994400",
}

_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_PORT_ROW_RE = re.compile(
    r"^\s*(\d+)/(tcp|udp|sctp)\s+(\S+)\s+(\S+)", re.IGNORECASE
)


class MindMapInjectorError(Exception):
    """A clear, user-facing processing error."""


@dataclass(frozen=True)
class InjectionSummary:
    """Outcome returned by :func:`inject_nmap_into_mindmap`."""

    scanned_hosts: int
    scanned_ports: int
    matched_hosts: int
    updated_hosts: int
    ports_added: int
    test_case_groups_added: int
    output_path: Path
    backup_path: Optional[Path]
    nmap_hosts: int = 0
    nessus_hosts: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.ports_added or self.test_case_groups_added)


# ── Nmap parsing ──────────────────────────────────────────────────────────────

def _address_from_scan_header(value: str) -> Optional[str]:
    """Extract an IPv4 or IPv6 address from an Nmap report header."""
    value = value.strip()

    # Nmap's common hostname form is: ``host.example (203.0.113.10)``.
    parenthesized = re.search(r"\(([^()]+)\)\s*$", value)
    candidates = []
    if parenthesized:
        candidates.append(parenthesized.group(1).strip())

    # Prefer IPv4 candidates so dotted host names do not accidentally win.
    candidates.extend(match.group(1) for match in _IPV4_RE.finditer(value))
    candidates.extend(token.strip("[](),") for token in value.split())

    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def parse_nmap_output(filepath: str | Path) -> dict[str, list[dict[str, str]]]:
    """Parse regular text Nmap output into ``IP -> port record`` mappings.

    Accepts standard TCP, UDP, and SCTP port-table rows. Nmap XML is not
    supported because the tool intentionally works with the human-readable
    text output that users already keep with their assessment files.
    """
    results: dict[str, list[dict[str, str]]] = {}
    current_ip: Optional[str] = None
    in_port_table = False

    try:
        scan_file = open(filepath, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        raise MindMapInjectorError("Could not read Nmap output: {}".format(exc)) from exc

    with scan_file:
        for raw_line in scan_file:
            line = raw_line.rstrip()
            header = re.search(r"^Nmap scan report for\s+(.+?)\s*$", line, re.IGNORECASE)
            if header:
                current_ip = _address_from_scan_header(header.group(1))
                if current_ip:
                    results.setdefault(current_ip, [])
                in_port_table = False
                continue

            if current_ip is None:
                continue

            columns = line.split()
            if len(columns) >= 3 and [item.upper() for item in columns[:3]] == [
                "PORT", "STATE", "SERVICE"
            ]:
                in_port_table = True
                continue

            if not in_port_table:
                continue

            row = _PORT_ROW_RE.match(line)
            if row:
                results[current_ip].append(
                    {
                        "port": row.group(1),
                        "proto": row.group(2).lower(),
                        "state": row.group(3).lower(),
                        "service": row.group(4),
                    }
                )
            elif not line.strip():
                in_port_table = False

    return results


# ── Nessus parsing ────────────────────────────────────────────────────────────

def parse_nessus_output(filepath: str | Path) -> dict[str, list[dict[str, str]]]:
    """Parse Nessus output into ``IP -> port record`` mappings.

    Supports:

    * ``.nessus`` — Nessus v2 XML export (``NessusClientData_v2``).
    * ``.csv``    — Nessus CSV export with columns Host, Protocol, Port, Name.

    Nessus only reports open/listening ports, so every discovered port is
    labelled ``state = open``.
    """
    path = Path(filepath)
    if not path.is_file():
        raise MindMapInjectorError("Nessus file not found: {}".format(path))
    if path.suffix.lower() == ".csv":
        return _parse_nessus_csv(path)
    return _parse_nessus_xml(path)


def _parse_nessus_xml(path: Path) -> dict[str, list[dict[str, str]]]:
    """Parse a ``.nessus`` (Nessus v2 XML) export file."""
    try:
        tree = ET.parse(str(path))
    except ET.ParseError as exc:
        raise MindMapInjectorError(
            "Failed to parse Nessus XML: {}".format(exc)
        ) from exc
    except OSError as exc:
        raise MindMapInjectorError(
            "Could not read Nessus file: {}".format(exc)
        ) from exc

    results: dict[str, list[dict[str, str]]] = {}
    root = tree.getroot()

    for report_host in root.iter("ReportHost"):
        ip = report_host.get("name", "").strip()

        # Prefer the explicit host-ip tag when the name attribute is a hostname.
        for tag in report_host.iter("tag"):
            if tag.get("name") == "host-ip":
                ip = (tag.text or "").strip()
                break

        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue  # Skip unresolvable hostnames.

        results.setdefault(ip, [])
        seen: set[tuple[str, str]] = {(p["port"], p["proto"]) for p in results[ip]}

        for item in report_host.iter("ReportItem"):
            port = item.get("port", "0").strip()
            proto = item.get("protocol", "tcp").strip().lower()
            svc = item.get("svc_name", "unknown").strip()

            if port == "0" or not port.isdigit():
                continue

            key = (port, proto)
            if key in seen:
                continue
            seen.add(key)

            results[ip].append(
                {
                    "port": port,
                    "proto": proto,
                    "state": "open",
                    "service": svc,
                    "source": "nessus",
                }
            )

    return results


def _parse_nessus_csv(path: Path) -> dict[str, list[dict[str, str]]]:
    """Parse a Nessus CSV export file (Host, Protocol, Port, Name columns)."""
    try:
        raw = open(path, "r", encoding="utf-8", errors="replace", newline="")
    except OSError as exc:
        raise MindMapInjectorError(
            "Could not read Nessus CSV: {}".format(exc)
        ) from exc

    results: dict[str, list[dict[str, str]]] = {}
    seen: dict[str, set[tuple[str, str]]] = {}

    with raw:
        reader = csv.DictReader(raw)
        for row in reader:
            ip = (row.get("Host") or "").strip()
            port = (row.get("Port") or "0").strip()
            proto = (row.get("Protocol") or "tcp").strip().lower()
            svc = (row.get("Name") or "unknown").strip()

            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                continue

            if not port.isdigit() or port == "0":
                continue

            results.setdefault(ip, [])
            seen.setdefault(ip, set())
            key = (port, proto)
            if key in seen[ip]:
                continue
            seen[ip].add(key)

            results[ip].append(
                {
                    "port": port,
                    "proto": proto,
                    "state": "open",
                    "service": svc,
                    "source": "nessus",
                }
            )

    return results


# ── Port map merging ──────────────────────────────────────────────────────────

def merge_port_maps(
    *port_maps: dict[str, list[dict[str, str]]],
) -> dict[str, list[dict[str, str]]]:
    """Merge multiple IP→port maps, keeping only unique ``(port, proto)`` per IP.

    Maps are processed in the order supplied, so the *first* map that provides
    a particular ``(IP, port, proto)`` triple wins.  Pass the Nmap map before
    the Nessus map so Nmap's richer ``state`` information is preserved for
    ports that appear in both tools.
    """
    merged: dict[str, list[dict[str, str]]] = {}

    for pmap in port_maps:
        for ip, ports in pmap.items():
            merged.setdefault(ip, [])
            existing_keys: set[tuple[str, str]] = {
                (p["port"], p["proto"]) for p in merged[ip]
            }
            for port in ports:
                key = (port["port"], port["proto"])
                if key not in existing_keys:
                    merged[ip].append(port)
                    existing_keys.add(key)

    return merged


# ── Extra test-case loader ────────────────────────────────────────────────────

def load_extra_test_cases(json_path: str | Path) -> tuple[int, int]:
    """Merge user-supplied JSON test cases into the in-memory VAPT databases.

    **JSON format**::

        {
            "tcp": {
                "8080": ["Test case 1", ["Parent node", ["child A", "child B"]]],
                "9200": ["Elasticsearch info disclosure"]
            },
            "udp": {
                "161": ["SNMP walk", "Community string brute force"]
            }
        }

    Port numbers must be JSON **string** keys.  Each test-case item is either
    a plain string (leaf node) or a two-element array ``[label, [children]]``
    (parent node with sub-items), matching the shape already used in
    ``vapt_db.py``.

    Returns ``(tcp_ports_merged, udp_ports_merged)``.
    Raises :class:`MindMapInjectorError` on file or parse errors.
    """
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise MindMapInjectorError(
            "Could not read test-case JSON: {}".format(exc)
        ) from exc
    except json.JSONDecodeError as exc:
        raise MindMapInjectorError(
            "Invalid JSON in test-case file: {}".format(exc)
        ) from exc

    if not isinstance(data, dict):
        raise MindMapInjectorError(
            "Test-case JSON must be a top-level object with 'tcp' and/or 'udp' keys."
        )

    tcp_count = 0
    udp_count = 0

    for proto_key, proto_map in data.items():
        proto_lower = proto_key.lower()
        if proto_lower not in ("tcp", "udp"):
            continue
        if not isinstance(proto_map, dict):
            continue

        db = VAPT_DB_UDP if proto_lower == "udp" else VAPT_DB

        for port_str, new_tests in proto_map.items():
            try:
                port_num = int(port_str)
            except ValueError:
                continue
            if not isinstance(new_tests, list):
                continue

            existing = list(db.get(port_num, []))

            # Build a set of all labels already in the existing list
            # (plain strings and the first element of [label, children] pairs).
            existing_labels: set[str] = set()
            for t in existing:
                if isinstance(t, str):
                    existing_labels.add(t)
                elif isinstance(t, (list, tuple)) and t:
                    existing_labels.add(str(t[0]))

            for item in new_tests:
                if isinstance(item, str):
                    if item in existing_labels:
                        continue
                elif isinstance(item, (list, tuple)) and item:
                    if str(item[0]) in existing_labels:
                        continue
                existing.append(item)

            db[port_num] = existing

            if proto_lower == "udp":
                udp_count += 1
            else:
                tcp_count += 1

    return tcp_count, udp_count


# ── Mind map XML helpers ──────────────────────────────────────────────────────

def color_for_state(state: str) -> str:
    return STATE_COLOR.get(state.lower(), "#555555")


def port_label(port: dict[str, str]) -> str:
    return "{}/{} - {} - {}".format(
        port["port"], port["proto"], port["state"], port["service"]
    )


def _normalise_node_text(text: Optional[str]) -> str:
    """Normalise IP labels copied from FreeMind, including non-breaking spaces."""
    return (text or "").replace("\xa0", " ").strip().strip('"').strip()


def _build_tc_nodes(parent_elem: ET.Element, items: list[object]) -> None:
    for item in items:
        if isinstance(item, str):
            child = ET.SubElement(parent_elem, "node")
            child.set("TEXT", item)
            child.set("FOLDED", "true")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            text, children = item
            child = ET.SubElement(parent_elem, "node")
            child.set("TEXT", str(text))
            child.set("FOLDED", "true")
            if children:
                _build_tc_nodes(child, children)


def _has_test_case_node(port_node: ET.Element) -> bool:
    return any(
        child.tag == "node"
        and _normalise_node_text(child.get("TEXT")).lower() == "test cases"
        for child in port_node
    )


def add_vapt_test_cases(port_node: ET.Element, port_number: str, proto: str) -> bool:
    """Attach a Test Cases subtree if the embedded database has an entry."""
    if _has_test_case_node(port_node):
        return False

    database = VAPT_DB_UDP if proto.lower() == "udp" else VAPT_DB
    test_cases = database.get(int(port_number))
    if not test_cases:
        return False

    group = ET.SubElement(port_node, "node")
    group.set("TEXT", "Test Cases")
    group.set("FOLDED", "true")
    font = ET.SubElement(group, "font")
    font.set("BOLD", "true")
    font.set("NAME", "SansSerif")
    font.set("SIZE", "12")
    _build_tc_nodes(group, test_cases)
    return True


def _find_child_node(parent: ET.Element, label: str) -> Optional[ET.Element]:
    for child in parent:
        if child.tag == "node" and child.get("TEXT") == label:
            return child
    return None


# ── Injection ─────────────────────────────────────────────────────────────────

def inject_ports(
    tree: ET.ElementTree,
    ip_ports: dict[str, list[dict[str, str]]],
    *,
    add_test_cases: bool = True,
) -> tuple[int, int, int, int]:
    """Inject ports into matching IP nodes.

    Returns ``(matched_hosts, updated_hosts, ports_added, test_cases_added)``.
    Re-running the tool is safe: exact port labels and Test Cases groups are
    detected before new nodes are added.
    """
    matched_hosts = 0
    updated_hosts = 0
    ports_added = 0
    test_cases_added = 0

    for node in tree.getroot().iter("node"):
        address = _normalise_node_text(node.get("TEXT"))
        if address not in ip_ports:
            continue

        matched_hosts += 1
        host_changed = False
        for port in ip_ports[address]:
            label = port_label(port)
            existing = _find_child_node(node, label)
            if existing is not None:
                if add_test_cases and add_vapt_test_cases(
                    existing, port["port"], port["proto"]
                ):
                    test_cases_added += 1
                    host_changed = True
                continue

            port_node = ET.SubElement(node, "node")
            port_node.set("TEXT", label)
            port_node.set("COLOR", color_for_state(port["state"]))
            port_node.set("STYLE", "fork")
            ports_added += 1
            host_changed = True

            if add_test_cases and add_vapt_test_cases(
                port_node, port["port"], port["proto"]
            ):
                test_cases_added += 1

        if host_changed:
            updated_hosts += 1

    return matched_hosts, updated_hosts, ports_added, test_cases_added


def indent(elem: ET.Element, level: int = 0) -> None:
    """Pretty-print an ElementTree without needing a newer Python version."""
    pad = "\n" + "    " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = pad + "    "
        if not elem.tail or not elem.tail.strip():
            elem.tail = pad
        for child in elem:
            indent(child, level + 1)
        if not elem[-1].tail or not elem[-1].tail.strip():
            elem[-1].tail = pad
    elif level and (not elem.tail or not elem.tail.strip()):
        elem.tail = pad


def _timestamped_backup(path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = path.with_name("{}_backup_{}{}".format(path.stem, stamp, path.suffix))
    counter = 2
    while candidate.exists():
        candidate = path.with_name(
            "{}_backup_{}_{}{}" .format(path.stem, stamp, counter, path.suffix)
        )
        counter += 1
    shutil.copy2(path, candidate)
    return candidate


def _write_tree_atomically(tree: ET.ElementTree, target: Path) -> None:
    """Write a complete temporary map then atomically replace the target."""
    file_descriptor, temp_name = tempfile.mkstemp(
        prefix=".{}_".format(target.stem), suffix=".tmp", dir=str(target.parent)
    )
    os.close(file_descriptor)
    temporary = Path(temp_name)
    try:
        indent(tree.getroot())
        tree.write(str(temporary), encoding="UTF-8", xml_declaration=True)
        os.replace(temporary, target)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def inject_nmap_into_mindmap(
    nmap_file: Optional[str | Path],
    mindmap_file: str | Path,
    output_file: str | Path | None = None,
    log: Optional[Callable[[str], None]] = None,
    *,
    nessus_file: Optional[str | Path] = None,
    add_test_cases: bool = True,
) -> InjectionSummary:
    """Read Nmap and/or Nessus scan files and add results to a FreeMind map.

    At least one of *nmap_file* or *nessus_file* must be supplied.  When both
    are provided, their port lists are correlated per IP and only unique
    ``(port, proto)`` pairs are injected — Nmap data takes precedence, so its
    richer ``state`` information is preserved for ports reported by both tools.

    ``output_file`` defaults to ``mindmap_file`` for CLI compatibility. The
    GUI supplies a separate ``*_enriched.mm`` output by default, so the
    selected source map stays untouched. If an existing file will be
    overwritten, a timestamped sibling backup is created first.
    """
    log = log or (lambda _message: None)
    source_map = Path(mindmap_file)
    target_map = Path(output_file) if output_file else source_map

    if nmap_file is None and nessus_file is None:
        raise MindMapInjectorError(
            "At least one of Nmap output or Nessus file must be provided."
        )

    if not source_map.is_file():
        raise MindMapInjectorError("Mind map file not found: {}".format(source_map))
    if not target_map.parent.is_dir():
        raise MindMapInjectorError(
            "Output folder does not exist: {}".format(target_map.parent)
        )

    # ── Parse supplied scan files ─────────────────────────────────────────
    nmap_ports: dict[str, list[dict[str, str]]] = {}
    nessus_ports: dict[str, list[dict[str, str]]] = {}

    if nmap_file is not None:
        nmap_path = Path(nmap_file)
        if not nmap_path.is_file():
            raise MindMapInjectorError("Nmap file not found: {}".format(nmap_path))
        log("[*] Parsing Nmap output: {}".format(nmap_path.name))
        nmap_ports = parse_nmap_output(nmap_path)
        log("[*] Nmap — {} host(s), {} port row(s).".format(
            len(nmap_ports),
            sum(len(p) for p in nmap_ports.values()),
        ))

    if nessus_file is not None:
        nessus_path = Path(nessus_file)
        log("[*] Parsing Nessus output: {}".format(nessus_path.name))
        nessus_ports = parse_nessus_output(nessus_path)
        log("[*] Nessus — {} host(s), {} port row(s).".format(
            len(nessus_ports),
            sum(len(p) for p in nessus_ports.values()),
        ))

    # ── Merge: Nmap first so its state/service wins on duplicates ─────────
    ip_ports = merge_port_maps(nmap_ports, nessus_ports)
    scanned_hosts = len(ip_ports)
    scanned_ports = sum(len(ports) for ports in ip_ports.values())

    if not ip_ports:
        raise MindMapInjectorError(
            "No scan results were found in the supplied file(s). "
            "For Nmap, select normal text output (not XML). "
            "For Nessus, select a .nessus or .csv export."
        )

    if nmap_file and nessus_file:
        log("[*] Merged — {} unique host(s), {} unique port(s) across both tools.".format(
            scanned_hosts, scanned_ports
        ))

    # ── Parse the source mind map ─────────────────────────────────────────
    try:
        tree = ET.parse(str(source_map))
    except ET.ParseError as exc:
        raise MindMapInjectorError(
            "Failed to parse mind map XML: {}".format(exc)
        ) from exc
    except OSError as exc:
        raise MindMapInjectorError("Could not read mind map: {}".format(exc)) from exc

    matched, updated, ports_added, tests_added = inject_ports(
        tree, ip_ports, add_test_cases=add_test_cases
    )

    summary_kwargs = dict(
        scanned_hosts=scanned_hosts,
        scanned_ports=scanned_ports,
        matched_hosts=matched,
        updated_hosts=updated,
        ports_added=ports_added,
        test_case_groups_added=tests_added,
        output_path=target_map,
        backup_path=None,
        nmap_hosts=len(nmap_ports),
        nessus_hosts=len(nessus_ports),
    )

    summary = InjectionSummary(**summary_kwargs)

    if not summary.changed:
        if matched == 0:
            log("[!] No scanned IP address matched an IP node in the mind map.")
        else:
            log("[OK] All matching entries are already present. No file was changed.")
        return summary

    backup = None
    if target_map.exists():
        try:
            backup = _timestamped_backup(target_map)
        except OSError as exc:
            raise MindMapInjectorError(
                "Could not create backup: {}".format(exc)
            ) from exc
        log("[*] Backup saved: {}".format(backup.name))

    try:
        _write_tree_atomically(tree, target_map)
    except OSError as exc:
        raise MindMapInjectorError("Could not save mind map: {}".format(exc)) from exc

    return InjectionSummary(**{**summary_kwargs, "backup_path": backup})


# ── CLI ───────────────────────────────────────────────────────────────────────

def _print_summary(summary: InjectionSummary) -> None:
    if not summary.changed:
        if summary.matched_hosts == 0:
            print("[!] No scanned IP address matched an IP node in the mind map.")
        else:
            print("[OK] All matching entries are already present. No file was changed.")
        return

    print("[OK] Done!")
    print("     Scanned hosts      : {}".format(summary.scanned_hosts))
    print("     Matching map nodes : {}".format(summary.matched_hosts))
    print("     Hosts updated      : {}".format(summary.updated_hosts))
    print("     Port nodes added   : {}".format(summary.ports_added))
    print("     Test Case groups   : {}".format(summary.test_case_groups_added))
    if summary.backup_path:
        print("     Backup             : {}".format(summary.backup_path))
    print("     Output             : {}".format(summary.output_path))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inject Nmap/Nessus ports and VAPT test cases into a FreeMind (.mm) file.",
        epilog=(
            "Examples:\n"
            "  %(prog)s scan.txt map.mm                        # Nmap only (original usage)\n"
            "  %(prog)s scan.txt map.mm --nessus report.csv   # Nmap + Nessus, unique ports\n"
            "  %(prog)s map.mm --nessus report.nessus          # Nessus only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "nmap_file", nargs="?", default=None,
        help="Plain-text Nmap output file (optional when --nessus is supplied).",
    )
    parser.add_argument("mindmap_file", help="FreeMind (.mm) source file")
    parser.add_argument(
        "--nessus", metavar="FILE",
        help="Nessus export (.nessus XML or .csv) to correlate with Nmap (optional).",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output .mm file. Defaults to updating mindmap_file after making a backup.",
    )
    parser.add_argument(
        "--no-test-cases", action="store_true",
        help="Skip adding VAPT test cases to port nodes.",
    )
    arguments = parser.parse_args(argv)

    if not arguments.nmap_file and not arguments.nessus:
        parser.error("Supply at least a positional Nmap file or --nessus FILE.")

    if not DB_LOADED:
        print("[WARNING] vapt_db.py is unavailable; VAPT test cases will not be added.")

    try:
        summary = inject_nmap_into_mindmap(
            arguments.nmap_file,
            arguments.mindmap_file,
            arguments.output,
            print,
            nessus_file=arguments.nessus,
            add_test_cases=not arguments.no_test_cases,
        )
    except MindMapInjectorError as exc:
        print("[ERROR] {}".format(exc), file=sys.stderr)
        return 1

    _print_summary(summary)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        from nmap_mindmap_gui import launch

        launch()
    else:
        raise SystemExit(main())
