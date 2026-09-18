# Nmap MindMap Injector

**A portable Windows tool that turns raw Nmap and Nessus scan results into an enriched FreeMind mind map in one click, no Python or setup required.**

---

## What it does

During a VAPT engagement we end up with Nmap text output, a Nessus report, and a FreeMind `.mm` file listing the in-scope IPs.
This tool bridges all three:

1. **Parses your Nmap output and/or Nessus export** (`.nessus` XML or `.csv`).
2. **Correlates ports per IP** if the same port appears in both tools, it is added only once. Nmap's richer state info (`open`, `filtered`, etc.) takes priority.
3. **Injects unique ports** as colour-coded child nodes directly under the matching IP node in your FreeMind map.
4. **Optionally annotates each port** with a pre-built library of VAPT test cases scripts to run, CVEs to check, common misconfigurations so every tester starts from the same checklist.
5. **Never overwrites your source map** output goes to a new `*_enriched.mm` file by default, and any existing output gets a timestamped backup before it is replaced.

---

## Key features

| Feature | Detail |
|---|---|
| Nmap support | Standard text output (.txt, .nmap, .log, .out) |
| Nessus support | .nessus v2 XML export and Nessus CSV export |
| Deduplication | Only unique (port, protocol) pairs per IP are added |
| Conflict resolution | Nmap data wins when the same port appears in both tools |
| VAPT test cases | Built-in database of 40+ ports with ready-to-use test scripts |
| Custom test cases | Upload your own JSON file to extend the database at runtime |
| Safe re-runs | Already-present port nodes are detected and skipped |
| Portable | Single .exe no Python, pip, or Nmap needed on the target machine |

---

## How to use it

1. Run `NmapMindmap.exe` (no installation needed).
2. Tick which scan sources you have Nmap, Nessus, or both.
3. Browse to your scan file(s) and your source FreeMind `.mm` map.
4. (Optional) Untick **Add VAPT test cases** if you want ports only.
5. (Optional) Click **Upload extra test cases (JSON)** to load your own checks.
6. Click **Run Injection** the enriched map is saved and the output folder opens.

---

## Extra test cases JSON format

You can extend the built-in test case library by uploading a JSON file:

```json
{
    "tcp": {
        "8080": [
            "Directory brute-force (gobuster)",
            ["Common admin paths", ["/manager/html", "/admin", "/phpmyadmin"]]
        ],
        "9200": ["Elasticsearch unauthenticated access — GET /_cat/indices"]
    },
    "udp": {
        "161": ["SNMP walk: snmpwalk -v2c -c public <IP>"]
    }
}
```

Each entry is either a plain string (leaf node) or `["Parent label", ["child 1", "child 2"]]` (nested node), matching the shape of the built-in database.

---

## Sample activity log

`
[*] Nmap   — 12 host(s), 87 port row(s).
[*] Nessus — 14 host(s), 103 port row(s).
[*] Merged — 14 unique host(s), 97 unique port(s) across both tools.
[OK] Done!
     Nmap hosts parsed   : 12
     Nessus hosts parsed : 14
     Unique ports merged : 97
     Matching map nodes  : 14
     Hosts updated       : 14
     Port nodes added    : 97
     Test Case groups    : 63
     Output              : 23 IPs Firewall - PT_enriched.mm
`

Open the `.mm` file in FreeMind every IP node now has its ports as child nodes,
each colour-coded by state, each with a folded **Test Cases** subtree ready to work through.

---
