#!/usr/bin/env python3
"""Defensive seed-indicator matching against MCP JSONL logs.

This emits candidate matches, NOT attack verdicts. For real detection, enrich with
authorization policy, trusted source, request-response sequence and independent
outcome verification. Avoid scanning real credentials unless appropriately protected.

Usage:
  python scan_mcp_logs.py examples/example_mcp_logs.jsonl --output matches.csv
"""
import argparse
import csv
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent


def load_keywords():
    with (BASE / "data" / "keywords.csv").open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def readable_surfaces(event):
    """Extract MCP content and tool arguments, avoiding unrelated metadata."""
    payload = event.get("raw_payload") or event.get("payload") or event
    params = payload.get("params", {}) if isinstance(payload, dict) else {}
    result = payload.get("result", {}) if isinstance(payload, dict) else {}
    surfaces = {}
    if isinstance(params, dict):
        surfaces["tool_arguments"] = json.dumps(params.get("arguments", {}), ensure_ascii=False)
        surfaces["tool_metadata"] = json.dumps(params.get("tools", []), ensure_ascii=False)
    if isinstance(result, (dict, list)):
        surfaces["tool_result"] = json.dumps(result, ensure_ascii=False)
    return surfaces


def scan(log_path, output):
    keywords = load_keywords()
    records = []
    with log_path.open(encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Ignoring malformed JSON at line {line_number}: {exc}")
                continue
            for surface_name, value in readable_surfaces(event).items():
                lowered = value.casefold()
                if not lowered or lowered in ("{}", "[]"):
                    continue
                for kw in keywords:
                    literal = kw["Keyword / Phrase"]
                    if literal and literal.casefold() in lowered:
                        records.append({
                            "line": line_number,
                            "server": event.get("server", ""),
                            "direction": event.get("direction", ""),
                            "surface": surface_name,
                            "keyword_id": kw["ID"],
                            "keyword": literal,
                            "scenarios": kw["Scenario(s)"],
                            "false_positive_risk": kw["False-Positive Risk"],
                            "verdict": "candidate_indicator_only",
                        })
    fields = ["line", "server", "direction", "surface", "keyword_id", "keyword",
              "scenarios", "false_positive_risk", "verdict"]
    with output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    print(f"Wrote {len(records)} candidate keyword hits to {output}; these are not confirmed attacks.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--output", type=Path, default=Path("matches.csv"))
    args = parser.parse_args()
    scan(args.jsonl, args.output)
