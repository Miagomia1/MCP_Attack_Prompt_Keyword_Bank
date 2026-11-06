#!/usr/bin/env python3
"""Rebuild the audited MCP Attack Prompt Keyword Bank from versioned CSV source.

Usage:
    python build_bank.py
    python build_bank.py --output MCP_Keyword_Bank.xlsx

This is a reproducible reconstruction of the supplied workbook's tabular contents.
It does not recreate the original author's undocumented keyword-curation process.
"""
import argparse
import csv
from pathlib import Path
from artifact_tool import Workbook, SpreadsheetFile

BASE = Path(__file__).resolve().parent
SHEETS = [
    ("START HERE", "start_here.csv"),
    ("Keyword Bank", "keywords.csv"),
    ("Detection Rules", "detection_rules.csv"),
    ("Test Samples", "test_samples.csv"),
    ("E1-E6 Mapping", "e1_e6_mapping.csv"),
    ("Field Guide", "field_guide.csv"),
    ("Audit Summary", "audit_summary.csv"),
]
HEADER_COLOR = "#0F766E"
HEADER_TEXT = "#FFFFFF"
FILL_HIGH = "#FFF0B3"
FILL_MEDIUM = "#FFE2C7"
FILL_LOW = "#F8D5E3"


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.reader(fh))


def column_letter(index):
    out = ""
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(65 + rem) + out
    return out


def build(output):
    book = Workbook.create()
    for name, filename in SHEETS:
        rows = read_csv(BASE / "data" / filename)
        if not rows:
            continue
        width = max(map(len, rows))
        matrix = [row + [""] * (width - len(row)) for row in rows]
        sheet = book.worksheets.add(name)
        last_col = column_letter(width)
        sheet.get_range(f"A1:{last_col}{len(matrix)}").values = matrix
        sheet.get_range(f"A1:{last_col}1").format = {
            "fill": HEADER_COLOR,
            "font": {"bold": True, "color": HEADER_TEXT},
            "row_height": 27,
            "wrap_text": True,
        }
        sheet.freeze_panes.freeze_rows(1)
        for col_idx in range(1, width + 1):
            letter = column_letter(col_idx)
            col_width = 26
            if name == "Keyword Bank":
                col_width = {1:12, 2:12, 3:32, 4:35, 5:20, 6:19,
                             7:18, 8:17, 9:41, 10:45, 11:39, 12:20,
                             13:22, 14:55, 15:60, 16:34}.get(col_idx, 26)
            elif name in ("Detection Rules", "E1-E6 Mapping", "Test Samples"):
                col_width = 35 if col_idx < 3 else 48
            else:
                col_width = 31 if col_idx == 1 else 80
            sheet.get_range(f"{letter}1:{letter}{len(matrix)}").format.column_width = col_width
        if name == "Keyword Bank":
            risk_col_idx = rows[0].index("False-Positive Risk")
            for row_idx, row in enumerate(rows[1:], 2):
                risk = row[risk_col_idx].upper()
                color = {"HIGH": FILL_HIGH, "MEDIUM": FILL_MEDIUM,
                         "LOW": FILL_LOW}.get(risk)
                if color:
                    sheet.get_range(f"M{row_idx}").format.fill = color
                    sheet.get_range(f"P{row_idx}").format.fill = color
    output.parent.mkdir(parents=True, exist_ok=True)
    SpreadsheetFile.export_xlsx(book).save(str(output))
    print(f"Wrote {output} ({len(SHEETS)} worksheets)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=BASE / "MCP_Attack_Prompt_Keyword_Bank_Rebuilt.xlsx")
    args = parser.parse_args()
    build(args.output)
