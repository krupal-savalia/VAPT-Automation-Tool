import json
import csv
from typing import List, Dict, Any


class ReportGenerator:
    """Simple legacy report generator providing JSON/CSV output.

    This mirrors the behavior expected by older tests and the original
    project layout.  The newer scanner.reporting.* classes supersede this
    but the legacy API is retained for backwards compatibility.
    """

    def generate_report(self, results: List[Dict[str, Any]], filename: str, fmt: str) -> str:
        fmt = fmt.lower()
        if fmt == "json":
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(results, f)
            return filename
        elif fmt == "csv":
            # collect all keys for header (union of all result dictionaries)
            fieldnames = set()
            for r in results:
                fieldnames.update(r.keys())
            fieldnames = list(fieldnames)
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    writer.writerow(r)
            return filename
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def summary(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        total = len(results)
        counts = {"total": total, "high": 0, "medium": 0, "low": 0}
        for r in results:
            sev = r.get("severity", "").lower()
            if "high" in sev:
                counts["high"] += 1
            elif "medium" in sev:
                counts["medium"] += 1
            elif "low" in sev:
                counts["low"] += 1
        return counts
