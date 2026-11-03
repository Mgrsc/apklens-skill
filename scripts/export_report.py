import argparse
import json
import sqlite3
import sys
from pathlib import Path

from static_analysis.common import AnalysisError, diagnostic
from static_analysis.reports import close_report, export_reports, load_report


def main():
    parser = argparse.ArgumentParser(
        description="Export views from an existing local analysis result"
    )
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--view-limit", type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.view_limit <= 1000:
        parser.error("View limit must be between 1 and 1000")
    report = None
    try:
        if args.output.exists():
            raise AnalysisError(
                "Output directory already exists; choose a new directory"
            )
        report = load_report(args.report)
        args.output.mkdir(parents=True, exist_ok=False)
        files = export_reports(
            report, args.output, args.view_limit, write_analysis=False
        )
        print(json.dumps({"status": "COMPLETE", "files": files}, ensure_ascii=True))
        return 0
    except (
        AnalysisError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        sqlite3.Error,
    ) as error:
        diagnostic("export.failed", level="ERROR", status="FAILED", error=str(error))
        return 1
    finally:
        if report is not None:
            close_report(report)


if __name__ == "__main__":
    sys.exit(main())
