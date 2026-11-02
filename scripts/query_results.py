import argparse
import json
import sys

from static_analysis.common import AnalysisError, diagnostic
from static_analysis.reports import SECTIONS, load_report, query, summary


def main():
    parser = argparse.ArgumentParser(
        description="Query local static analysis results without rerunning the analysis"
    )
    parser.add_argument("report")
    parser.add_argument("--section", choices=("summary", *SECTIONS), default="summary")
    parser.add_argument("--package")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--id")
    parser.add_argument("--contains")
    parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Return local original values; do not send them to a remote model without authorization",
    )
    args = parser.parse_args()
    if args.offset < 0 or not 1 <= args.limit <= 500:
        parser.error("Offset must be nonnegative and limit must be between 1 and 500")
    if args.section == "summary" and any(
        (args.package, args.id, args.contains, args.offset, args.include_sensitive)
    ):
        parser.error(
            "Use a specific section for filtering, pagination, or sensitive values"
        )
    try:
        report = load_report(args.report)
        result = (
            summary(report)
            if args.section == "summary"
            else query(
                report,
                args.section,
                args.package,
                args.offset,
                args.limit,
                args.id,
                args.contains,
                args.include_sensitive,
            )
        )
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (AnalysisError, OSError, ValueError, KeyError, TypeError) as error:
        diagnostic("query.failed", level="ERROR", status="FAILED", error=str(error))
        return 1


if __name__ == "__main__":
    sys.exit(main())
