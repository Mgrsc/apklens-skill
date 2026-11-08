import argparse
import json
import sqlite3
import sys
from pathlib import Path

from static_analysis.advice_reporting import (
    render_assessment,
    validate_delivery,
)
from static_analysis.assessment import prepare_assessment
from static_analysis.common import (
    AnalysisError,
    atomic_json,
    atomic_text,
    diagnostic,
    read_json,
)
from static_analysis.endpoints import sanitized
from static_analysis.reports import close_report, load_report


def main():
    parser = argparse.ArgumentParser(
        description="Prepare, validate or render an evidence-bound application assessment"
    )
    parser.add_argument("action", choices=("prepare", "validate", "render"))
    parser.add_argument("report", type=Path)
    parser.add_argument("--assessment", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--skill-revision")
    parser.add_argument("--language", choices=("en", "zh-CN"), default="en")
    args = parser.parse_args()
    if args.action != "prepare" and args.assessment is None:
        parser.error("Validation and rendering require --assessment")
    if args.action != "validate" and args.output is None:
        parser.error("Preparation and rendering require a new --output directory")
    report = None
    try:
        if args.output and args.output.exists():
            raise AnalysisError(
                "Output directory already exists; choose a new directory"
            )
        report = load_report(args.report)
        assessment = (
            prepare_assessment(report, args.skill_revision)
            if args.action == "prepare"
            else read_json(args.assessment)
        )
        result = validate_delivery(report, assessment)
        if (
            result["validation_status"] != "PASS"
            or result["reporting"]["status"] == "invalid"
        ):
            print(json.dumps(result, ensure_ascii=True, indent=2))
            return 1
        if args.action != "validate":
            rendered = (
                render_assessment(report, assessment, args.language, validation=result)
                if args.action == "render"
                else None
            )
            args.output.mkdir(parents=True, exist_ok=False)
            atomic_json(args.output / "assessment.json", sanitized(assessment))
            result["files"] = {"assessment.json": str(args.output / "assessment.json")}
            atomic_json(
                args.output / "delivery-summary.json", result["delivery_summary"]
            )
            result["files"]["delivery-summary.json"] = str(
                args.output / "delivery-summary.json"
            )
            for name, text in (rendered or {}).items():
                atomic_text(args.output / name, text)
                result["files"][name] = str(args.output / name)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (
        AnalysisError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        sqlite3.Error,
    ) as error:
        diagnostic(
            "assessment.failed",
            level="ERROR",
            status="FAILED",
            correlation_id=report["run"]["id"] if report else None,
            error=str(error),
        )
        return 1
    finally:
        if report is not None:
            close_report(report)


if __name__ == "__main__":
    sys.exit(main())
