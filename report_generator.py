"""
report_generator.py: Phase 2 report generation for the vuln-ai-assistant pipeline.

Reads the prioritized JSON produced by prioritizer.py, derives scan metadata,
asks Gemini to fill the Markdown report template, writes report.md, and renders
report.pdf via WeasyPrint.

Public API:
    generate_report(prioritized_path: str, output_dir: str) -> str

Usage (standalone):
    python report_generator.py output/enriched_findings.prioritized.json output/
"""

from __future__ import annotations

import copy
import json
import logging
import re
import sys
from pathlib import Path

import markdown as md
from google import genai
from google.genai import errors, types
from weasyprint import CSS, HTML

log = logging.getLogger(__name__)

# This module lives in the project root, alongside the template/prompt/style files.
_ROOT = Path(__file__).resolve().parent
TEMPLATE_PATH = _ROOT / "report_template.md"
PROMPT_PATH = _ROOT / "report_prompt.md"
STYLE_PATH = _ROOT / "report_style.css"

# The google-genai SDK reads GEMINI_API_KEY (or GOOGLE_API_KEY) from the environment.
MODEL = "gemini-3.5-flash"
MAX_TOKENS = 65536  # gemini-3.5-flash output ceiling; a full report needs the headroom

_SEVERITIES = ("critical", "high", "medium", "low", "informational")

# Tags a severity word that fills a whole table cell so the stylesheet can colour it.
_SEV_CELL_RE = re.compile(
    r"(<td[^>]*?)>(\s*)(Critical|High|Medium|Low|Informational)(\s*)</td>",
    re.IGNORECASE,
)


# Helpers

def _extract_section(text: str, heading: str) -> str:
    """Return the lines under a ``## heading`` up to (but not including) the next ``## `` heading."""
    out: list[str] = []
    capturing = False
    for line in text.splitlines():
        if line.strip() == heading:
            capturing = True
            continue
        if capturing and line.startswith("## "):
            break
        if capturing:
            out.append(line)
    return "\n".join(out).strip()


def _build_scan_metadata(data: dict) -> dict:
    """Derive the scan_metadata block injected into the prompt."""
    meta = data.get("metadata", {})

    tools: set = set()
    for findings in data.get("by_priority", {}).values():
        for f in findings:
            tool = f.get("tool")
            if tool:
                tools.add(tool)
            for st in f.get("source_tools") or []:
                if st:
                    tools.add(st)

    # Title page should show only the calendar date, not the full ISO timestamp.
    generated_at = meta.get("generated_at")
    scan_date = generated_at.split("T", 1)[0] if isinstance(generated_at, str) else generated_at

    return {
        "target": meta.get("scan_target", "unknown"),
        "scan_date": scan_date,
        "priority_counts": meta.get("priority_counts", {}),
        "total_findings": meta.get("total_findings_deduplicated", 0),
        "host_count": len(data.get("by_host", {})),
        "subdomain_count": len(data.get("by_category", {}).get("subdomain", [])),
        "tools_used": sorted(tools),
    }


def _markdown_to_pdf(report_md: str, pdf_path: Path) -> None:
    """Render Markdown to HTML (with severity cell tagging), then to a styled PDF."""
    html_body = md.markdown(report_md, extensions=["tables", "sane_lists"])

    def _tag(m: re.Match) -> str:
        sev = m.group(3).lower()
        return f'{m.group(1)} class="sev-{sev}">{m.group(2)}{m.group(3)}{m.group(4)}</td>'

    html_body = _SEV_CELL_RE.sub(_tag, html_body)

    html_doc = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'></head>"
        f"<body>{html_body}</body></html>"
    )
    HTML(string=html_doc, base_url=str(_ROOT)).write_pdf(
        str(pdf_path), stylesheets=[CSS(filename=str(STYLE_PATH))]
    )


# Public API

def generate_report(prioritized_path: str, output_dir: str) -> str:
    """
    Generate a Markdown + PDF attack-surface report from a prioritized JSON file.

    Returns the path to the generated PDF. Raises RuntimeError on any failure.
    """
    out_dir = Path(output_dir)
    md_path = out_dir / "report.md"
    pdf_path = out_dir / "report.pdf"

    # 1. Load the prioritized findings.
    try:
        with open(prioritized_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as e:
        raise RuntimeError(f"Prioritized findings file not found: {prioritized_path}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Prioritized findings file is not valid JSON: {e}") from e
    except OSError as e:
        raise RuntimeError(f"Could not read prioritized findings file: {e}") from e

    # 2. Load the template and prompt.
    try:
        template_content = TEMPLATE_PATH.read_text(encoding="utf-8")
        prompt_content = PROMPT_PATH.read_text(encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"Could not read report template/prompt: {e}") from e

    system_prompt = _extract_section(prompt_content, "## SYSTEM PROMPT")
    user_template = _extract_section(prompt_content, "## USER PROMPT TEMPLATE")
    if not system_prompt:
        raise RuntimeError("Could not locate '## SYSTEM PROMPT' section in report_prompt.md")
    if not user_template:
        raise RuntimeError("Could not locate '## USER PROMPT TEMPLATE' section in report_prompt.md")

    # 3. Build the prompt payload. Drop the bulky raw_records provenance (it duplicates
    #    each record verbatim) so the model gets clean findings and a far smaller prompt.
    scan_metadata = _build_scan_metadata(data)
    by_priority = copy.deepcopy(data.get("by_priority", {}))
    for _findings in by_priority.values():
        for _f in _findings:
            _f.pop("raw_records", None)

    user_prompt = (
        user_template
        .replace("{{SCAN_METADATA_JSON}}", json.dumps(scan_metadata, indent=2, ensure_ascii=False))
        .replace("{{BY_PRIORITY_JSON}}", json.dumps(by_priority, indent=2, ensure_ascii=False))
        .replace("{{REPORT_TEMPLATE_CONTENT}}", template_content)
    )

    # 4. Call Gemini (single blocking request; the SDK reads GEMINI_API_KEY from env).
    try:
        client = genai.Client()
        response = client.models.generate_content(
            model=MODEL,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                max_output_tokens=MAX_TOKENS,
                # Disable "thinking"; otherwise it consumes the output budget and the
                # visible report gets truncated mid-section.
                thinking_config=types.ThinkingConfig(thinking_budget=0),
            ),
        )
    except errors.APIError as e:
        raise RuntimeError(f"Gemini API request failed: {e}") from e
    except Exception as e:  # network, auth resolution, etc.
        raise RuntimeError(f"Report generation request failed: {e}") from e

    feedback = getattr(response, "prompt_feedback", None)
    if feedback is not None and getattr(feedback, "block_reason", None):
        raise RuntimeError(f"Gemini blocked the prompt: {feedback.block_reason}")

    candidates = getattr(response, "candidates", None) or []
    if not candidates:
        raise RuntimeError("Gemini returned no candidates.")
    finish_name = getattr(getattr(candidates[0], "finish_reason", None), "name", "")
    if finish_name == "MAX_TOKENS":
        log.warning("Report response hit max_output_tokens (%d) — output may be truncated.", MAX_TOKENS)
    elif finish_name not in ("STOP", "MAX_TOKENS", ""):
        raise RuntimeError(f"Gemini stopped unexpectedly ({finish_name}).")

    report_md = (getattr(response, "text", None) or "").strip()
    if not report_md:
        raise RuntimeError("Gemini returned an empty report.")

    # 5. Write Markdown.
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path.write_text(report_md, encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"Could not write {md_path}: {e}") from e

    # 6. Render PDF.
    try:
        _markdown_to_pdf(report_md, pdf_path)
    except Exception as e:
        raise RuntimeError(f"Could not render PDF report: {e}") from e

    log.info("Report written: %s / %s", md_path, pdf_path)
    return str(pdf_path)


# CLI

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if len(sys.argv) != 3:
        print("Usage: python report_generator.py <prioritized_json> <output_dir>")
        raise SystemExit(2)
    try:
        result = generate_report(sys.argv[1], sys.argv[2])
        print(f"Report generated: {result}")
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)
