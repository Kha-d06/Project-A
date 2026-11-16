"""Macro analysis for Office documents using oletools' olevba.

olevba extracts and decompresses VBA (and Excel 4 / XLM) macros without running
them, and flags keywords: auto-run triggers, shell and download functions, and
hard-coded network indicators.
"""

import logging
from pathlib import Path

from oletools.olevba import VBA_Parser

from app.analyzers.types import FindingData

logger = logging.getLogger(__name__)
SOURCE = "olevba (oletools)"
_MAX_KEYWORDS = 8
_MAX_INDICATORS = 10


def macro_findings(path: Path) -> tuple[list[FindingData], dict[str, object]]:
    """Findings and a details summary. Empty if the file has no macros."""
    try:
        parser = VBA_Parser(str(path))
    except Exception:  # noqa: BLE001 - olevba raises many types on malformed files
        logger.info("olevba could not parse %s", path.name)
        return [], {}
    try:
        if not parser.detect_vba_macros():
            return [], {}
        results = parser.analyze_macros() or []
        modules = sum(1 for _ in parser.extract_macros())
        xlm = bool(getattr(parser, "xlm_macros", None))
    except Exception:  # noqa: BLE001
        logger.info("olevba failed while analysing %s", path.name)
        return [
            FindingData(
                "medium",
                "macros",
                "Document contains macros that could not be fully analysed",
                "Macros are programs inside the document. These could not be decoded, which "
                "can itself be a sign of deliberate obfuscation.",
                SOURCE,
            )
        ], {"macro_modules": "unknown"}
    finally:
        parser.close()

    auto_exec = sorted({keyword for kind, keyword, _ in results if kind == "AutoExec"})
    suspicious = sorted({keyword for kind, keyword, _ in results if kind == "Suspicious"})
    indicators = sorted({keyword for kind, keyword, _ in results if kind == "IOC"})
    details: dict[str, object] = {
        "macro_modules": modules,
        "runs_automatically": bool(auto_exec),
        "suspicious_keywords": suspicious[:_MAX_KEYWORDS],
        "embedded_indicators": indicators[:_MAX_INDICATORS],
    }

    findings: list[FindingData] = []
    if auto_exec and suspicious:
        findings.append(
            FindingData(
                "high",
                "macros",
                "Macro runs automatically and uses risky functions",
                "When macros are enabled, this code starts on its own as soon as the document "
                "opens and uses functions that can run programs, download files or hide its "
                "behaviour. This is how most malicious Office documents work.",
                SOURCE,
                {"triggers": auto_exec[:_MAX_KEYWORDS], "functions": suspicious[:_MAX_KEYWORDS]},
            )
        )
    else:
        findings.append(
            FindingData(
                "medium",
                "macros",
                "Document contains macros" + (" that run automatically" if auto_exec else ""),
                "Macros are small programs embedded in a document. They are the most common way "
                "Office files deliver malware. Do not click “Enable content” unless you trust "
                "the sender and expected a document with macros.",
                SOURCE,
                {"triggers": auto_exec[:_MAX_KEYWORDS]} if auto_exec else {},
            )
        )
    if xlm:
        findings.append(
            FindingData(
                "medium",
                "macros",
                "Contains old-style Excel 4 macros",
                "Excel 4 (XLM) macros are rarely used today except by malware, because many "
                "security tools overlook them.",
                SOURCE,
            )
        )
    if indicators:
        findings.append(
            FindingData(
                "low",
                "macros",
                "Macro code contains web addresses or other network indicators",
                "The macro refers to addresses it may contact or download from.",
                SOURCE,
                {"indicators": indicators[:_MAX_INDICATORS]},
            )
        )
    return findings, details
