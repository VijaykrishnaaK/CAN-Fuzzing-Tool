"""
reporter/tara_reporter.py
==========================
Generates ISO/SAE 21434 aligned TARA security reports from fuzzing findings.

Output formats:
  1. Terminal — color-coded summary
  2. JSON     — machine-readable audit log (CSMS-ready)
  3. Markdown — full TARA report with threat table

ISO/SAE 21434 structure followed:
  - Asset identification (Clause 9)
  - Threat scenario identification (Clause 9)
  - Impact + Likelihood → Risk rating (Annex E)
  - Countermeasure proposals (Clause 10/11)
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from config import *
from monitor.anomaly_detector import Finding

log = logging.getLogger("Reporter")

# Terminal colors
class C:
    RED      = "\033[91m"
    YELLOW   = "\033[93m"
    GREEN    = "\033[92m"
    CYAN     = "\033[96m"
    BOLD     = "\033[1m"
    RESET    = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": C.BOLD + C.RED,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.GREEN,
    "INFO":     C.CYAN,
}

# ISO/SAE 21434 Risk Matrix (Impact × Likelihood)
RISK_MATRIX = {
    (4, 4): "CRITICAL", (4, 3): "HIGH",   (4, 2): "HIGH",   (4, 1): "MEDIUM",
    (3, 4): "HIGH",     (3, 3): "HIGH",   (3, 2): "MEDIUM", (3, 1): "MEDIUM",
    (2, 4): "MEDIUM",   (2, 3): "MEDIUM", (2, 2): "LOW",    (2, 1): "LOW",
    (1, 4): "LOW",      (1, 3): "LOW",    (1, 2): "LOW",    (1, 1): "LOW",
}

# Map finding severity to impact/likelihood ratings for TARA
SEVERITY_TO_IMPACT = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 1
}
CATEGORY_TO_LIKELIHOOD = {
    "ACCESS_CONTROL_BYPASS":      4,
    "STATE_MACHINE_VIOLATION":    4,
    "UNDEFINED_SERVICE_ACCEPTED": 3,
    "NO_RESPONSE_TIMEOUT":        3,
    "TIMING_ORACLE":              2,
    "WRONG_NRC":                  2,
    "UNEXPECTED_RESPONSE_LENGTH": 2,
    "SUSPICIOUS_FAST_RESPONSE":   1,
    "RESPONSE_PENDING":           1,
}


class TARAReporter:
    """Generates full security reports from fuzzing findings."""

    def __init__(self, output_dir: str = REPORT_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, findings: list[Finding], fuzz_stats: dict,
                 run_id: str = None, ids_summary: dict = None) -> dict:
        """
        Generate all report formats.
        Returns dict with paths to generated files.
        """
        if run_id is None:
            run_id = datetime.now().strftime("run_%Y%m%d_%H%M%S")

        self._print_terminal(findings, fuzz_stats, ids_summary)
        json_path = self._save_json(findings, fuzz_stats, run_id, ids_summary)
        md_path   = self._save_markdown(findings, fuzz_stats, run_id, ids_summary)

        return {
            "run_id":    run_id,
            "json":      str(json_path),
            "markdown":  str(md_path),
        }

    # ── Terminal Output ───────────────────────────────────────────────────────

    def _print_terminal(self, findings: list[Finding],
                         stats: dict, ids_summary: dict = None):
        """Print color-coded security report to terminal."""
        risk = "NONE"
        print("\n" + "━"*65)
        print(f"  UDS SECURITY FUZZER — FINDINGS REPORT")
        print(f"  {TARA_STANDARD} | {TARA_WP29_REF}")
        print("━"*65)

        print(f"\n  Fuzz cases run:     {stats.get('total_cases', 0)}")
        print(f"  Positive responses: {stats.get('positive_count', 0)}")
        print(f"  Timeouts:           {stats.get('timeout_count', 0)}")
        print(f"  Fuzzer findings:    {len(findings)}")

        # IDS summary block
        if ids_summary and ids_summary.get("total_alerts", 0) > 0:
            print(f"\n  {'─'*61}")
            print(f"  IDS ALERTS (Real-time detection during fuzzing)")
            print(f"  {'─'*61}")
            print(f"  {'ID':<8} {'SEV':<10} {'RULE'}")
            print(f"  {'─'*61}")
            for alert in ids_summary.get("alerts", []):
                col = SEVERITY_COLOR.get(alert.severity, "")
                print(f"  {alert.alert_id:<8} "
                      f"{col}{alert.severity:<10}{C.RESET} "
                      f"{alert.rule_name}")
            print(f"  {'─'*61}")

        if not findings:
            print(f"\n  {C.GREEN}No fuzzer findings.{C.RESET}")
            print("━"*65 + "\n")
            return

        print(f"\n  {'─'*61}")
        print(f"  {'ID':<8} {'SEV':<10} {'CATEGORY':<35} {'TIME'}")
        print(f"  {'─'*61}")

        for f in sorted(findings,
                        key=lambda x: SEVERITY_TO_IMPACT.get(x.severity, 0),
                        reverse=True):
            col = SEVERITY_COLOR.get(f.severity, "")
            print(f"  {f.finding_id:<8} "
                  f"{col}{f.severity:<10}{C.RESET} "
                  f"{f.category:<35} "
                  f"{f.response_time*1000:.1f}ms")

        print(f"  {'─'*61}")

        critical_high = [f for f in findings
                         if f.severity in ("CRITICAL", "HIGH")]
        if critical_high:
            print(f"\n  {C.BOLD}CRITICAL / HIGH FINDINGS:{C.RESET}\n")
            for f in critical_high:
                col = SEVERITY_COLOR.get(f.severity, "")
                print(f"  {col}[{f.finding_id}] {f.title}{C.RESET}")
                print(f"  Strategy:  {f.fuzz_strategy}")
                print(f"  Request:   {f.request_hex}")
                print(f"  Response:  {f.response_hex}")
                print(f"  Fix:       {f.countermeasure[:70]}...")
                print()

        print("━"*65 + "\n")

    # ── JSON Report ───────────────────────────────────────────────────────────

    def _save_json(self, findings: list[Finding],
                   stats: dict, run_id: str,
                   ids_summary: dict = None) -> Path:
        """Save machine-readable JSON audit log."""
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        report = {
            "run_id":           run_id,
            "timestamp":        datetime.now().isoformat(),
            "standard":         TARA_STANDARD,
            "wp29_ref":         TARA_WP29_REF,
            "target":           "Virtual ECU (vcan0)",
            "fuzz_statistics":  stats,
            "finding_summary": {
                "total":          len(findings),
                "by_severity":    severity_counts,
            },
            "findings": [
                {
                    "finding_id":     f.finding_id,
                    "severity":       f.severity,
                    "category":       f.category,
                    "title":          f.title,
                    "description":    f.description,
                    "request_hex":    f.request_hex,
                    "response_hex":   f.response_hex,
                    "response_time_ms": round(f.response_time * 1000, 2),
                    "fuzz_strategy":  f.fuzz_strategy,
                    "iso_14229_ref":  f.iso_14229_ref,
                    "iso_21434_ref":  f.iso_21434_ref,
                    "countermeasure": f.countermeasure,
                    "timestamp":      f.timestamp,
                }
                for f in findings
            ],
            "ids_alerts": [
                {
                    "alert_id":    a.alert_id,
                    "rule_id":     a.rule_id,
                    "severity":    a.severity,
                    "rule_name":   a.rule_name,
                    "description": a.description,
                    "evidence":    a.evidence,
                    "iso_clause":  a.iso_clause,
                    "wp29_ref":    a.wp29_ref,
                    "action":      a.recommended_action,
                    "timestamp":   a.timestamp,
                }
                for a in (ids_summary or {}).get("alerts", [])
            ],
            "standard": TARA_STANDARD,
        }

        path = self.output_dir / f"{run_id}_findings.json"
        with open(path, "w") as fp:
            json.dump(report, fp, indent=2)
        log.info(f"JSON report: {path}")
        return path

    # ── Markdown TARA Report ──────────────────────────────────────────────────

    def _save_markdown(self, findings: list[Finding],
                        stats: dict, run_id: str,
                        ids_summary: dict = None) -> Path:
        """Generate full ISO/SAE 21434 aligned Markdown TARA report."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = []

        lines += [
            f"# UDS Security Fuzzer — TARA Report",
            f"",
            f"> **Standard**: {TARA_STANDARD}  ",
            f"> **WP.29 Ref**: {TARA_WP29_REF}  ",
            f"> **Run ID**: `{run_id}`  ",
            f"> **Timestamp**: {ts}  ",
            f"> **Target**: Virtual ECU over vcan0 (ISO 14229-1 UDS)  ",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary",
            f"",
            f"This report documents security findings from automated UDS protocol "
            f"fuzzing of a virtual ECU target. Findings are mapped to "
            f"ISO/SAE 21434:2021 threat scenarios and UNECE WP.29 R155 CSMS requirements.",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Fuzz cases executed | {stats.get('total_cases', 0)} |",
            f"| Strategies used | Mutation, Generation, Smart (state-aware) |",
            f"| Total findings | {len(findings)} |",
            f"| Critical findings | {sum(1 for f in findings if f.severity == 'CRITICAL')} |",
            f"| High findings | {sum(1 for f in findings if f.severity == 'HIGH')} |",
            f"| Timeouts detected | {stats.get('timeout_count', 0)} |",
            f"",
            f"---",
            f"",
            f"## 2. Asset Identification (ISO/SAE 21434 Clause 9)",
            f"",
            f"| Asset | Type | Cybersecurity Property | Description |",
            f"|-------|------|------------------------|-------------|",
            f"| UDS Diagnostic Interface | Communication | Integrity + Availability | "
            f"ISO 14229-1 UDS service handler on ECU |",
            f"| Security Access Module | Function | Confidentiality | "
            f"0x27 seed/key authentication mechanism |",
            f"| ECU Calibration Data | Data | Integrity | "
            f"Writable DIDs (0x2E) — safety-critical parameters |",
            f"| ECU Memory | Data | Confidentiality + Integrity | "
            f"0x23 Read Memory By Address target |",
            f"| Routine Control | Function | Integrity + Availability | "
            f"0x31 executable routines on ECU |",
            f"",
            f"---",
            f"",
            f"## 3. Threat Scenarios and Risk Assessment (TARA)",
            f"",
            f"*Risk matrix per ISO/SAE 21434 Annex E*",
            f"",
            f"| ID | Title | Category | Impact | Likelihood | Risk | "
            f"ISO 14229 Ref | ISO 21434 Ref |",
            f"|----|-------|----------|--------|------------|------|"
            f"--------------|--------------|",
        ]

        for f in sorted(findings,
                        key=lambda x: SEVERITY_TO_IMPACT.get(x.severity, 0),
                        reverse=True):
            impact     = SEVERITY_TO_IMPACT.get(f.severity, 1)
            likelihood = CATEGORY_TO_LIKELIHOOD.get(f.category, 2)
            risk       = RISK_MATRIX.get((impact, likelihood), "MEDIUM")
            lines.append(
                f"| {f.finding_id} | {f.title[:40]} | {f.category} | "
                f"{impact}/4 | {likelihood}/4 | **{risk}** | "
                f"{f.iso_14229_ref[:30]}... | {f.iso_21434_ref[:25]}... |"
            )

        lines += [
            f"",
            f"---",
            f"",
            f"## 4. Detailed Findings",
            f"",
        ]

        for f in findings:
            impact     = SEVERITY_TO_IMPACT.get(f.severity, 1)
            likelihood = CATEGORY_TO_LIKELIHOOD.get(f.category, 2)
            risk       = RISK_MATRIX.get((impact, likelihood), "MEDIUM")
            lines += [
                f"### {f.finding_id} — {f.title}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Severity** | {f.severity} |",
                f"| **Risk Level** | {risk} |",
                f"| **Category** | {f.category} |",
                f"| **Fuzz Strategy** | {f.fuzz_strategy} |",
                f"| **Request** | `{f.request_hex}` |",
                f"| **Response** | `{f.response_hex}` |",
                f"| **Response Time** | {f.response_time*1000:.2f}ms |",
                f"",
                f"**Description:**  ",
                f"{f.description}",
                f"",
                f"**ISO 14229-1 Reference:** {f.iso_14229_ref}  ",
                f"**ISO/SAE 21434 Reference:** {f.iso_21434_ref}  ",
                f"",
                f"**Countermeasure:**  ",
                f"{f.countermeasure}",
                f"",
            ]

        lines += [
            f"---",
            f"",
            f"## 5. UNECE WP.29 R155 CSMS Alignment",
            f"",
            f"| WP.29 Requirement | Coverage |",
            f"|-------------------|----------|",
            f"| Art. 7.2.2 — Threat identification (TARA) | ✅ Section 3 |",
            f"| Art. 7.3.3 — Cybersecurity testing | ✅ Fuzzing simulation |",
            f"| Art. 7.3.5 — Monitoring of cyber threats | ✅ JSON audit log |",
            f"",
            f"---",
            f"",
            f"## 6. Fuzzing Methodology",
            f"",
            f"| Strategy | Description | ISO 14229 Coverage |",
            f"|----------|-------------|-------------------|",
            f"| Mutation | Bit flips, byte substitution, length changes | All services |",
            f"| Generation | Grammar-based, full SID/subfunction sweep | All services |",
            f"| Smart | UDS state-machine-aware sequence testing | Session + SA |",
            f"",
            f"---",
            f"",
            f"*Generated by UDS Security Fuzzer*  ",
            f"*{TARA_STANDARD} | {TARA_WP29_REF} | ISO 14229-1*",
        ]

        path = self.output_dir / f"{run_id}_tara_report.md"
        with open(path, "w") as fp:
            fp.write("\n".join(lines))
        log.info(f"Markdown report: {path}")
        return path
