"""
monitor/vuln_engine.py
=======================
Vulnerability Analysis Engine.

Takes all fuzz cases, IDS alerts, and adaptive corpus — analyses
the complete picture and generates a professional vulnerability report
with CVSS v3.1 scoring, attack scenarios, and remediation guidance.

This is what penetration testers produce after a security assessment.
Your fuzzer generates the findings — this engine writes the report.

CVSS v3.1 scoring implemented per:
  https://www.first.org/cvss/v3.1/specification-document

ISO/SAE 21434 alignment:
  Clause 15 — Cybersecurity validation findings
  Clause 10 — Cybersecurity goals (CIA triad)
  Annex E   — Risk assessment matrix
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from config import *
from monitor.anomaly_detector import Finding
from monitor.ids_engine import IDSAlert

log = logging.getLogger("VulnEngine")


# ── CVSS v3.1 Scoring ─────────────────────────────────────────────────────────

@dataclass
class CVSSScore:
    """CVSS v3.1 base score components."""
    attack_vector:       str    # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity:   str    # L=Low, H=High
    privileges_required: str    # N=None, L=Low, H=High
    user_interaction:    str    # N=None, R=Required
    scope:               str    # U=Unchanged, C=Changed
    confidentiality:     str    # N=None, L=Low, H=High
    integrity:           str    # N=None, L=Low, H=High
    availability:        str    # N=None, L=Low, H=High

    @property
    def vector_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
                f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
                f"/S:{self.scope}/C:{self.confidentiality}"
                f"/I:{self.integrity}/A:{self.availability}")

    @property
    def base_score(self) -> float:
        """
        Simplified CVSS v3.1 base score calculation.
        Full formula per FIRST specification.
        """
        # Impact sub-score
        isc_base = (1 - (1 - self._c_val) *
                        (1 - self._i_val) *
                        (1 - self._a_val))

        if self.scope == "U":
            iss = 6.42 * isc_base
        else:
            iss = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

        if iss <= 0:
            return 0.0

        # Exploitability sub-score
        ess = (8.22 * self._av_val * self._ac_val *
               self._pr_val * self._ui_val)

        if self.scope == "U":
            raw = min(iss + ess, 10)
        else:
            raw = min(1.08 * (iss + ess), 10)

        # Round up to 1 decimal
        return round(raw * 10) / 10

    @property
    def severity_label(self) -> str:
        score = self.base_score
        if score == 0.0:              return "NONE"
        elif score <= 3.9:            return "LOW"
        elif score <= 6.9:            return "MEDIUM"
        elif score <= 8.9:            return "HIGH"
        else:                         return "CRITICAL"

    # Value mappings per CVSS v3.1 spec
    @property
    def _av_val(self):
        return {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[self.attack_vector]
    @property
    def _ac_val(self):
        return {"L": 0.77, "H": 0.44}[self.attack_complexity]
    @property
    def _pr_val(self):
        scope_map = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.50},
        }
        return scope_map[self.scope][self.privileges_required]
    @property
    def _ui_val(self):
        return {"N": 0.85, "R": 0.62}[self.user_interaction]
    @property
    def _c_val(self):
        return {"N": 0.00, "L": 0.22, "H": 0.56}[self.confidentiality]
    @property
    def _i_val(self):
        return {"N": 0.00, "L": 0.22, "H": 0.56}[self.integrity]
    @property
    def _a_val(self):
        return {"N": 0.00, "L": 0.22, "H": 0.56}[self.availability]


# ── Vulnerability ─────────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """A confirmed or potential vulnerability with full technical detail."""
    vuln_id:         str
    title:           str
    severity:        str
    cvss:            CVSSScore
    affected_service:str
    description:     str
    attack_scenario: str         # Step-by-step how an attacker exploits this
    impact:          str         # What happens if exploited
    evidence:        list[str]   # Finding IDs and IDS alert IDs that support this
    iso_14229_ref:   str
    iso_21434_ref:   str
    cwe_id:          str         # Common Weakness Enumeration reference
    remediation:     str         # How to fix it
    verification:    str         # How to verify the fix worked
    confidence:      str         # HIGH / MEDIUM / LOW — how sure we are


# ── Vulnerability Engine ──────────────────────────────────────────────────────

class VulnerabilityEngine:
    """
    Analyses fuzzer findings + IDS alerts → confirmed vulnerabilities.

    Unlike the anomaly detector (which flags individual suspicious responses)
    and the IDS (which flags individual suspicious requests), this engine
    looks at the COMPLETE PICTURE across all findings to identify
    confirmed vulnerability patterns.

    This is what a security engineer does after running a fuzzer:
    correlate findings, eliminate false positives, write the report.
    """

    def __init__(self):
        self.vulnerabilities: list[Vulnerability] = []
        self._vuln_count = 0

    def analyse(self, findings: list[Finding],
                ids_alerts: list[IDSAlert],
                adaptive_corpus=None) -> list[Vulnerability]:
        """
        Analyse all findings and alerts to identify vulnerabilities.

        Args:
            findings:         Anomaly detector findings
            ids_alerts:       IDS alert list
            adaptive_corpus:  Top corpus entries from adaptive fuzzer

        Returns:
            List of identified vulnerabilities
        """
        vulns = []

        # Check each vulnerability pattern
        vulns += self._check_sa_brute_force(findings, ids_alerts)
        vulns += self._check_session_escalation(findings, ids_alerts)
        vulns += self._check_access_control_bypass(findings)
        vulns += self._check_dos_vulnerability(findings, ids_alerts)
        vulns += self._check_timing_oracle(findings)
        vulns += self._check_post_reset_weakness(ids_alerts)
        vulns += self._check_did_enumeration(ids_alerts)
        vulns += self._check_write_without_authentication(findings)

        self.vulnerabilities = vulns
        return vulns

    # ── Vulnerability Checks ──────────────────────────────────────────────────

    def _check_sa_brute_force(self, findings, alerts) -> list[Vulnerability]:
        """
        Vulnerability: Security Access brute force possible.
        Evidence: IDS-001 alerts + no lockout enforced.
        """
        sa_alerts = [a for a in alerts if a.rule_id == "IDS-001"]
        if not sa_alerts:
            return []

        return [self._make_vuln(
            title    = "Security Access (0x27) Susceptible to Brute Force",
            severity = "HIGH",
            cvss     = CVSSScore("L","L","N","N","U","L","H","N"),
            service  = "SID 0x27 — Security Access",
            description = (
                "The ECU's Security Access implementation does not "
                "sufficiently prevent automated key brute force attacks. "
                f"{len(sa_alerts)} brute force alert(s) were triggered during "
                "testing, indicating the SA mechanism can be systematically probed."
            ),
            attack_scenario = (
                "1. Attacker connects to OBD-II port with custom tool\n"
                "2. Sends DSC 0x10 0x03 to enter extended session\n"
                "3. Sends SA 0x27 0x01 to request seed\n"
                "4. Tries all possible 4-byte key values systematically\n"
                "5. After correct key found — sends SA 0x27 0x02 <key>\n"
                "6. Security unlocked — attacker can now write calibration "
                "data, trigger routines, flash firmware"
            ),
            impact = (
                "Full ECU security bypass. Attacker can modify calibration "
                "data, execute protected routines, and potentially flash "
                "malicious firmware. Safety-critical systems affected."
            ),
            evidence   = [a.alert_id for a in sa_alerts[:3]],
            iso_14229  = "ISO 14229-1 §10.4.5 — SA attempt limiting required",
            iso_21434  = "ISO/SAE 21434 Clause 10 — Cybersecurity goal: integrity",
            cwe        = "CWE-307: Improper Restriction of Excessive Authentication Attempts",
            remediation = (
                "1. Enforce SA_MAX_ATTEMPTS (≤3) lockout in RAM\n"
                "2. Implement exponential backoff: 10s → 30s → 300s lockout\n"
                "3. Persist lockout counter in NVM — survives reset\n"
                "4. Use HMAC-based key derivation instead of XOR\n"
                "5. Implement HSM-backed seed generation"
            ),
            verification = (
                "Send 4+ wrong keys in sequence. "
                "ECU must return NRC 0x36 (exceededNumberOfAttempts) "
                "and lock for minimum 10 seconds."
            ),
            confidence = "HIGH" if len(sa_alerts) >= 3 else "MEDIUM",
        )]

    def _check_session_escalation(self, findings, alerts) -> list[Vulnerability]:
        """
        Vulnerability: Direct programming session access from default.
        Evidence: SESSION_ESCALATION_BYPASS finding or IDS-002 alert.
        """
        escalation_findings = [f for f in findings
                               if f.category == "SESSION_ESCALATION_BYPASS"]
        escalation_alerts   = [a for a in alerts if a.rule_id == "IDS-002"]

        if not escalation_findings and not escalation_alerts:
            return []

        confirmed = len(escalation_findings) > 0

        return [self._make_vuln(
            title    = "Programming Session Prerequisite Bypass",
            severity = "CRITICAL" if confirmed else "MEDIUM",
            cvss     = CVSSScore("L","L","N","N","C","L","H","L"),
            service  = "SID 0x10 — Diagnostic Session Control",
            description = (
                "ECU allowed direct access to programming session (0x02) "
                "without requiring the mandatory Extended session + "
                "Security Access unlock prerequisite chain. "
                + ("CONFIRMED by positive response during testing. "
                   if confirmed else "Attempted — verify ECU rejected correctly.")
            ),
            attack_scenario = (
                "1. Attacker connects to OBD-II port\n"
                "2. Sends DSC 0x10 0x02 (programming session) directly\n"
                "3. ECU accepts without requiring SA unlock\n"
                "4. Attacker now has access to firmware flashing services\n"
                "5. Sends RequestDownload 0x34 + TransferData 0x36\n"
                "6. Malicious firmware flashed to ECU"
            ),
            impact = (
                "Unauthorized firmware flashing. Attacker can install "
                "malicious ECU software affecting safety-critical functions "
                "including braking, steering, and powertrain control."
            ),
            evidence   = ([f.finding_id for f in escalation_findings] +
                          [a.alert_id for a in escalation_alerts[:2]]),
            iso_14229  = "ISO 14229-1 §9.2 — Session prerequisite chain mandatory",
            iso_21434  = "ISO/SAE 21434 Clause 10 — Cybersecurity goal: integrity",
            cwe        = "CWE-284: Improper Access Control",
            remediation = (
                "In DSC handler:\n"
                "  if requested == PROGRAMMING and current == DEFAULT:\n"
                "      return NRC 0x22 (conditionsNotCorrect)\n"
                "  if requested == PROGRAMMING and not sa_unlocked:\n"
                "      return NRC 0x22\n"
                "Test: verify NRC 0x22 for direct default→programming."
            ),
            verification = (
                "From default session, send DSC 0x10 0x02. "
                "Must receive NRC 0x22 (conditionsNotCorrect). "
                "Any positive response is a confirmed critical vulnerability."
            ),
            confidence = "HIGH" if confirmed else "LOW",
        )]

    def _check_access_control_bypass(self, findings) -> list[Vulnerability]:
        """
        Vulnerability: Write service accepted without SA unlock.
        Evidence: ACCESS_CONTROL_BYPASS findings.
        """
        bypass_findings = [f for f in findings
                           if f.category == "ACCESS_CONTROL_BYPASS"]
        if not bypass_findings:
            return []

        return [self._make_vuln(
            title    = "Write Data Accepted Without Security Access",
            severity = "CRITICAL",
            cvss     = CVSSScore("L","L","N","N","U","N","H","N"),
            service  = "SID 0x2E — Write Data By Identifier",
            description = (
                f"ECU accepted {len(bypass_findings)} WDBI request(s) "
                "without Security Access being unlocked. "
                "This allows unauthorized modification of ECU calibration "
                "data and operating parameters."
            ),
            attack_scenario = (
                "1. Attacker connects to OBD-II port\n"
                "2. Enters extended session (DSC 0x10 0x03)\n"
                "3. Skips Security Access — sends WDBI 0x2E directly\n"
                "4. ECU accepts write without SA check\n"
                "5. Calibration data overwritten with attacker-controlled values\n"
                "6. Could affect fuel injection, engine timing, ABS thresholds"
            ),
            impact = (
                "Unauthorized ECU parameter modification. "
                "Safety-critical calibration data can be corrupted or "
                "manipulated to cause vehicle malfunction."
            ),
            evidence   = [f.finding_id for f in bypass_findings[:3]],
            iso_14229  = "ISO 14229-1 §9.4 — WDBI requires SA in extended session",
            iso_21434  = "ISO/SAE 21434 Clause 10 — Integrity cybersecurity goal",
            cwe        = "CWE-862: Missing Authorization",
            remediation = (
                "Add SA check at start of WDBI handler:\n"
                "  if not sa_manager.unlocked:\n"
                "      return NRC 0x33 (securityAccessDenied)\n"
                "Apply same check to RMBA, RC, and all write services."
            ),
            verification = (
                "Enter extended session. Send WDBI without SA unlock. "
                "Must receive NRC 0x33 (securityAccessDenied)."
            ),
            confidence = "HIGH",
        )]

    def _check_dos_vulnerability(self, findings, alerts) -> list[Vulnerability]:
        """
        Vulnerability: ECU susceptible to diagnostic DoS.
        Evidence: Timeout findings + diagnostic storm alerts.
        """
        timeout_findings = [f for f in findings
                            if f.category == "NO_RESPONSE_TIMEOUT"]
        storm_alerts     = [a for a in alerts if a.rule_id == "IDS-007"]

        if not timeout_findings and not storm_alerts:
            return []

        return [self._make_vuln(
            title    = "ECU Susceptible to Diagnostic Denial of Service",
            severity = "MEDIUM",
            cvss     = CVSSScore("L","L","N","N","U","N","N","H"),
            service  = "UDS Stack — All Services",
            description = (
                f"ECU showed {len(timeout_findings)} timeout(s) "
                "during fuzzing and exhibited high request rate sensitivity. "
                "Malformed or high-rate diagnostic requests may cause ECU "
                "processing delays or temporary unavailability."
            ),
            attack_scenario = (
                "1. Attacker connects to OBD-II port or injects via CAN\n"
                "2. Sends malformed UDS requests at high rate\n"
                "3. ECU diagnostic stack overwhelmed or crashes\n"
                "4. Safety-relevant ECU functions delayed or unavailable\n"
                "5. e.g. ABS, ADAS, or powertrain functions disrupted"
            ),
            impact = (
                "Temporary ECU unavailability. In safety-critical ECUs, "
                "diagnostic stack overload can affect runtime functions "
                "sharing the same processor."
            ),
            evidence   = ([f.finding_id for f in timeout_findings[:2]] +
                          [a.alert_id for a in storm_alerts[:2]]),
            iso_14229  = "ISO 14229-1 §7.4.1 — P2Server timing requirements",
            iso_21434  = "ISO/SAE 21434 Clause 14 — Availability monitoring",
            cwe        = "CWE-400: Uncontrolled Resource Consumption",
            remediation = (
                "1. Implement UDS request rate limiting (max 20 req/sec)\n"
                "2. Add input length validation before any processing\n"
                "3. Implement watchdog timer for UDS request handling\n"
                "4. Isolate diagnostic stack from runtime functions"
            ),
            verification = (
                "Send 50 requests/second for 10 seconds. "
                "ECU must remain responsive and return NRC 0x21 "
                "(busyRepeatRequest) for excess requests."
            ),
            confidence = "MEDIUM",
        )]

    def _check_timing_oracle(self, findings) -> list[Vulnerability]:
        """
        Vulnerability: SA key validation timing oracle.
        Evidence: TIMING_ORACLE findings.
        """
        timing_findings = [f for f in findings
                           if f.category == "TIMING_ORACLE"]
        if not timing_findings:
            return []

        return [self._make_vuln(
            title    = "Security Access Timing Side-Channel Oracle",
            severity = "MEDIUM",
            cvss     = CVSSScore("P","H","N","N","U","N","L","N"),
            service  = "SID 0x27 — Security Access",
            description = (
                f"SA key validation showed variable response timing "
                f"({len(timing_findings)} timing anomaly/ies detected). "
                "Non-constant-time key comparison leaks information about "
                "the correct key through response time measurement."
            ),
            attack_scenario = (
                "1. Attacker requests seed from ECU\n"
                "2. Tries different key values and measures response time\n"
                "3. Keys that match more bytes take slightly longer\n"
                "4. Attacker narrows down correct key byte by byte\n"
                "5. Full key recovered without brute force"
            ),
            impact = (
                "Security Access key recovery without brute force. "
                "Reduces attack complexity significantly for an attacker "
                "with physical access and precise timing measurement."
            ),
            evidence   = [f.finding_id for f in timing_findings],
            iso_14229  = "ISO 14229-1 §10.4.5 — SA implementation security",
            iso_21434  = "ISO/SAE 21434 Clause 15 — Side-channel resistance",
            cwe        = "CWE-208: Observable Timing Discrepancy",
            remediation = (
                "Use constant-time byte comparison for key validation:\n"
                "  result = 0\n"
                "  for i in range(len(expected)):\n"
                "      result |= expected[i] ^ received[i]\n"
                "  return result == 0  # constant time\n"
                "Never use early-exit comparison for security keys."
            ),
            verification = (
                "Measure response time for 1000 key attempts. "
                "Standard deviation must be < 1ms. "
                "No correlation between key value and response time."
            ),
            confidence = "MEDIUM",
        )]

    def _check_post_reset_weakness(self, alerts) -> list[Vulnerability]:
        """
        Vulnerability: Post-reset security initialization window.
        Evidence: IDS-008 alerts.
        """
        reset_alerts = [a for a in alerts if a.rule_id == "IDS-008"]
        if not reset_alerts:
            return []

        return [self._make_vuln(
            title    = "Post-Reset Security Initialization Race Window",
            severity = "HIGH",
            cvss     = CVSSScore("L","H","N","N","U","N","H","N"),
            service  = "SID 0x11 — ECU Reset + SID 0x2E — Write Data",
            description = (
                f"Write requests were detected within {SA_LOCKOUT_TIME}s "
                "of ECU reset. Some ECU implementations have a brief "
                "post-reset window where security modules are not fully "
                "initialized, potentially allowing unauthorized writes."
            ),
            attack_scenario = (
                "1. Attacker forces ECU reset (0x11 hard reset)\n"
                "2. Immediately sends WDBI or RMBA request\n"
                "3. If security module not yet initialized — request accepted\n"
                "4. Attacker can write data during initialization window\n"
                "Note: Timing must be precise — typically 50-200ms window"
            ),
            impact = (
                "Potential bypass of security initialization. "
                "Write access to ECU memory or calibration data "
                "during unprotected startup window."
            ),
            evidence   = [a.alert_id for a in reset_alerts[:3]],
            iso_14229  = "ISO 14229-1 §9.3 — Security state after reset",
            iso_21434  = "ISO/SAE 21434 Clause 15 — Security validation",
            cwe        = "CWE-362: Race Condition",
            remediation = (
                "1. Initialize security module BEFORE UDS stack starts\n"
                "2. UDS stack must not process requests until all security\n"
                "   modules report INITIALIZED\n"
                "3. Implement minimum post-reset delay before accepting\n"
                "   write services (recommend 500ms minimum)"
            ),
            verification = (
                "Send ECU reset then immediately send WDBI. "
                "Must receive NRC 0x22 (conditionsNotCorrect) "
                "for minimum 500ms after any reset."
            ),
            confidence = "LOW",
        )]

    def _check_did_enumeration(self, alerts) -> list[Vulnerability]:
        """
        Vulnerability: DID enumeration / information disclosure.
        Evidence: IDS-005 alerts.
        """
        enum_alerts = [a for a in alerts if a.rule_id == "IDS-005"]
        if not enum_alerts:
            return []

        return [self._make_vuln(
            title    = "DID Enumeration Possible — Information Disclosure Risk",
            severity = "LOW",
            cvss     = CVSSScore("L","L","N","N","U","L","N","N"),
            service  = "SID 0x22 — Read Data By Identifier",
            description = (
                "ECU responded to systematic DID scanning, allowing an attacker "
                "to map all available data identifiers. "
                "This enables targeted reconnaissance before an attack."
            ),
            attack_scenario = (
                "1. Attacker scans all DID values 0x0000-0xFFFF\n"
                "2. ECU NRC codes reveal which DIDs exist\n"
                "3. NRC 0x31 (out of range) = DID unknown\n"
                "4. Any other NRC or positive = DID exists\n"
                "5. Attacker builds complete DID map for targeted attack"
            ),
            impact = (
                "Information disclosure — attacker learns ECU data structure. "
                "Enables targeted attacks on specific DIDs containing "
                "calibration data, VIN, or security parameters."
            ),
            evidence   = [a.alert_id for a in enum_alerts[:2]],
            iso_14229  = "ISO 14229-1 §9.3 — Access control for DIDs",
            iso_21434  = "ISO/SAE 21434 Clause 9 — Asset: DID data",
            cwe        = "CWE-204: Observable Response Discrepancy",
            remediation = (
                "1. Return uniform NRC 0x31 for all unauthorized DIDs\n"
                "   (don't differentiate between 'not found' and 'not allowed')\n"
                "2. Require extended session for non-standard DID ranges\n"
                "3. Implement DID access rate limiting"
            ),
            verification = (
                "Scan DIDs 0x0000-0x00FF from default session. "
                "All non-whitelisted DIDs must return identical NRC 0x31."
            ),
            confidence = "MEDIUM",
        )]

    def _check_write_without_authentication(self, findings) -> list[Vulnerability]:
        """Check for any write/execute operations that succeeded without auth."""
        unauth_writes = [f for f in findings
                         if f.category in ("ACCESS_CONTROL_BYPASS",
                                           "STATE_MACHINE_VIOLATION")
                         and f.severity == "CRITICAL"]
        if not unauth_writes:
            return []

        return [self._make_vuln(
            title    = "Authenticated Write Operations Accessible Without Authentication",
            severity = "CRITICAL",
            cvss     = CVSSScore("L","L","N","N","C","L","H","L"),
            service  = "Multiple — WDBI/RMBA/RC",
            description = (
                f"{len(unauth_writes)} write or execute operation(s) succeeded "
                "without proper authentication. "
                "This is a fundamental access control failure."
            ),
            attack_scenario = (
                "1. Connect to OBD-II\n"
                "2. Send write/execute request without Security Access\n"
                "3. ECU accepts request\n"
                "4. Full calibration and control access without authentication"
            ),
            impact = (
                "Complete ECU compromise. "
                "All write and execute protections bypassed."
            ),
            evidence   = [f.finding_id for f in unauth_writes[:3]],
            iso_14229  = "ISO 14229-1 §10.4 — Authentication requirements",
            iso_21434  = "ISO/SAE 21434 Clause 10 — All cybersecurity goals",
            cwe        = "CWE-306: Missing Authentication for Critical Function",
            remediation = (
                "Implement centralized access control function:\n"
                "  def check_access(service_id, session, sa_unlocked):\n"
                "      if service_id in WRITE_SERVICES:\n"
                "          assert session != DEFAULT\n"
                "          assert sa_unlocked\n"
                "Call this at start of every service handler."
            ),
            verification = (
                "Attempt all write services without SA unlock. "
                "Every attempt must return NRC 0x33 or 0x7F."
            ),
            confidence = "HIGH",
        )]

    # ── Report Generator ──────────────────────────────────────────────────────

    def generate_report(self, run_id: str, output_dir: str = REPORT_DIR) -> dict:
        """Generate vulnerability report in JSON and Markdown."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        json_path = self._save_json(run_id, output_dir)
        md_path   = self._save_markdown(run_id, output_dir)
        self._print_terminal()

        return {"json": json_path, "markdown": md_path}

    def _print_terminal(self):
        """Print vulnerability summary to terminal."""
        print("\n" + "═"*65)
        print("  VULNERABILITY ANALYSIS REPORT")
        print(f"  {TARA_STANDARD} | CVSS v3.1 | CWE")
        print("═"*65)

        if not self.vulnerabilities:
            print("\n  No vulnerabilities identified.")
            print("═"*65 + "\n")
            return

        # Sort by CVSS score
        sorted_vulns = sorted(self.vulnerabilities,
                               key=lambda v: v.cvss.base_score, reverse=True)

        print(f"\n  {'ID':<8} {'CVSS':<6} {'SEV':<10} {'TITLE'}")
        print(f"  {'─'*61}")
        for v in sorted_vulns:
            sev = v.cvss.severity_label
            col = ("\033[91m" if sev in ("CRITICAL","HIGH") else
                   "\033[93m" if sev == "MEDIUM" else "\033[92m")
            print(f"  {v.vuln_id:<8} "
                  f"{col}{v.cvss.base_score:<6.1f}{sev:<10}\033[0m "
                  f"{v.title[:40]}")
        print(f"  {'─'*61}\n")

        for v in sorted_vulns:
            if v.cvss.severity_label in ("CRITICAL", "HIGH"):
                print(f"  [{v.vuln_id}] {v.title}")
                print(f"  CVSS: {v.cvss.base_score} ({v.cvss.vector_string})")
                print(f"  CWE:  {v.cwe_id}")
                print(f"  Fix:  {v.remediation.split(chr(10))[0]}")
                print()

        print("═"*65 + "\n")

    def _save_json(self, run_id: str, output_dir: str) -> str:
        report = {
            "run_id":          run_id,
            "timestamp":       datetime.now().isoformat(),
            "standard":        TARA_STANDARD,
            "cvss_version":    "3.1",
            "total_vulns":     len(self.vulnerabilities),
            "by_severity":     self._count_by_severity(),
            "vulnerabilities": [
                {
                    "vuln_id":         v.vuln_id,
                    "title":           v.title,
                    "severity":        v.severity,
                    "cvss_score":      v.cvss.base_score,
                    "cvss_vector":     v.cvss.vector_string,
                    "cvss_severity":   v.cvss.severity_label,
                    "cwe_id":          v.cwe_id,
                    "affected_service":v.affected_service,
                    "description":     v.description,
                    "attack_scenario": v.attack_scenario,
                    "impact":          v.impact,
                    "evidence":        v.evidence,
                    "iso_14229_ref":   v.iso_14229_ref,
                    "iso_21434_ref":   v.iso_21434_ref,
                    "remediation":     v.remediation,
                    "verification":    v.verification,
                    "confidence":      v.confidence,
                }
                for v in self.vulnerabilities
            ],
        }
        path = str(Path(output_dir) / f"{run_id}_vulnerabilities.json")
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        log.info(f"Vulnerability JSON: {path}")
        return path

    def _save_markdown(self, run_id: str, output_dir: str) -> str:
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# ECU Vulnerability Assessment Report",
            f"",
            f"> **Run ID**: `{run_id}`  ",
            f"> **Timestamp**: {ts}  ",
            f"> **Standard**: {TARA_STANDARD}  ",
            f"> **CVSS Version**: 3.1  ",
            f"> **Target**: Virtual ECU — ISO 14229-1 UDS  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev, count in self._count_by_severity().items():
            lines.append(f"| {sev} | {count} |")

        lines += [f"", f"---", f"", f"## Vulnerability Details", f""]

        for v in sorted(self.vulnerabilities,
                         key=lambda x: x.cvss.base_score, reverse=True):
            lines += [
                f"### {v.vuln_id} — {v.title}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **CVSS Score** | {v.cvss.base_score} ({v.cvss.severity_label}) |",
                f"| **CVSS Vector** | `{v.cvss.vector_string}` |",
                f"| **CWE** | {v.cwe_id} |",
                f"| **Affected Service** | {v.affected_service} |",
                f"| **Confidence** | {v.confidence} |",
                f"| **Evidence** | {', '.join(v.evidence)} |",
                f"",
                f"**Description:**  ",
                f"{v.description}",
                f"",
                f"**Attack Scenario:**  ",
                f"```",
                f"{v.attack_scenario}",
                f"```",
                f"",
                f"**Impact:**  ",
                f"{v.impact}",
                f"",
                f"**Remediation:**  ",
                f"```",
                f"{v.remediation}",
                f"```",
                f"",
                f"**Verification:**  ",
                f"{v.verification}",
                f"",
                f"**References:**  ",
                f"- {v.iso_14229_ref}  ",
                f"- {v.iso_21434_ref}  ",
                f"",
            ]

        path = str(Path(output_dir) / f"{run_id}_vulnerability_report.md")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        log.info(f"Vulnerability Markdown: {path}")
        return path

    def _count_by_severity(self) -> dict:
        counts = {}
        for v in self.vulnerabilities:
            sev = v.cvss.severity_label
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    # ── Factory ───────────────────────────────────────────────────────────────

    def _make_vuln(self, title, severity, cvss, service, description,
                    attack_scenario, impact, evidence, iso_14229, iso_21434,
                    cwe, remediation, verification, confidence) -> Vulnerability:
        self._vuln_count += 1
        return Vulnerability(
            vuln_id          = f"V-{self._vuln_count:03d}",
            title            = title,
            severity         = severity,
            cvss             = cvss,
            affected_service = service,
            description      = description,
            attack_scenario  = attack_scenario,
            impact           = impact,
            evidence         = evidence,
            iso_14229_ref    = iso_14229,
            iso_21434_ref    = iso_21434,
            cwe_id           = cwe,
            remediation      = remediation,
            verification     = verification,
            confidence       = confidence,
        )