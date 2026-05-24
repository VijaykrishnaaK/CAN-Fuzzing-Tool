"""
monitor/anomaly_detector.py
============================
Analyses UDS responses during fuzzing to flag interesting findings.

What counts as "interesting" (a potential vulnerability):
  1. Unexpected positive response   — ECU accepted something it shouldn't
  2. Timeout on valid request       — possible DoS / crash
  3. Wrong NRC code                 — ECU behavior doesn't match ISO 14229
  4. Response timing anomaly        — too fast/slow (timing attack surface)
  5. Unexpected response length     — parser bug indicator
  6. State machine violation        — ECU accepted request in wrong session

Each finding is severity-rated and ISO/SAE 21434 mapped.
"""

import time
import logging
from dataclasses import dataclass, field
from config import *
from fuzzer.uds_client import UDSResponse
from fuzzer.fuzz_engine import FuzzCase

log = logging.getLogger("AnomalyDetector")


@dataclass
class Finding:
    """A single security finding from fuzzing."""
    finding_id:     str
    severity:       str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category:       str           # What type of finding
    title:          str
    description:    str
    request_hex:    str           # The payload that triggered this
    response_hex:   str           # The response received
    response_time:  float         # In seconds
    iso_14229_ref:  str           # Which ISO 14229 rule was violated
    iso_21434_ref:  str           # ISO/SAE 21434 clause
    countermeasure: str
    fuzz_strategy:  str
    timestamp:      str = ""

    def __post_init__(self):
        if not self.timestamp:
            from datetime import datetime
            self.timestamp = datetime.now().isoformat()


class AnomalyDetector:
    """
    Analyses fuzz results and flags security-relevant findings.
    Run after each fuzz case or in batch after a full run.
    """

    def __init__(self):
        self.findings:       list[Finding] = []
        self._finding_count: int = 0

        # Expected NRC codes per service+session context
        # Used to detect wrong NRC responses
        self._expected_nrc_map = {
            # (service_id, in_default_session): expected_nrc_if_rejected
            SID_WDBI: 0x7F,   # Should get serviceNotSupportedInActiveSession
            SID_RC:   0x7F,
            SID_RMBA: 0x33,   # Should get securityAccessDenied
        }

    def analyse(self, case: FuzzCase) -> list[Finding]:
        """
        Analyse a single fuzz case result.
        Returns list of findings (empty if nothing interesting).
        """
        if case.response is None:
            return []

        resp = case.response
        new_findings = []

        # Run all detection rules
        new_findings += self._rule_unexpected_positive(case, resp)
        new_findings += self._rule_timeout_detected(case, resp)
        new_findings += self._rule_timing_anomaly(case, resp)
        new_findings += self._rule_wrong_nrc(case, resp)
        new_findings += self._rule_unexpected_length(case, resp)
        new_findings += self._rule_state_machine_violation(case, resp)

        # Mark case as interesting if any findings
        if new_findings:
            case.is_interesting = True
            case.finding_reason = " | ".join(f.title for f in new_findings)

        self.findings.extend(new_findings)
        return new_findings

    def analyse_batch(self, cases: list[FuzzCase]) -> list[Finding]:
        """Analyse a batch of fuzz cases. Returns all findings."""
        all_findings = []
        for case in cases:
            all_findings.extend(self.analyse(case))
        return all_findings

    def get_summary(self) -> dict:
        """Return summary statistics of all findings."""
        by_severity = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        return {
            "total_findings":    len(self.findings),
            "by_severity":       by_severity,
            "critical_count":    by_severity.get("CRITICAL", 0),
            "high_count":        by_severity.get("HIGH", 0),
            "medium_count":      by_severity.get("MEDIUM", 0),
            "findings":          self.findings,
        }

    # ── Detection Rules ───────────────────────────────────────────────────────

    def _rule_unexpected_positive(self, case: FuzzCase,
                                   resp: UDSResponse) -> list[Finding]:
        """
        Rule: ECU returned positive response to a request it should reject.
        
        Examples:
          - Positive response to undefined service ID
          - WDBI accepted without Security Access
          - Programming session accepted without Extended session first
        
        This is the most critical finding — indicates an access control bypass.
        """
        findings = []

        if not resp.is_positive:
            return findings

        sid = case.payload[0] if case.payload else 0

        # Undefined service ID got positive response — major bug
        defined_sids = [0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27,
                        0x28, 0x2E, 0x31, 0x34, 0x35, 0x36, 0x37,
                        0x38, 0x3E, 0x85, 0x86]
        if sid not in defined_sids:
            findings.append(self._make_finding(
                severity    = "CRITICAL",
                category    = "UNDEFINED_SERVICE_ACCEPTED",
                title       = f"Undefined SID 0x{sid:02X} returned positive response",
                description = (
                    f"ECU returned positive response to service ID 0x{sid:02X} "
                    f"which is not defined in ISO 14229-1. This indicates the ECU "
                    f"may have undocumented services or a response routing bug."
                ),
                case        = case,
                resp        = resp,
                iso_14229   = "ISO 14229-1 §7.4 — Undefined SIDs must return NRC 0x11",
                iso_21434   = "ISO/SAE 21434 Clause 15 — Cybersecurity validation",
                countermeasure = (
                    "Implement strict service ID whitelist in UDS server. "
                    "All undefined SIDs must return NRC 0x11 "
                    "(serviceNotSupported)."
                ),
            ))

        # Skip_SA strategy got positive WDBI — access control bypass
        if ("skip_sa" in case.strategy and sid == SID_WDBI
                and resp.is_positive):
            findings.append(self._make_finding(
                severity    = "CRITICAL",
                category    = "ACCESS_CONTROL_BYPASS",
                title       = "WDBI accepted without Security Access unlock",
                description = (
                    "ECU accepted a Write Data By Identifier (0x2E) request "
                    "without requiring Security Access (0x27) to be unlocked first. "
                    "This allows unauthorized modification of ECU calibration data."
                ),
                case        = case,
                resp        = resp,
                iso_14229   = "ISO 14229-1 §9.4 — WDBI requires SA in extended session",
                iso_21434   = "ISO/SAE 21434 Clause 10 — Cybersecurity goal: integrity",
                countermeasure = (
                    "Enforce Security Access check before processing WDBI. "
                    "Return NRC 0x33 (securityAccessDenied) if SA not unlocked."
                ),
            ))

        return findings

    def _rule_timeout_detected(self, case: FuzzCase,
                                resp: UDSResponse) -> list[Finding]:
        """
        Rule: No response received within timeout.
        Could indicate: ECU crash, infinite loop, DoS vulnerability.
        """
        if not resp.timed_out:
            return []

        # Only flag if this service normally gets a response
        sid = case.payload[0] if case.payload else 0
        if sid in [SID_DSC, SID_ER, SID_SA, SID_RDBI, SID_WDBI, SID_RC]:
            return [self._make_finding(
                severity    = "HIGH",
                category    = "NO_RESPONSE_TIMEOUT",
                title       = f"No response to SID 0x{sid:02X} — possible DoS",
                description = (
                    f"ECU did not respond to service 0x{sid:02X} within "
                    f"{BUS_TIMEOUT}s. This may indicate: ECU crash caused by "
                    f"malformed payload, infinite processing loop, or bus error. "
                    f"Payload: {case.payload.hex().upper()}"
                ),
                case        = case,
                resp        = resp,
                iso_14229   = "ISO 14229-1 §7.4.1 — P2Server timing requirements",
                iso_21434   = "ISO/SAE 21434 Clause 14 — Availability requirement",
                countermeasure = (
                    "Implement watchdog timer on UDS request processing. "
                    "Input validation must occur before any processing begins. "
                    "Fuzzing should be part of ECU security validation."
                ),
            )]
        return []

    def _rule_timing_anomaly(self, case: FuzzCase,
                              resp: UDSResponse) -> list[Finding]:
        """
        Rule: Response timing outside expected bounds.
        
        Too fast: ECU may not be processing request (canned response bug)
        Too slow: possible timing oracle for Security Access attacks
        
        Security Access timing is especially important — variable response
        time can leak information about key validation algorithm.
        """
        findings = []
        if resp.timed_out or resp.response_time_s <= 0:
            return findings

        sid = case.payload[0] if case.payload else 0

        # SA timing oracle detection
        if sid == SID_SA and len(case.payload) > 1:
            subfunction = case.payload[1]
            if subfunction % 2 == 0:  # Key response
                # If correct key takes different time than wrong key — timing oracle
                if resp.response_time_s > SA_P2_TIMEOUT * 3:
                    findings.append(self._make_finding(
                        severity    = "HIGH",
                        category    = "TIMING_ORACLE",
                        title       = "Security Access key validation timing anomaly",
                        description = (
                            f"SA key validation took {resp.response_time_s*1000:.1f}ms "
                            f"which is {resp.response_time_s/SA_P2_TIMEOUT:.1f}× "
                            f"the expected P2 timeout ({SA_P2_TIMEOUT*1000:.0f}ms). "
                            f"Variable timing in key validation can reveal information "
                            f"about the key comparison algorithm (timing side-channel)."
                        ),
                        case        = case,
                        resp        = resp,
                        iso_14229   = "ISO 14229-1 §10.4.5 — SA timing requirements",
                        iso_21434   = "ISO/SAE 21434 Clause 15 — Side-channel resistance",
                        countermeasure = (
                            "Use constant-time comparison for key validation. "
                            "Ensure reject and accept paths take equal processing time. "
                            "Consider HMAC-based key validation instead of XOR."
                        ),
                    ))

        # Suspiciously fast response (< 0.1ms) to complex write/routine request
        # Note: virtual ECU is fast — only flag extremely fast responses
        # that suggest the ECU isn't processing the request at all
        if resp.response_time_s < 0.0001 and sid in [SID_WDBI, SID_RC]:
            findings.append(self._make_finding(
                severity    = "INFO",
                category    = "SUSPICIOUS_FAST_RESPONSE",
                title       = f"Very fast response to SID 0x{sid:02X} ({resp.response_time_s*1000:.3f}ms)",
                description = (
                    f"Response received in {resp.response_time_s*1000:.3f}ms. "
                    f"On a real ECU this would suggest a canned/hardcoded response. "
                    f"On virtual ECU this is expected — verify on real hardware."
                ),
                case        = case,
                resp        = resp,
                iso_14229   = "ISO 14229-1 §7.4.1 — P2Server timing",
                iso_21434   = "ISO/SAE 21434 Clause 15 — Validation on target hardware",
                countermeasure = "Verify on real ECU hardware — virtual timing is not representative.",
            ))

        return findings

    def _rule_wrong_nrc(self, case: FuzzCase,
                         resp: UDSResponse) -> list[Finding]:
        """
        Rule: ECU returned wrong NRC code for the situation.
        E.g. returning 0x22 (conditionsNotCorrect) when 0x7F
        (serviceNotSupportedInSession) is expected.
        Wrong NRC can reveal internal ECU state.
        """
        findings = []
        if resp.is_positive or resp.timed_out or resp.nrc_code is None:
            return findings

        sid = case.payload[0] if case.payload else 0

        # NRC 0x78 (responsePending) in wrong context
        if resp.nrc_code == 0x78:
            findings.append(self._make_finding(
                severity    = "INFO",
                category    = "RESPONSE_PENDING",
                title       = f"ECU returned NRC 0x78 (responsePending) for 0x{sid:02X}",
                description = (
                    "ECU returned 0x78 (requestCorrectlyReceivedResponsePending). "
                    "This indicates a long-running operation. Multiple consecutive "
                    "0x78 responses could be used to extend timeouts and probe "
                    "ECU processing behavior."
                ),
                case        = case,
                resp        = resp,
                iso_14229   = "ISO 14229-1 §7.4.2 — Response pending handling",
                iso_21434   = "ISO/SAE 21434 Clause 14 — Availability",
                countermeasure = "Limit number of consecutive 0x78 responses. Implement timeout.",
            ))

        return findings

    def _rule_unexpected_length(self, case: FuzzCase,
                                 resp: UDSResponse) -> list[Finding]:
        """
        Rule: Response length doesn't match expected for the service.
        Could indicate buffer overflow, partial response, or parser bug.
        """
        if resp.timed_out or not resp.response_bytes:
            return []

        sid = case.payload[0] if case.payload else 0
        resp_len = len(resp.response_bytes)

        # Positive response too short to be valid
        if resp.is_positive and resp_len < 2 and  resp.response_bytes[0:2] != b'\x54':
            return [self._make_finding(
                severity    = "MEDIUM",
                category    = "UNEXPECTED_RESPONSE_LENGTH",
                title       = f"Positive response too short for SID 0x{sid:02X}",
                description = (
                    f"Positive response has only {resp_len} byte(s) — "
                    f"too short to be a valid UDS response. "
                    f"May indicate response truncation or buffer issue."
                ),
                case        = case,
                resp        = resp,
                iso_14229   = "ISO 14229-1 §7.4 — Response format requirements",
                iso_21434   = "ISO/SAE 21434 Clause 15 — Validation",
                countermeasure = "Validate response frame length before sending.",
            )]
        return []

    def _rule_state_machine_violation(self, case: FuzzCase,
                                       resp: UDSResponse) -> list[Finding]:
        """
        Rule: ECU accepted a request that requires prerequisites it hasn't met.

        Key insight: DSC (0x10) is ALWAYS legitimately accepted — you can
        always request a session change. A positive response to DSC is NOT
        a bypass. Only flag services that genuinely require SA or a specific
        session before they can return positive.

        Services that require Security Access unlock:
          - WDBI (0x2E) → needs SA
          - RMBA (0x23) → needs SA
          - RC   (0x31) → needs SA for protected routines

        Services that require Extended/Programming session:
          - SA   (0x27) → needs non-default session (but seed request OK to probe)
          - WDBI (0x2E) → needs extended session
          - RC   (0x31) → needs extended/programming session

        Services that are always valid regardless of session:
          - DSC  (0x10) → always accepted — session change is always valid
          - RDBI (0x22) → read-only, always valid in any session
          - RDTC (0x19) → read-only, always valid
        """
        findings = []

        if not resp.is_positive:
            return findings

        sid      = case.payload[0] if case.payload else 0
        strategy = case.strategy

        # ── Services that are ALWAYS legitimately accepted ────────────────────
        # DSC: session change requests are always valid — never a bypass
        # RDBI: read-only, no security prerequisite
        # RDTC: read-only DTC read, always valid
        # ER: reset is always valid (though may be flagged by IDS separately)
        always_valid_sids = {SID_DSC, SID_RDBI, SID_RDTC, SID_ER}
        if sid in always_valid_sids:
            return []

        # ── Strategy-specific bypass detection ────────────────────────────────

        # skip_sa strategy: entered session but skipped Security Access.
        # Only flag services that genuinely need SA to return positive.
        if "skip_sa" in strategy:
            sa_required_sids = {SID_WDBI, SID_RMBA, SID_RC}
            if sid in sa_required_sids:
                findings.append(self._make_finding(
                    severity    = "CRITICAL",
                    category    = "ACCESS_CONTROL_BYPASS",
                    title       = (f"SID 0x{sid:02X} accepted without "
                                   f"Security Access unlock"),
                    description = (
                        f"Service 0x{sid:02X} returned positive response without "
                        f"Security Access (0x27) being unlocked first. "
                        f"ISO 14229-1 requires SA unlock before this service "
                        f"can return a positive response. "
                        f"This is a genuine access control bypass."
                    ),
                    case        = case,
                    resp        = resp,
                    iso_14229   = (f"ISO 14229-1 §10.4 — Service 0x{sid:02X} "
                                   f"requires SA unlock"),
                    iso_21434   = "ISO/SAE 21434 Clause 10 — Cybersecurity goals: integrity",
                    countermeasure = (
                        "Check sa_manager.unlocked at start of every "
                        "write/memory service handler. Return NRC 0x33 "
                        "(securityAccessDenied) if SA not unlocked."
                    ),
                ))

        # escalation_bypass: tried to jump default→programming directly.
        # DSC accepted this — flag it only if the session IS programming.
        if "escalation_bypass" in strategy:
            if (sid == SID_DSC
                    and len(case.payload) > 1
                    and case.payload[1] == SESSION_PROGRAMMING):
                findings.append(self._make_finding(
                    severity    = "CRITICAL",
                    category    = "SESSION_ESCALATION_BYPASS",
                    title       = "Programming session granted from default — prerequisite bypass",
                    description = (
                        "ECU accepted a programming session request (0x10 0x02) "
                        "directly from default session without requiring Extended "
                        "session + Security Access first. "
                        "ISO 14229-1 mandates: Default → Extended → SA → Programming. "
                        "This allows unauthorized firmware flashing access."
                    ),
                    case        = case,
                    resp        = resp,
                    iso_14229   = "ISO 14229-1 §9.2 — Session prerequisite chain",
                    iso_21434   = "ISO/SAE 21434 Clause 10 — Cybersecurity goal: integrity",
                    countermeasure = (
                        "In DSC handler: if requested=programming AND "
                        "current=default, always return NRC 0x22 (conditionsNotCorrect). "
                        "Programming session must only be reachable via Extended+SA."
                    ),
                ))

        # wrong_session: services sent in default session that need extended.
        if "wrong_session" in strategy:
            extended_required_sids = {SID_WDBI, SID_RC, SID_CC}
            if sid in extended_required_sids:
                findings.append(self._make_finding(
                    severity    = "HIGH",
                    category    = "STATE_MACHINE_VIOLATION",
                    title       = (f"SID 0x{sid:02X} accepted in wrong session"),
                    description = (
                        f"Service 0x{sid:02X} returned positive response "
                        f"in default session — this service requires extended "
                        f"or programming session per ISO 14229-1. "
                        f"ECU is not enforcing session prerequisites."
                    ),
                    case        = case,
                    resp        = resp,
                    iso_14229   = (f"ISO 14229-1 §7.5 — Session prerequisites "
                                   f"for service 0x{sid:02X}"),
                    iso_21434   = "ISO/SAE 21434 Clause 10 — Cybersecurity goals",
                    countermeasure = (
                        f"Return NRC 0x7F (serviceNotSupportedInActiveSession) "
                        f"for SID 0x{sid:02X} when session is default."
                    ),
                ))

        # reset_persistence: SA state should NOT survive ECU reset.
        if "reset_persistence" in strategy:
            sa_required_sids = {SID_WDBI, SID_RMBA, SID_RC}
            if sid in sa_required_sids:
                findings.append(self._make_finding(
                    severity    = "CRITICAL",
                    category    = "SA_STATE_PERSISTENCE_BUG",
                    title       = (f"SA state persisted across ECU reset — "
                                   f"SID 0x{sid:02X} accepted"),
                    description = (
                        f"Security Access unlock state survived an ECU reset. "
                        f"Service 0x{sid:02X} accepted positive after reset, "
                        f"indicating SA lock was not cleared. "
                        f"ISO 14229-1 requires all security state to reset on 0x11."
                    ),
                    case        = case,
                    resp        = resp,
                    iso_14229   = "ISO 14229-1 §9.3 — SA state must clear on reset",
                    iso_21434   = "ISO/SAE 21434 Clause 15 — Security validation",
                    countermeasure = (
                        "Call sa_manager.reset() in ECU Reset (0x11) handler. "
                        "SA unlock flag must be stored in RAM only — never NVM."
                    ),
                ))

        return findings

    # ── Factory ───────────────────────────────────────────────────────────────

    def _make_finding(self, severity: str, category: str, title: str,
                       description: str, case: FuzzCase, resp: UDSResponse,
                       iso_14229: str, iso_21434: str,
                       countermeasure: str) -> Finding:
        self._finding_count += 1
        return Finding(
            finding_id     = f"F-{self._finding_count:03d}",
            severity       = severity,
            category       = category,
            title          = title,
            description    = description,
            request_hex    = case.payload.hex().upper(),
            response_hex   = (resp.response_bytes.hex().upper()
                              if resp.response_bytes else "TIMEOUT"),
            response_time  = resp.response_time_s,
            iso_14229_ref  = iso_14229,
            iso_21434_ref  = iso_21434,
            countermeasure = countermeasure,
            fuzz_strategy  = case.strategy,
        )