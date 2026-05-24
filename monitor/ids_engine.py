"""
monitor/ids_engine.py
======================
Real-time Intrusion Detection System (IDS) for CAN/UDS traffic.

Monitors live CAN bus traffic and flags suspicious UDS behavior
based on rule-based detection — the same approach used in
production automotive IDS implementations today.

Why rule-based (not ML)?
  ISO/SAE 21434 and UNECE WP.29 R155 require explainable,
  deterministic security behavior. ML-based IDS exists in research
  but production ECU IDS uses rules because:
    - Safety certification requires deterministic behavior
    - Low RAM/CPU on ECUs — no room for ML inference
    - Every alert must be traceable to a specific rule (auditability)

Detection Rules Implemented:
  Rule 1 — SA Rate Limiter        : Too many Security Access attempts
  Rule 2 — Session Escalation     : Unexpected jump to programming session
  Rule 3 — Write Storm            : Too many WDBI writes in short window
  Rule 4 — Unknown Service        : Service ID not in whitelist
  Rule 5 — DID Enumeration        : Scanning many DIDs rapidly
  Rule 6 — Reset Flood            : Repeated ECU resets
  Rule 7 — Diagnostic Storm       : Overall request rate too high
  Rule 8 — Post-Reset Write       : Write attempt immediately after reset

ISO/SAE 21434 Reference:
  Clause 14 — Cybersecurity monitoring in operations
UNECE WP.29 R155 Reference:
  Article 7.3.5 — Monitoring of cyber threats in the field
"""

import time
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from config import *

log = logging.getLogger("IDS")


# ── IDS Alert ─────────────────────────────────────────────────────────────────

@dataclass
class IDSAlert:
    """A single IDS detection alert."""
    alert_id:       str
    rule_id:        str
    severity:       str           # CRITICAL / HIGH / MEDIUM / LOW
    rule_name:      str
    description:    str
    evidence:       dict          # Quantitative evidence
    service_id:     int | None    # UDS SID that triggered it
    iso_clause:     str
    wp29_ref:       str
    recommended_action: str
    timestamp:      str = ""
    session_at_alert: int = SESSION_DEFAULT

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


# ── UDS Request Record ────────────────────────────────────────────────────────

@dataclass
class UDSRecord:
    """Record of a single UDS request seen on the bus."""
    service_id:  int
    payload:     bytes
    timestamp:   float
    session:     int


# ── IDS Engine ────────────────────────────────────────────────────────────────

class IDSEngine:
    """
    Real-time UDS/CAN intrusion detection engine.

    Feed UDS requests into analyse_request() as they arrive.
    The engine maintains a sliding time window of recent traffic
    and fires alerts when rules are triggered.

    Usage:
        ids = IDSEngine()
        # Called for every UDS request seen on the bus:
        alerts = ids.analyse_request(service_id=0x27, payload=b'\\x01',
                                      current_session=SESSION_EXTENDED)
        for alert in alerts:
            print(alert.severity, alert.rule_name)
    """

    def __init__(self, window_seconds: float = 10.0, mode: str = "production"):
        """
        Args:
            window_seconds: Sliding time window for rate-based rules.
            mode: 'production' — thresholds for real ECU monitoring
                  'fuzzing'    — relaxed thresholds, storm rule disabled
                                 (use this when intentionally fuzzing your own ECU)
        """
        self.window_s     = window_seconds
        self.mode         = mode
        self._history:    deque[UDSRecord] = deque()
        self._alert_count = 0
        self.alerts:      list[IDSAlert]   = []

        # Per-rule state
        self._sa_attempts:       list[float] = []
        self._wdbi_timestamps:   list[float] = []
        self._reset_timestamps:  list[float] = []
        self._did_set:           set[int]    = set()
        self._did_scan_window:   list[float] = []
        self._last_reset_time:   float       = 0.0
        self._session_history:   list[tuple[float, int]] = []

        # Thresholds — production mode (real ECU monitoring)
        if mode == "production":
            self.thresholds = {
                "sa_max_attempts_per_window":  3,
                "wdbi_max_per_window":         5,
                "did_scan_threshold":          8,
                "reset_max_per_window":        2,
                "request_rate_max_per_sec":    20,
                "post_reset_write_delay_s":    2.0,
            }
        else:
            # Fuzzing mode — only flag true security violations
            # Storm/rate rules disabled (fuzzer is intentionally fast)
            self.thresholds = {
                "sa_max_attempts_per_window":  10,   # Allow more SA probing
                "wdbi_max_per_window":         50,   # Fuzzer sends many writes
                "did_scan_threshold":          100,  # DID sweep is intentional
                "reset_max_per_window":        20,   # Fuzzer resets a lot
                "request_rate_max_per_sec":    10000, # Effectively disabled
                "post_reset_write_delay_s":    0.5,  # Shorter window
            }
            log.info("IDS running in FUZZING mode — rate rules relaxed")

        # Whitelisted service IDs — anything outside this is Rule 4
        self.service_whitelist = {
            SID_DSC, SID_ER, SID_SA, SID_CC,
            SID_RDBI, SID_WDBI, SID_RC,
            SID_CDTC, SID_RDTC, SID_RMBA,
            0x3E,   # Tester Present
            0x29,   # Authentication (newer ECUs)
        }

    # ── Main Entry Point ──────────────────────────────────────────────────────

    def analyse_request(self, service_id: int, payload: bytes,
                         current_session: int = SESSION_DEFAULT) -> list[IDSAlert]:
        """
        Analyse a single incoming UDS request.
        Call this for every UDS frame seen on the bus.

        Args:
            service_id:      UDS service byte (e.g. 0x27)
            payload:         Remaining bytes after service ID
            current_session: Current ECU session state

        Returns:
            List of IDSAlert objects (empty if no rules triggered)
        """
        now    = time.time()
        record = UDSRecord(
            service_id = service_id,
            payload    = payload,
            timestamp  = now,
            session    = current_session,
        )

        self._history.append(record)
        self._prune_window(now)

        new_alerts = []
        new_alerts += self._rule_sa_rate(record, now)
        new_alerts += self._rule_session_escalation(record, now, current_session)
        new_alerts += self._rule_write_storm(record, now)
        new_alerts += self._rule_unknown_service(record)
        new_alerts += self._rule_did_enumeration(record, now)
        new_alerts += self._rule_reset_flood(record, now)
        new_alerts += self._rule_diagnostic_storm(now)
        new_alerts += self._rule_post_reset_write(record, now)

        self.alerts.extend(new_alerts)
        return new_alerts

    def get_summary(self) -> dict:
        """Return summary of all IDS alerts."""
        by_severity = {}
        by_rule     = {}
        for a in self.alerts:
            by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
            by_rule[a.rule_id]      = by_rule.get(a.rule_id, 0) + 1

        return {
            "total_alerts":     len(self.alerts),
            "by_severity":      by_severity,
            "by_rule":          by_rule,
            "critical_count":   by_severity.get("CRITICAL", 0),
            "high_count":       by_severity.get("HIGH", 0),
            "alerts":           self.alerts,
        }

    def reset(self):
        """Reset IDS state — call when starting a new session."""
        self._history.clear()
        self._sa_attempts.clear()
        self._wdbi_timestamps.clear()
        self._reset_timestamps.clear()
        self._did_set.clear()
        self._did_scan_window.clear()
        self._session_history.clear()
        self.alerts.clear()
        self._alert_count = 0

    # ── Detection Rules ───────────────────────────────────────────────────────

    def _rule_sa_rate(self, record: UDSRecord,
                       now: float) -> list[IDSAlert]:
        """
        Rule 1 — Security Access Rate Limiter.

        Trigger: More than N Security Access key attempts
                 within the sliding window.

        Why it matters: SA brute force attack — attacker sends
        many wrong keys trying to find the correct one.
        ISO 14229-1 mandates lockout after SA_MAX_ATTEMPTS,
        but an attacker can try across multiple sessions.

        Real-world: Miller & Valasek (2015 Jeep hack) used
        repeated SA attempts to unlock diagnostic services.
        """
        if record.service_id != SID_SA:
            return []

        # Even subfunction = sending a key (odd = requesting seed)
        if len(record.payload) < 1:
            return []
        subfunction = record.payload[0]
        if subfunction % 2 != 0:
            return []   # This is a seed request, not a key attempt

        self._sa_attempts.append(now)
        # Prune to window
        self._sa_attempts = [t for t in self._sa_attempts
                              if now - t <= self.window_s]

        threshold = self.thresholds["sa_max_attempts_per_window"]
        if len(self._sa_attempts) > threshold:
            return [self._make_alert(
                rule_id  = "IDS-001",
                severity = "CRITICAL",
                rule_name= "Security Access Brute Force Detected",
                description=(
                    f"{len(self._sa_attempts)} Security Access key attempts "
                    f"in {self.window_s:.0f}s window "
                    f"(threshold: {threshold}). "
                    f"Indicates automated brute force attack on SA 0x27."
                ),
                evidence = {
                    "attempts_in_window": len(self._sa_attempts),
                    "window_seconds":     self.window_s,
                    "threshold":          threshold,
                    "subfunction":        f"0x{subfunction:02X}",
                },
                service_id = SID_SA,
                iso_clause = "ISO/SAE 21434 Clause 14 — Monitoring; "
                             "ISO 14229-1 §10.4.5 SA attempt limiting",
                wp29_ref   = "WP.29 R155 Art 7.3.5 — Threat monitoring",
                action     = (
                    "Lock Security Access for extended period. "
                    "Log tester CAN ID. Alert vehicle SOC (Security Operations). "
                    "Countermeasure: implement exponential backoff on SA."
                ),
                session    = record.session,
            )]
        return []

    def _rule_session_escalation(self, record: UDSRecord, now: float,
                                  current_session: int) -> list[IDSAlert]:
        """
        Rule 2 — Unexpected Session Escalation.

        Trigger: Direct jump to programming session without
                 prior extended session + SA unlock.

        Why it matters: Programming session gives access to
        firmware flashing (0x34/0x36) and memory erase routines.
        An attacker trying to flash malicious firmware must
        reach programming session first.
        """
        if record.service_id != SID_DSC:
            return []
        if not record.payload:
            return []

        requested = record.payload[0]
        self._session_history.append((now, requested))

        # Flag direct programming session attempt from default
        if (requested == SESSION_PROGRAMMING
                and current_session == SESSION_DEFAULT):
            return [self._make_alert(
                rule_id  = "IDS-002",
                severity = "HIGH",
                rule_name= "Unauthorized Programming Session Attempt",
                description=(
                    f"Direct request for programming session (0x{SESSION_PROGRAMMING:02X}) "
                    f"from default session — skipping required extended session + "
                    f"Security Access prerequisites. "
                    f"Indicates attempt to bypass authentication for firmware access."
                ),
                evidence = {
                    "requested_session": f"0x{requested:02X}",
                    "current_session":   f"0x{current_session:02X}",
                    "required_path":     "Default → Extended → SA unlock → Programming",
                },
                service_id = SID_DSC,
                iso_clause = "ISO/SAE 21434 Clause 10 — Cybersecurity goals: integrity",
                wp29_ref   = "WP.29 R155 Art 7.2.2 — Threat scenario: firmware manipulation",
                action     = (
                    "Reject session request with NRC 0x22. "
                    "Log attempt with timestamp and tester address. "
                    "Countermeasure: enforce strict session prerequisite chain."
                ),
                session    = record.session,
            )]
        return []

    def _rule_write_storm(self, record: UDSRecord,
                           now: float) -> list[IDSAlert]:
        """
        Rule 3 — Write Data Storm.

        Trigger: Excessive WDBI (0x2E) requests in short window.

        Why it matters: Attacker may try to rapidly overwrite
        calibration data, threshold values, or ECU parameters
        to cause malfunction. Also a DoS pattern — flooding
        WDBI to exhaust ECU NVM write cycles.
        """
        if record.service_id != SID_WDBI:
            return []

        self._wdbi_timestamps.append(now)
        self._wdbi_timestamps = [t for t in self._wdbi_timestamps
                                  if now - t <= self.window_s]

        threshold = self.thresholds["wdbi_max_per_window"]
        if len(self._wdbi_timestamps) > threshold:
            return [self._make_alert(
                rule_id  = "IDS-003",
                severity = "HIGH",
                rule_name= "Write Data Storm Detected",
                description=(
                    f"{len(self._wdbi_timestamps)} WDBI (0x2E) requests "
                    f"in {self.window_s:.0f}s window "
                    f"(threshold: {threshold}). "
                    f"May indicate calibration data manipulation or NVM DoS attack."
                ),
                evidence = {
                    "wdbi_count_in_window": len(self._wdbi_timestamps),
                    "window_seconds":       self.window_s,
                    "threshold":            threshold,
                },
                service_id = SID_WDBI,
                iso_clause = "ISO/SAE 21434 Clause 14 — Monitoring",
                wp29_ref   = "WP.29 R155 Art 7.3.5",
                action     = (
                    "Rate-limit WDBI requests. Reject excess with NRC 0x21 "
                    "(busyRepeatRequest). Log DID values being written."
                ),
                session    = record.session,
            )]
        return []

    def _rule_unknown_service(self, record: UDSRecord) -> list[IDSAlert]:
        """
        Rule 4 — Unknown Service ID.

        Trigger: Service ID not in the ECU's known whitelist.

        Why it matters: Attacker probing for undocumented/backdoor
        services. Legitimate testers only use documented services.
        Unknown SID on a production ECU is always suspicious.
        """
        if record.service_id in self.service_whitelist:
            return []

        return [self._make_alert(
            rule_id  = "IDS-004",
            severity = "MEDIUM",
            rule_name= "Unknown Service ID Probe",
            description=(
                f"Received service ID 0x{record.service_id:02X} which is "
                f"not in the ECU's service whitelist. "
                f"May indicate attacker probing for undocumented services "
                f"or reconnaissance activity."
            ),
            evidence = {
                "service_id":  f"0x{record.service_id:02X}",
                "whitelist":   [f"0x{s:02X}" for s in sorted(self.service_whitelist)],
                "payload_hex": record.payload.hex().upper(),
            },
            service_id = record.service_id,
            iso_clause = "ISO/SAE 21434 Clause 9 — Asset: diagnostic interface",
            wp29_ref   = "WP.29 R155 Art 7.2.2 — Attack surface: OBD port",
            action     = (
                "Return NRC 0x11 (serviceNotSupported). "
                "Log CAN ID of sender. "
                "Multiple unknown SID probes = active reconnaissance."
            ),
            session    = record.session,
        )]

    def _rule_did_enumeration(self, record: UDSRecord,
                               now: float) -> list[IDSAlert]:
        """
        Rule 5 — DID Enumeration / Scanning.

        Trigger: Many unique DIDs requested in short window.

        Why it matters: Attacker scanning all possible DIDs (0x0000-0xFFFF)
        to map ECU data. This is reconnaissance — understanding what
        data is available before mounting a targeted attack.
        Legitimate tools request specific known DIDs, not sequential scans.
        """
        if record.service_id not in (SID_RDBI, SID_WDBI):
            return []
        if len(record.payload) < 2:
            return []

        did = (record.payload[0] << 8) | record.payload[1]
        self._did_set.add(did)
        self._did_scan_window.append(now)
        self._did_scan_window = [t for t in self._did_scan_window
                                  if now - t <= self.window_s]

        # Reset DID set when window resets
        if len(self._did_scan_window) == 1:
            self._did_set = {did}

        threshold = self.thresholds["did_scan_threshold"]
        if len(self._did_set) > threshold:
            return [self._make_alert(
                rule_id  = "IDS-005",
                severity = "MEDIUM",
                rule_name= "DID Enumeration / Scanning Detected",
                description=(
                    f"{len(self._did_set)} unique DIDs requested "
                    f"in {self.window_s:.0f}s window "
                    f"(threshold: {threshold}). "
                    f"Sequential or broad DID access pattern suggests "
                    f"automated reconnaissance scanning."
                ),
                evidence = {
                    "unique_dids_accessed": len(self._did_set),
                    "sample_dids": [f"0x{d:04X}" for d in list(self._did_set)[:5]],
                    "window_seconds":       self.window_s,
                },
                service_id = record.service_id,
                iso_clause = "ISO/SAE 21434 Clause 9 — Information disclosure threat",
                wp29_ref   = "WP.29 R155 Art 7.2.2 — Data exfiltration",
                action     = (
                    "Rate-limit RDBI requests per session. "
                    "Require extended session for sensitive DIDs. "
                    "Log accessed DID list for forensics."
                ),
                session    = record.session,
            )]
        return []

    def _rule_reset_flood(self, record: UDSRecord,
                           now: float) -> list[IDSAlert]:
        """
        Rule 6 — ECU Reset Flood.

        Trigger: Multiple ECU resets in short window.

        Why it matters: Repeated resets can:
          1. Clear security lockout (reset SA attempt counter)
          2. Disrupt vehicle operation (DoS)
          3. Force ECU into bootloader mode if timed correctly
        """
        if record.service_id != SID_ER:
            return []

        self._reset_timestamps.append(now)
        self._last_reset_time = now
        self._reset_timestamps = [t for t in self._reset_timestamps
                                   if now - t <= self.window_s]

        threshold = self.thresholds["reset_max_per_window"]
        if len(self._reset_timestamps) > threshold:
            return [self._make_alert(
                rule_id  = "IDS-006",
                severity = "HIGH",
                rule_name= "ECU Reset Flood Detected",
                description=(
                    f"{len(self._reset_timestamps)} ECU Reset (0x11) requests "
                    f"in {self.window_s:.0f}s window "
                    f"(threshold: {threshold}). "
                    f"Repeated resets may attempt to bypass SA lockout, "
                    f"trigger bootloader mode, or cause operational DoS."
                ),
                evidence = {
                    "reset_count_in_window": len(self._reset_timestamps),
                    "window_seconds":        self.window_s,
                    "threshold":             threshold,
                },
                service_id = SID_ER,
                iso_clause = "ISO/SAE 21434 Clause 14 — Availability monitoring",
                wp29_ref   = "WP.29 R155 Art 7.3.5",
                action     = (
                    "Reject reset with NRC 0x22 after threshold. "
                    "Persist SA lockout counter across resets in NVM. "
                    "Alert if reset pattern matches bootloader entry timing."
                ),
                session    = record.session,
            )]
        return []

    def _rule_diagnostic_storm(self, now: float) -> list[IDSAlert]:
        """
        Rule 7 — Diagnostic Request Storm (Overall Rate).

        Trigger: Overall UDS request rate exceeds safe threshold.

        Why it matters: High request rate can:
          1. Overwhelm ECU processing (DoS)
          2. Exhaust CAN bus bandwidth
          3. Mask other attacks in noise
        Normal tester tools send 5-10 req/sec max.
        """
        recent = [r for r in self._history
                  if now - r.timestamp <= 1.0]   # Last 1 second
        rate   = len(recent)

        threshold = self.thresholds["request_rate_max_per_sec"]
        if rate > threshold:
            return [self._make_alert(
                rule_id  = "IDS-007",
                severity = "HIGH",
                rule_name= "Diagnostic Request Storm",
                description=(
                    f"UDS request rate: {rate} req/sec "
                    f"(threshold: {threshold} req/sec). "
                    f"Abnormally high request rate — possible fuzzing, "
                    f"automated attack, or CAN bus DoS."
                ),
                evidence = {
                    "current_rate_per_sec": rate,
                    "threshold_per_sec":    threshold,
                    "measurement_window_s": 1.0,
                },
                service_id = None,
                iso_clause = "ISO/SAE 21434 Clause 14 — Availability",
                wp29_ref   = "WP.29 R155 Art 7.3.5",
                action     = (
                    "Implement rate limiting at gateway ECU level. "
                    "Drop excess requests. "
                    "Log burst source CAN ID for forensics."
                ),
                session    = SESSION_DEFAULT,
            )]
        return []

    def _rule_post_reset_write(self, record: UDSRecord,
                                now: float) -> list[IDSAlert]:
        """
        Rule 8 — Write Attempt Immediately After Reset.

        Trigger: WDBI or RMBA request within N seconds of ECU reset.

        Why it matters: Some ECUs have a brief window after reset
        where security checks are not fully initialized.
        Attackers time write requests to this window to bypass SA.
        This is a real attack pattern seen in ECU pen testing.
        """
        if record.service_id not in (SID_WDBI, SID_RMBA):
            return []

        delay_threshold = self.thresholds["post_reset_write_delay_s"]
        if (self._last_reset_time > 0
                and now - self._last_reset_time < delay_threshold):
            elapsed = now - self._last_reset_time
            return [self._make_alert(
                rule_id  = "IDS-008",
                severity = "CRITICAL",
                rule_name= "Write Attempt in Post-Reset Window",
                description=(
                    f"SID 0x{record.service_id:02X} received only "
                    f"{elapsed*1000:.0f}ms after ECU reset — "
                    f"within the {delay_threshold*1000:.0f}ms post-reset "
                    f"security initialization window. "
                    f"This timing matches known post-reset bypass attack patterns."
                ),
                evidence = {
                    "service_id":           f"0x{record.service_id:02X}",
                    "ms_since_reset":       round(elapsed * 1000, 1),
                    "threshold_ms":         delay_threshold * 1000,
                    "payload_hex":          record.payload.hex().upper(),
                },
                service_id = record.service_id,
                iso_clause = "ISO/SAE 21434 Clause 15 — Security validation",
                wp29_ref   = "WP.29 R155 Art 7.3.3 — Cybersecurity testing",
                action     = (
                    "Enforce minimum post-reset delay before accepting "
                    "any write or memory access service. "
                    "Security module must initialize before UDS stack starts."
                ),
                session    = record.session,
            )]
        return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _prune_window(self, now: float):
        """Remove history entries outside the sliding window."""
        cutoff = now - self.window_s
        while self._history and self._history[0].timestamp < cutoff:
            self._history.popleft()

    def _make_alert(self, rule_id: str, severity: str, rule_name: str,
                     description: str, evidence: dict, service_id: int | None,
                     iso_clause: str, wp29_ref: str, action: str,
                     session: int = SESSION_DEFAULT) -> IDSAlert:
        self._alert_count += 1
        return IDSAlert(
            alert_id            = f"A-{self._alert_count:03d}",
            rule_id             = rule_id,
            severity            = severity,
            rule_name           = rule_name,
            description         = description,
            evidence            = evidence,
            service_id          = service_id,
            iso_clause          = iso_clause,
            wp29_ref            = wp29_ref,
            recommended_action  = action,
            session_at_alert    = session,
        )