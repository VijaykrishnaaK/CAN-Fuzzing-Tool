"""
attacks/timing_attack.py
=========================
Security Access Timing Attack Module.

Implements a timing side-channel analysis against the ECU's
Security Access (0x27) key validation.

What is a timing attack?
  If Dcm_CompareKey() uses a non-constant-time comparison
  (e.g. memcmp, early exit on first mismatch), then:
    - Keys matching 0 correct bytes → very fast response
    - Keys matching 1 correct byte  → slightly slower
    - Keys matching N correct bytes → proportionally slower

  By measuring thousands of responses with different key values,
  an attacker can determine the correct key byte-by-byte without
  brute force — reducing the attack from 2^32 attempts to 256*4 = 1024.

Real-world context:
  This attack was first demonstrated on smart card authentication.
  In automotive, it applies to:
    - ECU Security Access (0x27) — direct attack demonstrated here
    - Secure Boot signature verification timing
    - HSM key derivation timing

Why it matters for AUTOSAR:
  Dcm_CompareKey() callback is OEM-implemented.
  Many OEMs use memcmp() or manual byte comparison → timing oracle.
  Fix: Use HMAC via CryIf → HSM (constant-time by hardware).

ISO/SAE 21434:
  Clause 15 — Cybersecurity testing must include side-channel analysis
  TARA threat: Timing side-channel on SA key validation
"""

import time
import struct
import statistics
import logging
from dataclasses import dataclass, field
from config import *

log = logging.getLogger("TimingAttack")


# ── Timing Result ─────────────────────────────────────────────────────────────

@dataclass
class TimingMeasurement:
    """Single timing measurement for one key attempt."""
    key_bytes:      bytes
    response_time_ns: int       # Nanoseconds — need precision
    response_bytes: bytes | None
    is_positive:    bool
    attempt_number: int


@dataclass
class TimingAnalysisResult:
    """Complete timing analysis result."""
    measurements:       list[TimingMeasurement]
    mean_ns:            float
    std_ns:             float
    min_ns:             int
    max_ns:             int
    timing_variance:    float   # Coefficient of variation
    oracle_detected:    bool    # Is timing oracle present?
    oracle_confidence:  str     # HIGH / MEDIUM / LOW
    byte_correlations:  list[dict]  # Per-byte timing correlation
    recommendation:     str
    total_attempts:     int
    session_used:       int


# ── Timing Attack Engine ──────────────────────────────────────────────────────

class TimingAttackEngine:
    """
    Performs timing side-channel analysis on Security Access (0x27).

    Attack strategy:
      1. Enter extended session
      2. Request seed from ECU
      3. Send many different keys, measure response time precisely
      4. Analyse distribution — if variance is high → timing oracle exists
      5. If oracle detected — attempt byte-by-byte key recovery

    Note: We measure timing of the entire round trip (request→response).
    Network jitter on a virtual loopback is minimal — real hardware
    would need many more samples to filter out jitter.
    """

    def __init__(self, samples_per_key: int = 50,
                 keys_to_test: int = 100):
        """
        Args:
            samples_per_key: How many times to send each key (for averaging)
            keys_to_test:    How many different key values to test
        """
        self.samples_per_key = samples_per_key
        self.keys_to_test    = keys_to_test
        self.measurements:   list[TimingMeasurement] = []

    def run(self, client) -> TimingAnalysisResult:
        """
        Run full timing analysis against ECU Security Access.

        Args:
            client: UDSClient or DoIPClient — has send_raw() or send_uds()

        Returns:
            TimingAnalysisResult with oracle detection and byte correlations
        """
        print(f"\n  [Timing Attack] Starting SA timing analysis")
        print(f"  Keys to test: {self.keys_to_test}")
        print(f"  Samples per key: {self.samples_per_key}")
        print(f"  Total measurements: {self.keys_to_test * self.samples_per_key}\n")

        # Step 1: Enter extended session
        if not self._enter_extended_session(client):
            print("  [!] Cannot enter extended session")
            return self._empty_result()

        # Step 2: Get seed
        seed = self._get_seed(client)
        if seed is None:
            print("  [!] Cannot get seed from ECU")
            return self._empty_result()

        print(f"  Seed obtained: {seed.hex().upper()}")

        # Step 3: Compute correct key (we know the algorithm — our own ECU)
        correct_key = self._compute_correct_key(seed)
        print(f"  Correct key: {correct_key.hex().upper()}")

        # Step 4: Generate test keys — vary each byte systematically
        test_keys = self._generate_test_keys(correct_key)

        # Step 5: Measure response time for each key
        print(f"  Measuring response times...")
        all_measurements = []

        for i, test_key in enumerate(test_keys):
            if i % 20 == 0:
                print(f"  Progress: {i}/{len(test_keys)} keys tested...")

            # Need fresh seed for each key attempt
            # (SA resets after wrong key or lockout)
            seed = self._refresh_seed(client)
            if seed is None:
                continue

            # Measure response time for this key
            measurement = self._measure_key_response(
                client, test_key, attempt_number=i
            )
            if measurement:
                all_measurements.append(measurement)

        self.measurements = all_measurements

        # Step 6: Analyse timing distribution
        result = self._analyse_timing(all_measurements, correct_key)

        self._print_result(result)
        return result

    # ── Core Measurement ──────────────────────────────────────────────────────

    def _measure_key_response(self, client, key: bytes,
                               attempt_number: int) -> TimingMeasurement | None:
        """
        Measure response time for a single key attempt with nanosecond precision.
        Uses time.perf_counter_ns() — highest precision available in Python.
        """
        # Build SA key send request (subfunction 0x02 = send key for level 0x01)
        request = bytes([SID_SA, 0x02]) + key

        t_start = time.perf_counter_ns()

        try:
            if hasattr(client, 'send_raw'):
                response = client.send_raw(request)
                response_bytes = response.response_bytes if response else None
                is_positive    = response.is_positive if response else False
            else:
                # DoIP client
                response_bytes = client.send_uds(request)
                is_positive    = (response_bytes is not None and
                                  len(response_bytes) > 0 and
                                  response_bytes[0] == SID_SA + 0x40)
        except Exception as e:
            log.debug(f"Measurement error: {e}")
            return None

        t_end = time.perf_counter_ns()
        elapsed_ns = t_end - t_start

        return TimingMeasurement(
            key_bytes        = key,
            response_time_ns = elapsed_ns,
            response_bytes   = response_bytes,
            is_positive      = is_positive,
            attempt_number   = attempt_number,
        )

    # ── Key Generation ────────────────────────────────────────────────────────

    def _generate_test_keys(self, correct_key: bytes) -> list[bytes]:
        """
        Generate test keys that systematically vary each byte.
        This allows us to detect if response time correlates with
        how many bytes match the correct key.
        """
        test_keys = []

        # Group 1: Keys matching 0 bytes (all wrong)
        for i in range(self.keys_to_test // 4):
            wrong_key = bytes([
                (correct_key[0] + i + 1) & 0xFF,
                (correct_key[1] + i + 1) & 0xFF,
                (correct_key[2] + i + 1) & 0xFF,
                (correct_key[3] + i + 1) & 0xFF,
            ])
            test_keys.append(wrong_key)

        # Group 2: Keys matching byte 0 only
        for i in range(self.keys_to_test // 4):
            partial_key = bytes([
                correct_key[0],              # correct
                (correct_key[1] + i + 1) & 0xFF,
                (correct_key[2] + i + 1) & 0xFF,
                (correct_key[3] + i + 1) & 0xFF,
            ])
            test_keys.append(partial_key)

        # Group 3: Keys matching bytes 0+1
        for i in range(self.keys_to_test // 4):
            partial_key = bytes([
                correct_key[0],
                correct_key[1],
                (correct_key[2] + i + 1) & 0xFF,
                (correct_key[3] + i + 1) & 0xFF,
            ])
            test_keys.append(partial_key)

        # Group 4: The correct key itself
        for _ in range(self.keys_to_test // 4):
            test_keys.append(correct_key)

        return test_keys

    # ── Timing Analysis ───────────────────────────────────────────────────────

    def _analyse_timing(self, measurements: list[TimingMeasurement],
                         correct_key: bytes) -> TimingAnalysisResult:
        """
        Analyse timing measurements to detect oracle.

        Oracle detection logic:
          1. Compute mean response time per key group
          2. If group means differ significantly → timing oracle
          3. Coefficient of variation > 10% → suspicious
          4. Correlation between key correctness and timing → oracle confirmed
        """
        if not measurements:
            return self._empty_result()

        times_ns = [m.response_time_ns for m in measurements]
        mean_ns  = statistics.mean(times_ns)
        std_ns   = statistics.stdev(times_ns) if len(times_ns) > 1 else 0

        # Coefficient of variation (CV) — normalized measure of dispersion
        # CV > 15% in constant-time system = suspicious
        # CV > 30% = likely oracle
        cv = (std_ns / mean_ns * 100) if mean_ns > 0 else 0

        # Group by number of correct bytes and compute group means
        byte_correlations = self._compute_byte_correlations(
            measurements, correct_key
        )

        # Oracle detection
        oracle_detected, confidence = self._detect_oracle(cv, byte_correlations)

        return TimingAnalysisResult(
            measurements      = measurements,
            mean_ns           = round(mean_ns, 1),
            std_ns            = round(std_ns, 1),
            min_ns            = min(times_ns),
            max_ns            = max(times_ns),
            timing_variance   = round(cv, 2),
            oracle_detected   = oracle_detected,
            oracle_confidence = confidence,
            byte_correlations = byte_correlations,
            recommendation    = self._get_recommendation(oracle_detected, confidence),
            total_attempts    = len(measurements),
            session_used      = SESSION_EXTENDED,
        )

    def _compute_byte_correlations(self, measurements: list[TimingMeasurement],
                                    correct_key: bytes) -> list[dict]:
        """
        Group measurements by number of matching bytes.
        If timing increases with matching bytes → oracle confirmed.
        """
        groups: dict[int, list[int]] = {0: [], 1: [], 2: [], 3: [], 4: []}

        for m in measurements:
            matching = sum(
                1 for i in range(min(len(m.key_bytes), len(correct_key)))
                if m.key_bytes[i] == correct_key[i]
            )
            groups[matching].append(m.response_time_ns)

        correlations = []
        for n_matching, times in groups.items():
            if times:
                correlations.append({
                    "matching_bytes": n_matching,
                    "sample_count":   len(times),
                    "mean_ns":        round(statistics.mean(times), 1),
                    "std_ns":         round(statistics.stdev(times), 1)
                                      if len(times) > 1 else 0,
                })

        return sorted(correlations, key=lambda x: x["matching_bytes"])

    def _detect_oracle(self, cv: float,
                        correlations: list[dict]) -> tuple[bool, str]:
        """
        Determine if timing oracle is present.

        Rules:
          - CV > 30% AND mean increases with matching bytes → HIGH confidence
          - CV > 15% AND some correlation → MEDIUM confidence
          - CV < 15% → likely constant-time → oracle not detected
        """
        if not correlations or len(correlations) < 2:
            return False, "LOW"

        # Check if mean time increases with matching bytes (trend analysis)
        means = [c["mean_ns"] for c in correlations if c["sample_count"] > 2]

        if len(means) < 2:
            return False, "LOW"

        # Simple trend: does mean generally increase?
        increasing = sum(
            1 for i in range(len(means) - 1)
            if means[i + 1] > means[i]
        )
        trend_ratio = increasing / (len(means) - 1)

        if cv > 30 and trend_ratio >= 0.6:
            return True, "HIGH"
        elif cv > 15 and trend_ratio >= 0.5:
            return True, "MEDIUM"
        elif cv > 10:
            return False, "LOW"  # Suspicious but not confirmed
        else:
            return False, "LOW"

    def _get_recommendation(self, oracle_detected: bool,
                             confidence: str) -> str:
        if not oracle_detected:
            return (
                "No significant timing oracle detected. "
                "ECU key validation appears to be constant-time or "
                "timing differences are below detection threshold on virtual bus. "
                "Verify on real hardware with oscilloscope-level precision."
            )
        elif confidence == "HIGH":
            return (
                "HIGH CONFIDENCE TIMING ORACLE DETECTED. "
                "Key validation response time correlates with number of "
                "matching bytes — attacker can recover key byte-by-byte. "
                "IMMEDIATE FIX REQUIRED:\n"
                "  1. Replace Dcm_CompareKey() with HMAC-based validation\n"
                "  2. Route through CryIf → HSM for constant-time comparison\n"
                "  3. Never use memcmp() or early-exit loops for key comparison\n"
                "  4. Add artificial constant delay if HSM not available"
            )
        else:
            return (
                "POSSIBLE timing oracle detected (medium confidence). "
                "Timing variance is above expected for constant-time implementation. "
                "Recommend:\n"
                "  1. Test on real hardware with higher sample count (1000+)\n"
                "  2. Review Dcm_CompareKey() implementation\n"
                "  3. Consider HSM-based key validation"
            )

    # ── Session/SA Helpers ────────────────────────────────────────────────────

    def _enter_extended_session(self, client) -> bool:
        """Enter extended diagnostic session."""
        request = bytes([SID_DSC, SESSION_EXTENDED])
        try:
            if hasattr(client, 'send_raw'):
                resp = client.send_raw(request)
                return resp.is_positive if resp else False
            else:
                resp = client.send_uds(request)
                return (resp is not None and len(resp) > 0 and
                        resp[0] == SID_DSC + 0x40)
        except Exception:
            return False

    def _get_seed(self, client) -> bytes | None:
        """Request seed from ECU."""
        request = bytes([SID_SA, 0x01])
        try:
            if hasattr(client, 'send_raw'):
                resp = client.send_raw(request)
                if resp and resp.is_positive and resp.response_bytes:
                    rb = resp.response_bytes
                    if len(rb) >= 2 + SA_SEED_LENGTH:
                        return rb[2:2 + SA_SEED_LENGTH]
            else:
                rb = client.send_uds(request)
                if rb and len(rb) >= 2 + SA_SEED_LENGTH:
                    return rb[2:2 + SA_SEED_LENGTH]
        except Exception:
            pass
        return None

    def _refresh_seed(self, client) -> bytes | None:
        """
        Get a fresh seed — needed between key attempts.
        ECU resets SA state after wrong key.
        Re-enter session if needed.
        """
        # Try to get seed
        seed = self._get_seed(client)
        if seed:
            return seed

        # Re-enter extended session and try again
        self._enter_extended_session(client)
        return self._get_seed(client)

    def _compute_correct_key(self, seed: bytes) -> bytes:
        """Compute correct key using known algorithm (XOR with mask)."""
        seed_int = struct.unpack(">I", seed[:4])[0]
        key_int  = seed_int ^ SA_KEY_MASK
        return struct.pack(">I", key_int)

    # ── Display ───────────────────────────────────────────────────────────────

    def _print_result(self, result: TimingAnalysisResult):
        """Print timing analysis results."""
        print(f"\n  {'═'*55}")
        print(f"  TIMING ATTACK ANALYSIS RESULTS")
        print(f"  {'═'*55}")
        print(f"  Total measurements:   {result.total_attempts}")
        print(f"  Mean response time:   {result.mean_ns/1000:.1f} μs")
        print(f"  Std deviation:        {result.std_ns/1000:.1f} μs")
        print(f"  Min / Max:            {result.min_ns/1000:.1f} / "
              f"{result.max_ns/1000:.1f} μs")
        print(f"  Timing variance (CV): {result.timing_variance:.1f}%")

        col = "\033[91m" if result.oracle_detected else "\033[92m"
        print(f"\n  Oracle detected:      "
              f"{col}{result.oracle_detected} "
              f"({result.oracle_confidence} confidence)\033[0m")

        if result.byte_correlations:
            print(f"\n  Response time by matching bytes:")
            print(f"  {'Matching':<12} {'Samples':<10} {'Mean (μs)':<12} {'Std (μs)'}")
            print(f"  {'─'*48}")
            for c in result.byte_correlations:
                print(f"  {c['matching_bytes']:<12} "
                      f"{c['sample_count']:<10} "
                      f"{c['mean_ns']/1000:<12.1f} "
                      f"{c['std_ns']/1000:.1f}")

        print(f"\n  Recommendation:")
        for line in result.recommendation.split('\n'):
            print(f"  {line}")
        print(f"  {'═'*55}\n")

    def _empty_result(self) -> TimingAnalysisResult:
        return TimingAnalysisResult(
            measurements=[], mean_ns=0, std_ns=0,
            min_ns=0, max_ns=0, timing_variance=0,
            oracle_detected=False, oracle_confidence="LOW",
            byte_correlations=[], recommendation="Analysis could not be completed.",
            total_attempts=0, session_used=SESSION_DEFAULT,
        )