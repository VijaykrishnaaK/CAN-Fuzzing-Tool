"""
fuzzer/fuzz_engine.py
======================
Three fuzzing strategies for UDS protocol security testing.

Strategy 1 — Mutation Fuzzer:
  Takes valid UDS messages and mutates them.
  Bit flips, byte substitution, length changes, boundary values.
  Good for finding: format handling bugs, parser crashes.

Strategy 2 — Generation Fuzzer:
  Builds UDS messages from scratch using a grammar.
  Every service ID, every subfunction combination.
  Good for finding: missing service handling, NRC mapping errors.

Strategy 3 — Smart Fuzzer (UDS State-Aware):
  Knows the UDS session state machine.
  Generates sequences that respect — then deliberately violate — 
  session rules. Sends requests in wrong session, wrong order.
  Good for finding: access control bypasses, state machine bugs.

Reference: ISO 14229-1 for UDS grammar rules.
"""

import random
import struct
import itertools
import logging
from dataclasses import dataclass, field
from config import *
from fuzzer.uds_client import UDSClient, UDSResponse

log = logging.getLogger("FuzzEngine")
    # All defined UDS service IDs (ISO 14229-1)
DEFINED_SIDS = [
        0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x24, 0x27,
        0x28, 0x29, 0x2A, 0x2C, 0x2E, 0x2F, 0x31, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x3D, 0x3E, 0x83, 0x84,
        0x85, 0x86, 0x87,
    ]
DEFINED_SID_SET = set(DEFINED_SIDS)
    # Undefined SIDs — should always get NRC 0x11
UNDEFINED_SIDS = [s for s in range(0x00, 0xFF)
                      if s not in DEFINED_SID_SET]

@dataclass
class FuzzCase:
    """A single fuzz test case and its result."""
    case_id:        int
    strategy:       str
    payload:        bytes
    description:    str
    response:       UDSResponse | None = None
    is_interesting: bool = False    # True if anomalous response found
    finding_reason: str = ""        # Why it's interesting


class MutationFuzzer:
    """
    Mutation-based fuzzer.
    Takes valid UDS frames and mutates them systematically.
    
    Mutations applied:
      - Bit flip: flip single bits in the payload
      - Byte substitute: replace byte with random/boundary value
      - Length extension: add extra bytes beyond expected
      - Length truncation: cut payload short
      - Boundary values: 0x00, 0xFF, 0x7F, 0x80
    """

    BOUNDARY_BYTES = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]

    def __init__(self):
        self.seed_corpus = self._build_seed_corpus()

    def _build_seed_corpus(self) -> list[bytes]:
        """
        Seed corpus: valid UDS messages from ProxiCan knowledge.
        These are the starting points for mutation.
        """
        return [
            # DSC — all session types
            bytes([SID_DSC, SESSION_DEFAULT]),
            bytes([SID_DSC, SESSION_EXTENDED]),
            bytes([SID_DSC, SESSION_PROGRAMMING]),

            # ECU Reset
            bytes([SID_ER, 0x01]),   # Hard reset
            bytes([SID_ER, 0x02]),   # Key off/on reset
            bytes([SID_ER, 0x03]),   # Soft reset

            # Security Access
            bytes([SID_SA, 0x01]),   # Request seed level 1
            bytes([SID_SA, 0x02, 0xDE, 0xAD, 0xBE, 0xEF]),  # Send key

            # RDBI — valid DIDs
            bytes([SID_RDBI, 0xF1, 0x90]),   # VIN
            bytes([SID_RDBI, 0xF1, 0x8C]),   # Serial

            # WDBI — writable DID
            bytes([SID_WDBI, 0x02, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00]),

            # Routine Control
            bytes([SID_RC, 0x01, 0x03, 0x01]),   # Start routine
            bytes([SID_RC, 0x02, 0x03, 0x01]),   # Stop routine
            bytes([SID_RC, 0x03, 0x03, 0x01]),   # Request results

            # Read DTC
            bytes([SID_RDTC, 0x02, 0xFF]),

            # Clear DTC
            bytes([SID_CDTC, 0xFF, 0xFF, 0xFF]),

            # Read Memory By Address
            bytes([SID_RMBA, 0x12, 0x00, 0x00, 0x04]),
        ]

    def generate(self, count: int = FUZZ_ITERATIONS) -> list[FuzzCase]:
        """Generate N mutation fuzz cases."""
        cases = []
        case_id = 0

        for i in range(count):
            # Pick a seed to mutate
            seed = random.choice(self.seed_corpus)
            mutation_type = random.choice([
                "bit_flip",
                "byte_substitute",
                "length_extend",
                "length_truncate",
                "boundary_value",
                "subfunction_sweep",
            ])

            payload, description = self._mutate(seed, mutation_type)

            cases.append(FuzzCase(
                case_id     = case_id,
                strategy    = f"mutation/{mutation_type}",
                payload     = payload,
                description = description,
            ))
            case_id += 1

        return cases

    def _mutate(self, seed: bytes, mutation_type: str) -> tuple[bytes, str]:
        data = bytearray(seed)

        if mutation_type == "bit_flip" and len(data) > 1:
            idx = random.randint(1, len(data) - 1)  # Skip SID byte
            bit = random.randint(0, 7)
            data[idx] ^= (1 << bit)
            return bytes(data), f"bit_flip byte[{idx}] bit[{bit}]"

        elif mutation_type == "byte_substitute" and len(data) > 1:
            idx = random.randint(1, len(data) - 1)
            old = data[idx]
            data[idx] = random.randint(0, 255)
            return bytes(data), f"byte_sub byte[{idx}] 0x{old:02X}→0x{data[idx]:02X}"

        elif mutation_type == "length_extend":
            extra = bytes([random.randint(0, 255)
                           for _ in range(random.randint(1, 4))])
            return bytes(data) + extra, f"extend +{len(extra)} bytes"

        elif mutation_type == "length_truncate" and len(data) > 1:
            cut = random.randint(1, len(data))
            return bytes(data[:cut]), f"truncate to {cut} bytes"

        elif mutation_type == "boundary_value" and len(data) > 1:
            idx = random.randint(1, len(data) - 1)
            bval = random.choice(self.BOUNDARY_BYTES)
            data[idx] = bval
            return bytes(data), f"boundary byte[{idx}]=0x{bval:02X}"

        elif mutation_type == "subfunction_sweep" and len(data) > 1:
            # Try every possible subfunction value
            sf = random.randint(0, 255)
            data[1] = sf
            return bytes(data), f"subfunction_sweep SID=0x{data[0]:02X} SF=0x{sf:02X}"

        return bytes(data), "no_op"


class GenerationFuzzer:
    """
    Generation-based fuzzer.
    Builds UDS messages from a grammar — covers all service IDs
    and subfunction combinations systematically.
    
    Unlike mutation, this generates cases the seed corpus might miss:
    - Completely unknown service IDs
    - Reserved/vendor-specific subfunctions
    - Malformed multi-byte fields
    """



    def generate(self, count: int = FUZZ_ITERATIONS) -> list[FuzzCase]:
        cases = []
        case_id = 0
        strategies = [
            self._gen_undefined_service,
            self._gen_empty_payload,
            self._gen_defined_sid_random_payload,
            self._gen_max_length_payload,
            self._gen_did_sweep,
            self._gen_nrc_probe,
        ]

        for i in range(count):
            strategy_fn = random.choice(strategies)
            payload, description = strategy_fn()
            cases.append(FuzzCase(
                case_id     = case_id,
                strategy    = f"generation/{strategy_fn.__name__[5:]}",
                payload     = payload,
                description = description,
            ))
            case_id += 1

        return cases

    def _gen_undefined_service(self) -> tuple[bytes, str]:
        sid = random.choice(UNDEFINED_SIDS)
        payload = bytes([sid] + [random.randint(0, 255)
                                  for _ in range(random.randint(0, 6))])
        return payload, f"undefined SID=0x{sid:02X}"

    def _gen_empty_payload(self) -> tuple[bytes, str]:
        """Empty or single-byte payloads — tests length validation."""
        sid = random.choice(DEFINED_SIDS)
        payload = bytes([sid])  # No subfunction or data
        return payload, f"empty payload SID=0x{sid:02X}"

    def _gen_defined_sid_random_payload(self) -> tuple[bytes, str]:
        sid = random.choice(DEFINED_SIDS)
        length = random.randint(1, 7)
        payload = bytes([sid] + [random.randint(0, 255) for _ in range(length)])
        return payload, f"random payload SID=0x{sid:02X} len={length+1}"

    def _gen_max_length_payload(self) -> tuple[bytes, str]:
        """Max CAN payload — 8 bytes. Tests buffer handling."""
        sid = random.choice(DEFINED_SIDS)
        payload = bytes([sid] + [0xFF] * 7)
        return payload, f"max_length SID=0x{sid:02X} all-0xFF"

    def _gen_did_sweep(self) -> tuple[bytes, str]:
        """Sweep DID space for 0x22/0x2E — find undocumented DIDs."""
        sid = random.choice([SID_RDBI, SID_WDBI])
        did = random.randint(0x0000, 0xFFFF)
        did_bytes = struct.pack(">H", did)
        if sid == SID_WDBI:
            payload = bytes([sid]) + did_bytes + bytes(4)
        else:
            payload = bytes([sid]) + did_bytes
        return payload, f"DID_sweep SID=0x{sid:02X} DID=0x{did:04X}"

    def _gen_nrc_probe(self) -> tuple[bytes, str]:
        """
        Send requests designed to trigger specific NRC codes.
        Useful for mapping ECU behavior.
        """
        probes = [
            # Trigger 0x7F (serviceNotSupportedInActiveSession)
            (bytes([SID_WDBI, 0x02, 0x00, 0x00]),
             "probe NRC 0x7F — WDBI in default session"),
            # Trigger 0x33 (securityAccessDenied)
            (bytes([SID_RMBA, 0x12, 0x00, 0x00, 0x04]),
             "probe NRC 0x33 — RMBA without SA"),
            # Trigger 0x12 (subFunctionNotSupported)
            (bytes([SID_DSC, 0xFF]),
             "probe NRC 0x12 — invalid session type"),
            # Trigger 0x31 (requestOutOfRange)
            (bytes([SID_RDBI, 0xFF, 0xFF]),
             "probe NRC 0x31 — invalid DID"),
        ]
        return random.choice(probes)


class SmartFuzzer:
    """
    UDS State-Machine-Aware Fuzzer.
    
    Knows the UDS session state machine and deliberately
    violates it in targeted ways:
    
    1. Service in wrong session      → expects NRC 0x7F
    2. Skip Security Access          → expects NRC 0x33
    3. Wrong session order           → expects NRC 0x22
    4. Rapid session switching       → stress test state machine
    5. Request after reset           → state persistence check
    6. Concurrent service requests   → race condition probe
    
    This is the most valuable fuzzer for finding real vulnerabilities.
    """

    def generate_sequences(self, count: int = 50) -> list[list[FuzzCase]]:
        """
        Generate sequences of UDS requests (not individual frames).
        Each sequence tests a specific state machine violation.
        Returns list of sequences — each sequence is a list of FuzzCases.
        """
        sequences = []
        generators = [
            self._seq_wrong_session_service,
            self._seq_skip_security_access,
            self._seq_session_escalation_bypass,
            self._seq_rapid_session_switch,
            self._seq_sa_brute_force_probe,
            self._seq_reset_state_persistence,
            self._seq_interleaved_services,
        ]

        for i in range(count):
            gen_fn = random.choice(generators)
            seq = gen_fn(base_id=i * 10)
            sequences.append(seq)

        return sequences

    def _seq_wrong_session_service(self, base_id: int) -> list[FuzzCase]:
        """
        Send security-requiring services without entering correct session.
        e.g. Try WDBI in default session — should get NRC 0x7F.
        A vulnerability: if ECU accepts it anyway.
        """
        return [
            FuzzCase(
                case_id     = base_id,
                strategy    = "smart/wrong_session",
                payload     = bytes([SID_WDBI, 0x02, 0x00,
                                     0xDE, 0xAD, 0xBE, 0xEF]),
                description = "WDBI in default session — expect NRC 0x7F",
            ),
            FuzzCase(
                case_id     = base_id + 1,
                strategy    = "smart/wrong_session",
                payload     = bytes([SID_RC, 0x01, 0x02, 0x02]),
                description = "Routine Control in default session — expect NRC 0x7F",
            ),
            FuzzCase(
                case_id     = base_id + 2,
                strategy    = "smart/wrong_session",
                payload     = bytes([SID_RMBA, 0x12, 0x00, 0x00, 0x04]),
                description = "RMBA in default session without SA — expect NRC 0x33",
            ),
        ]

    def _seq_skip_security_access(self, base_id: int) -> list[FuzzCase]:
        """
        Enter extended session but skip Security Access.
        Try to write data directly — should get NRC 0x33.
        """
        return [
            FuzzCase(
                case_id     = base_id,
                strategy    = "smart/skip_sa",
                payload     = bytes([SID_DSC, SESSION_EXTENDED]),
                description = "Enter extended session",
            ),
            FuzzCase(
                case_id     = base_id + 1,
                strategy    = "smart/skip_sa",
                payload     = bytes([SID_WDBI, 0x02, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00]),
                description = "WDBI without SA unlock — expect NRC 0x33",
            ),
        ]

    def _seq_session_escalation_bypass(self, base_id: int) -> list[FuzzCase]:
        """
        Try to jump directly to programming session from default.
        Should need extended session + SA first.
        """
        return [
            FuzzCase(
                case_id     = base_id,
                strategy    = "smart/escalation_bypass",
                payload     = bytes([SID_DSC, SESSION_PROGRAMMING]),
                description = "Direct programming session from default — "
                              "expect NRC 0x22",
            ),
        ]

    def _seq_rapid_session_switch(self, base_id: int) -> list[FuzzCase]:
        """
        Rapidly switch sessions — stress tests session state machine.
        Can expose timing bugs or state corruption.
        """
        sessions = [SESSION_DEFAULT, SESSION_EXTENDED,
                    SESSION_DEFAULT, SESSION_EXTENDED,
                    SESSION_PROGRAMMING]
        return [
            FuzzCase(
                case_id     = base_id + i,
                strategy    = "smart/rapid_session_switch",
                payload     = bytes([SID_DSC, s]),
                description = f"Rapid switch → session 0x{s:02X}",
            )
            for i, s in enumerate(sessions)
        ]

    def _seq_sa_brute_force_probe(self, base_id: int) -> list[FuzzCase]:
        """
        Send wrong keys repeatedly — probe lockout behavior.
        Tests: does ECU enforce SA_MAX_ATTEMPTS correctly?
        Vulnerability: if ECU doesn't lock out, key can be brute-forced.
        """
        cases = [
            FuzzCase(
                case_id     = base_id,
                strategy    = "smart/sa_brute_force",
                payload     = bytes([SID_DSC, SESSION_EXTENDED]),
                description = "Enter extended session for SA",
            ),
            FuzzCase(
                case_id     = base_id + 1,
                strategy    = "smart/sa_brute_force",
                payload     = bytes([SID_SA, 0x01]),
                description = "Request seed",
            ),
        ]
        # Send wrong keys up to lockout
        for attempt in range(SA_MAX_ATTEMPTS + 2):
            wrong_key = bytes([0xDE, 0xAD, 0x00, attempt & 0xFF])
            cases.append(FuzzCase(
                case_id     = base_id + 2 + attempt,
                strategy    = "smart/sa_brute_force",
                payload     = bytes([SID_SA, 0x02]) + wrong_key,
                description = f"Wrong key attempt {attempt+1} "
                              f"— key={wrong_key.hex().upper()}",
            ))
        return cases

    def _seq_reset_state_persistence(self, base_id: int) -> list[FuzzCase]:
        """
        Unlock SA, then send ECU reset, then try to use secured service.
        Tests: does reset properly clear security state?
        Vulnerability: if SA state persists after reset.
        """
        return [
            FuzzCase(base_id,   "smart/reset_persistence",
                     bytes([SID_DSC, SESSION_EXTENDED]),
                     "Enter extended session"),
            FuzzCase(base_id+1, "smart/reset_persistence",
                     bytes([SID_SA, 0x01]),
                     "Request seed"),
            # Attacker sends reset before key — does session/SA state reset?
            FuzzCase(base_id+2, "smart/reset_persistence",
                     bytes([SID_ER, 0x01]),
                     "ECU reset — SA state should clear"),
            FuzzCase(base_id+3, "smart/reset_persistence",
                     bytes([SID_SA, 0x02, 0xDE, 0xAD, 0xBE, 0xEF]),
                     "Send key after reset — expect NRC (seed invalidated)"),
        ]

    def _seq_interleaved_services(self, base_id: int) -> list[FuzzCase]:
        """
        Interleave different services mid-sequence.
        e.g. Start SA sequence, interrupt with RDBI, resume SA.
        Tests: does interrupted SA sequence handle gracefully?
        """
        return [
            FuzzCase(base_id,   "smart/interleaved",
                     bytes([SID_DSC, SESSION_EXTENDED]),
                     "Enter extended session"),
            FuzzCase(base_id+1, "smart/interleaved",
                     bytes([SID_SA, 0x01]),
                     "Request seed (SA sequence start)"),
            FuzzCase(base_id+2, "smart/interleaved",
                     bytes([SID_RDBI, 0xF1, 0x90]),
                     "Interrupt SA with RDBI — does seed stay valid?"),
            FuzzCase(base_id+3, "smart/interleaved",
                     bytes([SID_SA, 0x02, 0x00, 0x00, 0x00, 0x00]),
                     "Send wrong key after interruption"),
        ]
