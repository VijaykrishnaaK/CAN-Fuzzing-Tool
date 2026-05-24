"""
fuzzer/adaptive_fuzzer.py
==========================
Feedback-Guided Adaptive Fuzzing Engine.

Standard fuzzing (mutation/generation) treats all inputs equally.
Adaptive fuzzing learns from responses — inputs that produce
interesting behavior get higher scores and are mutated more.

This is the core idea behind coverage-guided fuzzers like AFL++ and
libFuzzer — which you automate at BMW Techworks but haven't built yourself.
Now you're building the logic.

Scoring System:
  +5   new_sid_seen           — ECU responded to a SID we haven't seen before
  +10  positive_response      — ECU accepted the request (worth exploring more)
  +20  state_change_detected  — Session or SA state changed (high value)
  +30  nrc_code_new           — New NRC code seen (maps new ECU behavior)
  +50  potential_bypass       — Positive response where we expected rejection
  -5   timeout                — ECU didn't respond (usually noise)
  -2   duplicate_response     — Exact same response as a previous input

High-score inputs go into the corpus.
Corpus inputs are mutated to generate the next generation of test cases.
Low-score inputs are deprioritized.

This is called "feedback-guided" because the fuzzer adapts based on
what the ECU tells it — just like AFL++ adapts based on code coverage.

References:
  AFL++: https://github.com/AFLplusplus/AFLplusplus
  libFuzzer: https://llvm.org/docs/LibFuzzer.html (what BMW Techworks uses)
  UDS fuzzing research: Pese et al. 2019 "SeqFuzzer"
"""

import random
import time
import logging
from dataclasses import dataclass, field
from collections import defaultdict
from config import *
from fuzzer.fuzz_engine import FuzzCase, MutationFuzzer

log = logging.getLogger("AdaptiveFuzzer")


# ── Scoring Constants ─────────────────────────────────────────────────────────

SCORE_NEW_SID_SEEN       = 5
SCORE_POSITIVE_RESPONSE  = 10
SCORE_STATE_CHANGE       = 20
SCORE_NEW_NRC_CODE       = 30
SCORE_POTENTIAL_BYPASS   = 50
SCORE_TIMEOUT            = -5
SCORE_DUPLICATE_RESPONSE = -2


# ── Corpus Entry ──────────────────────────────────────────────────────────────

@dataclass
class CorpusEntry:
    """
    A high-value input stored in the corpus for future mutation.
    The corpus is the adaptive fuzzer's memory — it remembers
    what worked and builds on it.
    """
    payload:         bytes
    score:           int
    response_bytes:  bytes | None
    nrc_code:        int | None
    is_positive:     bool
    sid:             int
    generation:      int          # How many mutation rounds this has gone through
    reason:          str          # Why this was added to corpus
    timestamp:       float = field(default_factory=time.time)

    def __lt__(self, other):
        return self.score > other.score   # Higher score = higher priority


# ── Adaptive Fuzzer ───────────────────────────────────────────────────────────

class AdaptiveFuzzer:
    """
    Feedback-guided adaptive fuzzer for UDS protocol.

    How it works:
      1. Start with a seed corpus (valid UDS messages)
      2. Send each seed, observe response
      3. Score the response
      4. High-score inputs → added to corpus
      5. Corpus inputs → mutated to generate next generation
      6. Repeat — fuzzer gets smarter over time

    Unlike mutation/generation fuzzers which are stateless,
    this fuzzer builds knowledge across iterations.
    """

    def __init__(self):
        self.corpus:            list[CorpusEntry] = []
        self.seen_sids:         set[int]          = set()
        self.seen_nrc_codes:    set[int]          = set()
        self.seen_responses:    set[bytes]        = set()
        self.current_session:   int               = SESSION_DEFAULT
        self.sa_unlocked:       bool              = False

        self.stats = {
            "total_cases":        0,
            "corpus_size":        0,
            "positive_responses": 0,
            "state_changes":      0,
            "new_behaviors":      0,
            "generations":        0,
            "high_score_cases":   0,
        }

        # Mutation engine for corpus mutation
        self._mutation_engine = MutationFuzzer()

        # Initialize with seed corpus
        self._init_seed_corpus()

    # ── Public Interface ──────────────────────────────────────────────────────

    def generate_adaptive(self, client, iterations: int = 100,
                           verbose: bool = False) -> list[FuzzCase]:
        """
        Run adaptive fuzzing loop.

        Args:
            client:     UDSClient — sends requests and receives responses
            iterations: Total number of fuzz cases to run
            verbose:    Print scoring details

        Returns:
            List of all FuzzCase objects with responses and scores
        """
        all_cases  = []
        generation = 0

        print(f"  Adaptive fuzzer starting — {iterations} iterations")
        print(f"  Initial corpus size: {len(self.corpus)} seeds\n")

        # Phase 1: Run initial corpus to establish baseline
        print("  [Phase 1] Baseline — running initial seed corpus...")
        baseline_cases = self._run_corpus_phase(
            client, max_cases=min(len(self.corpus) * 2, 30),
            generation=0, verbose=verbose
        )
        all_cases.extend(baseline_cases)

        remaining = iterations - len(baseline_cases)

        # Phase 2: Adaptive loop — score, select, mutate, repeat
        print(f"\n  [Phase 2] Adaptive loop — {remaining} cases remaining...")
        while len(all_cases) < iterations and self.corpus:
            generation += 1
            self.stats["generations"] = generation

            # Select high-value inputs from corpus
            selected = self._select_from_corpus(n=5)

            # Mutate selected inputs to generate new cases
            new_cases = self._mutate_corpus_entries(selected, generation)

            # Run new cases
            for case in new_cases:
                if len(all_cases) >= iterations:
                    break

                case.response = client.send_raw(case.payload)
                self.stats["total_cases"] += 1

                # Score and potentially add to corpus
                score = self._score_response(case)
                case.description += f" [score={score}]"

                if score >= SCORE_POSITIVE_RESPONSE:
                    self._add_to_corpus(case, score, generation)
                    self.stats["high_score_cases"] += 1

                if verbose:
                    self._print_case(case, score)

                all_cases.append(case)

            # Print generation summary every 5 generations
            if generation % 5 == 0:
                top = self._get_top_corpus(n=3)
                print(f"  Gen {generation:03d} | "
                      f"Corpus: {len(self.corpus)} | "
                      f"Cases: {len(all_cases)} | "
                      f"Top score: {top[0].score if top else 0}")

        self.stats["corpus_size"] = len(self.corpus)
        return all_cases

    def get_top_findings(self, n: int = 10) -> list[CorpusEntry]:
        """Return the N highest-scoring corpus entries."""
        return sorted(self.corpus, key=lambda e: e.score, reverse=True)[:n]

    def get_stats(self) -> dict:
        return self.stats

    def print_corpus_summary(self):
        """Print what the adaptive fuzzer learned."""
        print(f"\n  {'─'*55}")
        print(f"  ADAPTIVE FUZZER — WHAT IT LEARNED")
        print(f"  {'─'*55}")
        print(f"  Corpus size:         {len(self.corpus)}")
        print(f"  Generations run:     {self.stats['generations']}")
        print(f"  New behaviors found: {self.stats['new_behaviors']}")
        print(f"  State changes seen:  {self.stats['state_changes']}")
        print(f"  Unique SIDs seen:    {len(self.seen_sids)}")
        print(f"  Unique NRC codes:    {len(self.seen_nrc_codes)}")
        print(f"\n  Top 5 corpus entries by score:")
        for i, entry in enumerate(self.get_top_findings(n=5), 1):
            resp_hex = entry.response_bytes.hex().upper() \
                       if entry.response_bytes else "TIMEOUT"
            print(f"  {i}. Score={entry.score:>4} | "
                  f"REQ={entry.payload.hex().upper():<20} | "
                  f"RESP={resp_hex[:20]:<20} | "
                  f"{entry.reason}")
        print(f"  {'─'*55}\n")

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score_response(self, case: FuzzCase) -> int:
        """
        Score a fuzz case response.
        Higher score = more interesting = worth mutating further.

        This is the core of adaptive fuzzing — the feedback signal.
        """
        resp  = case.response
        score = 0
        sid   = case.payload[0] if case.payload else 0

        if resp is None:
            return 0

        # ── Timeout ───────────────────────────────────────────────
        if resp.timed_out:
            score += SCORE_TIMEOUT
            return score

        # ── New SID seen ──────────────────────────────────────────
        # ECU responded to a SID we haven't tested before
        if sid not in self.seen_sids:
            score += SCORE_NEW_SID_SEEN
            self.seen_sids.add(sid)
            self.stats["new_behaviors"] += 1
            log.debug(f"  New SID: 0x{sid:02X} (+{SCORE_NEW_SID_SEEN})")

        # ── Positive response ─────────────────────────────────────
        if resp.is_positive:
            score += SCORE_POSITIVE_RESPONSE
            self.stats["positive_responses"] += 1

            # ── Session state change ──────────────────────────────
            if sid == SID_DSC and len(case.payload) > 1:
                new_session = case.payload[1]
                if new_session != self.current_session:
                    score += SCORE_STATE_CHANGE
                    old = self.current_session
                    self.current_session = new_session
                    self.stats["state_changes"] += 1
                    log.debug(f"  State change: 0x{old:02X}→"
                              f"0x{new_session:02X} (+{SCORE_STATE_CHANGE})")

            # ── SA unlock state change ────────────────────────────
            if sid == SID_SA and len(case.payload) > 1:
                if case.payload[1] % 2 == 0 and not self.sa_unlocked:
                    # Even subfunction = key send → potentially unlocked
                    score += SCORE_STATE_CHANGE
                    self.sa_unlocked = True
                    self.stats["state_changes"] += 1

            # ── Potential bypass — positive where we didn't expect ─
            if self._is_unexpected_positive(case, resp):
                score += SCORE_POTENTIAL_BYPASS
                log.debug(f"  Potential bypass! (+{SCORE_POTENTIAL_BYPASS})")

        # ── New NRC code ──────────────────────────────────────────
        if resp.nrc_code and resp.nrc_code not in self.seen_nrc_codes:
            score += SCORE_NEW_NRC_CODE
            self.seen_nrc_codes.add(resp.nrc_code)
            self.stats["new_behaviors"] += 1
            log.debug(f"  New NRC: 0x{resp.nrc_code:02X} "
                      f"({NRC.get(resp.nrc_code, '?')}) "
                      f"(+{SCORE_NEW_NRC_CODE})")

        # ── Duplicate response ────────────────────────────────────
        if resp.response_bytes:
            resp_key = bytes([sid]) + resp.response_bytes
            if resp_key in self.seen_responses:
                score += SCORE_DUPLICATE_RESPONSE
            else:
                self.seen_responses.add(resp_key)

        return score

    def _is_unexpected_positive(self, case: FuzzCase,
                                  resp) -> bool:
        """
        Check if a positive response is unexpected given context.
        These are the highest-value findings — potential bypasses.
        """
        sid = case.payload[0] if case.payload else 0

        # Positive to write service when SA not unlocked
        if sid in (SID_WDBI, SID_RMBA) and not self.sa_unlocked:
            if resp.is_positive:
                return True

        # Positive to programming session from default
        if (sid == SID_DSC and len(case.payload) > 1
                and case.payload[1] == SESSION_PROGRAMMING
                and self.current_session == SESSION_DEFAULT):
            if resp.is_positive:
                return True

        # Positive to undefined SID
        defined_sids = {0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27,
                        0x28, 0x2E, 0x31, 0x34, 0x35, 0x36, 0x37,
                        0x38, 0x3E, 0x85, 0x86, 0x29}
        if sid not in defined_sids and resp.is_positive:
            return True

        return False

    # ── Corpus Management ─────────────────────────────────────────────────────

    def _add_to_corpus(self, case: FuzzCase, score: int, generation: int):
        """Add a high-value case to the corpus."""
        resp = case.response
        sid  = case.payload[0] if case.payload else 0

        entry = CorpusEntry(
            payload        = case.payload,
            score          = score,
            response_bytes = resp.response_bytes if resp else None,
            nrc_code       = resp.nrc_code if resp else None,
            is_positive    = resp.is_positive if resp else False,
            sid            = sid,
            generation     = generation,
            reason         = case.description[:60],
        )
        self.corpus.append(entry)

        # Cap corpus size — keep highest scoring entries
        if len(self.corpus) > 200:
            self.corpus.sort(key=lambda e: e.score, reverse=True)
            self.corpus = self.corpus[:150]

    def _select_from_corpus(self, n: int = 5) -> list[CorpusEntry]:
        """
        Select corpus entries for mutation.
        Weighted by score — higher score = higher chance of selection.
        Also includes some random low-score entries to avoid getting stuck.
        """
        if not self.corpus:
            return []

        # Sort by score
        sorted_corpus = sorted(self.corpus, key=lambda e: e.score, reverse=True)

        selected = []

        # 70% from top scorers (exploitation)
        top_n = max(1, int(len(sorted_corpus) * 0.3))
        top   = sorted_corpus[:top_n]
        exploit_count = max(1, int(n * 0.7))
        selected.extend(random.choices(top, k=min(exploit_count, len(top))))

        # 30% random (exploration — avoid getting stuck in local maximum)
        explore_count = n - len(selected)
        selected.extend(random.choices(sorted_corpus,
                                        k=min(explore_count, len(sorted_corpus))))

        return selected

    def _get_top_corpus(self, n: int = 5) -> list[CorpusEntry]:
        return sorted(self.corpus, key=lambda e: e.score, reverse=True)[:n]

    def _mutate_corpus_entries(self, entries: list[CorpusEntry],
                                generation: int) -> list[FuzzCase]:
        """
        Mutate corpus entries to generate new fuzz cases.
        Applies more aggressive mutations to higher-generation entries.
        """
        cases = []
        case_id = generation * 1000

        for entry in entries:
            # More mutations per entry for high scorers
            num_mutations = min(3 + entry.score // 10, 8)

            for _ in range(num_mutations):
                mutation_type = random.choice([
                    "bit_flip", "byte_substitute", "length_extend",
                    "length_truncate", "boundary_value",
                    "subfunction_sweep", "append_known_payload",
                ])

                mutated, desc = self._apply_mutation(
                    entry.payload, mutation_type, entry.generation
                )

                cases.append(FuzzCase(
                    case_id     = case_id,
                    strategy    = f"adaptive/gen{generation}/{mutation_type}",
                    payload     = mutated,
                    description = (f"Corpus[score={entry.score}] "
                                   f"gen{generation} {desc}"),
                ))
                case_id += 1

        return cases

    def _apply_mutation(self, payload: bytes, mutation_type: str,
                         parent_generation: int) -> tuple[bytes, str]:
        """Apply a single mutation to a payload."""
        data = bytearray(payload)

        if not data:
            return bytes([random.randint(0, 0xFF)]), "random_byte"

        if mutation_type == "bit_flip" and len(data) > 1:
            idx = random.randint(1, len(data) - 1)
            bit = random.randint(0, 7)
            data[idx] ^= (1 << bit)
            return bytes(data), f"bit_flip[{idx}][{bit}]"

        elif mutation_type == "byte_substitute" and len(data) > 1:
            idx = random.randint(1, len(data) - 1)
            data[idx] = random.randint(0, 255)
            return bytes(data), f"byte_sub[{idx}]"

        elif mutation_type == "length_extend":
            extra_len = random.randint(1, 3)
            extra = bytes([random.randint(0, 255) for _ in range(extra_len)])
            return (bytes(data) + extra)[:8], f"extend+{extra_len}"

        elif mutation_type == "length_truncate" and len(data) > 1:
            cut = random.randint(1, len(data))
            return bytes(data[:cut]), f"truncate→{cut}"

        elif mutation_type == "boundary_value" and len(data) > 1:
            idx = random.randint(1, len(data) - 1)
            bval = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
            data[idx] = bval
            return bytes(data), f"boundary[{idx}]=0x{bval:02X}"

        elif mutation_type == "subfunction_sweep":
            sf = random.randint(0, 0xFF)
            if len(data) > 1:
                data[1] = sf
            return bytes(data), f"sf_sweep=0x{sf:02X}"

        elif mutation_type == "append_known_payload":
            # Append payloads we've seen work before — smart cross-pollination
            known_suffixes = [
                b'\x01', b'\x03', b'\xF1\x90', b'\x02\x00',
                b'\xFF\xFF\xFF', b'\x00\x00\x00\x00',
            ]
            suffix = random.choice(known_suffixes)
            return (bytes(data) + suffix)[:8], f"append_known"

        return bytes(data), "no_op"

    # ── Corpus Initialization ─────────────────────────────────────────────────

    def _run_corpus_phase(self, client, max_cases: int,
                           generation: int, verbose: bool) -> list[FuzzCase]:
        """Run the initial seed corpus to establish baseline behavior."""
        cases = []
        for i, entry in enumerate(self.corpus[:max_cases]):
            case = FuzzCase(
                case_id     = i,
                strategy    = "adaptive/seed",
                payload     = entry.payload,
                description = f"seed[{i}]",
            )
            case.response = client.send_raw(entry.payload)
            score = self._score_response(case)
            entry.score = score

            if verbose:
                self._print_case(case, score)

            cases.append(case)
            self.stats["total_cases"] += 1

        return cases

    def _init_seed_corpus(self):
        """
        Initialize corpus with high-value seed inputs.
        These cover all major UDS services and session states.
        Seeds are ordered to maximize early state coverage.
        """
        seeds = [
            # Session transitions — highest value, explore state space first
            (bytes([SID_DSC, SESSION_DEFAULT]),      "DSC default session"),
            (bytes([SID_DSC, SESSION_EXTENDED]),     "DSC extended session"),
            (bytes([SID_DSC, SESSION_PROGRAMMING]),  "DSC programming session"),

            # Security Access — critical attack surface
            (bytes([SID_SA, 0x01]),                  "SA request seed L1"),
            (bytes([SID_SA, 0x03]),                  "SA request seed L3"),
            (bytes([SID_SA, 0x02, 0xDE, 0xAD, 0xBE, 0xEF]), "SA send key"),

            # Read services — baseline behavior mapping
            (bytes([SID_RDBI, 0xF1, 0x90]),          "RDBI VIN"),
            (bytes([SID_RDBI, 0xF1, 0x8C]),          "RDBI serial"),
            (bytes([SID_RDBI, 0x01, 0x00]),          "RDBI engine speed"),
            (bytes([SID_RDTC, 0x02, 0xFF]),          "RDTC all DTCs"),

            # Write services — high value, need SA
            (bytes([SID_WDBI, 0x02, 0x00,
                    0x00, 0x00, 0x00, 0x00]),        "WDBI calib data"),
            (bytes([SID_WDBI, 0x02, 0x01,
                    0x00, 0x32]),                    "WDBI threshold"),

            # Routine Control — attack surface
            (bytes([SID_RC, 0x01, 0x03, 0x01]),     "RC start self-test"),
            (bytes([SID_RC, 0x01, 0x02, 0x02]),     "RC start erase"),
            (bytes([SID_RC, 0x01, 0xFF, 0x00]),     "RC erase all"),

            # ECU Reset — state machine reset
            (bytes([SID_ER, 0x01]),                  "ER hard reset"),
            (bytes([SID_ER, 0x03]),                  "ER soft reset"),

            # Memory — attack surface
            (bytes([SID_RMBA, 0x12, 0x00, 0x00, 0x04]), "RMBA read mem"),
            (bytes([SID_RMBA, 0x12, 0x00, 0x00, 0xFF]), "RMBA large read"),

            # Boundary/edge cases
            (bytes([SID_DSC, 0xFF]),                 "DSC invalid session"),
            (bytes([SID_SA, 0x00]),                  "SA subfunction 0"),
            (bytes([SID_RDBI, 0xFF, 0xFF]),          "RDBI invalid DID"),
        ]

        for payload, reason in seeds:
            self.corpus.append(CorpusEntry(
                payload        = payload,
                score          = 0,       # Score set after first run
                response_bytes = None,
                nrc_code       = None,
                is_positive    = False,
                sid            = payload[0],
                generation     = 0,
                reason         = reason,
            ))

    # ── Display ───────────────────────────────────────────────────────────────

    def _print_case(self, case: FuzzCase, score: int):
        """Print a single case result with score."""
        resp = case.response
        if not resp:
            return

        status = ("✅" if resp.is_positive else
                  "⏱" if resp.timed_out else "❌")
        resp_hex = resp.response_bytes.hex().upper() \
                   if resp.response_bytes else "TIMEOUT"

        score_col = ("\033[92m" if score >= 20 else
                     "\033[93m" if score >= 10 else
                     "\033[91m" if score < 0 else "")

        print(f"  {status} {case.strategy:<40} "
              f"REQ={case.payload.hex().upper():<18} "
              f"RESP={resp_hex[:16]:<18} "
              f"{score_col}score={score:>4}\033[0m")