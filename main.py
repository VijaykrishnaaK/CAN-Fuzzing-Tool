"""
main.py — UDS Security Fuzzer
==============================
Complete automotive ECU security research platform.

Transports:
  CAN → ISO-TP (ISO 15765-2) → UDS  — classic vehicles
  TCP → DoIP   (ISO 13400-2) → UDS  — modern vehicles (Option A: both run simultaneously)

Fuzzing:
  Mutation + Generation + Smart + Adaptive feedback-guided

Analysis:
  IDS (8 rules) + Anomaly detector + Vulnerability engine (CVSS v3.1)
  Timing attack (SA side-channel) + Replay attack (freshness validation)

Reporting:
  TARA (ISO/SAE 21434) + Vulnerability report + AUTOSAR DCM mapping

Usage:
  python main.py                              # Full run, CAN transport
  python main.py --transport doip             # DoIP transport
  python main.py --transport both             # Run both sequentially
  python main.py --strategy adaptive          # Adaptive fuzzer only
  python main.py --attacks timing,replay      # Run attack modules
  python main.py --count 500 --verbose        # 500 cases, verbose
"""

import argparse
import logging
import time
from datetime import datetime
from config import *
from fuzzer.uds_client import UDSClient
from fuzzer.fuzz_engine import MutationFuzzer, GenerationFuzzer, SmartFuzzer
from fuzzer.adaptive_fuzzer import AdaptiveFuzzer
from fuzzer.fuzz_engine import FuzzCase
from monitor.anomaly_detector import AnomalyDetector
from monitor.ids_engine import IDSEngine
from monitor.vuln_engine import VulnerabilityEngine
from reporter.tara_reporter import TARAReporter
from doip.doip_layer import DoIPClient
from autosar.dcm_mapping import AutosarDCMMapper
from attacks.timing_attack import TimingAttackEngine
from attacks.replay_attack import ReplayAttackEngine

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("Main")


def parse_args():
    p = argparse.ArgumentParser(
        description="UDS Security Fuzzer — Full Automotive Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Transport:
  --transport can   CAN/ISO-TP (classic vehicles, default)
  --transport doip  DoIP/TCP (modern vehicles, port 13400)
  --transport both  Run fuzzer on both transports

Strategy:
  --strategy all        All fuzzers (default)
  --strategy adaptive   Adaptive feedback-guided only
  --strategy smart      State-machine fuzzer only
  --strategy mutation   Mutation fuzzer only

Attack modules:
  --attacks timing      SA timing side-channel analysis
  --attacks replay      Replay attack freshness testing
  --attacks all         Both attack modules
  --attacks none        Skip attack modules (default)

Examples:
  python main.py --transport can --strategy all --attacks all
  python main.py --transport doip --strategy smart
  python main.py --attacks timing --no-fuzz
        """
    )
    p.add_argument("--transport", choices=["can","doip","both"],
                   default="can")
    p.add_argument("--strategy",
                   choices=["mutation","generation","smart","adaptive","all"],
                   default="all")
    p.add_argument("--attacks", default="none",
                   help="Attack modules: timing, replay, all, none")
    p.add_argument("--count", type=int, default=FUZZ_ITERATIONS)
    p.add_argument("--interface", default=CAN_INTERFACE)
    p.add_argument("--doip-host", default="127.0.0.1")
    p.add_argument("--doip-port", type=int, default=13400)
    p.add_argument("--no-fuzz", action="store_true",
                   help="Skip fuzzing — only run attack modules")
    p.add_argument("--no-report", action="store_true")
    p.add_argument("--no-vuln-engine", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def get_client(args):
    """Create and connect appropriate transport client."""
    if args.transport == "doip":
        print(f"[*] Connecting via DoIP to {args.doip_host}:{args.doip_port}...")
        client = DoIPClient(host=args.doip_host, port=args.doip_port)
        if not client.connect():
            print(f"[!] DoIP connection failed. Is the ECU running?")
            return None
        print(f"[✓] DoIP connected")

        # Vehicle discovery — demonstrate info disclosure risk
        info = client.discover_vehicle()
        if info:
            print(f"[✓] Vehicle identified: VIN={info['vin']} "
                  f"Addr={info['logical_addr']}")
        return client
    else:
        print(f"[*] Connecting via CAN to {args.interface}...")
        client = UDSClient(interface=args.interface)
        if not client.connect():
            print(f"[!] CAN connection failed.")
            print(f"[!] Start ECU: python -m ecu_simulator.virtual_ecu")
            return None
        print(f"[✓] CAN connected")
        return client


def run_cases(client, cases, detector, ids, verbose, current_session):
    """Execute fuzz cases with IDS + anomaly detection."""
    positive_count = 0
    timeout_count  = 0

    for i, case in enumerate(cases):
        if i % 50 == 0:
            print(f"  [{i:>4}/{len(cases)}] Running {case.strategy}...")

        if case.payload and case.payload[0] == SID_DSC and len(case.payload) > 1:
            current_session[0] = case.payload[1]

        ids_alerts = ids.analyse_request(
            service_id      = case.payload[0] if case.payload else 0,
            payload         = case.payload[1:] if len(case.payload) > 1 else b'',
            current_session = current_session[0],
        )
        for alert in ids_alerts:
            col = "\033[91m" if alert.severity in ("CRITICAL","HIGH") else "\033[93m"
            print(f"  🚨 [{alert.alert_id}] {col}{alert.severity}\033[0m "
                  f"— {alert.rule_name}")

        # Send via appropriate client
        if hasattr(client, 'send_raw'):
            case.response = client.send_raw(case.payload)
        else:
            # DoIP client — wrap response
            from fuzzer.uds_client import UDSResponse
            resp_bytes = client.send_uds(case.payload)
            sid = case.payload[0] if case.payload else 0
            is_pos = (resp_bytes is not None and len(resp_bytes) > 0
                      and resp_bytes[0] == sid + 0x40)
            nrc = resp_bytes[2] if (resp_bytes and len(resp_bytes) >= 3
                                     and resp_bytes[0] == 0x7F) else None
            case.response = UDSResponse(
                request_bytes=case.payload,
                response_bytes=resp_bytes,
                is_positive=is_pos,
                service_id=sid,
                nrc_code=nrc,
                nrc_name=NRC.get(nrc) if nrc else None,
                response_time_s=0.01,
                timed_out=(resp_bytes is None),
            )

        if case.response.is_positive:
            positive_count += 1
        if case.response.timed_out:
            timeout_count += 1

        findings = detector.analyse(case)
        if verbose or findings:
            status = ("✅" if case.response.is_positive else
                      "⏱" if case.response.timed_out else "❌")
            resp_hex = (case.response.response_bytes.hex().upper()
                        if case.response.response_bytes else "TIMEOUT")
            print(f"  {status} [{case.case_id:04d}] {case.strategy:<38} "
                  f"REQ={case.payload.hex().upper():<18} RESP={resp_hex[:18]}")
            for f in findings:
                col = "\033[91m" if f.severity in ("CRITICAL","HIGH") else "\033[93m"
                print(f"    🔴 [{f.finding_id}] {col}{f.severity}\033[0m — {f.title}")

    return {
        "total_cases":    len(cases),
        "positive_count": positive_count,
        "timeout_count":  timeout_count,
        "negative_count": len(cases) - positive_count - timeout_count,
    }


def run_fuzzing(args, client, detector, ids, current_session) -> dict:
    """Run all selected fuzzing strategies."""
    adaptive_fuzzer = AdaptiveFuzzer()
    all_stats = {"total_cases":0,"positive_count":0,
                 "timeout_count":0,"negative_count":0}

    if args.strategy in ("mutation","all"):
        print(f"\n[1/4] Mutation Fuzzer — {args.count} cases")
        print("─"*45)
        cases = MutationFuzzer().generate(count=args.count)
        s = run_cases(client, cases, detector, ids, args.verbose, current_session)
        for k,v in s.items(): all_stats[k] += v
        print(f"  Done. Findings: {len(detector.findings)} | IDS: {len(ids.alerts)}")

    if args.strategy in ("generation","all"):
        print(f"\n[2/4] Generation Fuzzer — {args.count} cases")
        print("─"*45)
        cases = GenerationFuzzer().generate(count=args.count)
        s = run_cases(client, cases, detector, ids, args.verbose, current_session)
        for k,v in s.items(): all_stats[k] += v
        print(f"  Done. Findings: {len(detector.findings)} | IDS: {len(ids.alerts)}")

    if args.strategy in ("smart","all"):
        sequences = args.count // 10
        print(f"\n[3/4] Smart Fuzzer — {sequences} sequences")
        print("─"*45)
        smart_cases = []
        for seq in SmartFuzzer().generate_sequences(count=sequences):
            smart_cases.extend(seq)
        s = run_cases(client, smart_cases, detector, ids,
                      args.verbose, current_session)
        for k,v in s.items(): all_stats[k] += v
        print(f"  Done. Findings: {len(detector.findings)} | IDS: {len(ids.alerts)}")

    if args.strategy in ("adaptive","all"):
        print(f"\n[4/4] Adaptive Fuzzer — {args.count} cases")
        print("─"*45)
        adaptive_cases = adaptive_fuzzer.generate_adaptive(
            client=client, iterations=args.count, verbose=args.verbose
        )
        for case in adaptive_cases:
            if case.response:
                detector.analyse(case)
        astats = adaptive_fuzzer.get_stats()
        all_stats["total_cases"]    += astats["total_cases"]
        all_stats["positive_count"] += astats["positive_responses"]
        adaptive_fuzzer.print_corpus_summary()

    return all_stats


def run_attacks(args, client):
    """Run selected attack modules."""
    attack_list = [a.strip().lower() for a in args.attacks.split(",")]
    results = {}

    if "timing" in attack_list or "all" in attack_list:
        print(f"\n[Attack] Timing Side-Channel Analysis")
        print("─"*45)
        engine = TimingAttackEngine(samples_per_key=30, keys_to_test=60)
        results["timing"] = engine.run(client)

    if "replay" in attack_list or "all" in attack_list:
        print(f"\n[Attack] Replay Attack Analysis")
        print("─"*45)
        engine = ReplayAttackEngine()
        results["replay"] = engine.run_all(client)

    return results


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    print("\n" + "="*65)
    print("  UDS SECURITY FUZZER — Full Automotive Security Platform")
    print(f"  ISO 14229-1 | ISO 15765-2 | ISO 13400-2 | ISO/SAE 21434")
    print(f"  CVSS v3.1 | AUTOSAR DCM | CWE")
    print("="*65 + "\n")

    run_id          = datetime.now().strftime("run_%Y%m%d_%H%M%S")
    detector        = AnomalyDetector()
    ids             = IDSEngine(window_seconds=10.0, mode="fuzzing")
    vuln_engine     = VulnerabilityEngine()
    dcm_mapper      = AutosarDCMMapper()
    current_session = [SESSION_DEFAULT]
    all_stats       = {"total_cases":0,"positive_count":0,
                       "timeout_count":0,"negative_count":0}

    # ── Connect ───────────────────────────────────────────────────
    client = get_client(args)
    if not client:
        return

    print(f"[✓] IDS engine active (fuzzing mode — 8 rules)\n")

    try:
        t_start = time.time()

        # ── Fuzzing ───────────────────────────────────────────────
        if not args.no_fuzz:
            fuzz_stats = run_fuzzing(args, client, detector, ids, current_session)
            for k,v in fuzz_stats.items():
                all_stats[k] += v

        # ── Attack Modules ────────────────────────────────────────
        attack_results = {}
        if args.attacks != "none":
            attack_results = run_attacks(args, client)

        elapsed = time.time() - t_start
        all_stats["elapsed_seconds"]  = round(elapsed, 1)
        all_stats["requests_per_sec"] = round(
            all_stats["total_cases"] / max(elapsed, 0.1), 1)

    finally:
        client.disconnect()

    # ── Summary ───────────────────────────────────────────────────
    ids_summary = ids.get_summary()
    print("\n" + "─"*65)
    print(f"  Transport:         {args.transport.upper()}")
    print(f"  Total fuzz cases:  {all_stats['total_cases']}")
    print(f"  Fuzzer findings:   {len(detector.findings)}")
    print(f"  IDS alerts:        {ids_summary['total_alerts']}")
    print(f"  Runtime:           {all_stats.get('elapsed_seconds',0):.1f}s")
    if attack_results:
        print(f"  Attack modules:    {', '.join(attack_results.keys())}")
    print("─"*65 + "\n")

    # ── AUTOSAR DCM mapping ───────────────────────────────────────
    print("[*] Generating AUTOSAR DCM mapping...")
    dcm_summary = dcm_mapper.generate_dcm_summary()

    # ── Vulnerability Engine ──────────────────────────────────────
    if not args.no_vuln_engine:
        print("[*] Running Vulnerability Engine (CVSS v3.1 + CWE)...")
        vulns = vuln_engine.analyse(
            findings   = detector.findings,
            ids_alerts = ids_summary.get("alerts", []),
        )
        if not args.no_report:
            vuln_paths = vuln_engine.generate_report(run_id)
            print(f"[✓] Vuln report:     {vuln_paths['markdown']}")
        else:
            vuln_engine._print_terminal()

    # ── TARA Report ───────────────────────────────────────────────
    if not args.no_report:
        # Save AUTOSAR DCM mapping
        from pathlib import Path
        dcm_path = Path(REPORT_DIR) / f"{run_id}_autosar_dcm_mapping.md"
        Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
        dcm_path.write_text(dcm_summary)
        print(f"[✓] AUTOSAR mapping: {dcm_path}")

        reporter = TARAReporter()
        paths    = reporter.generate(
            findings    = detector.findings,
            fuzz_stats  = all_stats,
            run_id      = run_id,
            ids_summary = ids_summary,
        )
        print(f"[✓] TARA report:     {paths['markdown']}")
    else:
        TARAReporter()._print_terminal(detector.findings, all_stats, ids_summary)

    print(f"\n[✓] Run complete.\n")


if __name__ == "__main__":
    main()