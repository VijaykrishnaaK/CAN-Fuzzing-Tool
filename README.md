# CAN-Fuzzing-Tool

Automotive UDS security fuzzing and reporting platform.

This repository implements a full research-grade CAN/DoIP fuzzer for UDS (ISO 14229) with:

- CAN/ISO-TP transport over `vcan0`
- DoIP transport over TCP/IP
- Mutation, generation, smart state-aware and adaptive fuzzing strategies
- Real-time IDS rule engine and anomaly detection
- Timing attack and replay attack modules
- ISO/SAE 21434 TARA-aligned reporting and AUTOSAR DCM mapping

## Key Features

- `main.py`: orchestrates fuzzing, attack modules, monitoring, and reporting
- `ecu_simulator/virtual_ecu.py`: virtual ECU target with session, security access, timing and NRC behavior
- `fuzzer/`: multiple fuzz strategies and UDS transport client
- `monitor/`: anomaly detector and IDS engine for live analysis
- `attacks/`: timing side-channel and replay attack engines
- `reporter/`: TARA/ISO 21434 report generation in terminal, JSON and Markdown

## Repository Structure

- `main.py` - main executable for running fuzzing and attack workflows
- `config.py` - shared constants, UDS/DoIP parameters, default directories
- `attacks/`
  - `timing_attack.py` - Security Access timing oracle analysis
  - `replay_attack.py` - UDS replay freshness validation tests
- `autosar/`
  - `dcm_mapping.py` - AUTOSAR DCM mapping for UDS service findings
- `doip/`
  - `doip_layer.py` - DoIP transport implementation and frame builder/parser
- `ecu_simulator/`
  - `virtual_ecu.py` - virtual ECU target for CAN/ISO-TP fuzzing
- `fuzzer/`
  - `uds_client.py` - low-level UDS client over CAN/ISO-TP
  - `fuzz_engine.py` - mutation, generation, smart fuzzers
  - `adaptive_fuzzer.py` - feedback-guided adaptive fuzzing engine
- `isotp/`
  - `isotp_layer.py` - ISO-TP stack used by CAN transport
- `monitor/`
  - `anomaly_detector.py` - security finding detection from fuzz responses
  - `ids_engine.py` - rule-based IDS for live UDS/CAN traffic
  - `vuln_engine.py` - vulnerability engine and scoring (used by reports)
- `reporter/`
  - `tara_reporter.py` - report generation for ISO/SAE 21434/TARA
- `output/` - generated fuzz logs, reports, and images
- `test_can.py` - simple CAN send test script

## Prerequisites

- Linux with SocketCAN support
- Python 3.10+ or newer
- `python-can` installed
- `vcan0` configured for local CAN testing

> This repository uses `vcan0` by default. If you need a physical CAN interface, update `config.py` or pass `--interface`.

## Quick Start

1. Start the virtual ECU target:

```bash
python -m ecu_simulator.virtual_ecu
```

2. In another terminal, run the fuzzer:

```bash
python main.py
```

3. For DoIP testing:

```bash
python main.py --transport doip --doip-host 127.0.0.1 --doip-port 13400
```

## Main CLI Options

```bash
python main.py [--transport can|doip|both] \
               [--strategy mutation|generation|smart|adaptive|all] \
               [--attacks timing,replay,all,none] \
               [--count N] [--interface vcan0] \
               [--doip-host 127.0.0.1] [--doip-port 13400] \
               [--no-fuzz] [--no-report] [--no-vuln-engine] [--verbose]
```

### Common examples

- Full CAN fuzzing run:
  `python main.py --transport can --strategy all --attacks all`
- Adaptive-only fuzzing:
  `python main.py --strategy adaptive`
- Run only attack modules:
  `python main.py --no-fuzz --attacks all`
- Use a different CAN interface:
  `python main.py --interface can0`

## Supported Modules

### Fuzzers

- `MutationFuzzer`: mutates valid UDS message seeds
- `GenerationFuzzer`: constructs raw UDS payloads and edge cases
- `SmartFuzzer`: session-aware sequence generation, intentional state violations
- `AdaptiveFuzzer`: feedback-guided fuzzing with corpus scoring

### Monitoring

- `AnomalyDetector`: flags unexpected positive responses, timeouts, wrong NRCs, timing anomalies, and state-machine violations
- `IDSEngine`: rule-based detection for auditability and live alerts

### Attacks

- `TimingAttackEngine`: measures Security Access response timing for side-channel leakage
- `ReplayAttackEngine`: records and replays UDS sequences to test freshness validation

### Reporting

- `TARAReporter`: generates terminal summaries plus JSON and Markdown reports aligned with ISO/SAE 21434
- `dcm_mapping.py`: maps UDS findings to AUTOSAR DCM service handlers and secure configuration parameters

## Output

Reports and artifacts are generated under `outputs/`:

- `outputs/fuzz_logs`
- `outputs/reports`
- `outputs/images`

## Testing

Use `test_can.py` to validate CAN sending on `vcan0`:

```bash
python test_can.py
```

## Notes

- The virtual ECU is designed for research and demonstration; it intentionally includes weak Security Access behavior so timing and replay attacks can be exercised.
- `config.py` centralizes UDS constants, default interface values, timing thresholds, and output directories.
- If `python-can` cannot open `vcan0`, ensure the interface is created with:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```
