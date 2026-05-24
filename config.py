"""
config.py - Shared constants across the entire UDS Security Fuzzer
==================================================================
All CAN IDs, timing values, UDS constants defined in one place.
Change here → changes everywhere. No magic numbers in code.
"""

# ── CAN Bus Configuration ─────────────────────────────────────────────────────
CAN_INTERFACE   = "vcan0"          # WSL2 virtual CAN interface
CAN_BITRATE     = 500_000          # 500 kbps — standard automotive
ECU_TX_ID       = 0x7E8            # ECU response CAN ID  (standard OBD: 0x7E8)
ECU_RX_ID       = 0x7DF            # Tester request CAN ID (standard OBD: 0x7DF)
BUS_TIMEOUT     = 2.0              # Seconds to wait for ECU response

# ── UDS Service IDs (ISO 14229-1) ─────────────────────────────────────────────
SID_DSC  = 0x10    # Diagnostic Session Control
SID_ER   = 0x11    # ECU Reset
SID_SA   = 0x27    # Security Access
SID_CC   = 0x28    # Communication Control
SID_RDBI = 0x22    # Read Data By Identifier
SID_WDBI = 0x2E    # Write Data By Identifier
SID_RC   = 0x31    # Routine Control
SID_RD   = 0x34    # Request Download
SID_TD   = 0x36    # Transfer Data
SID_RTE  = 0x37    # Request Transfer Exit
SID_CDTC = 0x14    # Clear Diagnostic Information
SID_RDTC = 0x19    # Read DTC Information
SID_RMBA = 0x23    # Read Memory By Address
SID_CDCS = 0x85    # Control DTC Setting

# Positive response = request SID + 0x40
POSITIVE_RESPONSE_OFFSET = 0x40

# ── UDS Session Types ─────────────────────────────────────────────────────────
SESSION_DEFAULT     = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED    = 0x03

# ── UDS Negative Response Codes (NRC) — ISO 14229-1 Table A.1 ────────────────
NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

# ── Security Access Config (0x27) ─────────────────────────────────────────────
SA_SEED_LENGTH      = 4            # Bytes in seed
SA_KEY_LENGTH       = 4            # Bytes in key
SA_MAX_ATTEMPTS     = 3            # Lock out after N failures
SA_LOCKOUT_TIME     = 10.0         # Seconds locked after max attempts
SA_P2_TIMEOUT       = 0.05         # 50ms — ECU response timing window

# Simple seed→key algorithm for virtual ECU (XOR with fixed mask)
# In real ECUs this is proprietary — we simulate a weak one deliberately
SA_KEY_MASK         = 0xDEADBEEF   # XOR mask for seed→key calculation

# ── DIDs for Read/Write Data By Identifier (0x22 / 0x2E) ─────────────────────
VALID_DIDS = {
    0xF190: ("VIN",              17, False),  # (name, length, writable)
    0xF18C: ("ECU_SERIAL",       4,  False),
    0xF187: ("PART_NUMBER",      10, False),
    0x0100: ("ENGINE_SPEED",     2,  False),
    0x0101: ("VEHICLE_SPEED",    2,  False),
    0x0200: ("CALIB_DATA",       8,  True),   # Writable — attack target
    0x0201: ("THRESHOLD_VALUE",  2,  True),   # Writable — attack target
    0x0300: ("ODOMETER",         4,  False),
}

# ── Routine Control IDs (0x31) ────────────────────────────────────────────────
VALID_ROUTINES = {
    0x0202: ("ERASE_MEMORY",    SESSION_PROGRAMMING),  # Only in programming
    0x0203: ("CHECK_MEMORY",    SESSION_PROGRAMMING),
    0x0301: ("RESET_COUNTERS",  SESSION_EXTENDED),
    0x0302: ("RUN_SELF_TEST",   SESSION_EXTENDED),
    0xFF00: ("ERASE_ALL",       SESSION_PROGRAMMING),  # Dangerous routine
}

# ── Fuzzer Configuration ──────────────────────────────────────────────────────
FUZZ_ITERATIONS     = 40          # Default number of fuzz cases per run
FUZZ_TIMEOUT        = 1.0          # Seconds to wait per fuzz case
FUZZ_LOG_DIR        = "outputs/fuzz_logs"
REPORT_DIR          = "outputs/reports"
IMAGE_DIR           = "outputs/images"

# ── ISO/SAE 21434 TARA Config ─────────────────────────────────────────────────
TARA_STANDARD       = "ISO/SAE 21434:2021"
TARA_WP29_REF       = "UNECE WP.29 R155"
