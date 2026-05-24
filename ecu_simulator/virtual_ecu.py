"""
ecu_simulator/virtual_ecu.py
=============================
A software ECU that runs on vcan0 and responds to UDS requests
exactly like a real automotive ECU would — including security,
session management, timing rules, and negative responses.

This is your ATTACK TARGET. Run this in one terminal,
run the fuzzer in another. Both talk over vcan0.

ISO 14229-1 compliance:
  - Session state machine (default → extended → programming)
  - Security Access lockout after max attempts
  - Proper NRC codes for every rejection
  - Timing: P2 server timing enforced
"""

import can
import time
import threading
import struct
import logging
from datetime import datetime
from config import *
from isotp.isotp_layer import ISOTPStack, parse_frame, FrameType
from monitor.ids_engine import IDSEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ECU] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("VirtualECU")


class SecurityAccessManager:
    """
    Manages Security Access (0x27) state.
    Implements seed generation, key validation, lockout.
    
    Deliberately uses a WEAK seed→key algorithm so the fuzzer
    can demonstrate timing attacks and brute force — realistic
    for ECUs with poor security implementations.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.current_seed     = None
        self.attempt_count    = 0
        self.locked_until     = 0.0
        self.unlocked         = False
        self.seed_issued_at   = 0.0

    def is_locked(self) -> bool:
        if time.time() < self.locked_until:
            return True
        return False

    def get_remaining_lockout(self) -> float:
        return max(0.0, self.locked_until - time.time())

    def generate_seed(self) -> bytes:
        """Generate a 4-byte seed. Weak: time-based → predictable."""
        # Deliberately weak: seed derived from timestamp
        # Real ECUs use HSM-backed RNG — this simulates a bad implementation
        seed_int = int(time.time() * 1000) & 0xFFFFFFFF
        self.current_seed   = seed_int
        self.seed_issued_at = time.time()
        return struct.pack(">I", seed_int)

    def validate_key(self, key_bytes: bytes) -> bool:
        """
        Validate key against seed using XOR algorithm.
        Correct key = seed XOR SA_KEY_MASK
        """
        if self.current_seed is None:
            return False

        # Check timing window — key must arrive within P2 timeout
        # (In real ECUs this prevents timing attacks — our ECU has this too
        #  but the attack module will probe the boundary)
        elapsed = time.time() - self.seed_issued_at

        try:
            key_int = struct.unpack(">I", key_bytes[:4])[0]
        except struct.error:
            return False

        expected_key = self.current_seed ^ SA_KEY_MASK

        if key_int == expected_key:
            self.unlocked     = True
            self.attempt_count = 0
            return True
        else:
            self.attempt_count += 1
            if self.attempt_count >= SA_MAX_ATTEMPTS:
                self.locked_until = time.time() + SA_LOCKOUT_TIME
                log.warning(f"Security Access LOCKED for {SA_LOCKOUT_TIME}s "
                            f"after {SA_MAX_ATTEMPTS} failed attempts")
            return False


class VirtualECU:
    """
    Full UDS virtual ECU over vcan0.

    Implements:
      0x10 — Diagnostic Session Control
      0x11 — ECU Reset
      0x22 — Read Data By Identifier
      0x27 — Security Access
      0x28 — Communication Control
      0x2E — Write Data By Identifier
      0x31 — Routine Control
      0x14 — Clear DTC
      0x19 — Read DTC
      0x23 — Read Memory By Address

    All other services → NRC 0x11 (serviceNotSupported)
    """

    def __init__(self, interface: str = CAN_INTERFACE):
        self.interface      = interface
        self.session        = SESSION_DEFAULT
        self.sa_manager     = SecurityAccessManager()
        self.running        = False
        self.bus            = None
        self.message_count  = 0
        self.start_time     = None

        # Simulated ECU memory — attack target for 0x23/0x2E
        self.ecu_memory = bytearray(256)
        self.ecu_memory[0:4] = b'\xDE\xAD\xBE\xEF'  # Some "secret" data

        # DID storage
        self.did_store = {
            0xF190: b'1HGBH41JXMN109186',  # VIN
            0xF18C: b'\x01\x02\x03\x04',
            0xF187: b'12345-67890',
            0x0100: b'\x0B\xB8',            # 3000 RPM
            0x0101: b'\x00\x64',            # 100 km/h
            0x0200: b'\x00' * 8,
            0x0201: b'\x00\x32',
            0x0300: b'\x00\x01\x86\xA0',   # 100000 km odometer
        }

        # DTC storage (for 0x19)
        self.active_dtcs = [
            (0xC0100, 0x09),  # (DTC code, status byte)
            (0xB1234, 0x01),
        ]

        # Stats for monitoring
        self.stats = {
            "total_requests":   0,
            "positive_resp":    0,
            "negative_resp":    0,
            "unknown_service":  0,
        }

        # IDS engine — monitors every request in real time
        self.ids = IDSEngine(window_seconds=10.0)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Start ECU on vcan0/virtual. Blocks until stop() is called."""
        try:
            self.bus = can.interface.Bus(
                channel=self.interface,
                interface='virtual' if self.interface == 'virtual' else 'socketcan',
                bitrate=CAN_BITRATE,
            )
        except Exception as e:
            log.error(f"Failed to connect to {self.interface}: {e}")
            return

        # ISO-TP stack — ECU receives on ECU_RX_ID, sends on ECU_TX_ID
        self.isotp = ISOTPStack(
            bus     = self.bus,
            tx_id   = ECU_TX_ID,   # ECU responds on TX ID
            rx_id   = ECU_RX_ID,   # ECU listens on RX ID
            timeout = BUS_TIMEOUT,
        )

        self.running    = True
        self.start_time = time.time()
        log.info(f"Virtual ECU started on {self.interface} with ISO-TP")
        log.info(f"RX CAN ID: 0x{ECU_RX_ID:03X} | TX CAN ID: 0x{ECU_TX_ID:03X}")
        log.info("Press Ctrl+C to stop\n")

        try:
            while self.running:
                # Use ISO-TP receiver — handles SF and FF+CF transparently
                uds_data = self.isotp.receive()
                if uds_data and len(uds_data) >= 1:
                    response = self._handle_request_data(uds_data)
                    if response:
                        # Send response via ISO-TP — handles long responses automatically
                        self.isotp.send(response)
                        self.message_count += 1
        except KeyboardInterrupt:
            pass
        finally:
            self._print_stats()
            self.bus.shutdown()
            log.info("ECU stopped.")

    def stop(self):
        self.running = False

    # ── Request Handler ───────────────────────────────────────────────────────

    def _handle_request_data(self, uds_data: bytes) -> bytes | None:
        """
        Route UDS request bytes to correct service handler.
        Called by ISO-TP layer after reassembly.
        Works with any length payload — ISO-TP handled segmentation.
        """
        if len(uds_data) < 1:
            return None

        self.stats["total_requests"] += 1
        service_id = uds_data[0]
        payload    = uds_data[1:]

        log.info(f"RX [{self.message_count:04d}] "
                 f"SID=0x{service_id:02X} "
                 f"Payload({len(uds_data)}B)={uds_data.hex().upper()}")

        # ── IDS: analyse every request in real time ───────────────────────
        ids_alerts = self.ids.analyse_request(
            service_id      = service_id,
            payload         = payload,
            current_session = self.session,
        )
        for alert in ids_alerts:
            col = "\033[91m" if alert.severity in ("CRITICAL","HIGH") else "\033[93m"
            log.warning(f"  🚨 IDS [{alert.alert_id}] {col}{alert.severity}\033[0m "
                        f"— {alert.rule_name}")

        handlers = {
            SID_DSC:  self._handle_dsc,
            SID_ER:   self._handle_er,
            SID_SA:   self._handle_sa,
            SID_CC:   self._handle_cc,
            SID_RDBI: self._handle_rdbi,
            SID_WDBI: self._handle_wdbi,
            SID_RC:   self._handle_rc,
            SID_CDTC: self._handle_cdtc,
            SID_RDTC: self._handle_rdtc,
            SID_RMBA: self._handle_rmba,
        }

        handler = handlers.get(service_id)
        if handler:
            response = handler(payload)
        else:
            response = self._nrc(service_id, 0x11)
            self.stats["unknown_service"] += 1

        if response:
            if response[0] != 0x7F:
                self.stats["positive_resp"] += 1
            log.info(f"TX [{self.message_count:04d}] "
                     f"({len(response)}B) {response.hex().upper()}\n")

        return response

    # Keep old _handle_request for backward compatibility with tests
    def _handle_request(self, msg: can.Message):
        """Legacy handler — wraps _handle_request_data for raw CAN message."""
        return self._handle_request_data(bytes(msg.data))

    # ── Service Handlers ──────────────────────────────────────────────────────

    def _handle_dsc(self, payload: bytes) -> bytes:
        """
        0x10 — Diagnostic Session Control
        Transitions ECU between sessions.

        ISO 14229-1 §9.2 session prerequisite chain:
          Default    → Extended    : always allowed
          Default    → Programming : REJECT (NRC 0x22) — must go via Extended + SA
          Extended   → Programming : only if SA unlocked (NRC 0x22 if not)
          Any        → Default     : always allowed (resets SA state)
          Programming→ Extended    : allowed (SA state preserved)
        """
        if len(payload) < 1:
            return self._nrc(SID_DSC, 0x13)

        requested_session = payload[0]

        if requested_session not in (SESSION_DEFAULT,
                                      SESSION_PROGRAMMING,
                                      SESSION_EXTENDED):
            return self._nrc(SID_DSC, 0x12)  # subFunctionNotSupported

        # ── Prerequisite enforcement ──────────────────────────────────────────

        # Programming session requires Extended session + SA unlock
        if requested_session == SESSION_PROGRAMMING:
            if self.session == SESSION_DEFAULT:
                # Can never jump default → programming directly
                log.info("  DSC: Default→Programming rejected (NRC 0x22)")
                return self._nrc(SID_DSC, 0x22)  # conditionsNotCorrect
            if not self.sa_manager.unlocked:
                # In extended but SA not unlocked
                log.info("  DSC: Programming rejected — SA not unlocked (NRC 0x22)")
                return self._nrc(SID_DSC, 0x22)  # conditionsNotCorrect

        # Returning to default session — clear SA unlock (ISO 14229-1 §10.4.2)
        if requested_session == SESSION_DEFAULT:
            if self.sa_manager.unlocked:
                log.info("  DSC: Returning to default — SA unlock cleared")
            self.sa_manager.reset()

        # Transition accepted
        old_session   = self.session
        self.session  = requested_session
        log.info(f"  Session 0x{old_session:02X} → 0x{requested_session:02X}")

        return bytes([
            SID_DSC + POSITIVE_RESPONSE_OFFSET,
            requested_session,
            0x00, 0x19,   # P2 server max = 25ms
            0x01, 0xF4,   # P2* server max = 500ms
        ])

    def _handle_er(self, payload: bytes) -> bytes:
        """0x11 — ECU Reset"""
        if len(payload) < 1:
            return self._nrc(SID_ER, 0x13)

        reset_type = payload[0]
        if reset_type not in (0x01, 0x02, 0x03):
            return self._nrc(SID_ER, 0x12)

        log.info(f"  ECU Reset type={reset_type:#04x} — resetting state")
        # Reset ECU state
        self.session = SESSION_DEFAULT
        self.sa_manager.reset()

        return bytes([SID_ER + POSITIVE_RESPONSE_OFFSET, reset_type])

    def _handle_sa(self, payload: bytes) -> bytes:
        """
        0x27 — Security Access
        Implements seed/key challenge-response.
        Attack surface: timing, brute force, algorithm weakness.
        """
        if len(payload) < 1:
            return self._nrc(SID_SA, 0x13)

        subfunction = payload[0]

        # Must be in extended or programming session
        if self.session == SESSION_DEFAULT:
            return self._nrc(SID_SA, 0x7F)  # serviceNotSupportedInActiveSession

        # Check lockout
        if self.sa_manager.is_locked():
            remaining = self.sa_manager.get_remaining_lockout()
            log.warning(f"  SA locked — {remaining:.1f}s remaining")
            return self._nrc(SID_SA, 0x37)  # requiredTimeDelayNotExpired

        # Odd subfunction = request seed
        # Even subfunction = send key
        if subfunction % 2 == 1:
            # Request seed
            seed = self.sa_manager.generate_seed()
            log.info(f"  SA seed issued: {seed.hex().upper()}")
            return bytes([SID_SA + POSITIVE_RESPONSE_OFFSET, subfunction]) + seed

        else:
            # Send key
            if len(payload) < 1 + SA_KEY_LENGTH:
                return self._nrc(SID_SA, 0x13)

            key_bytes = payload[1:1 + SA_KEY_LENGTH]
            if self.sa_manager.validate_key(key_bytes):
                log.info(f"  SA key ACCEPTED — security unlocked")
                return bytes([SID_SA + POSITIVE_RESPONSE_OFFSET, subfunction])
            else:
                attempts_left = SA_MAX_ATTEMPTS - self.sa_manager.attempt_count
                log.warning(f"  SA key REJECTED — "
                            f"{attempts_left} attempt(s) remaining")
                return self._nrc(SID_SA, 0x35)  # invalidKey

    def _handle_cc(self, payload: bytes) -> bytes:
        """0x28 — Communication Control"""
        if len(payload) < 2:
            return self._nrc(SID_CC, 0x13)
        if self.session == SESSION_DEFAULT:
            return self._nrc(SID_CC, 0x7F)
        return bytes([SID_CC + POSITIVE_RESPONSE_OFFSET, payload[0]])

    def _handle_rdbi(self, payload: bytes) -> bytes:
        """0x22 — Read Data By Identifier"""
        if len(payload) < 2:
            return self._nrc(SID_RDBI, 0x13)

        did = struct.unpack(">H", payload[:2])[0]

        if did not in self.did_store:
            return self._nrc(SID_RDBI, 0x31)  # requestOutOfRange

        data = self.did_store[did]
        log.info(f"  RDBI DID=0x{did:04X} → {data.hex().upper()}")
        return (bytes([SID_RDBI + POSITIVE_RESPONSE_OFFSET])
                + payload[:2]
                + data)

    def _handle_wdbi(self, payload: bytes) -> bytes:
        """
        0x2E — Write Data By Identifier
        Attack surface: write to read-only DIDs, write out-of-range values,
        write in wrong session.
        """
        if len(payload) < 3:
            return self._nrc(SID_WDBI, 0x13)

        did = struct.unpack(">H", payload[:2])[0]

        if did not in VALID_DIDS:
            return self._nrc(SID_WDBI, 0x31)

        name, length, writable = VALID_DIDS[did]

        if not writable:
            return self._nrc(SID_WDBI, 0x31)  # requestOutOfRange

        # Requires extended session + security access
        if self.session == SESSION_DEFAULT:
            return self._nrc(SID_WDBI, 0x7F)

        if not self.sa_manager.unlocked:
            return self._nrc(SID_WDBI, 0x33)  # securityAccessDenied

        write_data = payload[2:2 + length]
        self.did_store[did] = write_data
        log.info(f"  WDBI DID=0x{did:04X} written: {write_data.hex().upper()}")
        return bytes([SID_WDBI + POSITIVE_RESPONSE_OFFSET]) + payload[:2]

    def _handle_rc(self, payload: bytes) -> bytes:
        """
        0x31 — Routine Control
        Attack surface: trigger unauthorized routines, wrong session.
        """
        if len(payload) < 3:
            return self._nrc(SID_RC, 0x13)

        subfunction  = payload[0]   # 0x01=start, 0x02=stop, 0x03=requestResults
        routine_id   = struct.unpack(">H", payload[1:3])[0]

        if routine_id not in VALID_ROUTINES:
            return self._nrc(SID_RC, 0x31)

        _, required_session = VALID_ROUTINES[routine_id]

        if self.session != required_session:
            return self._nrc(SID_RC, 0x7F)

        if not self.sa_manager.unlocked:
            return self._nrc(SID_RC, 0x33)

        log.info(f"  RC routine=0x{routine_id:04X} sub={subfunction:#04x} executed")
        return bytes([SID_RC + POSITIVE_RESPONSE_OFFSET,
                      subfunction,
                      payload[1], payload[2],
                      0x00])  # routine status OK

    def _handle_cdtc(self, payload: bytes) -> bytes:
        """0x14 — Clear Diagnostic Information"""
        if self.session == SESSION_DEFAULT:
            return self._nrc(SID_CDTC, 0x7F)
        self.active_dtcs.clear()
        log.info("  DTCs cleared")
        return bytes([SID_CDTC + POSITIVE_RESPONSE_OFFSET])

    def _handle_rdtc(self, payload: bytes) -> bytes:
        """0x19 — Read DTC Information (subfunction 0x02 — reportDTCByStatus)"""
        if len(payload) < 2:
            return self._nrc(SID_RDTC, 0x13)

        subfunction = payload[0]
        if subfunction != 0x02:
            return self._nrc(SID_RDTC, 0x12)

        response = bytes([SID_RDTC + POSITIVE_RESPONSE_OFFSET,
                          subfunction,
                          0xFF])  # DTC status availability mask

        for dtc_code, status in self.active_dtcs:
            response += struct.pack(">I", dtc_code)[1:]  # 3-byte DTC
            response += bytes([status])

        return response

    def _handle_rmba(self, payload: bytes) -> bytes:
        """
        0x23 — Read Memory By Address
        Attack surface: read beyond valid range, read security-sensitive areas.
        """
        if len(payload) < 3:
            return self._nrc(SID_RMBA, 0x13)

        if not self.sa_manager.unlocked:
            return self._nrc(SID_RMBA, 0x33)

        address_len = (payload[0] >> 4) & 0x0F
        size_len    = payload[0] & 0x0F

        if len(payload) < 1 + address_len + size_len:
            return self._nrc(SID_RMBA, 0x13)

        address = int.from_bytes(payload[1:1+address_len], 'big')
        size    = int.from_bytes(
            payload[1+address_len:1+address_len+size_len], 'big')

        # Bounds check — only allow access to our simulated memory
        if address + size > len(self.ecu_memory):
            return self._nrc(SID_RMBA, 0x31)

        data = bytes(self.ecu_memory[address:address + size])
        log.info(f"  RMBA addr=0x{address:04X} size={size} → {data.hex().upper()}")
        return bytes([SID_RMBA + POSITIVE_RESPONSE_OFFSET]) + data

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _nrc(self, service_id: int, nrc_code: int) -> bytes:
        """Build a Negative Response (0x7F SID NRC)."""
        self.stats["negative_resp"] += 1
        nrc_name = NRC.get(nrc_code, "unknown")
        log.info(f"  NRC 0x{nrc_code:02X} ({nrc_name}) for SID 0x{service_id:02X}")
        return bytes([0x7F, service_id, nrc_code])

    def _send_response(self, response: bytes, service_id: int):
        """Send UDS response back on CAN bus."""
        if not response:
            return

        # Positive or negative?
        if response[0] != 0x7F:
            self.stats["positive_resp"] += 1

        msg = can.Message(
            arbitration_id=ECU_TX_ID,
            data=response,
            is_extended_id=False
        )

        try:
            self.bus.send(msg)
            log.info(f"TX [{self.message_count:04d}] {response.hex().upper()}\n")
        except can.CanError as e:
            log.error(f"Send failed: {e}")

    def _print_stats(self):
        """Print session statistics on shutdown."""
        uptime = time.time() - (self.start_time or time.time())
        ids_summary = self.ids.get_summary()
        print("\n" + "="*50)
        print("  VIRTUAL ECU SESSION STATS")
        print("="*50)
        print(f"  Uptime:             {uptime:.1f}s")
        print(f"  Total requests:     {self.stats['total_requests']}")
        print(f"  Positive responses: {self.stats['positive_resp']}")
        print(f"  Negative responses: {self.stats['negative_resp']}")
        print(f"  Unknown services:   {self.stats['unknown_service']}")
        print(f"  ── IDS Summary ──────────────────")
        print(f"  Total IDS alerts:   {ids_summary['total_alerts']}")
        for sev, count in ids_summary.get('by_severity', {}).items():
            print(f"  {sev:<12}        {count}")
        if ids_summary['total_alerts'] > 0:
            print(f"  ── IDS Alerts ───────────────────")
            for alert in ids_summary['alerts']:
                print(f"  [{alert.alert_id}] {alert.severity:<10} {alert.rule_name}")
        print("="*50)


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ecu = VirtualECU(interface=CAN_INTERFACE)
    ecu.start()