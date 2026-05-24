"""
fuzzer/uds_client.py
=====================
Base UDS communication layer used by all fuzzers and attack modules.
Handles raw CAN send/receive so fuzzers only think about payloads.

Two modes:
  - Normal mode: sends valid UDS frames, waits for response
  - Raw mode:    sends arbitrary bytes (for fuzzing invalid frames)
"""

import can
import time
import struct
import logging
from dataclasses import dataclass
from config import *
from isotp.isotp_layer import ISOTPStack

log = logging.getLogger("UDSClient")


@dataclass
class UDSResponse:
    """Result of a single UDS request."""
    request_bytes:   bytes
    response_bytes:  bytes | None
    is_positive:     bool
    service_id:      int
    nrc_code:        int | None       # Set if negative response
    nrc_name:        str | None
    response_time_s: float
    timed_out:       bool


class UDSClient:
    """
    Low-level UDS client over vcan0.
    Used by all fuzzers to send requests and collect responses.
    """

    def __init__(self, interface: str = CAN_INTERFACE,
                 timeout: float = BUS_TIMEOUT):
        self.interface  = interface
        self.timeout    = timeout
        self.bus        = None
        self.tx_id      = ECU_RX_ID   # We send to ECU's RX
        self.rx_id      = ECU_TX_ID   # We receive from ECU's TX
        self._request_count = 0

    def connect(self) -> bool:
        """Open CAN bus connection with ISO-TP stack."""
        try:
            self.bus = can.interface.Bus(
                channel   = self.interface,
                interface = 'socketcan' if self.interface == 'virtual' else 'socketcan',
                bitrate   = CAN_BITRATE,
            )
            # ISO-TP stack — client sends on ECU_RX_ID, receives on ECU_TX_ID
            self.isotp = ISOTPStack(
                bus     = self.bus,
                tx_id   = ECU_RX_ID,   # Client sends to ECU's RX
                rx_id   = ECU_TX_ID,   # Client receives from ECU's TX
                timeout = self.timeout,
            )
            log.info(f"Connected to {self.interface} with ISO-TP")
            return True
        except Exception as e:
            log.error(f"Cannot connect to {self.interface}: {e}")
            return False

    def disconnect(self):
        if self.bus:
            self.bus.shutdown()
            self.bus = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    # ── Core Send/Receive ─────────────────────────────────────────────────────

    def send_raw(self, data: bytes) -> UDSResponse:
        """
        Send raw UDS bytes via ISO-TP.
        ISO-TP handles segmentation automatically:
          ≤7 bytes → Single Frame
          >7 bytes → First Frame + Consecutive Frames
        """
        if not self.bus:
            raise RuntimeError("Not connected. Call connect() first.")

        service_id = data[0] if data else 0x00
        self._request_count += 1
        t_start = time.time()

        # Send via ISO-TP (handles SF/FF/CF automatically)
        sent = self.isotp.send(data)
        if not sent:
            return self._timeout_response(data, service_id, t_start)

        # Receive response via ISO-TP (handles reassembly automatically)
        response_data = self.isotp.receive()
        elapsed = time.time() - t_start

        if response_data is None:
            return self._timeout_response(data, service_id, t_start)

        return self._parse_response(
            request_bytes  = data,
            response_bytes = response_data,
            service_id     = service_id,
            elapsed        = elapsed,
        )

    def send_uds(self, service_id: int, *args: int | bytes) -> UDSResponse:
        """
        Send a structured UDS request.
        
        Usage:
            client.send_uds(0x10, 0x03)          # DSC extended session
            client.send_uds(0x27, 0x01)          # SA request seed
            client.send_uds(0x22, 0xF1, 0x90)   # RDBI VIN
        """
        payload = bytes([service_id])
        for arg in args:
            if isinstance(arg, int):
                payload += bytes([arg])
            elif isinstance(arg, bytes):
                payload += arg
        return self.send_raw(payload)

    # ── Convenience Methods (used by smart fuzzer) ────────────────────────────

    def enter_session(self, session_type: int = SESSION_EXTENDED) -> UDSResponse:
        return self.send_uds(SID_DSC, session_type)

    def request_seed(self, level: int = 0x01) -> tuple[UDSResponse, bytes | None]:
        """Request seed from ECU. Returns (response, seed_bytes)."""
        resp = self.send_uds(SID_SA, level)
        if resp.is_positive and len(resp.response_bytes) >= 6:
            seed = resp.response_bytes[2:2 + SA_SEED_LENGTH]
            return resp, seed
        return resp, None

    def send_key(self, key: bytes, level: int = 0x02) -> UDSResponse:
        """Send key response to ECU."""
        return self.send_uds(SID_SA, level, key)

    def compute_key(self, seed: bytes) -> bytes:
        """
        Compute correct key from seed using known algorithm.
        seed XOR SA_KEY_MASK = key
        """
        seed_int = struct.unpack(">I", seed[:4])[0]
        key_int  = seed_int ^ SA_KEY_MASK
        return struct.pack(">I", key_int)

    def unlock_security_access(self, level: int = 0x01) -> bool:
        """Full Security Access sequence. Returns True if unlocked."""
        # Enter extended session first
        self.enter_session(SESSION_EXTENDED)

        # Request seed
        resp, seed = self.request_seed(level)
        if seed is None:
            return False

        # Compute and send key
        key  = self.compute_key(seed)
        resp = self.send_key(key, level + 1)
        return resp.is_positive

    # ── Response Parsing ──────────────────────────────────────────────────────

    def _parse_response(self, request_bytes: bytes, response_bytes: bytes,
                         service_id: int, elapsed: float) -> UDSResponse:
        """Parse raw CAN response bytes into UDSResponse."""
        if not response_bytes:
            return self._timeout_response(request_bytes, service_id,
                                           time.time() - elapsed)

        is_positive = (len(response_bytes) >= 1 and
                       response_bytes[0] == service_id + POSITIVE_RESPONSE_OFFSET)

        nrc_code = None
        nrc_name = None

        if (len(response_bytes) >= 3 and response_bytes[0] == 0x7F):
            nrc_code = response_bytes[2]
            nrc_name = NRC.get(nrc_code, "unknown")

        return UDSResponse(
            request_bytes   = request_bytes,
            response_bytes  = response_bytes,
            is_positive     = is_positive,
            service_id      = service_id,
            nrc_code        = nrc_code,
            nrc_name        = nrc_name,
            response_time_s = elapsed,
            timed_out       = False,
        )

    def _timeout_response(self, request_bytes: bytes,
                           service_id: int, t_start: float) -> UDSResponse:
        return UDSResponse(
            request_bytes   = request_bytes,
            response_bytes  = None,
            is_positive     = False,
            service_id      = service_id,
            nrc_code        = None,
            nrc_name        = "TIMEOUT",
            response_time_s = time.time() - t_start,
            timed_out       = True,
        )

    @property
    def request_count(self) -> int:
        return self._request_count
