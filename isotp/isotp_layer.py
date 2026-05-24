"""
isotp/isotp_layer.py
=====================
ISO 15765-2 (ISO-TP) Transport Protocol implementation.

Sits between raw CAN and UDS — handles segmentation and reassembly
of UDS messages longer than 8 bytes.

Frame Types (ISO 15765-2 §9):
  Single Frame      (SF) — PCI nibble 0x0 — full message in one frame (≤7 bytes)
  First Frame       (FF) — PCI nibble 0x1 — start of multi-frame message
  Consecutive Frame (CF) — PCI nibble 0x2 — continuation data
  Flow Control      (FC) — PCI nibble 0x3 — receiver controls sender pace

Real-world use:
  - VIN read response    = 20 bytes → needs FF + CF
  - DTC list response    = variable → needs FF + multiple CFs
  - Firmware download    = kilobytes → needs FF + many CFs + multiple FC
  - Short NRC response   = 3 bytes  → single frame

ISO/SAE 21434 relevance:
  ISO-TP is an attack surface — malformed FF lengths, missing FC,
  CF out of sequence are all valid fuzz vectors for ECU robustness testing.
"""

import can
import time
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from config import CAN_BITRATE, ECU_TX_ID, ECU_RX_ID, BUS_TIMEOUT

log = logging.getLogger("ISO-TP")


# ── Frame Type Constants (ISO 15765-2 §9.6) ───────────────────────────────────

class FrameType(IntEnum):
    SINGLE_FRAME      = 0x0
    FIRST_FRAME       = 0x1
    CONSECUTIVE_FRAME = 0x2
    FLOW_CONTROL      = 0x3


class FlowStatus(IntEnum):
    CONTINUE_TO_SEND = 0x0   # CTS — sender may continue
    WAIT             = 0x1   # WT  — sender must wait
    OVERFLOW         = 0x2   # OVFLW — sender must abort


# ── ISO-TP Timing Parameters (ISO 15765-2 §6.6) ──────────────────────────────

N_As  = 0.025   # 25ms  — time to transmit a CAN frame
N_Bs  = 0.075   # 75ms  — time between FF and FC
N_Cs  = 0.010   # 10ms  — time between FC and first CF
N_Cr  = 0.150   # 150ms — time between consecutive frames

# Separation time between consecutive frames (STmin)
STMIN_DEFAULT = 0x00   # 0ms — send as fast as possible
BLOCK_SIZE    = 0x00   # 0 = send all CFs without intermediate FC


# ── Frame Builders ────────────────────────────────────────────────────────────

def build_single_frame(data: bytes) -> bytes:
    """
    Build a Single Frame (SF).
    Format: [0x0N | data...]
    where N = data length (0-7)

    Used when: total UDS payload ≤ 7 bytes
    """
    assert 1 <= len(data) <= 7, f"SF data must be 1-7 bytes, got {len(data)}"
    pci = (FrameType.SINGLE_FRAME << 4) | (len(data) & 0x0F)
    frame = bytes([pci]) + data
    # Pad to 8 bytes with 0xCC (ISO-TP padding byte)
    return frame + bytes([0xCC] * (8 - len(frame)))


def build_first_frame(data: bytes, total_length: int) -> bytes:
    """
    Build a First Frame (FF).
    Format: [0x1H 0xLL | first 6 bytes of data]
    where H:LL = 12-bit total message length

    Used when: total UDS payload > 7 bytes
    Carries first 6 bytes of data.
    """
    assert total_length <= 0xFFF, \
        f"Standard ISO-TP max length is 4095 bytes, got {total_length}"
    pci_high = (FrameType.FIRST_FRAME << 4) | ((total_length >> 8) & 0x0F)
    pci_low  = total_length & 0xFF
    return bytes([pci_high, pci_low]) + data[:6]


def build_consecutive_frame(sequence_number: int, data: bytes) -> bytes:
    """
    Build a Consecutive Frame (CF).
    Format: [0x2N | data...]
    where N = sequence number (1-F, wraps around)

    Carries 7 bytes of data per frame.
    """
    sn  = sequence_number & 0x0F   # 4-bit sequence number, wraps 0xF → 0x0
    pci = (FrameType.CONSECUTIVE_FRAME << 4) | sn
    frame = bytes([pci]) + data[:7]
    # Pad last frame with 0xCC if needed
    return frame + bytes([0xCC] * (8 - len(frame)))


def build_flow_control(flow_status: FlowStatus = FlowStatus.CONTINUE_TO_SEND,
                        block_size: int = BLOCK_SIZE,
                        stmin: int = STMIN_DEFAULT) -> bytes:
    """
    Build a Flow Control (FC) frame.
    Format: [0x3S BS STmin 0xCC 0xCC 0xCC 0xCC 0xCC]
    where S = flow status, BS = block size, STmin = separation time

    Sent by receiver after getting First Frame.
    Tells sender: go ahead (CTS), wait (WT), or abort (OVFLW).
    """
    pci = (FrameType.FLOW_CONTROL << 4) | (flow_status & 0x0F)
    return bytes([pci, block_size & 0xFF, stmin & 0xFF,
                  0xCC, 0xCC, 0xCC, 0xCC, 0xCC])


# ── Frame Parser ──────────────────────────────────────────────────────────────

@dataclass
class ParsedFrame:
    """Result of parsing a raw CAN frame."""
    frame_type:    FrameType
    # Single Frame
    sf_length:     int   = 0
    sf_data:       bytes = b''
    # First Frame
    ff_length:     int   = 0
    ff_data:       bytes = b''
    # Consecutive Frame
    cf_sn:         int   = 0
    cf_data:       bytes = b''
    # Flow Control
    fc_status:     int   = 0
    fc_block_size: int   = 0
    fc_stmin:      int   = 0


def parse_frame(raw: bytes) -> ParsedFrame | None:
    """
    Parse raw CAN frame bytes into a ParsedFrame.
    Returns None if frame is malformed.
    """
    if not raw or len(raw) < 1:
        return None

    frame_type = (raw[0] >> 4) & 0x0F

    if frame_type == FrameType.SINGLE_FRAME:
        length = raw[0] & 0x0F
        if length == 0 or length > 7 or len(raw) < length + 1:
            log.debug(f"Malformed SF: length={length} raw={raw.hex()}")
            return None
        return ParsedFrame(
            frame_type = FrameType.SINGLE_FRAME,
            sf_length  = length,
            sf_data    = raw[1:1 + length],
        )

    elif frame_type == FrameType.FIRST_FRAME:
        if len(raw) < 8:
            return None
        ff_length = ((raw[0] & 0x0F) << 8) | raw[1]
        return ParsedFrame(
            frame_type = FrameType.FIRST_FRAME,
            ff_length  = ff_length,
            ff_data    = raw[2:8],   # First 6 bytes of data
        )

    elif frame_type == FrameType.CONSECUTIVE_FRAME:
        sn = raw[0] & 0x0F
        return ParsedFrame(
            frame_type = FrameType.CONSECUTIVE_FRAME,
            cf_sn      = sn,
            cf_data    = raw[1:8],   # Up to 7 bytes of data
        )

    elif frame_type == FrameType.FLOW_CONTROL:
        if len(raw) < 3:
            return None
        return ParsedFrame(
            frame_type    = FrameType.FLOW_CONTROL,
            fc_status     = raw[0] & 0x0F,
            fc_block_size = raw[1],
            fc_stmin      = raw[2],
        )

    return None


# ── ISO-TP Sender ─────────────────────────────────────────────────────────────

class ISOTPSender:
    """
    Sends UDS messages using ISO-TP segmentation.
    Handles SF for short messages, FF+CF+FC for long messages.
    """

    def __init__(self, bus: can.BusABC, tx_id: int, rx_id: int,
                 timeout: float = BUS_TIMEOUT):
        self.bus     = bus
        self.tx_id   = tx_id
        self.rx_id   = rx_id
        self.timeout = timeout

    def send(self, data: bytes) -> bool:
        """
        Send a UDS message using ISO-TP.
        Automatically chooses SF or FF+CF based on length.

        Returns True if sent successfully.
        """
        if len(data) <= 7:
            return self._send_single_frame(data)
        else:
            return self._send_multi_frame(data)

    def _send_single_frame(self, data: bytes) -> bool:
        """Send as Single Frame — message fits in one CAN frame."""
        frame = build_single_frame(data)
        log.debug(f"TX SF: {frame.hex().upper()}")
        return self._send_can(frame)

    def _send_multi_frame(self, data: bytes) -> bool:
        """
        Send as multi-frame: FF → wait for FC → send CFs.
        """
        total_length = len(data)

        # Send First Frame
        ff = build_first_frame(data, total_length)
        log.debug(f"TX FF: {ff.hex().upper()} (total={total_length} bytes)")
        if not self._send_can(ff):
            return False

        # Wait for Flow Control from receiver
        fc_frame = self._wait_for_flow_control()
        if fc_frame is None:
            log.error("No Flow Control received after FF")
            return False

        if fc_frame.fc_status == FlowStatus.OVERFLOW:
            log.error("Receiver sent OVERFLOW — aborting")
            return False

        if fc_frame.fc_status == FlowStatus.WAIT:
            # Wait and retry FC — simplified: wait N_Bs then check again
            time.sleep(N_Bs)
            fc_frame = self._wait_for_flow_control()
            if fc_frame is None:
                return False

        # Send Consecutive Frames
        stmin     = self._parse_stmin(fc_frame.fc_stmin)
        remaining = data[6:]   # First 6 bytes already sent in FF
        sn        = 1          # Sequence number starts at 1

        while remaining:
            chunk     = remaining[:7]
            remaining = remaining[7:]
            cf        = build_consecutive_frame(sn, chunk)
            log.debug(f"TX CF[{sn}]: {cf.hex().upper()}")
            if not self._send_can(cf):
                return False
            sn = (sn + 1) & 0x0F   # Wrap at 0xF back to 0x0
            if stmin > 0:
                time.sleep(stmin)

        return True

    def _wait_for_flow_control(self) -> ParsedFrame | None:
        """Wait for a Flow Control frame from the receiver."""
        deadline = time.time() + N_Bs
        while time.time() < deadline:
            msg = self.bus.recv(timeout=N_Bs)
            if msg and msg.arbitration_id == self.rx_id:
                parsed = parse_frame(bytes(msg.data))
                if parsed and parsed.frame_type == FrameType.FLOW_CONTROL:
                    log.debug(f"RX FC: status={parsed.fc_status} "
                              f"bs={parsed.fc_block_size} "
                              f"stmin={parsed.fc_stmin}")
                    return parsed
        return None

    def _parse_stmin(self, stmin_byte: int) -> float:
        """
        Convert STmin byte to seconds.
        0x00-0x7F: 0-127ms
        0xF1-0xF9: 100-900 microseconds
        """
        if stmin_byte <= 0x7F:
            return stmin_byte / 1000.0      # milliseconds → seconds
        elif 0xF1 <= stmin_byte <= 0xF9:
            return (stmin_byte - 0xF0) / 10000.0  # 100μs units
        return 0.0

    def _send_can(self, data: bytes) -> bool:
        """Send raw CAN frame."""
        try:
            msg = can.Message(
                arbitration_id = self.tx_id,
                data           = data[:8],
                is_extended_id = False,
            )
            self.bus.send(msg)
            return True
        except can.CanError as e:
            log.error(f"CAN send error: {e}")
            return False


# ── ISO-TP Receiver ───────────────────────────────────────────────────────────

class ISOTPReceiver:
    """
    Receives and reassembles UDS messages using ISO-TP.
    Handles SF (direct) and FF+CF sequences (with FC acknowledgement).
    """

    def __init__(self, bus: can.BusABC, tx_id: int, rx_id: int,
                 timeout: float = BUS_TIMEOUT):
        self.bus     = bus
        self.tx_id   = tx_id   # We send FC on this ID
        self.rx_id   = rx_id   # We receive on this ID
        self.timeout = timeout

    def receive(self) -> bytes | None:
        """
        Wait for and reassemble a complete UDS message.
        Handles both single-frame and multi-frame transparently.

        Returns complete UDS payload bytes, or None on timeout/error.
        """
        deadline = time.time() + self.timeout

        while time.time() < deadline:
            msg = self.bus.recv(timeout=deadline - time.time())
            if not msg or msg.arbitration_id != self.rx_id:
                continue

            parsed = parse_frame(bytes(msg.data))
            if parsed is None:
                log.debug(f"Malformed frame: {bytes(msg.data).hex()}")
                continue

            if parsed.frame_type == FrameType.SINGLE_FRAME:
                log.debug(f"RX SF: {parsed.sf_data.hex().upper()}")
                return parsed.sf_data

            elif parsed.frame_type == FrameType.FIRST_FRAME:
                return self._receive_multi_frame(parsed)

            # Ignore CF and FC that arrive without a prior FF
            # (may be from previous incomplete session)

        log.debug("Receive timeout")
        return None

    def _receive_multi_frame(self, ff: ParsedFrame) -> bytes | None:
        """
        Receive and reassemble a multi-frame message.
        Called after receiving the First Frame.
        """
        total_length = ff.ff_length
        assembled    = bytearray(ff.ff_data)
        expected_sn  = 1

        log.debug(f"RX FF: total={total_length} bytes, "
                  f"first 6: {ff.ff_data.hex().upper()}")

        # Send Flow Control — CTS (Continue To Send)
        fc = build_flow_control(
            flow_status = FlowStatus.CONTINUE_TO_SEND,
            block_size  = BLOCK_SIZE,
            stmin       = STMIN_DEFAULT,
        )
        self._send_can(fc)
        log.debug(f"TX FC: {fc.hex().upper()}")

        # Receive Consecutive Frames until we have all data
        deadline = time.time() + N_Cr * 10   # Allow time for all CFs

        while len(assembled) < total_length:
            if time.time() > deadline:
                log.error("Timeout waiting for consecutive frames")
                return None

            msg = self.bus.recv(timeout=N_Cr)
            if not msg or msg.arbitration_id != self.rx_id:
                continue

            parsed = parse_frame(bytes(msg.data))
            if not parsed:
                continue

            if parsed.frame_type != FrameType.CONSECUTIVE_FRAME:
                log.warning(f"Expected CF, got frame type {parsed.frame_type}")
                continue

            # Sequence number check
            if parsed.cf_sn != expected_sn:
                log.error(f"Wrong CF sequence: expected {expected_sn}, "
                          f"got {parsed.cf_sn}")
                return None

            assembled.extend(parsed.cf_data)
            expected_sn = (expected_sn + 1) & 0x0F
            log.debug(f"RX CF[{parsed.cf_sn}]: "
                      f"{parsed.cf_data.hex().upper()} "
                      f"({len(assembled)}/{total_length} bytes)")

        # Trim to exact length (last CF may have padding)
        result = bytes(assembled[:total_length])
        log.debug(f"Reassembled: {result.hex().upper()}")
        return result

    def _send_can(self, data: bytes):
        """Send raw CAN frame (for Flow Control)."""
        try:
            msg = can.Message(
                arbitration_id = self.tx_id,
                data           = data[:8],
                is_extended_id = False,
            )
            self.bus.send(msg)
        except can.CanError as e:
            log.error(f"FC send error: {e}")


# ── ISO-TP Stack (Sender + Receiver combined) ─────────────────────────────────

class ISOTPStack:
    """
    Combined ISO-TP stack — use this in both ECU and client.
    Wraps sender and receiver into one clean interface.

    Usage:
        stack = ISOTPStack(bus, tx_id=ECU_TX_ID, rx_id=ECU_RX_ID)
        stack.send(uds_payload)
        data = stack.receive()
    """

    def __init__(self, bus: can.BusABC, tx_id: int, rx_id: int,
                 timeout: float = BUS_TIMEOUT):
        self.sender   = ISOTPSender(bus, tx_id, rx_id, timeout)
        self.receiver = ISOTPReceiver(bus, tx_id, rx_id, timeout)

    def send(self, data: bytes) -> bool:
        return self.sender.send(data)

    def receive(self) -> bytes | None:
        return self.receiver.receive()

    def send_and_receive(self, data: bytes) -> bytes | None:
        """Send request and wait for response."""
        if not self.sender.send(data):
            return None
        return self.receiver.receive()
