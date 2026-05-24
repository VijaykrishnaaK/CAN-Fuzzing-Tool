"""
doip/doip_layer.py
===================
DoIP (Diagnostic over IP) — ISO 13400-2 implementation.

DoIP is the transport protocol that carries UDS over TCP/IP.
Modern vehicles (2020+) use Ethernet for diagnostics instead of CAN.

Architecture in a real vehicle:
  Diagnostic Tool (PC/Tester)
         ↓ TCP port 13400
  Vehicle Ethernet Gateway
         ↓ CAN/LIN/FlexRay
  Target ECU

DoIP message structure (ISO 13400-2 §7):
  [2B Protocol Version] [2B Inverse Version] [2B Payload Type]
  [4B Payload Length] [Payload...]

Payload Types (ISO 13400-2 Table 17):
  0x0000 — Generic DoIP header NACK
  0x0001 — Vehicle Identification Request
  0x0004 — Vehicle Announcement / Identification Response
  0x0005 — Routing Activation Request
  0x0006 — Routing Activation Response
  0x8001 — Diagnostic Message (carries UDS)
  0x8002 — Diagnostic Message Positive ACK
  0x8003 — Diagnostic Message Negative ACK

Why DoIP matters:
  CAN max speed: 1 Mbps (CAN FD: 8 Mbps)
  Ethernet speed: 100 Mbps / 1 Gbps
  Modern ADAS ECUs process camera/radar data — need high bandwidth
  DoIP enables high-speed diagnostics over existing Ethernet backbone

ISO/SAE 21434 relevance:
  DoIP is an attack surface — network-accessible diagnostic interface
  Threat: Remote diagnostic session from outside vehicle
  Asset: Diagnostic communication channel
  Clause 9 — Threat scenario: Remote UDS attack via DoIP
"""

import socket
import struct
import threading
import time
import logging
from dataclasses import dataclass
from config import *

log = logging.getLogger("DoIP")

# ── DoIP Constants (ISO 13400-2) ──────────────────────────────────────────────

DOIP_VERSION          = 0x02    # ISO 13400-2:2012
DOIP_INVERSE_VERSION  = 0xFD    # Bitwise inverse of version
DOIP_PORT             = 13400   # Standard DoIP TCP port (IANA assigned)
DOIP_HEADER_LENGTH    = 8       # Fixed header: 2+2+2+4 bytes

# Payload type codes
DOIP_GENERIC_NACK             = 0x0000
DOIP_VEHICLE_ID_REQUEST       = 0x0001
DOIP_VEHICLE_ANNOUNCEMENT     = 0x0004
DOIP_ROUTING_ACTIVATION_REQ   = 0x0005
DOIP_ROUTING_ACTIVATION_RESP  = 0x0006
DOIP_DIAGNOSTIC_MESSAGE       = 0x8001
DOIP_DIAGNOSTIC_POSITIVE_ACK  = 0x8002
DOIP_DIAGNOSTIC_NEGATIVE_ACK  = 0x8003

# Routing activation response codes
ROUTING_SUCCESS               = 0x10
ROUTING_DENIED_UNKNOWN_SOURCE = 0x00
ROUTING_DENIED_MAX_SOCKETS    = 0x01

# Diagnostic NACK codes
DIAG_NACK_INVALID_SOURCE      = 0x02
DIAG_NACK_UNKNOWN_TARGET      = 0x03
DIAG_NACK_MESSAGE_TOO_LARGE   = 0x04
DIAG_NACK_OUT_OF_MEMORY       = 0x05
DIAG_NACK_TARGET_UNREACHABLE  = 0x06

# Logical addresses (ISO 13400-2 §7.7)
TESTER_LOGICAL_ADDR           = 0x0E00   # External test tool
ECU_LOGICAL_ADDR              = 0x0E01   # Target ECU


# ── DoIP Frame Builder ────────────────────────────────────────────────────────

def build_doip_header(payload_type: int, payload: bytes) -> bytes:
    """
    Build DoIP header + payload.

    Header format (ISO 13400-2 §7.1):
      Byte 0:   Protocol version (0x02)
      Byte 1:   Inverse protocol version (0xFD)
      Byte 2-3: Payload type (big-endian)
      Byte 4-7: Payload length (big-endian, excludes header)
    """
    header = struct.pack(
        ">BBHI",
        DOIP_VERSION,
        DOIP_INVERSE_VERSION,
        payload_type,
        len(payload)
    )
    return header + payload


def build_routing_activation_request(source_addr: int = TESTER_LOGICAL_ADDR,
                                      activation_type: int = 0x00) -> bytes:
    """
    Build Routing Activation Request (0x0005).
    Must be sent before any diagnostic messages.
    Like a "handshake" — tester identifies itself to gateway.

    Format: [2B Source Address] [1B Activation Type] [4B Reserved]
    """
    payload = struct.pack(">HB4x", source_addr, activation_type)
    return build_doip_header(DOIP_ROUTING_ACTIVATION_REQ, payload)


def build_diagnostic_message(source_addr: int, target_addr: int,
                               uds_data: bytes) -> bytes:
    """
    Build DoIP Diagnostic Message (0x8001).
    This is how UDS travels over DoIP.

    Format: [2B Source Address] [2B Target Address] [UDS Data...]
    The UDS data is the complete UDS request (SID + payload).
    """
    payload = struct.pack(">HH", source_addr, target_addr) + uds_data
    return build_doip_header(DOIP_DIAGNOSTIC_MESSAGE, payload)


def build_vehicle_id_request() -> bytes:
    """
    Build Vehicle Identification Request (0x0001).
    Sent during discovery — ECU responds with VIN, logical address etc.
    Attack surface: unauthenticated discovery leaks vehicle identity.
    """
    return build_doip_header(DOIP_VEHICLE_ID_REQUEST, b'')


# ── DoIP Frame Parser ─────────────────────────────────────────────────────────

@dataclass
class DoIPFrame:
    """Parsed DoIP frame."""
    version:      int
    payload_type: int
    payload_len:  int
    payload:      bytes
    # Parsed fields (filled based on payload_type)
    source_addr:  int = 0
    target_addr:  int = 0
    uds_data:     bytes = b''
    nack_code:    int = 0
    routing_code: int = 0


def parse_doip_frame(data: bytes) -> DoIPFrame | None:
    """
    Parse raw bytes into a DoIPFrame.
    Returns None if data is malformed or incomplete.
    """
    if len(data) < DOIP_HEADER_LENGTH:
        return None

    version, inv_version, payload_type, payload_len = struct.unpack(
        ">BBHI", data[:DOIP_HEADER_LENGTH]
    )

    # Verify header integrity
    if version != DOIP_VERSION or inv_version != DOIP_INVERSE_VERSION:
        log.debug(f"Invalid DoIP version: {version:#04x}/{inv_version:#04x}")
        return None

    if len(data) < DOIP_HEADER_LENGTH + payload_len:
        log.debug("Incomplete DoIP frame")
        return None

    payload = data[DOIP_HEADER_LENGTH:DOIP_HEADER_LENGTH + payload_len]

    frame = DoIPFrame(
        version      = version,
        payload_type = payload_type,
        payload_len  = payload_len,
        payload      = payload,
    )

    # Parse payload fields based on type
    if payload_type == DOIP_ROUTING_ACTIVATION_RESP and len(payload) >= 6:
        frame.source_addr  = struct.unpack(">H", payload[0:2])[0]
        frame.routing_code = payload[5]

    elif payload_type == DOIP_DIAGNOSTIC_MESSAGE and len(payload) >= 4:
        frame.source_addr = struct.unpack(">H", payload[0:2])[0]
        frame.target_addr = struct.unpack(">H", payload[2:4])[0]
        frame.uds_data    = payload[4:]

    elif payload_type == DOIP_DIAGNOSTIC_POSITIVE_ACK and len(payload) >= 5:
        frame.source_addr = struct.unpack(">H", payload[0:2])[0]
        frame.target_addr = struct.unpack(">H", payload[2:4])[0]

    elif payload_type == DOIP_DIAGNOSTIC_NEGATIVE_ACK and len(payload) >= 5:
        frame.source_addr = struct.unpack(">H", payload[0:2])[0]
        frame.target_addr = struct.unpack(">H", payload[2:4])[0]
        frame.nack_code   = payload[4]

    elif payload_type == DOIP_GENERIC_NACK and len(payload) >= 1:
        frame.nack_code = payload[0]

    return frame


# ── DoIP ECU Server ───────────────────────────────────────────────────────────

class DoIPECUServer:
    """
    DoIP server that exposes UDS services over TCP/IP.
    Runs alongside the CAN/ISO-TP ECU server.

    The same UDS service handlers from VirtualECU are reused —
    only the transport layer changes (TCP instead of CAN).

    This mirrors real vehicle architecture where a gateway ECU
    accepts both CAN and Ethernet diagnostic connections.
    """

    def __init__(self, uds_handler, host: str = "127.0.0.1",
                 port: int = DOIP_PORT):
        """
        Args:
            uds_handler: Callable — takes UDS bytes, returns UDS response bytes
                         This is VirtualECU._handle_request_data()
            host:        IP to listen on
            port:        TCP port (default 13400)
        """
        self.uds_handler      = uds_handler
        self.host             = host
        self.port             = port
        self.server_socket    = None
        self.running          = False
        self._active_sessions: set[str] = set()   # Routing-activated clients
        self.stats = {
            "connections":      0,
            "routing_activated":0,
            "diag_messages":    0,
            "nacks_sent":       0,
        }

    def start(self):
        """Start DoIP server in background thread."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True

        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        log.info(f"DoIP server listening on {self.host}:{self.port}")

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()

    def _accept_loop(self):
        """Accept incoming TCP connections."""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                conn, addr = self.server_socket.accept()
                self.stats["connections"] += 1
                log.info(f"DoIP connection from {addr}")
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, conn: socket.socket, addr: tuple):
        """Handle a single DoIP client connection."""
        session_key    = f"{addr[0]}:{addr[1]}"
        routing_active = False

        try:
            conn.settimeout(BUS_TIMEOUT)
            while self.running:
                # Receive DoIP frame
                data = self._recv_frame(conn)
                if not data:
                    break

                frame = parse_doip_frame(data)
                if frame is None:
                    # Send generic NACK for malformed header
                    conn.send(build_doip_header(
                        DOIP_GENERIC_NACK, bytes([0x00])
                    ))
                    self.stats["nacks_sent"] += 1
                    continue

                # Handle frame by type
                if frame.payload_type == DOIP_VEHICLE_ID_REQUEST:
                    response = self._handle_vehicle_id()
                    conn.send(response)

                elif frame.payload_type == DOIP_ROUTING_ACTIVATION_REQ:
                    response, success = self._handle_routing_activation(frame)
                    conn.send(response)
                    if success:
                        routing_active = True
                        self._active_sessions.add(session_key)
                        self.stats["routing_activated"] += 1
                        log.info(f"  DoIP routing activated for {addr}")

                elif frame.payload_type == DOIP_DIAGNOSTIC_MESSAGE:
                    if not routing_active:
                        # Must activate routing first
                        nack = build_doip_header(
                            DOIP_DIAGNOSTIC_NEGATIVE_ACK,
                            struct.pack(">HHB",
                                        frame.target_addr,
                                        frame.source_addr,
                                        DIAG_NACK_INVALID_SOURCE)
                        )
                        conn.send(nack)
                        self.stats["nacks_sent"] += 1
                        continue

                    self.stats["diag_messages"] += 1
                    response = self._handle_diagnostic(frame, conn)
                    if response:
                        conn.send(response)

        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            pass
        finally:
            self._active_sessions.discard(session_key)
            conn.close()
            log.info(f"DoIP connection closed: {addr}")

    def _handle_vehicle_id(self) -> bytes:
        """
        Respond to Vehicle Identification Request.
        Returns VIN + logical address + EID.

        Security note: This is unauthenticated — any node on the
        network can discover the vehicle's VIN and ECU addresses.
        ISO/SAE 21434 threat: Information disclosure via DoIP discovery.
        """
        vin           = b'1HGBH41JXMN109186'  # 17-byte VIN
        logical_addr  = struct.pack(">H", ECU_LOGICAL_ADDR)
        eid           = b'\x00\x11\x22\x33\x44\x55'    # 6-byte EID
        gid           = b'\xFF\xFF\xFF\xFF\xFF\xFF'    # 6-byte GID
        further_action= b'\x00'                          # No further action

        payload = vin + logical_addr + eid + gid + further_action
        return build_doip_header(DOIP_VEHICLE_ANNOUNCEMENT, payload)

    def _handle_routing_activation(self, frame: DoIPFrame) -> tuple[bytes, bool]:
        """
        Handle Routing Activation Request.
        In a real gateway, this validates the tester's logical address
        and activation type. We implement basic validation.
        """
        # Build response: [2B Tester Addr] [2B ECU Addr] [1B Response Code] [4B Reserved]
        payload = struct.pack(
            ">HHB4x",
            frame.source_addr,
            ECU_LOGICAL_ADDR,
            ROUTING_SUCCESS,
        )
        return build_doip_header(DOIP_ROUTING_ACTIVATION_RESP, payload), True

    def _handle_diagnostic(self, frame: DoIPFrame,
                             conn: socket.socket) -> bytes | None:
        """
        Handle Diagnostic Message — pass UDS to handler, return response.

        Flow:
          1. Send Diagnostic Positive ACK (confirms receipt)
          2. Process UDS request
          3. Send Diagnostic Message with UDS response
        """
        if not frame.uds_data:
            return None

        log.info(f"  DoIP UDS RX: {frame.uds_data.hex().upper()}")

        # Step 1: Send positive ACK (confirms we received the message)
        ack_payload = struct.pack(
            ">HHB",
            frame.target_addr,
            frame.source_addr,
            0x00   # ACK code: correctly received
        )
        ack = build_doip_header(DOIP_DIAGNOSTIC_POSITIVE_ACK, ack_payload)
        conn.send(ack)

        # Step 2: Process UDS request through the same handler as CAN
        uds_response = self.uds_handler(frame.uds_data)
        if not uds_response:
            return None

        log.info(f"  DoIP UDS TX: {uds_response.hex().upper()}")

        # Step 3: Send UDS response wrapped in DoIP Diagnostic Message
        payload = struct.pack(
            ">HH",
            ECU_LOGICAL_ADDR,
            frame.source_addr,
        ) + uds_response
        return build_doip_header(DOIP_DIAGNOSTIC_MESSAGE, payload)

    def _recv_frame(self, conn: socket.socket) -> bytes | None:
        """Receive a complete DoIP frame from TCP stream."""
        try:
            # Read header first
            header = b''
            while len(header) < DOIP_HEADER_LENGTH:
                chunk = conn.recv(DOIP_HEADER_LENGTH - len(header))
                if not chunk:
                    return None
                header += chunk

            # Parse payload length from header
            payload_len = struct.unpack(">I", header[4:8])[0]

            # Sanity check — prevent memory exhaustion
            if payload_len > 65535:
                log.warning(f"DoIP payload too large: {payload_len}")
                return None

            # Read payload
            payload = b''
            while len(payload) < payload_len:
                chunk = conn.recv(payload_len - len(payload))
                if not chunk:
                    return None
                payload += chunk

            return header + payload

        except socket.timeout:
            return None


# ── DoIP Client ───────────────────────────────────────────────────────────────

class DoIPClient:
    """
    DoIP client — used by the fuzzer to send UDS over TCP/IP.
    Drop-in companion to UDSClient (which uses CAN/ISO-TP).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = DOIP_PORT,
                 timeout: float = BUS_TIMEOUT):
        self.host             = host
        self.port             = port
        self.timeout          = timeout
        self.sock             = None
        self.routing_active   = False
        self._request_count   = 0

    def connect(self) -> bool:
        """Connect and activate routing."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))

            # Send routing activation request
            req = build_routing_activation_request(TESTER_LOGICAL_ADDR)
            self.sock.send(req)

            # Wait for routing activation response
            data = self._recv_frame()
            if not data:
                return False

            frame = parse_doip_frame(data)
            if (frame and
                    frame.payload_type == DOIP_ROUTING_ACTIVATION_RESP and
                    frame.routing_code == ROUTING_SUCCESS):
                self.routing_active = True
                log.info(f"DoIP connected to {self.host}:{self.port}")
                return True

            return False

        except (ConnectionRefusedError, OSError) as e:
            log.error(f"DoIP connection failed: {e}")
            return False

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        self.routing_active = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    def send_uds(self, uds_data: bytes) -> bytes | None:
        """
        Send UDS request over DoIP, return UDS response.
        Handles: routing check, DoIP wrapping, ACK, response extraction.
        """
        if not self.routing_active or not self.sock:
            log.error("DoIP not connected or routing not activated")
            return None

        self._request_count += 1

        # Wrap UDS in DoIP diagnostic message
        msg = build_diagnostic_message(
            TESTER_LOGICAL_ADDR, ECU_LOGICAL_ADDR, uds_data
        )

        try:
            self.sock.send(msg)
        except OSError as e:
            log.error(f"DoIP send error: {e}")
            return None

        # Expect: Positive ACK + Diagnostic Message response
        deadline = time.time() + self.timeout
        uds_response = None

        while time.time() < deadline:
            data = self._recv_frame()
            if not data:
                break

            frame = parse_doip_frame(data)
            if not frame:
                continue

            if frame.payload_type == DOIP_DIAGNOSTIC_POSITIVE_ACK:
                continue  # Good — confirmed receipt, wait for response

            elif frame.payload_type == DOIP_DIAGNOSTIC_MESSAGE:
                uds_response = frame.uds_data
                break

            elif frame.payload_type == DOIP_DIAGNOSTIC_NEGATIVE_ACK:
                log.warning(f"DoIP NACK: code={frame.nack_code:#04x}")
                break

            elif frame.payload_type == DOIP_GENERIC_NACK:
                log.warning(f"DoIP generic NACK: code={frame.nack_code:#04x}")
                break

        return uds_response

    def discover_vehicle(self) -> dict | None:
        """
        Send Vehicle Identification Request.
        Returns vehicle info dict or None.

        This is unauthenticated — demonstrates information disclosure risk.
        """
        if not self.sock:
            return None

        try:
            self.sock.send(build_vehicle_id_request())
            data = self._recv_frame()
            if not data:
                return None

            frame = parse_doip_frame(data)
            if frame and frame.payload_type == DOIP_VEHICLE_ANNOUNCEMENT:
                payload = frame.payload
                if len(payload) >= 17:
                    return {
                        "vin":          payload[:17].decode("ascii", errors="replace"),
                        "logical_addr": f"0x{struct.unpack('>H', payload[17:19])[0]:04X}"
                                        if len(payload) >= 19 else "unknown",
                    }
        except OSError:
            pass
        return None

    def _recv_frame(self) -> bytes | None:
        """Receive a complete DoIP frame from TCP stream."""
        try:
            header = b''
            while len(header) < DOIP_HEADER_LENGTH:
                chunk = self.sock.recv(DOIP_HEADER_LENGTH - len(header))
                if not chunk:
                    return None
                header += chunk

            payload_len = struct.unpack(">I", header[4:8])[0]
            if payload_len > 65535:
                return None

            payload = b''
            while len(payload) < payload_len:
                chunk = self.sock.recv(payload_len - len(payload))
                if not chunk:
                    return None
                payload += chunk

            return header + payload

        except socket.timeout:
            return None

    @property
    def request_count(self) -> int:
        return self._request_count