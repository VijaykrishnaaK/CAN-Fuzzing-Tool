"""
autosar/dcm_mapping.py
=======================
AUTOSAR DCM (Diagnostic Communication Manager) mapping layer.

Maps UDS service IDs and findings to the corresponding
AUTOSAR BSW (Basic Software) module, function, and configuration.

Why this matters:
  Real ECUs don't implement UDS from scratch — they use AUTOSAR DCM.
  When a security team at BMW or Bosch finds a vulnerability,
  they need to know WHICH AUTOSAR module and configuration to fix.

  Without this mapping:
    "SID 0x27 Security Access brute force possible"

  With this mapping:
    "SID 0x27 → Dcm_SecurityAccess() → DcmDspSecurityLevel →
     Fix: DcmDspSecurityNumAttDelay = 10000ms,
          DcmDspSecurityMaxNumAttProt = 3"

  The second version is what an OEM engineer can action immediately.

AUTOSAR DCM References:
  AUTOSAR_SWS_DiagnosticCommunicationManager.pdf (free at autosar.org)
  AUTOSAR Classic Platform R23-11

Structure of AUTOSAR DCM:
  DCM module contains:
    DSP — Diagnostic Service Processing (handles UDS service logic)
    DSD — Diagnostic Service Dispatcher (routes requests)
    DSL — Diagnostic Session Layer (manages sessions/timing)

  Each UDS service maps to a DSP sub-module:
    0x10 → Dcm_DiagnosticSessionControl → DcmDspSession
    0x27 → Dcm_SecurityAccess          → DcmDspSecurity
    0x2E → Dcm_WriteDataByIdentifier   → DcmDspData
    etc.
"""

from dataclasses import dataclass
from config import *


# ── AUTOSAR DCM Function Mapping ──────────────────────────────────────────────

@dataclass
class DCMServiceMapping:
    """Maps a UDS service to its AUTOSAR DCM implementation."""
    service_id:        int
    service_name:      str         # UDS service name
    dcm_function:      str         # AUTOSAR function name
    dcm_module:        str         # DSP / DSD / DSL
    config_container:  str         # AUTOSAR configuration container
    key_config_params: list[str]   # Critical config parameters
    security_params:   list[str]   # Security-relevant parameters
    callback_function: str         # Application callback (OEM implements this)
    iso_ref:           str         # ISO 14229-1 reference
    vulnerability_note:str         # Common misconfiguration


# Complete AUTOSAR DCM mapping for all UDS services we fuzz
DCM_MAPPING: dict[int, DCMServiceMapping] = {

    SID_DSC: DCMServiceMapping(
        service_id        = SID_DSC,
        service_name      = "DiagnosticSessionControl",
        dcm_function      = "Dcm_DiagnosticSessionControl()",
        dcm_module        = "DSP",
        config_container  = "DcmDspSession",
        key_config_params = [
            "DcmDspSessionLevel — session type (default/extended/programming)",
            "DcmDspSessionP2ServerMax — max response time",
            "DcmDspSessionP2StarServerMax — enhanced response time",
        ],
        security_params   = [
            "DcmDspSessionAuthorizationRef — which sessions require auth",
            "DcmDspSessionSecurityLevelRef — required SA level per session",
        ],
        callback_function = "Dcm_SesCtrlChangeIndication() — OEM callback on session change",
        iso_ref           = "ISO 14229-1 §9.2 — Session control",
        vulnerability_note= (
            "Misconfiguration: DcmDspSessionSecurityLevelRef not set "
            "→ programming session accessible without SA"
        ),
    ),

    SID_ER: DCMServiceMapping(
        service_id        = SID_ER,
        service_name      = "ECUReset",
        dcm_function      = "Dcm_ResetECU()",
        dcm_module        = "DSP",
        config_container  = "DcmDspReset",
        key_config_params = [
            "DcmDspResetType — hard/keyOffOnReset/softReset",
            "DcmDspResetSessionRef — which session allows reset",
        ],
        security_params   = [
            "DcmDspResetSecurityLevelRef — SA level required for reset",
        ],
        callback_function = "Dcm_ResetIndication() — triggers EcuM reset sequence",
        iso_ref           = "ISO 14229-1 §9.3 — ECU Reset",
        vulnerability_note= (
            "Misconfiguration: Hard reset (0x01) allowed in default session "
            "→ attacker can reset ECU without authentication"
        ),
    ),

    SID_SA: DCMServiceMapping(
        service_id        = SID_SA,
        service_name      = "SecurityAccess",
        dcm_function      = "Dcm_SecurityAccess()",
        dcm_module        = "DSP",
        config_container  = "DcmDspSecurity",
        key_config_params = [
            "DcmDspSecurityLevel — SA level number (0x01, 0x03, etc.)",
            "DcmDspSecuritySeedSize — seed length in bytes (recommend ≥8)",
            "DcmDspSecurityKeySize — key length in bytes",
            "DcmDspSecurityNumAttDelay — lockout duration in ms",
            "DcmDspSecurityMaxNumAttProt — max wrong attempts before lockout",
            "DcmDspSecurityDelayTimeOnBoot — post-boot SA delay",
        ],
        security_params   = [
            "DcmDspSecurityADRSize — additional data for CMAC (if SecOC)",
            "DcmDspSecurityUsePort — TRUE: use SeedKey port interface",
            "DcmDspSecuritySeedRandomize — TRUE: use RNG for seed",
        ],
        callback_function = (
            "Dcm_GetSeed() — OEM implements seed generation (MUST use HSM)\n"
            "Dcm_CompareKey() — OEM implements key validation (MUST be constant-time)"
        ),
        iso_ref           = "ISO 14229-1 §10.4 — Security Access",
        vulnerability_note= (
            "Critical misconfigs:\n"
            "  1. DcmDspSecurityMaxNumAttProt=0 → no lockout → brute force possible\n"
            "  2. Dcm_GetSeed() uses timestamp → predictable seed → key derivable\n"
            "  3. Dcm_CompareKey() uses memcmp() → timing oracle attack possible\n"
            "  4. DcmDspSecurityDelayTimeOnBoot=0 → no post-boot delay → race window"
        ),
    ),

    SID_CC: DCMServiceMapping(
        service_id        = SID_CC,
        service_name      = "CommunicationControl",
        dcm_function      = "Dcm_CommunicationControl()",
        dcm_module        = "DSP",
        config_container  = "DcmDspComControl",
        key_config_params = [
            "DcmDspComControlAllOrSpecific — control scope",
            "DcmDspComControlNetworkRef — which networks are controlled",
        ],
        security_params   = [
            "DcmDspComControlSessionRef — session required",
            "DcmDspComControlSecurityLevelRef — SA level required",
        ],
        callback_function = "ComM_DCM_ActiveDiagnostic() — notify ComM of diagnostic state",
        iso_ref           = "ISO 14229-1 §9.5 — Communication Control",
        vulnerability_note= (
            "Risk: If allowed in default session, attacker can disable "
            "normal CAN communication, causing other ECUs to fault"
        ),
    ),

    SID_RDBI: DCMServiceMapping(
        service_id        = SID_RDBI,
        service_name      = "ReadDataByIdentifier",
        dcm_function      = "Dcm_ReadDataByIdentifier()",
        dcm_module        = "DSP",
        config_container  = "DcmDspData / DcmDspDataInfo",
        key_config_params = [
            "DcmDspDataIdentifier — DID value (0x0000-0xFFFF)",
            "DcmDspDataReadFnc — function to call when DID is read",
            "DcmDspDataConditionCheckReadFnc — pre-condition check",
            "DcmDspDataUsePort — TRUE: use port interface",
        ],
        security_params   = [
            "DcmDspDataReadSessionRef — sessions that can read this DID",
            "DcmDspDataReadSecurityLevelRef — SA level needed to read",
        ],
        callback_function = "App_ReadDID_0xF190() — OEM function per DID",
        iso_ref           = "ISO 14229-1 §9.6 — Read Data By Identifier",
        vulnerability_note= (
            "DID enumeration: If DID not found returns different NRC than "
            "'not authorized' → attacker maps all valid DIDs without auth"
        ),
    ),

    SID_WDBI: DCMServiceMapping(
        service_id        = SID_WDBI,
        service_name      = "WriteDataByIdentifier",
        dcm_function      = "Dcm_WriteDataByIdentifier()",
        dcm_module        = "DSP",
        config_container  = "DcmDspData / DcmDspDataInfo",
        key_config_params = [
            "DcmDspDataIdentifier — DID value",
            "DcmDspDataWriteFnc — function to call when DID is written",
            "DcmDspDataConditionCheckWriteFnc — write pre-condition",
        ],
        security_params   = [
            "DcmDspDataWriteSessionRef — sessions that allow write",
            "DcmDspDataWriteSecurityLevelRef — SA level needed to write",
        ],
        callback_function = "App_WriteDID_0x0200() — OEM validates + stores data",
        iso_ref           = "ISO 14229-1 §9.7 — Write Data By Identifier",
        vulnerability_note= (
            "Critical: DcmDspDataWriteSecurityLevelRef not configured "
            "→ calibration data writable without SA → safety impact"
        ),
    ),

    SID_RC: DCMServiceMapping(
        service_id        = SID_RC,
        service_name      = "RoutineControl",
        dcm_function      = "Dcm_RoutineControl()",
        dcm_module        = "DSP",
        config_container  = "DcmDspRoutine",
        key_config_params = [
            "DcmDspRoutineIdentifier — routine ID (e.g. 0xFF00 = EraseMemory)",
            "DcmDspStartRoutineFnc — function called on start",
            "DcmDspStopRoutineFnc — function called on stop",
            "DcmDspRequestResultsRoutineFnc — results function",
        ],
        security_params   = [
            "DcmDspRoutineSessionRef — allowed sessions",
            "DcmDspRoutineSecurityLevelRef — required SA level",
        ],
        callback_function = "App_StartRoutine_0xFF00() — OEM routine implementation",
        iso_ref           = "ISO 14229-1 §9.9 — Routine Control",
        vulnerability_note= (
            "DcmDspRoutineSecurityLevelRef=0 (no SA required) for erase/program "
            "routines → firmware erasure without authentication"
        ),
    ),

    SID_RDTC: DCMServiceMapping(
        service_id        = SID_RDTC,
        service_name      = "ReadDTCInformation",
        dcm_function      = "Dcm_ReadDtcInformation()",
        dcm_module        = "DSP",
        config_container  = "DcmDspReadDtcInformation",
        key_config_params = [
            "DcmDspSupportedDTCRef — DTC groups supported",
            "DcmDemClientRef — which Dem client to use",
        ],
        security_params   = [
            "DcmDspReadDTCSessionRef — sessions that can read DTCs",
        ],
        callback_function = "Dem_GetDTCStatusAvailabilityMask() — get DTC status",
        iso_ref           = "ISO 14229-1 §9.10 — Read DTC Information",
        vulnerability_note= (
            "DTC data can reveal internal ECU state — fault history, "
            "operating conditions. Restrict to extended session minimum."
        ),
    ),

    SID_RMBA: DCMServiceMapping(
        service_id        = SID_RMBA,
        service_name      = "ReadMemoryByAddress",
        dcm_function      = "Dcm_ReadMemoryByAddress()",
        dcm_module        = "DSP",
        config_container  = "DcmDspMemory / DcmDspReadMemoryRange",
        key_config_params = [
            "DcmDspReadMemoryRangeHigh — max allowed read address",
            "DcmDspReadMemoryRangeLow — min allowed read address",
            "DcmDspReadMemoryRangeInfo — address format identifier",
        ],
        security_params   = [
            "DcmDspReadMemoryRangeSessionRef — allowed sessions",
            "DcmDspReadMemoryRangeSecurityLevelRef — required SA level",
        ],
        callback_function = "Dcm_ReadMemory() — OEM validates address range",
        iso_ref           = "ISO 14229-1 §9.12 — Read Memory By Address",
        vulnerability_note= (
            "Address range not restricted → attacker reads calibration data, "
            "cryptographic keys, or seed generation algorithm from RAM/Flash"
        ),
    ),
}


# ── AUTOSAR Security Architecture Notes ──────────────────────────────────────

AUTOSAR_SECURITY_NOTES = {
    "SecOC": {
        "full_name": "Secure Onboard Communication",
        "module":    "AUTOSAR SecOC (AUTOSAR_SWS_SecureOnboardCommunication)",
        "what_it_does": (
            "Adds MAC (Message Authentication Code) to CAN/Ethernet messages. "
            "Prevents message injection — each frame is authenticated with "
            "a shared key and freshness counter. "
            "Countermeasure for CAN injection attacks your fuzzer simulates."
        ),
        "dcm_interaction": (
            "SecOC keys provisioned via DCM SID 0x2E (WDBI) in programming session. "
            "Key provisioning requires SA 0x27 unlock + programming session."
        ),
        "config": "SecOCTxPduProcessing, SecOCRxPduProcessing, SecOCFreshnessValueId",
    },
    "CryIf": {
        "full_name": "Crypto Interface",
        "module":    "AUTOSAR CryIf + Crypto Driver",
        "what_it_does": (
            "Abstraction layer between DCM/SecOC and hardware crypto (HSM). "
            "Dcm_GetSeed() should call CryIf_RandomGenerate() → HSM RNG "
            "instead of software RNG → prevents predictable seeds."
        ),
        "dcm_interaction": "Called by Dcm_GetSeed() for secure seed generation",
        "config": "CryIfKey, CryIfKeyElement, CryIfChannel",
    },
    "HSM": {
        "full_name": "Hardware Security Module",
        "module":    "SHE (Secure Hardware Extension) or SHE+",
        "what_it_does": (
            "Dedicated security processor on the MCU. "
            "Stores cryptographic keys in hardware — cannot be read via software. "
            "Performs AES encryption, MAC generation, RNG in hardware. "
            "Dcm_CompareKey() using HSM is constant-time by hardware design → "
            "eliminates timing oracle vulnerability."
        ),
        "dcm_interaction": (
            "Dcm_GetSeed() → CryIf → HSM RNG\n"
            "Dcm_CompareKey() → CryIf → HSM AES-CMAC verify"
        ),
        "config": "HsmKeySlot, HsmKeyId, HsmChannel",
    },
}


# ── Mapping Engine ────────────────────────────────────────────────────────────

class AutosarDCMMapper:
    """
    Annotates fuzzer findings with AUTOSAR DCM context.
    Adds actionable fix information that OEM engineers can use directly.
    """

    def annotate_finding(self, service_id: int, finding_description: str,
                          finding_category: str) -> dict:
        """
        Annotate a fuzzer finding with AUTOSAR DCM context.

        Args:
            service_id:           UDS SID that triggered the finding
            finding_description:  Human-readable finding description
            finding_category:     Category from anomaly detector

        Returns:
            dict with full AUTOSAR context
        """
        mapping = DCM_MAPPING.get(service_id)

        if not mapping:
            return {
                "autosar_mapped": False,
                "service_id":     f"0x{service_id:02X}",
                "note":           "No AUTOSAR DCM mapping for this service",
            }

        # Select relevant security params based on finding
        relevant_params = self._get_relevant_params(mapping, finding_category)

        return {
            "autosar_mapped":    True,
            "service_id":        f"0x{service_id:02X}",
            "service_name":      mapping.service_name,
            "dcm_function":      mapping.dcm_function,
            "dcm_module":        f"AUTOSAR DCM — {mapping.dcm_module}",
            "config_container":  mapping.config_container,
            "relevant_config":   relevant_params,
            "callback_function": mapping.callback_function,
            "iso_ref":           mapping.iso_ref,
            "known_misconfiguration": mapping.vulnerability_note,
            "fix_guidance":      self._get_fix_guidance(mapping, finding_category),
        }

    def annotate_vulnerability_report(self, vulnerabilities: list) -> list:
        """Add AUTOSAR context to all vulnerabilities in a report."""
        annotated = []
        for vuln in vulnerabilities:
            sid = self._extract_sid(vuln.get("affected_service", ""))
            if sid:
                autosar = self.annotate_finding(
                    sid,
                    vuln.get("description", ""),
                    vuln.get("category", ""),
                )
                vuln["autosar_context"] = autosar
            annotated.append(vuln)
        return annotated

    def generate_dcm_summary(self) -> str:
        """Generate a Markdown table of all UDS→AUTOSAR mappings."""
        lines = [
            "## AUTOSAR DCM Service Mapping",
            "",
            "| UDS SID | Service Name | AUTOSAR Function | Config Container |",
            "|---------|-------------|-----------------|-----------------|",
        ]
        for sid, mapping in DCM_MAPPING.items():
            lines.append(
                f"| 0x{sid:02X} | {mapping.service_name} | "
                f"`{mapping.dcm_function}` | `{mapping.config_container}` |"
            )
        lines += [
            "",
            "## AUTOSAR Security Architecture",
            "",
        ]
        for component, info in AUTOSAR_SECURITY_NOTES.items():
            lines += [
                f"### {component} — {info['full_name']}",
                f"**Module**: `{info['module']}`",
                f"",
                f"{info['what_it_does']}",
                f"",
                f"**DCM Interaction**: {info['dcm_interaction']}",
                f"",
                f"**Key Config**: `{info['config']}`",
                f"",
            ]
        return "\n".join(lines)

    def _get_relevant_params(self, mapping: DCMServiceMapping,
                              category: str) -> list[str]:
        """Select the most relevant config params for this finding type."""
        if "brute_force" in category.lower() or "sa" in category.lower():
            return mapping.security_params + mapping.key_config_params[:2]
        elif "bypass" in category.lower() or "access" in category.lower():
            return mapping.security_params
        elif "session" in category.lower():
            return [p for p in mapping.key_config_params if "Session" in p]
        return mapping.key_config_params[:3]

    def _get_fix_guidance(self, mapping: DCMServiceMapping,
                           category: str) -> str:
        """Generate specific AUTOSAR fix guidance."""
        fixes = {
            "ACCESS_CONTROL_BYPASS": (
                f"Set {mapping.config_container}.DcmDspDataWriteSecurityLevelRef "
                f"to require SA level 0x01 minimum."
            ),
            "SA_BRUTE_FORCE": (
                "Set DcmDspSecurityMaxNumAttProt = 3 (max 3 attempts). "
                "Set DcmDspSecurityNumAttDelay = 10000 (10 second lockout). "
                "Set DcmDspSecurityDelayTimeOnBoot = 10000 (post-boot delay). "
                "Implement Dcm_GetSeed() using CryIf → HSM RNG."
            ),
            "SESSION_ESCALATION_BYPASS": (
                f"Set DcmDspSession[programming].DcmDspSessionSecurityLevelRef "
                f"to require SA level 0x01. "
                "Verify DcmDspSessionAuthorizationRef is configured."
            ),
            "TIMING_ORACLE": (
                "Implement Dcm_CompareKey() using HMAC via CryIf → HSM. "
                "HSM MAC verification is constant-time by hardware design. "
                "Never use memcmp() or byte-by-byte comparison for keys."
            ),
        }
        for key, fix in fixes.items():
            if key.lower() in category.lower():
                return fix
        return (
            f"Review {mapping.config_container} configuration. "
            f"Ensure {mapping.security_params[0] if mapping.security_params else 'security params'} "
            "are correctly set."
        )

    def _extract_sid(self, service_str: str) -> int | None:
        """Extract SID integer from strings like 'SID 0x27 — Security Access'."""
        import re
        match = re.search(r"0x([0-9A-Fa-f]{2})", service_str)
        if match:
            return int(match.group(1), 16)
        return None