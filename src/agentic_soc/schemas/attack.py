"""MITRE ATT&CK techniques used by the simulated campaign, detectors and the triage agent."""

from __future__ import annotations

import re
from dataclasses import dataclass

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactic: str


_CATALOG = [
    Technique("T1110.003", "Brute Force: Password Spraying", "credential-access"),
    Technique("T1078", "Valid Accounts", "initial-access"),
    Technique("T1133", "External Remote Services", "initial-access"),
    Technique("T1087.002", "Account Discovery: Domain Account", "discovery"),
    Technique("T1018", "Remote System Discovery", "discovery"),
    Technique("T1059.001", "Command and Scripting Interpreter: PowerShell", "execution"),
    Technique("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access"),
    Technique("T1021.001", "Remote Services: Remote Desktop Protocol", "lateral-movement"),
    Technique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement"),
    Technique("T1569.002", "System Services: Service Execution", "execution"),
    Technique("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control"),
    Technique("T1573", "Encrypted Channel", "command-and-control"),
    Technique("T1560.001", "Archive Collected Data: Archive via Utility", "collection"),
    Technique("T1218.011", "System Binary Proxy Execution: Rundll32", "defense-evasion"),
    Technique("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
]

TECHNIQUES: dict[str, Technique] = {t.id: t for t in _CATALOG}

# Kill-chain order used to reason about campaign progression (earlier = smaller).
TACTIC_ORDER = {
    "initial-access": 0,
    "credential-access": 1,
    "discovery": 2,
    "execution": 3,
    "defense-evasion": 3,
    "lateral-movement": 4,
    "collection": 5,
    "command-and-control": 6,
    "exfiltration": 7,
}


def is_valid_technique(technique_id: str) -> bool:
    """Syntactically valid ATT&CK technique or sub-technique identifier."""
    return bool(TECHNIQUE_ID.match(technique_id))


def tactic_of(technique_id: str) -> str | None:
    technique = TECHNIQUES.get(technique_id) or TECHNIQUES.get(technique_id.split(".")[0])
    return technique.tactic if technique else None
