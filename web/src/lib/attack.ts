// MITRE ATT&CK techniques the detectors map to (mirrors agentic_soc.schemas.attack).
export const TECHNIQUES: Record<string, { name: string; tactic: string }> = {
  "T1003.001": { name: "OS Credential Dumping: LSASS Memory", tactic: "credential-access" },
  T1018: { name: "Remote System Discovery", tactic: "discovery" },
  "T1021.001": { name: "Remote Services: RDP", tactic: "lateral-movement" },
  "T1021.002": { name: "Remote Services: SMB/Admin Shares", tactic: "lateral-movement" },
  T1041: { name: "Exfiltration Over C2 Channel", tactic: "exfiltration" },
  "T1059.001": { name: "PowerShell", tactic: "execution" },
  "T1071.001": { name: "Application Layer Protocol: Web", tactic: "command-and-control" },
  T1078: { name: "Valid Accounts", tactic: "initial-access" },
  "T1087.002": { name: "Account Discovery: Domain Account", tactic: "discovery" },
  T1110: { name: "Brute Force", tactic: "credential-access" },
  "T1110.003": { name: "Password Spraying", tactic: "credential-access" },
  T1133: { name: "External Remote Services", tactic: "initial-access" },
  "T1218.011": { name: "System Binary Proxy Execution: Rundll32", tactic: "defense-evasion" },
  "T1560.001": { name: "Archive via Utility", tactic: "collection" },
  "T1569.002": { name: "Service Execution", tactic: "execution" },
  T1573: { name: "Encrypted Channel", tactic: "command-and-control" },
};

export const TACTIC_ORDER = [
  "initial-access",
  "execution",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
];

export const LATE_TACTICS = new Set(["credential-access", "lateral-movement", "collection", "command-and-control", "exfiltration"]);

export function tacticOf(technique: string) {
  return TECHNIQUES[technique]?.tactic ?? TECHNIQUES[technique.split(".")[0]]?.tactic ?? "unknown";
}

export function techniqueName(technique: string) {
  return TECHNIQUES[technique]?.name ?? TECHNIQUES[technique.split(".")[0]]?.name ?? technique;
}
