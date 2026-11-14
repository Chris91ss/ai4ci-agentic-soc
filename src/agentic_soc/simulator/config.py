"""Simulator configuration (YAML + seed).

``config/simulator.yaml`` documents every knob; values missing from a YAML file fall back to
the defaults declared here, so scenario files only need to contain what they change.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OfficeConfig(_Cfg):
    name: str
    city: str
    country: str = Field(pattern=r"^[A-Z]{2}$")
    lat: float
    lon: float
    egress_netblock: str = Field(description="Public netblock used for the office NAT.")
    share: float = Field(gt=0, description="Share of employees based in this office.")


class RoleConfig(_Cfg):
    share: float = Field(gt=0)
    department: str
    admin: bool = Field(False, description="Has a separate privileged adm- account.")
    remote_prob: float = Field(0.2, ge=0, le=1, description="Chance of working from home on a day.")
    travel_prob: float = Field(0.003, ge=0, le=1, description="Chance of starting a trip on a day.")
    after_hours_prob: float = Field(0.1, ge=0, le=1)
    weekend_prob: float = Field(0.04, ge=0, le=1)
    apps: list[str] = Field(description="SSO applications used by the role.")
    tools: list[str] = Field(description="Desktop executables typical for the role.")


class ServerGroupConfig(_Cfg):
    role: str
    count: int = Field(ge=1)
    zone: Literal["datacenter", "dmz"] = "datacenter"
    os: Literal["windows", "linux"] = "windows"
    criticality: int = Field(3, ge=1, le=5)


def _default_offices() -> list[OfficeConfig]:
    return [
        OfficeConfig(
            name="HQ", city="Cluj-Napoca", country="RO", lat=46.77, lon=23.60,
            egress_netblock="193.226.51.0/24", share=0.65,
        ),
        OfficeConfig(
            name="Bucharest", city="Bucharest", country="RO", lat=44.43, lon=26.10,
            egress_netblock="82.77.140.0/24", share=0.35,
        ),
    ]  # fmt: skip


_OFFICE_TOOLS = ["chrome.exe", "msedge.exe", "outlook.exe", "teams.exe", "excel.exe", "winword.exe"]


def _default_roles() -> dict[str, RoleConfig]:
    return {
        "engineering": RoleConfig(
            share=0.30, department="Engineering", remote_prob=0.35, after_hours_prob=0.15,
            apps=["o365", "teams", "github", "jira", "slack", "aws-console"],
            tools=["code.exe", "git.exe", "python.exe", "node.exe", "cmd.exe", "powershell.exe",
                   "chrome.exe", "teams.exe", "outlook.exe", "WindowsTerminal.exe"],
        ),
        "sales": RoleConfig(
            share=0.15, department="Sales", remote_prob=0.30, travel_prob=0.02,
            apps=["o365", "teams", "salesforce", "zoom"],
            tools=[*_OFFICE_TOOLS, "zoom.exe", "powerpnt.exe"],
        ),
        "finance": RoleConfig(
            share=0.10, department="Finance", remote_prob=0.15,
            apps=["o365", "teams", "sap", "salesforce"],
            tools=[*_OFFICE_TOOLS, "saplogon.exe", "acrord32.exe"],
        ),
        "hr": RoleConfig(
            share=0.05, department="HR", remote_prob=0.20,
            apps=["o365", "teams", "workday"],
            tools=[*_OFFICE_TOOLS, "acrord32.exe"],
        ),
        "operations": RoleConfig(
            share=0.15, department="Operations", remote_prob=0.05, after_hours_prob=0.05,
            apps=["o365", "teams", "sap"],
            tools=[*_OFFICE_TOOLS, "saplogon.exe"],
        ),
        "support": RoleConfig(
            share=0.12, department="Customer Support", remote_prob=0.25,
            apps=["o365", "teams", "zendesk", "slack"],
            tools=[*_OFFICE_TOOLS, "slack.exe"],
        ),
        "it_admin": RoleConfig(
            share=0.05, department="IT", admin=True, remote_prob=0.20, after_hours_prob=0.30,
            weekend_prob=0.15, apps=["o365", "teams", "azure-portal", "github"],
            tools=["mmc.exe", "powershell.exe", "mstsc.exe", "cmd.exe", "putty.exe", "chrome.exe",
                   "outlook.exe", "teams.exe", "WindowsTerminal.exe"],
        ),
        "executive": RoleConfig(
            share=0.03, department="Management", remote_prob=0.30, travel_prob=0.05,
            apps=["o365", "teams", "salesforce", "zoom"],
            tools=[*_OFFICE_TOOLS, "powerpnt.exe", "zoom.exe"],
        ),
        "marketing": RoleConfig(
            share=0.05, department="Marketing", remote_prob=0.30,
            apps=["o365", "teams", "slack", "hubspot"],
            tools=[*_OFFICE_TOOLS, "photoshop.exe", "slack.exe"],
        ),
    }  # fmt: skip


def _default_servers() -> list[ServerGroupConfig]:
    S = ServerGroupConfig
    return [
        S(role="dc", count=3, criticality=5),
        S(role="file", count=4, criticality=4),
        S(role="db", count=5, criticality=5),
        S(role="app", count=12, os="linux", criticality=3),
        S(role="erp", count=2, criticality=5),
        S(role="mail", count=2, criticality=4),
        S(role="backup", count=2, criticality=4),
        S(role="jump", count=2, criticality=4),
        S(role="edr", count=1, criticality=4),
        S(role="wsus", count=1, criticality=2),
        S(role="print", count=2, criticality=1),
        S(role="monitoring", count=2, os="linux", criticality=3),
        S(role="build", count=4, os="linux", criticality=3),
        S(role="web", count=5, zone="dmz", os="linux", criticality=3),
        S(role="proxy", count=2, zone="dmz", os="linux", criticality=3),
        S(role="vpn", count=1, zone="dmz", os="linux", criticality=5),
    ]


class OrgConfig(_Cfg):
    name: str = "Example Corp"
    domain: str = "corp.example"
    netbios: str = "CORP"
    timezone: str = "Europe/Bucharest"
    home_country: str = "RO"
    users: int = Field(200, ge=10, le=5000)
    weak_password_share: float = Field(0.04, ge=0, le=1)
    offices: list[OfficeConfig] = Field(default_factory=_default_offices, min_length=1)
    roles: dict[str, RoleConfig] = Field(default_factory=_default_roles, min_length=1)
    servers: list[ServerGroupConfig] = Field(default_factory=_default_servers)
    service_accounts: list[str] = Field(
        default_factory=lambda: ["svc_backup", "svc_sql", "svc_web", "svc_monitor", "svc_build"]
    )

    @model_validator(mode="after")
    def _roles_cover_it(self) -> OrgConfig:
        if not any(role.admin for role in self.roles.values()):
            raise ValueError("at least one role must have admin accounts (IT administrators)")
        return self

    @property
    def n_servers(self) -> int:
        return sum(group.count for group in self.servers)


class SigninActivity(_Cfg):
    sso_per_hour: float = Field(1.4, ge=0, description="Cloud SSO sign-ins per active user hour.")
    network_logons_per_hour: float = Field(1.0, ge=0, description="Kerberos logons to servers.")
    mobile_checks_per_evening: float = Field(1.5, ge=0)
    admin_rdp_per_day: float = Field(3.0, ge=0, description="RDP sessions per IT admin and day.")
    mfa_prob: float = Field(0.35, ge=0, le=1)
    monitor_logons_per_hour: float = Field(20, ge=0, description="svc_monitor health-check logons.")


class FlowActivity(_Cfg):
    web_per_hour: float = Field(40, ge=0, description="Internet flows per active workstation hour.")
    internal_per_hour: float = Field(18, ge=0, description="Intranet flows per active hour.")
    app_db_per_hour: float = Field(25, ge=0, description="App-to-database flows per server hour.")
    dmz_inbound_per_hour: float = Field(
        120, ge=0, description="Inbound requests per web server hour."
    )
    heartbeat_s: float = Field(900, gt=0, description="EDR agent heartbeat period of every host.")
    monitoring_s: float = Field(600, gt=0, description="Monitoring poll period per server.")
    edr_cloud_s: float = Field(60, gt=0, description="EDR server to vendor cloud sync period.")


class ProcessActivity(_Cfg):
    server_per_hour: float = Field(12, ge=0, description="Background launches per server hour.")


class ActivityConfig(_Cfg):
    signin: SigninActivity = Field(default_factory=SigninActivity)
    flow: FlowActivity = Field(default_factory=FlowActivity)
    process: ProcessActivity = Field(default_factory=ProcessActivity)
    weekday_attendance: float = Field(
        0.94, ge=0, le=1, description="Share of staff working a weekday."
    )


class LookalikeConfig(_Cfg):
    """Benign behaviour that resembles attack steps (the hard negatives)."""

    typos: bool = True
    travel: bool = True
    remote_vpn: bool = True
    admin_rdp: bool = True
    admin_maintenance_weekday: int = Field(1, ge=0, le=6, description="Patch night (0=Monday).")
    nightly_backup: bool = True
    backup_start_h: float = Field(1.0, ge=0, lt=24)
    backup_internal_gb: tuple[float, float] = (5.0, 15.0)
    backup_offsite_gb: tuple[float, float] = (2.0, 6.0)
    dev_hosting: bool = True
    edr_cloud_sync: bool = True


class DeliverySpec(_Cfg):
    """Transport of one stream from its producers to the broker."""

    median_delay_s: float = Field(gt=0)
    sigma: float = Field(0.6, ge=0, description="Log-normal spread of the delay.")
    late_prob: float = Field(ge=0, le=1, description="Share of stragglers (buffered, offline).")
    late_delay_s: tuple[float, float] = Field(description="Extra delay range of stragglers.")
    duplicate_prob: float = Field(ge=0, le=1, description="Share redelivered a second time.")
    duplicate_max_s: float = Field(120, gt=0)
    clock_skew_s: float = Field(0.5, ge=0, description="Std of per-producer clock offsets.")
    drifted_clock_prob: float = Field(0.0, ge=0, le=1, description="Producers off by 30-180 s.")
    malformed_prob: float = Field(0.0005, ge=0, le=1)
    legacy_prob: float = Field(0.0, ge=0, le=1, description="VPN sign-ins from the 0.9 appliance.")
    legacy_sources: list[str] = Field(
        default_factory=list, description="Flow sensors on schema 0.9."
    )


def _default_delivery() -> dict[str, DeliverySpec]:
    return {
        "signin": DeliverySpec(
            median_delay_s=2.0, sigma=0.6, late_prob=0.01, late_delay_s=(60, 600),
            duplicate_prob=0.003, clock_skew_s=0.3, malformed_prob=0.0005, legacy_prob=0.35,
        ),
        "flow": DeliverySpec(
            median_delay_s=15.0, sigma=0.5, late_prob=0.02, late_delay_s=(120, 900),
            duplicate_prob=0.01, clock_skew_s=1.0, malformed_prob=0.0003,
            legacy_sources=["sensor-dc-01"],
        ),
        "process": DeliverySpec(
            median_delay_s=4.0, sigma=0.9, late_prob=0.03, late_delay_s=(300, 3600),
            duplicate_prob=0.005, clock_skew_s=0.5, drifted_clock_prob=0.03,
            malformed_prob=0.0005,
        ),
    }  # fmt: skip


class CampaignConfig(_Cfg):
    """The injected intrusion (see :mod:`agentic_soc.simulator.campaign`)."""

    enabled: bool = True
    campaign_id: str = "CAMP-1"
    start_offset_h: float = Field(19.0, ge=0, description="Hours after the simulation start.")
    start_jitter_h: float = Field(3.0, ge=0, description="Seeded +/- shift of the start.")
    dwell_scale: float = Field(1.0, gt=0, description="Multiplies the pauses between stages.")
    spray_targets: int = Field(80, ge=1, description="Accounts tried by the password spray.")
    spray_passwords: int = Field(2, ge=1, le=10, description="Passwords tried per account.")
    spray_interval_s: tuple[float, float] = (15.0, 45.0)
    attacker_blocks: list[str] = Field(
        default_factory=lambda: [
            "45.32.0.0/16",
            "193.106.191.0/24",
            "185.220.100.0/22",
            "51.75.0.0/16",
        ],
        description="Netblocks of the servers used for spraying and VPN access.",
    )
    c2_blocks: list[str] = Field(
        default_factory=lambda: ["95.216.0.0/16", "159.89.0.0/16", "103.75.0.0/16"],
        description="Netblocks of the primary and fallback C2 servers.",
    )
    c2_ports: list[int] = Field(default_factory=lambda: [443])
    beacon_period_s: tuple[float, float] = (45.0, 180.0)
    beacon_jitter: tuple[float, float] = (0.1, 0.35)
    scan_targets: tuple[int, int] = (25, 60)
    exfil_gb: tuple[float, float] = (1.5, 4.0)
    pivot: bool = Field(True, description="Rotate infrastructure when it gets blocked.")
    prompt_injection: bool = Field(
        True, description="Embed instructions aimed at LLM analysts in attacker-controlled fields."
    )


class SimulatorConfig(_Cfg):
    seed: int = 7
    start: AwareDatetime = Field(
        default=datetime(2026, 3, 2, tzinfo=UTC), description="Simulation start (UTC)."
    )
    duration_h: float = Field(48.0, gt=0)
    tick_s: int = Field(60, ge=1, le=3600, description="Simulation step.")
    calibration: str = Field(
        "default", description="Name in config/calibration/ or path of a calibration YAML."
    )
    org: OrgConfig = Field(default_factory=OrgConfig)
    activity: ActivityConfig = Field(default_factory=ActivityConfig)
    lookalikes: LookalikeConfig = Field(default_factory=LookalikeConfig)
    delivery: dict[str, DeliverySpec] = Field(default_factory=_default_delivery)
    campaign: CampaignConfig = Field(default_factory=CampaignConfig)

    @model_validator(mode="after")
    def _all_streams_delivered(self) -> SimulatorConfig:
        missing = {"signin", "flow", "process"} - set(self.delivery)
        if missing:
            raise ValueError(f"delivery settings missing for {sorted(missing)}")
        return self

    @property
    def end(self) -> datetime:
        return self.start + timedelta(hours=self.duration_h)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base`` (dicts merge, other values replace)."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def repo_root() -> Path:
    """Repository root (directory holding ``config/``), overridable with ``SOC_HOME``."""
    if env := os.environ.get("SOC_HOME"):
        return Path(env)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "config" / "simulator.yaml").exists():
            return parent
    return Path.cwd()


DEFAULT_CONFIG = "config/simulator.yaml"


def load_config(
    path: str | Path | None = None,
    *overlays: str | Path,
    overrides: dict[str, Any] | None = None,
) -> SimulatorConfig:
    """Load the base YAML config, apply scenario overlays, then explicit overrides."""
    base_path = Path(path) if path else repo_root() / DEFAULT_CONFIG
    data: dict[str, Any] = {}
    if base_path.exists():
        data = yaml.safe_load(base_path.read_text()) or {}
    elif path is not None:
        raise FileNotFoundError(base_path)
    for overlay in overlays:
        data = deep_merge(data, yaml.safe_load(Path(overlay).read_text()) or {})
    if overrides:
        data = deep_merge(data, overrides)
    return SimulatorConfig.model_validate(data)
