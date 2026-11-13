from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

import pytest

from agentic_soc.simulator.config import SimulatorConfig, deep_merge, load_config
from agentic_soc.simulator.enterprise import Enterprise, is_internal, zone_of_ip


@pytest.fixture(scope="module")
def ent() -> Enterprise:
    return Enterprise.build(load_config())


def test_default_yaml_matches_rfc_scale(ent: Enterprise) -> None:
    assert len(ent.users) == 200
    assert len(ent.hosts) == 250
    assert len(ent.workstations) == 200
    assert len(ent.servers) == 50


def test_build_is_deterministic_under_seed() -> None:
    a = Enterprise.build(SimulatorConfig(seed=11))
    b = Enterprise.build(SimulatorConfig(seed=11))
    c = Enterprise.build(SimulatorConfig(seed=12))
    assert [u.user_id for u in a.users] == [u.user_id for u in b.users]
    assert [u.home_ip for u in a.users] == [u.home_ip for u in b.users]
    assert [u.user_id for u in a.users] != [u.user_id for u in c.users]


def test_identities_are_unique_and_consistent(ent: Enterprise) -> None:
    ids = [u.user_id for u in ent.users]
    assert len(set(ids)) == len(ids)
    assert all(u.upn == f"{u.user_id}@corp.example" for u in ent.users)
    assert all(ent.hosts_by_id[u.workstation].owner == u.user_id for u in ent.users)
    roles = Counter(u.role for u in ent.users)
    assert roles["engineering"] == 60 and roles["it_admin"] == 10
    assert {u.admin_account for u in ent.admins} == {f"adm-{u.user_id}" for u in ent.admins}
    assert 2 <= sum(u.weak_password for u in ent.users) <= 30
    assert not any(u.weak_password for u in ent.admins)


def test_server_addresses_and_zones(ent: Enterprise) -> None:
    ips = [h.static_ip for h in ent.servers]
    assert len(set(ips)) == len(ips)
    for host in ent.servers:
        assert zone_of_ip(host.static_ip) == host.zone
        assert ent.host_for_ip(host.static_ip, ent.config.start) == host.host_id
    assert len(ent.servers_by_role["dc"]) == 3
    assert ent.servers_by_role["vpn"][0].zone == "dmz"


def test_dhcp_leases_are_unique_per_day_and_mostly_stable(ent: Enterprise) -> None:
    t0 = ent.config.start + timedelta(hours=10)
    t1 = t0 + timedelta(days=1)
    day0 = {h.host_id: ent.dhcp_ip(h.host_id, t0) for h in ent.workstations}
    day1 = {h.host_id: ent.dhcp_ip(h.host_id, t1) for h in ent.workstations}
    assert len(set(day0.values())) == len(day0)
    assert len(set(day1.values())) == len(day1)
    changed = sum(day0[h] != day1[h] for h in day0)
    assert 0 < changed < len(day0) * 0.3
    for host_id, ip in day1.items():
        assert zone_of_ip(ip) == "corp"
        assert ent.host_for_ip(ip, t1) == host_id


def test_geoip_covers_allocated_external_addresses(ent: Enterprise) -> None:
    for user in ent.users:
        info = ent.geo.lookup(user.home_ip)
        assert info is not None and info.country == "RO"
    for service in ent.services.values():
        for ip in service.ips:
            assert ent.geo.lookup(ip) is not None
            assert not is_internal(ip)
    assert ent.geo.lookup("10.10.0.5") is None
    egress = ent.geo.lookup(ent.office_egress["HQ"])
    assert egress is not None and egress.category == "corporate"


def test_inventory_contains_no_ground_truth(ent: Enterprise) -> None:
    inv = ent.inventory()
    assert len(inv["users"]) == 200 and len(inv["hosts"]) == 250
    assert "weak_password" not in inv["users"][0]


def test_local_time_helpers(ent: Enterprise) -> None:
    t = datetime(2026, 3, 3, 22, 30, tzinfo=UTC)  # 00:30 local on March 4 (UTC+2)
    assert ent.local(t).hour == 0
    assert ent.day_index(t) == 2
    assert ent.day_start(2).isoformat().startswith("2026-03-04T00:00:00")


def test_overrides_and_validation() -> None:
    cfg = load_config(overrides={"seed": 3, "org": {"users": 50}})
    assert cfg.seed == 3 and cfg.org.users == 50
    assert cfg.org.domain == "corp.example"
    assert deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"c": 3}}) == {"a": {"b": 1, "c": 3}}
    with pytest.raises(ValueError):
        SimulatorConfig.model_validate(
            {"org": {"roles": {"x": {"share": 1, "department": "X", "apps": [], "tools": []}}}}
        )
    with pytest.raises(FileNotFoundError):
        load_config("does/not/exist.yaml")
