from app.services.arp_troubleshoot import ArpTroubleshoot


svc = ArpTroubleshoot(demo=True)


def test_wired_user_lan_and_wan():
    r = svc.query(ip="10.20.10.45")
    assert r["found"]
    assert r["identity"]["username"] == "dinesh.velapure"
    assert r["lan"]["access_type"] == "wired"
    assert r["lan"]["access_switch"]["device"] == "SW-MUM-ACC-01"
    assert r["lan"]["access_switch"]["port"] == "GigabitEthernet1/0/1"
    assert r["lan"]["arp_complete"] is True
    assert r["wan"]["edge"] == "VEDGE-MUM-001"
    assert r["wan"]["default_route"]["nexthop"] == "49.36.12.9"
    ids = {n["data"]["name"] for n in r["nodes"]}
    assert "LAPTOP-DINESH" in ids
    assert "Internet" in ids
    assert r["verdict"]["level"] in {"green", "amber"}


def test_cisco_wifi_splits_rf_from_wan():
    r = svc.query(username="priya.nair")
    assert r["lan"]["access_type"] == "wireless"
    assert r["lan"]["ap"]["name"] == "AP-MUM-01"
    assert r["lan"]["wlc"]["name"] == "WLC-MUM-01"
    names = [n["data"]["name"] for n in r["nodes"]]
    assert names[0] == "PRIYA-MBP"
    assert "WLC-MUM-01" in names
    assert names[-1] == "Internet"


def test_meraki_guest_policy_finding():
    r = svc.query(hostname="RAHUL-PIXEL")
    codes = {f["code"] for f in r["findings"]}
    assert "GUEST_POLICY" in codes
    assert r["lan"]["ap"]["name"] == "MR-MUM-01"


def test_unknown_user():
    r = svc.query(ip="1.2.3.4")
    assert r["found"] is False
    assert r["nodes"] == []
