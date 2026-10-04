"""
Peering Buddy tests, with the network calls replaced by fixed data.
"""

import json
import sys
from unittest.mock import MagicMock, Mock

import pytest
import requests

import peering_buddy
from pbuddy.pbuddy import Bcolors, PBuddy

ASN = "64496"
PREFIX = "192.0.2.0/24"
HIJACK = (
    " => Check your announce, ROA/RPKI is valid, not registered on IRR and"
    " whois (probably malicious activity or hijack)."
)
FAT_FINGER = (
    " => Check your announce, ROA/RPKI not published, not registered on IRR"
    " and whois (probably fat finger or hijack)."
)
FIRST = "First ASN (the other end ASN):  ['64510:1']"
SECOND = "Second ASN (the other end upstream):  ['64505:1']"
THIRD = "Third ASN (trying to find a common ASN on the path):  ['64500:1']"
NONTRANSIT = "Non transit peers directly attached to ASN 64496 : []"
TRANSIT = "Transit upstreams for the ASN 64496 : ['64500:1']"
LOCATIONS = "By locations:"


@pytest.mark.parametrize(
    "vrp, verdict",
    [("valid", HIJACK), ("unknown", FAT_FINGER), ("invalid_asn", FAT_FINGER)],
)
def test_consistency_of_a_prefix_only_seen_in_bgp(monkeypatch, vrp, verdict):
    """A prefix missing on IRR and whois is a hijack only with a valid ROA."""
    prefix = {
        "prefix": PREFIX,
        "in_whois": False,
        "irr_sources": "-",
        "in_bgp": True,
    }
    routing = json.dumps({"data": {"prefixes": [prefix]}})
    session = MagicMock()
    session.return_value.__enter__.return_value.get.return_value = Mock(
        status_code=200, text=routing
    )
    whois = Mock(return_value={"asns": [{"asn": 64511}]})
    monkeypatch.setattr(requests, "Session", session)
    monkeypatch.setattr(PBuddy, "bv_pfx_whois", whois)
    monkeypatch.setattr(PBuddy, "ripe_vrp_check", Mock(return_value=vrp))

    assert PBuddy().ripe_asn_announces_consistency(ASN) == [
        (
            Bcolors.FAIL + "Prefix: ",
            PREFIX,
            " | Whois: ",
            False,
            " | IRR: ",
            "-",
            " | BGP: ",
            True,
            " | RPKI: ",
            vrp,
            verdict + Bcolors.ENDC,
        )
    ]


def test_main_without_arguments_prints_the_help(monkeypatch, capsys):
    """Running with no option prints the usage on stderr and exits clean."""
    monkeypatch.setattr(sys, "argv", ["peering_buddy.py"])

    with pytest.raises(SystemExit) as stop:
        peering_buddy.main()

    assert stop.value.code == 0
    assert capsys.readouterr().err.startswith("usage: peering_buddy.py")


@pytest.mark.parametrize(
    "threshold, summary",
    [
        ("2", [FIRST, "", NONTRANSIT, "", TRANSIT, "", LOCATIONS, "rrc00:1"]),
        (
            "3",
            [FIRST, "", SECOND, "", NONTRANSIT, "", TRANSIT, "", LOCATIONS]
            + ["rrc00:1"],
        ),
        (
            "4",
            [FIRST, "", SECOND, "", THIRD, "", NONTRANSIT, "", TRANSIT, ""]
            + [LOCATIONS, "rrc00: 1"],
        ),
    ],
)
def test_main_aspath_length_summary(monkeypatch, capsys, threshold, summary):
    """The summary prints one block per ASN position, split by empty lines."""
    path = ("rrc00", " | ", PREFIX, " | ", "64510 64505 64500 64496")
    paths = Mock(
        return_value=(
            [path],
            ["64510"],
            ["64505"],
            ["64500"],
            [],
            ["64500"],
            ["64500"],
        )
    )
    argv = ["peering_buddy.py", "-nv", "-pa", ASN, threshold, "n"]
    monkeypatch.setattr(PBuddy, "ripe_bv_pfxs_aspath_length", paths)
    monkeypatch.setattr(sys, "argv", argv)

    peering_buddy.main()

    assert capsys.readouterr().out.splitlines() == ["".join(path), *summary]


def test_main_upstreams_on_transient_paths(monkeypatch, capsys):
    """An upstream counts as transient before the last two hops of a path."""
    transient = ("rrc00", " | ", PREFIX, " | ", "64510 64500 64501 64496")
    direct = ("rrc00", " | ", PREFIX, " | ", "64511 64500 64496")
    paths = Mock(return_value=([transient, direct], [], [], [], [], ["64500"]))
    monkeypatch.setattr(PBuddy, "ripe_bv_pfxs_aspath_length", paths)
    monkeypatch.setattr(sys, "argv", ["peering_buddy.py", "-nv", "-tu", ASN])

    peering_buddy.main()

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "".join(transient)
    assert lines[1].startswith("Transient upstreams for the ASN 64496 [")
    assert lines[2:4] == ["AS 64500 => 1 => 2 => 50.0 %", ""]
    assert lines[4].startswith("By locations [")
    assert lines[5:] == ["rrc00 => 1 => 2 => 50.0 %"]
