#!/usr/bin/env python3
# pylint: disable=too-many-locals, too-many-branches, too-many-statements, line-too-long, unnecessary-lambda-assignment
# noqa: E501
"""
Peering Buddy - Helping you dig data from internet for better decisions!
"""

import argparse
import json
import sys

from pbuddy.pbuddy import PBuddy


class CustomHelpFormatter(argparse.HelpFormatter):
    """
    Custom help formatter class.

    Extends the argparse.HelpFormatter class to set the maximum help position to 88 columns.

    Parameters:
        prog (str): The program name.

    Attributes:
        max_help_position (int): The maximum width of the help text.

    Methods:
        __init__: Initializes the CustomHelpFormatter object with the specified program name.
    """

    def __init__(self, prog):
        """
        Initialize the CustomHelpFormatter object.

        Args:
            prog (str): The program name.

        Returns:
            None
        """
        super().__init__(prog, max_help_position=88)


def main():
    """
    Peering Buddy main function.

    TODO: Refactor to improve readability and maintainability.
    """
    parser = argparse.ArgumentParser(
        description="Peering Buddy - Helping you dig data from internet for better decisions!",
        formatter_class=CustomHelpFormatter,
    )
    parser.add_argument(
        "-av",
        "--asn-visibility",
        action="store",
        dest="asn_visibility",
        metavar="ASN",
        help="[RIPE] Check ASN visibility RIPE RIS sensors.",
    )
    parser.add_argument(
        "-ap",
        "--asn-announced-pfxs",
        action="store",
        dest="asn_announcedpfxs",
        metavar="ASN",
        help="[RIPE] Check ASN announced prefixes to internet.",
    )
    parser.add_argument(
        "-ar",
        "--asn-roa-validation",
        action="store",
        dest="asn_roavalidation",
        metavar="ASN",
        help="[RIPE] Check ASN RPKI/ROA validation for announced prefixes.",
    )
    parser.add_argument(
        "-lg",
        "--looking-glass",
        action="store",
        dest="pfx_rislg",
        metavar="PREFIX",
        help="[RIPE] Get prefix using RIPE RIS as Looking Glass.",
    )
    parser.add_argument(
        "-al",
        "--aspath-length-overview",
        action="store",
        dest="asn_aspathoverview",
        metavar="ASN",
        help="[RIPE] Check AS-Path length overview.",
    )
    parser.add_argument(
        "-as",
        "--aspath-lenghth-stripped",
        action="store",
        dest="asn_aspathstripped",
        metavar="ASN",
        help="[RIPE] Check AS-Path length stripped [no as-prepend].",
    )
    parser.add_argument(
        "-au",
        "--aspath-lenghth-unstripped",
        action="store",
        dest="asn_aspathunstripped",
        metavar="ASN",
        help="[RIPE] Check AS-Path length unstripped [with as-prepend].",
    )
    parser.add_argument(
        "-tm",
        "--threshold-max",
        action="store",
        dest="asn_aspaththresholdmax",
        metavar="INTEGER",
        help="[RIPE][as|au] Threshold [>=] to be used with -as and -au for max.",
    )
    parser.add_argument(
        "-ti",
        "--threshold-min",
        action="store",
        dest="asn_aspaththresholdmin",
        metavar="INTEGER",
        help="[RIPE][as|au] Threshold [>=] to be used with -as and -au for min.",
    )
    parser.add_argument(
        "-ta",
        "--threshold-avg",
        action="store",
        dest="asn_aspaththresholdavg",
        metavar="INTEGER",
        help="[RIPE][as|au] Threshold [>=] to be used with -as and -au for avg.",
    )
    parser.add_argument(
        "-ao",
        "--asn-overview",
        action="store",
        dest="asn_overview",
        metavar="ASN",
        help="[RIPE] Check ASN public resources overview.",
    )
    parser.add_argument(
        "-ac",
        "--asn-announce-consistency",
        action="store",
        dest="asn_announcesconsistency",
        metavar="ASN",
        help="[RIPE][BGPView][IPInfo] Check ASN announces consistency.",
    )
    parser.add_argument(
        "-pa",
        "--asn-pfxs-aspath-length",
        action="store",
        dest="asn_asnpfxaspathlength",
        metavar=("ASN", "THRESHOLD", "PREPEND[y|n]"),
        help="[RIPE][BGPView] Check ASN prefixes where as-path length >= threshold.",
        nargs=3,
    )
    parser.add_argument(
        "-tu",
        "--asn-upstreams-transient",
        action="store",
        dest="asn_upstreamtransient",
        metavar="ASN",
        help="[RIPE][BGPView] Check ASN upstreams on transient paths.",
    )
    parser.add_argument(
        "-gu",
        "--asn-upstreams",
        action="store",
        dest="upstreams",
        metavar="ASN",
        help="[BGPView] Get ASN upstreams.",
    )
    parser.add_argument(
        "-gd",
        "--asn-downstreams",
        action="store",
        dest="downstreams",
        metavar="ASN",
        help="[BGPView] Get ASN downstreams.",
    )
    parser.add_argument(
        "-gw",
        "--whois",
        action="store",
        dest="whois",
        metavar="[ASN|PREFIX]",
        help="[BGPView] Get ASN/Prefix whois information.",
    )
    parser.add_argument(
        "-wi",
        "--whois-ip",
        action="store",
        dest="ipwhois",
        metavar="IP",
        help="[IPInfo] Get IP whois information.",
    )
    parser.add_argument(
        "-ip",
        "--pdb-ixp-pfxs",
        action="store_true",
        dest="pdb_ip",
        help="[PeeringDB] Get IXPs prefixes.",
    )
    parser.add_argument(
        "-ai",
        "--pdb-asn-info",
        action="store",
        dest="asninfo",
        metavar="ASN",
        help="[PeeringDB] Get ASN information on PeeringDB.",
    )
    parser.add_argument(
        "-ii",
        "--pdb-asn-ips",
        action="store",
        dest="ixpips",
        metavar="ASN",
        help="[PeeringDB] Get ASN IPS allocated on IXPs.",
    )
    parser.add_argument(
        "-gc",
        "--pdb-asn-contact",
        action="store",
        dest="asncontact",
        metavar="ASN",
        help="[PeeringDB] Get ASN contact.",
    )
    parser.add_argument(
        "-cc",
        "--pdb-ixp-bycc",
        action="store",
        dest="ixpcc",
        metavar="ASN",
        help="[PeeringDB] Get IXPs by Country Code [iso-3166-1 alpha-2].",
    )
    parser.add_argument(
        "-gl",
        "--lgs",
        action="store_true",
        dest="lgs",
        help="[Team Cymrus] Check a list of public LookingGlass.",
    )
    parser.add_argument(
        "-bo",
        "--bogons",
        action="store_true",
        dest="bogonspfx4",
        help="[Team Cymrus] Get ip4 bogons list.",
    )
    parser.add_argument(
        "-b4",
        "--bogons-v4",
        action="store_true",
        dest="fbogonspfx4",
        help="[Team Cymrus] Get ip4 full (+unallocated) bogons list.",
    )
    parser.add_argument(
        "-b6",
        "--bogons-v6",
        action="store_true",
        dest="fbogonspfx6",
        help="[Team Cymrus] Get ip6 full (+unallocated) bogons list.",
    )
    parser.add_argument(
        "-ba",
        "--bogons-asn",
        action="store_true",
        dest="bogonsasn",
        help="[NTT] Get ASN bogons list/examples.",
    )
    parser.add_argument(
        "-aa",
        "--asset",
        action="store",
        dest="asset",
        metavar="ASN",
        help="[NLNOG] Check ASN AS-SET and expand it.",
    )
    parser.add_argument(
        "-rh",
        "--resource-health-check",
        action="store",
        dest="resourcehealthcheck",
        metavar="ASN|PREFIX",
        help="[NLNOG] ASN or Prefix health check.",
    )
    parser.add_argument(
        "-nv",
        "--non-verbose",
        action="store_true",
        dest="nonverbose",
        help="Remove human-like text to the output.",
    )

    args = parser.parse_args()
    options = all(value is True for value in vars(args).values())
    pbuddy = PBuddy()

    re_asn = "^[0-9]{0,9}$"
    re_cc = "^[a-zA-Z]{0,2}$"
    re_int = "^[0-9]{0,2}$"
    re_yn = "^[yYnN]$"
    asn_invalid = "Invalid ASN, please type the ASN without the suffix AS."
    pfx_invalid = "Invalid prefix (v4/v6), please type prefix/mask."
    separator = "=" * 80

    if args.asn_visibility is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asn_visibility)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        result = pbuddy.ripe_asn_visibility(args.asn_visibility)
        if args.nonverbose is False:
            print(separator)
            print(
                "=> Visibilit percentage (RIS point of view)",
                args.asn_visibility,
                ":",
            )
            print(separator)
        for afi, perc in result.items():
            print(f"Visibility for {afi}: {perc}%")
        if args.nonverbose is False:
            print(separator)
    if args.asn_announcedpfxs is not None:
        regexp_asn = pbuddy.regex_validation(re_asn, args.asn_announcedpfxs)
        if regexp_asn is False:
            print(asn_invalid)
            sys.exit(1)
        pfxs = pbuddy.ripe_asn_announced_pfx(args.asn_announcedpfxs)
        if args.nonverbose is False:
            print(separator)
            print(
                "=> We are seeing the prefixes being announced to the internet for the ASN",
                args.asn_announcedpfxs,
                ":",
            )
            print(separator)
        print(json.dumps(pfxs, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.asn_roavalidation is not None:
        regexp_asn = pbuddy.regex_validation(re_asn, args.asn_roavalidation)
        if regexp_asn is False:
            print(asn_invalid)
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print(
                "=> We are validating the prefixes announced by the ASN",
                args.asn_roavalidation,
                ":",
            )
            print(separator)
        prefixes = pbuddy.ripe_asn_announced_pfx(args.asn_roavalidation)
        for prefix in prefixes:
            result = pbuddy.ripe_vrp_check(args.asn_roavalidation, prefix)
            print("Prefix", prefix, "is", result)
        if args.nonverbose is False:
            print(separator)
    if args.pfx_rislg is not None:
        repfx = pbuddy.pfx_validation(args.pfx_rislg)
        if repfx is False:
            print(pfx_invalid)
            sys.exit(1)
        field = None
        result = pbuddy.ripe_ris_lg(args.pfx_rislg, field)
        if args.nonverbose is False:
            print(separator)
            print("=> Looking glass results for the prefix", args.pfx_rislg, ":")
            print(separator)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.asn_aspathoverview is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asn_aspathoverview)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        result = pbuddy.ripe_aspth_length_overview(args.asn_aspathoverview)
        aspath_s_max = result[0]
        aspath_s_min = result[1]
        aspath_s_avg = result[2]
        aspath_u_max = result[3]
        aspath_u_min = result[4]
        aspath_u_avg = result[5]
        print(separator)
        print("=> AS-Path length overview for the ASN", args.asn_aspathoverview, ":")
        print(separator)
        print("Maximum AS-PATH Stripped [ignore as-prepend] => ", aspath_s_max)
        print("Minimum AS-PATH Stripped [ignore as-prepend] => ", aspath_s_min)
        print("Average AS-PATH Stripped [ignore as-prepend] => ", aspath_s_avg)
        print("Maximum AS-PATH Unstripped [considering as-prepend] => ", aspath_u_max)
        print("Minimum AS-PATH Unstripped [considering as-prepend] => ", aspath_u_min)
        print("Average AS-PATH Unstripped [considering as-prepend] => ", aspath_u_avg)
        print(separator)
    if args.asn_aspathstripped is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asn_aspathstripped)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if (
            args.asn_aspaththresholdmax is not None
            or args.asn_aspaththresholdmin is not None
            or args.asn_aspaththresholdavg is not None
        ):
            func = ["max", "min", "avg"]
            values = [
                args.asn_aspaththresholdmax,
                args.asn_aspaththresholdmin,
                args.asn_aspaththresholdavg,
            ]
            for value in values:
                if value:
                    regex_int = pbuddy.regex_validation(re_int, str(value))
                    if regex_int is False:
                        print(
                            "That's not a valid integer, please type an integer from 1 to 2 digits."
                        )
                        sys.exit(1)
            threshold = dict(zip(func, values))
            result = pbuddy.ripe_aspath_length(
                args.asn_aspathstripped, "stripped", func, threshold
            )
        else:
            result = pbuddy.ripe_aspath_length(
                args.asn_aspathstripped, "stripped", None, None
            )
        if args.nonverbose is False:
            print(separator)
            print(
                "=> AS-Path length (min, max and avg - stripping as-prepends) for the ASN",
                args.asn_aspathstripped,
                ":",
            )
            print(separator)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.asn_aspathunstripped is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asn_aspathunstripped)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if (
            args.asn_aspaththresholdmax is not None
            or args.asn_aspaththresholdmin is not None
            or args.asn_aspaththresholdavg is not None
        ):
            func = ["max", "min", "avg"]
            values = [
                args.asn_aspaththresholdmax,
                args.asn_aspaththresholdmin,
                args.asn_aspaththresholdavg,
            ]
            for value in values:
                if value:
                    regex_int = pbuddy.regex_validation(re_int, str(value))
                    if regex_int is False:
                        print(
                            "That's not a valid integer, please type an integer from 1 to 2 digits."
                        )
                        sys.exit(1)
            threshold = dict(zip(func, values))
            result = pbuddy.ripe_aspath_length(
                args.asn_aspathunstripped, "unstripped", func, threshold
            )
        else:
            result = pbuddy.ripe_aspath_length(
                args.asn_aspathunstripped, "unstripped", None, None
            )
        if args.nonverbose is False:
            print(separator)
            print(
                "=> AS-Path length (min, max and avg - unstripping as-prepends) for the ASN",
                args.asn_aspathunstripped,
                ":",
            )
            print(separator)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.asn_overview is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asn_overview)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        result = pbuddy.ripe_asn_resources_overview(args.asn_overview)
        if args.nonverbose is False:
            print(separator)
            print(
                "=> Public Internet resources overview for the ASN",
                args.asn_overview,
                ":",
            )
            print(separator)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.asn_announcesconsistency is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asn_announcesconsistency)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print(
                "=> ASN announces consistency for the ASN",
                args.asn_announcesconsistency,
                ":",
            )
            print(separator)
        result = pbuddy.ripe_asn_announces_consistency(args.asn_announcesconsistency)
        for item in result:
            print("".join(map(str, item)))
        if args.nonverbose is False:
            print(separator)
    if args.lgs is True:
        result = pbuddy.tc_public_lg()
        if args.nonverbose is False:
            print(separator)
            print("=> List of public looking glass.")
            print(separator)
        for key, value in result.items():
            print(key, "=>", value[0])
        if args.nonverbose is False:
            print(separator)
    if args.asset is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asset)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        result = pbuddy.pdb_asn_asset(args.asset)
        asset = result[0]
        expanded = pbuddy.nlnog_expand_asset(asset[args.asset])
        if args.nonverbose is False:
            print(separator)
        print(json.dumps(expanded, indent=4))
        if args.nonverbose is False:
            print(separator)

    if args.resourcehealthcheck is not None:
        resource_type = None
        reasn = pbuddy.regex_validation(re_asn, args.resourcehealthcheck)
        repfx = pbuddy.pfx_validation(args.resourcehealthcheck)
        if reasn is False and repfx is False:
            print(
                "That's not a valid ASN or prefix, please type the ASN without the suffix AS."
            )
            sys.exit(1)
        if reasn is True:
            resource_type = "asn"
        elif repfx is True:
            resource_type = "prefix"
        rhc = pbuddy.nlnog_resource_health_check(
            args.resourcehealthcheck, resource_type
        )
        if args.nonverbose is False:
            print(separator)
        print(json.dumps(rhc, indent=4))
        if args.nonverbose is False:
            print(separator)

    if args.pdb_ip is True:
        if args.nonverbose is False:
            print(separator)
            print("=> IXPs prefixes:")
            print(separator)
        result = pbuddy.pdb_ixps_pfxs()
        for item in result:
            print("".join(map(str, item)))
        if args.nonverbose is False:
            print(separator)
    if args.asninfo is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asninfo)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print("=> ASN ", args.asninfo, " info/summary:")
            print(separator)
        result = pbuddy.pdb_asn_info(args.asninfo)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.ixpips is not None:
        reasn = pbuddy.regex_validation(re_asn, args.ixpips)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print("=> Allocated IXPs IPs for the ASN ", args.ixpips, ":")
            print(separator)
        result = pbuddy.pdb_asn_ixps_ips(args.ixpips)
        for item in result:
            print("".join(map(str, item)))
        if args.nonverbose is False:
            print(separator)
    if args.asncontact is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asncontact)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print("=> ASN ", args.asncontact, " contacts:")
            print(separator)
        result = pbuddy.pdb_asn_contacts(args.asncontact)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.ixpcc is not None:
        reasn = pbuddy.regex_validation(re_cc, args.ixpcc)
        if reasn is False:
            print(
                "That's not a valid Country Code, please type the CC with two letters (IBAN Alpha-2)."
            )
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print("=> IXPs available on ", args.ixpcc, ":")
            print(separator)
        result = pbuddy.pdb_ixps_by_cc(args.ixpcc)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.bogonspfx4 is True:
        if args.nonverbose is False:
            print(separator)
            print("=> IPv4 bogons list:")
            print(separator)
        result = pbuddy.tc_bogons_pfxs(
            "https://www.team-cymru.org/Services/Bogons/bogon-bn-nonagg.txt"
        )
        for item in result:
            print("".join(map(str, item)))
        if args.nonverbose is False:
            print(separator)
    if args.fbogonspfx4 is True:
        if args.nonverbose is False:
            print(separator)
            print("=> IPv4 full (+unallocated) bogons list:")
            print(separator)
        result = pbuddy.tc_bogons_pfxs(
            "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
        )
        for item in result:
            print("".join(map(str, item)))
        if args.nonverbose is False:
            print(separator)
    if args.fbogonspfx6 is True:
        if args.nonverbose is False:
            print(separator)
            print("=> IPv6 full (+unallocated) bogons list:")
            print(separator)
        result = pbuddy.tc_bogons_pfxs(
            "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt"
        )
        for item in result:
            print("".join(map(str, item)))
        if args.nonverbose is False:
            print(separator)
    if args.upstreams is not None:
        reasn = pbuddy.regex_validation(re_asn, args.upstreams)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print("=> ASN ", args.upstreams, " upstreams are:")
            print(separator)
        result = pbuddy.bv_asn_upstreams(args.upstreams)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.downstreams is not None:
        reasn = pbuddy.regex_validation(re_asn, args.downstreams)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print("=> ASN ", args.downstreams, " downstreams are:")
            print(separator)
        result = pbuddy.bv_asn_downstreams(args.downstreams)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.whois is not None:
        reasn = pbuddy.regex_validation(re_asn, args.whois)
        repfx = pbuddy.pfx_validation(args.whois)
        if reasn is False and repfx is False:
            print(
                "That's not a valid ASN or prefix, please type the ASN without the suffix AS."
            )
            sys.exit(1)
        if reasn is True:
            if args.nonverbose is False:
                print(separator)
                print("=> ASN ", args.whois, " information:")
                print(separator)
            result = pbuddy.bv_asn_whois(args.whois)
            print(json.dumps(result, indent=4))
            if args.nonverbose is False:
                print(separator)
        elif repfx is True:
            if args.nonverbose is False:
                print(separator)
                print("=> Prefix ", args.whois, " information:")
                print(separator)
            result = pbuddy.bv_pfx_whois(args.whois)
            print(json.dumps(result, indent=4))
            if args.nonverbose is False:
                print(separator)
    if args.ipwhois is not None:
        reip = pbuddy.ip_validation(args.ipwhois)
        if reip is False:
            print("That's not a valid IP, please type the IP without the network mask.")
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print("=> Prefix ", args.ipwhois, " information:")
            print(separator)
        result = pbuddy.ii_ip_whois(args.ipwhois)
        print(json.dumps(result, indent=4))
        if args.nonverbose is False:
            print(separator)
    if args.bogonsasn is True:
        if args.nonverbose is False:
            print(separator)
            print("=> Bogons ASN list:")
            print(separator)
        result = pbuddy.ntt_bogons_asn()
        print(result)
        if args.nonverbose is False:
            print(separator)
    if args.asn_asnpfxaspathlength is not None:
        asn = args.asn_asnpfxaspathlength[0]
        threshold = args.asn_asnpfxaspathlength[1]
        asprepend = args.asn_asnpfxaspathlength[2]
        reasn = pbuddy.regex_validation(re_asn, args.asn_asnpfxaspathlength[0])
        repfx = pbuddy.regex_validation(re_int, args.asn_asnpfxaspathlength[1])
        reprep = pbuddy.regex_validation(re_yn, args.asn_asnpfxaspathlength[2])
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if repfx is False:
            print(
                "That's not a valid integer, please type an integer from 1 to 2 digits."
            )
            sys.exit(1)
        if reprep is False:
            print("That's not a valid option, please type an y [yes] or n [no].")
            sys.exit(1)
        if args.nonverbose is False:
            answer = None
            if asprepend == "y":
                answer = "considering as-prepend"
            elif asprepend == "n":
                answer = "not considering as-prepend"
            print(separator)
            print(
                "=> Getting prefixes for the ASN",
                asn,
                "where the AS-Path is greater than",
                threshold,
                "and",
                answer,
                ":",
            )
            print(separator)
        result = pbuddy.ripe_bv_pfxs_aspath_length(asn, threshold, asprepend)
        tuple_lpa = result[0]
        first_asns = result[1]
        second_asns = result[2]
        third_asns = result[3]
        nontransit = result[4]
        transit = result[5]
        direct = result[6]
        summary = pbuddy.ripe_bv_pfxs_aspath_length_summary(
            tuple_lpa, first_asns, second_asns, third_asns, nontransit, transit, direct
        )
        locations_d = summary[0]
        first_asn_d = summary[1]
        second_asn_d = summary[2]
        third_asn_d = summary[3]
        nontransit_d = summary[4]
        transit_d = summary[5]
        if args.nonverbose is False:
            print(separator)
        if args.nonverbose is False:
            print(separator)
            print("Summary => format [ ASN:COUNTER ]: ")
            print(separator)
        if int(threshold) <= 2:
            print(
                "First ASN (the other end ASN): ",
                [(":".join(map(str, item))) for item in first_asn_d],
            )
            print("")
            print(
                "Non transit peers directly attached to ASN",
                asn,
                ":",
                [(":".join(map(str, item))) for item in nontransit_d],
            )
            print("")
            print(
                "Transit upstreams for the ASN",
                asn,
                ":",
                [(":".join(map(str, item))) for item in transit_d],
            )
            print("")
            print("By locations:")
            for place in locations_d:
                print((":".join(map(str, place))))
        elif int(threshold) == 3:
            print(
                "First ASN (the other end ASN): ",
                [(":".join(map(str, item))) for item in first_asn_d],
            )
            print("")
            print(
                "Second ASN (the other end upstream): ",
                [(":".join(map(str, item))) for item in second_asn_d],
            )
            print("")
            print(
                "Non transit peers directly attached to ASN",
                asn,
                ":",
                [(":".join(map(str, item))) for item in nontransit_d],
            )
            print("")
            print(
                "Transit upstreams for the ASN",
                asn,
                ":",
                [(":".join(map(str, item))) for item in transit_d],
            )
            print("")
            print("By locations:")
            for place in locations_d:
                print((":".join(map(str, place))))
        elif int(threshold) >= 4:
            print(
                "First ASN (the other end ASN): ",
                [(":".join(map(str, item))) for item in first_asn_d],
            )
            print("")
            print(
                "Second ASN (the other end upstream): ",
                [(":".join(map(str, item))) for item in second_asn_d],
            )
            print("")
            print(
                "Third ASN (trying to find a common ASN on the path): ",
                [(":".join(map(str, item))) for item in third_asn_d],
            )
            print("")
            print(
                "Non transit peers directly attached to ASN",
                asn,
                ":",
                [(":".join(map(str, item))) for item in nontransit_d],
            )
            print("")
            print(
                "Transit upstreams for the ASN",
                asn,
                ":",
                [(":".join(map(str, item))) for item in transit_d],
            )
            print("")
            print("By locations:")
            for place in locations_d:
                print((": ".join(map(str, place))))
        if args.nonverbose is False:
            print(separator)
    if args.asn_upstreamtransient is not None:
        reasn = pbuddy.regex_validation(re_asn, args.asn_upstreamtransient)
        if reasn is False:
            print(asn_invalid)
            sys.exit(1)
        if args.nonverbose is False:
            print(separator)
            print(
                "=> Checking for upstreams on transient paths for the ASN",
                args.asn_upstreamtransient,
                ":",
            )
            print(separator)
        result = pbuddy.ripe_bv_upstreams_transient_path(args.asn_upstreamtransient)
        transient_paths = result[0]
        transient_ups = result[1]
        aspaths = result[2]
        full_aspaths = result[3]
        all_locations = result[4]
        locations = []
        transient_upstreams = {}
        for item in transient_paths:
            print("".join(map(str, item)))
            locations.append(item[0])
        locations_u = pbuddy.list_unique(locations)
        locations_dict = {}
        for location in locations_u:
            loc = locations.count(location)
            locations_dict[location] = loc
        asns_u = pbuddy.list_unique(transient_ups)
        for each in asns_u:
            rcount = aspaths.count(each[0])
            transient_upstreams[each[0]] = rcount
        transient_upstreams_d = sorted(
            transient_upstreams.items(), reverse=True, key=lambda x: x[1]
        )
        locations_d = sorted(locations_dict.items(), reverse=True, key=lambda x: x[1])
        if args.nonverbose is False:
            print(separator)
        print(
            "Transient upstreams for the ASN",
            args.asn_upstreamtransient,
            "[ Upstream transient ASN => Number of times this ASN was matched on the AS-Path => Total AS-Paths number seeing this ASN => Percentage ]:",
        )
        for item in transient_upstreams_d:
            upstreams_asn = item[0]
            upstreams_count = item[1]
            total_upstreams_count = full_aspaths.count(upstreams_asn)
            upstreams_percentage = round(
                100 * upstreams_count / total_upstreams_count, 2
            )
            print(
                "AS",
                upstreams_asn,
                "=>",
                upstreams_count,
                "=>",
                total_upstreams_count,
                "=>",
                upstreams_percentage,
                "%",
            )
        print("")
        print(
            "By locations [ Location => Number of transient upstreams ASNs on this location  => Total NLRI number seeing this location => Percentage ]:"
        )
        for place in locations_d:
            location = place[0]
            location_count = place[1]
            total_location_count = all_locations.count(location)
            location_percentage = round(100 * location_count / total_location_count, 2)
            print(
                location,
                "=>",
                location_count,
                "=>",
                total_location_count,
                "=>",
                location_percentage,
                "%",
            )
        if args.nonverbose is False:
            print(separator)

    if options is False:
        if len(sys.argv) == 1:
            parser.print_help(sys.stderr)
            sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted")
