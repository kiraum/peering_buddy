"""
Peering Buddy - Helping you dig data from internet for better decisions!
"""

# pylint: disable=too-many-locals, too-many-branches, too-many-statements, line-too-long, too-few-public-methods, too-many-lines, too-many-nested-blocks, too-many-arguments, too-many-public-methods

import ipaddress
import json
import re
import socket
import sys

import requests

from pbuddy.config import PDB_PASSWORD, PDB_USERNAME


class Bcolors:
    """
    ANSI colors class.

    Attributes:
        HEADER (str): ANSI escape code for header color.
        OKBLUE (str): ANSI escape code for blue color.
        OKGREEN (str): ANSI escape code for green color.
        WARNING (str): ANSI escape code for warning color.
        FAIL (str): ANSI escape code for fail color.
        ENDC (str): ANSI escape code to end color formatting.
        BOLD (str): ANSI escape code for bold text.
        UNDERLINE (str): ANSI escape code for underlined text.
    """

    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class PBuddy:
    """
    Peering Buddy
    """

    def regex_validation(self, regex, arginput):
        """
        Validates the input string against the provided regular expression pattern.

        Parameters:
            regex (str): The regular expression pattern to match against.
            arginput (str): The input string to be validated.

        Returns:
            bool: True if the input string matches the regex pattern, False otherwise.
        """
        regex = re.compile(regex)
        match = re.match(regex, arginput)
        return bool(match)

    def pfx_validation(self, prefix):
        """
        Validates the input string as a network prefix.

        Parameters:
            prefix (str): The input string to be validated as a network prefix.

        Returns:
            bool: True if the input string is a valid network prefix, False otherwise.
        """
        try:
            ipaddress.ip_network(prefix)
            return True
        except ValueError:
            return False

    def ip_validation(self, ipaddr):
        """
        Validates the input string as an IP address.

        Parameters:
            ipaddr (str): The input string to be validated as an IP address.

        Returns:
            bool: True if the input string is a valid IP address, False otherwise.
        """
        try:
            ipaddress.ip_address(ipaddr)
            return True
        except ValueError:
            return False

    def list_avg(self, list_l):
        """
        Calculates the average value of a list of integers.

        Parameters:
            list_l (list of int): The list of integers.

        Returns:
            float: The average value of the list.
        """
        return sum(list_l) / len(list_l)

    def ripe_asn_visibility(self, asn):
        """
        Retrieves ASN visibility using RIPE RIS.

        Parameters:
            asn (int): The ASN to check visibility for.

        Returns:
            dict: A dictionary containing visibility percentages for each AFI.
        """
        url = f"https://stat.ripe.net/data/routing-status/data.json?resource=AS{asn}"
        visibility_dict = {}
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = data["data"]
            for afi in result["visibility"]:
                visibility_perc = (
                    result["visibility"][afi]["ris_peers_seeing"]
                    / result["visibility"][afi]["total_ris_peers"]
                ) * 100
                visibility_dict[afi] = visibility_perc
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return visibility_dict

    def ripe_asn_announced_pfx(self, asn):
        """
        Retrieves announced prefixes to the internet using RIPE RIS.

        Parameters:
            asn (int): The ASN to retrieve announced prefixes for.

        Returns:
            list: A list of announced prefixes for the specified ASN.
        """
        url = (
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        )
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            pfxs = []
            for each in data["data"]["prefixes"]:
                pfxs.append(each["prefix"])
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return sorted(pfxs)

    def ripe_vrp_check(self, asn, pfx):
        """
        Checks ASN and prefix ROA validation using RIPE RIS.

        Parameters:
            asn (int): The ASN to check ROA validation for.
            pfx (str): The prefix to check ROA validation for.

        Returns:
            str: The validity status of the ASN and prefix ROA.
        """
        url = f"https://stat.ripe.net/data/rpki-validation/data.json?resource={asn}&prefix={pfx}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            try:
                vrp = data["data"]["validating_roas"][0]["validity"]
            except IndexError:
                vrp = data["data"]["status"]
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return vrp

    def ripe_ris_lg(self, pfx, field):
        """
        Retrieves RIPE RIS looking glass data for a given prefix.

        Parameters:
            pfx (str): The prefix to retrieve looking glass data for.
            field (str): The field to filter the data on.

        Returns:
            dict: A dictionary containing the filtered looking glass data.
                If no field is provided, returns the raw looking glass data.
        """
        url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={pfx}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            if field:
                filtered = {}
                for ris in data["data"]["rrcs"]:
                    pfxattr = {}
                    attribute = []
                    for peer in ris["peers"]:
                        attribute.append(peer[field])
                    pfxattr[pfx] = attribute
                    filtered[ris["location"]] = pfxattr
                result = filtered
            else:
                result = data["data"]["rrcs"]
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def ripe_aspth_length_overview(self, asn):
        """
        Retrieves AS-Path length overview for a given ASN.

        Parameters:
            asn (int): The ASN to retrieve AS-Path length overview for.

        Returns:
            tuple: A tuple containing the stripped and unstripped
                max, min, and average AS-Path lengths.
        """
        url = f"https://stat.ripe.net/data/as-path-length/data.json?resource=AS{asn}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            aspath_s_max = []
            aspath_s_min = []
            aspath_s_avg = []
            aspath_u_max = []
            aspath_u_min = []
            aspath_u_avg = []
            for each in data["data"]["stats"]:
                aspath_s_max.append(each["stripped"]["max"])
                aspath_s_min.append(each["stripped"]["min"])
                aspath_s_avg.append(each["stripped"]["avg"])
                aspath_u_max.append(each["unstripped"]["max"])
                aspath_u_min.append(each["unstripped"]["min"])
                aspath_u_avg.append(each["unstripped"]["avg"])
            stripped_max = max(aspath_s_max)
            stripped_min = min(aspath_s_min)
            stripped_avg = round(self.list_avg(aspath_s_avg), 2)
            unstripped_max = max(aspath_u_max)
            unstripped_min = min(aspath_u_min)
            unstripped_avg = round(self.list_avg(aspath_u_avg), 2)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return (
            stripped_max,
            stripped_min,
            stripped_avg,
            unstripped_max,
            unstripped_min,
            unstripped_avg,
        )

    def ripe_aspath_length(self, asn, view, func, threshold):
        """
        Checks RIPE RIS detailed view for the ASN AS-Path length.

        Parameters:
            asn (int): The ASN to check AS-Path length for.
            view (str): The view to retrieve AS-Path length for.
            func (list): A list of functions to apply on the data.
            threshold (dict): A dictionary containing threshold filters.

        Returns:
            list: A list containing location and AS-Path length information.
        """
        url = f"https://stat.ripe.net/data/as-path-length/data.json?resource=AS{asn}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            aspathlength = []
            for each in data["data"]["stats"]:
                if func:
                    control = None
                    match = None
                    for metric in func:
                        if threshold[metric]:
                            if each[view][metric] >= int(threshold[metric]):
                                if control is not True or control is None:
                                    match = True
                            else:
                                match = False
                                control = True
                    if match is True:
                        aspathlength.append(each["location"])
                        aspathlength.append(each[view])
                else:
                    aspathlength.append(each["location"])
                    aspathlength.append(each[view])
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return aspathlength

    def ripe_asn_resources_overview(self, asn):
        """
        Retrieves ASN public resources overview.

        Parameters:
            asn (int): The ASN to retrieve public resources overview for.

        Returns:
            dict: A dictionary containing public resources overview data.
        """
        url = f"https://stat.ripe.net/data/routing-status/data.json?resource=AS{asn}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = data["data"]
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def ripe_asn_announces_consistency(self, asn):
        """
        Checks the consistency of ASN announces.

        Parameters:
            asn (int): The ASN to check consistency for.

        Returns:
            list: A list containing information about the consistency of the ASN announces.
        """
        url = f"https://stat.ripe.net/data/as-routing-consistency/data.json?resource=AS{asn}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            acons = []
            for each in data["data"]["prefixes"]:
                prefix = each["prefix"]
                whois = each["in_whois"]
                irr = each["irr_sources"]
                bgp = each["in_bgp"]
                if whois is False:
                    retrywhois = self.bv_pfx_whois(prefix)
                    try:
                        bvasn = retrywhois["asns"][0]["asn"]
                        if bvasn == int(asn):
                            whois = True
                    except IndexError:
                        ipnet = str(prefix).split("/")
                        retrywhois = self.ii_ip_whois(ipnet[0])
                        org = retrywhois["org"]
                        orgitems = str(org).split()
                        iiasn = orgitems[0].strip("AS")
                        if iiasn == asn:
                            whois = True
                vrp = self.ripe_vrp_check(asn, prefix)
                if irr != "-" and bgp is True and whois is True and vrp == "valid":
                    result = (
                        Bcolors.ENDC + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Announce looks good.",
                    )
                elif irr != "-" and bgp is True and whois is True and vrp == "unknown":
                    result = (
                        Bcolors.WARNING + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Announce looks ok, but check the reasons to not have a ROA/RPKI published."
                        + Bcolors.ENDC,
                    )
                elif (
                    irr != "-"
                    and bgp is True
                    and whois is True
                    and (vrp != "valid" or vrp != "unknown")
                ):
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Announce is registered on IRR and whois, but ROA/RPKI invalid!!!"
                        " (probably wrongly published ROA/RPKI certificates)"
                        + Bcolors.ENDC,
                    )
                elif irr == "-" and bgp is True and whois is False and vrp == "valid":
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Check your announce, ROA/RPKI is valid, not registered on IRR and whois "
                        "(probably malicious activity or hijack)." + Bcolors.ENDC,
                    )
                elif irr == "-" and bgp is True and whois is False and vrp == "unknown":
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Check your announce, ROA/RPKI not published, not registered on IRR and whois "
                        "(probably fat finger or hijack)." + Bcolors.ENDC,
                    )
                elif (
                    irr == "-"
                    and bgp is True
                    and whois is False
                    and (vrp != "valid" or vrp != "unknown")
                ):
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Check your announce, ROA/RPKI not published, not registered on IRR and whois "
                        "(probably fat finger or hijack)." + Bcolors.ENDC,
                    )
                elif irr == "-" and bgp is True and whois is True and vrp == "valid":
                    result = (
                        Bcolors.WARNING + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Missing prefix on IRR." + Bcolors.ENDC,
                    )
                elif irr == "-" and bgp is True and whois is True and vrp == "unknown":
                    result = (
                        Bcolors.WARNING + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Missing prefix on IRR and ROA/RPKI not published."
                        + Bcolors.ENDC,
                    )
                elif (
                    irr == "-"
                    and bgp is True
                    and whois is True
                    and (vrp != "valid" or vrp != "unknown")
                ):
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Missing prefix on IRR and ROA/RPKI invalid (probably wrongly published "
                        "ROA/RPKI certificates)." + Bcolors.ENDC,
                    )
                elif irr != "-" and bgp is True and whois is False and vrp == "valid":
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Check your announce, registered on IRR, but not on whois and ROA/RPKI not "
                        "published (probably malicious activity or hijack)."
                        + Bcolors.ENDC,
                    )
                elif irr != "-" and bgp is True and whois is False and vrp == "unknown":
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Check your announce, registered on IRR, but not on whois and ROA/RPKI not "
                        "published (probably fat finger, malicious activity or hijack)."
                        + Bcolors.ENDC,
                    )
                elif (
                    irr != "-"
                    and bgp is True
                    and whois is False
                    and (vrp != "valid" or vrp != "unknown")
                ):
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Check your announce, registered on IRR, but not on whois and VRP/RPKI is "
                        "invalid (probably fat finger, malicious activity or hijack).."
                        + Bcolors.ENDC,
                    )
                elif irr != "-" and bgp is False and whois is True and vrp == "valid":
                    result = (
                        Bcolors.WARNING + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Not announced, but probably need to clean IRR sources and ROA/RPKI "
                        "certificates." + Bcolors.ENDC,
                    )
                elif irr != "-" and bgp is False and whois is True and vrp == "unknown":
                    result = (
                        Bcolors.WARNING + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Not announced, but probably need to clean IRR sources."
                        + Bcolors.ENDC,
                    )
                elif (
                    irr != "-"
                    and bgp is False
                    and whois is True
                    and (vrp != "valid" or vrp != "unknown")
                ):
                    result = (
                        Bcolors.WARNING + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Not announced, but probably need to clean IRR sources and ROA/RPKI "
                        "certificates." + Bcolors.ENDC,
                    )
                else:
                    result = (
                        Bcolors.FAIL + "Prefix: ",
                        prefix,
                        " | Whois: ",
                        whois,
                        " | IRR: ",
                        irr,
                        " | BGP: ",
                        bgp,
                        " | RPKI: ",
                        vrp,
                        " => Check this ONE(unknown)!!!" + Bcolors.ENDC,
                    )
                acons.append(result)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return acons

    def tc_public_lg(self):
        """
        Use sentex.ca DNS entries to get public looking glass available. (Deprecated)

        Returns:
            dict: A dictionary containing the reverse DNS and IP addresses of available looking glasses.
        """
        lgs = {}
        for i in range(1, 16):
            hostname = "routeserver" + str(i) + ".sentex.ca"
            try:
                answer = socket.gethostbyname_ex(hostname)
                rdns = answer[0]
                ipaddr = answer[2]
                lgs[rdns] = ipaddr
            except socket.gaierror:
                pass
        return lgs

    def pdb_asn_asset(self, asn):
        """
        Return ASN as-set from PeeringDB.

        Args:
            asn (str): ASN number.

        Returns:
            dict: ASN as-set information.
        """
        url = f"https://www.peeringdb.com/api/as_set/{asn}"
        with requests.Session() as session:
            if PDB_USERNAME != "" and PDB_PASSWORD != "":
                session.auth = (PDB_USERNAME, PDB_PASSWORD)
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = data["data"]
        elif response.status_code == 429:
            print("ERROR | PeeringDB rate-limit.")
            sys.exit(1)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def ripe_expand_asset(self, asset):
        """
        Expand AS-SET. (Deprecated)

        Args:
            asset (str): AS-SET to expand.

        Returns:
            dict: Expanded AS-SET information.
        """
        url = f"https://rest.db.ripe.net/search.json?query-string={asset}&type-filter=as-set&flags=no-referenced&flags=no-irt"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            objects = data["objects"]["object"]
            result = []
            result_dict = {}
            for obj in objects:
                for attribute in obj["attributes"]["attribute"]:
                    if attribute["name"] == "members":
                        result.append(attribute["value"])
            result_dict[asset] = result
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result_dict

    def nlnog_expand_asset(self, asset):
        """
        Expand AS-SET.

        Args:
            asset (str): AS-SET to expand.

        Returns:
            dict: Expanded AS-SET information.
        """
        url = f"https://irrexplorer.nlnog.net/api/sets/expand/{asset}"
        with requests.Session() as session:
            response = session.get(url, timeout=30)
        if response.status_code == 200:
            asset_json = json.loads(response.text)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return asset_json

    def nlnog_resource_health_check(self, resource, resource_type):
        """
        Resource health check.

        Args:
            resource (str): Resource identifier (ASN or prefix).
            resource_type (str): Type of resource ("asn" or "prefix").

        Returns:
            dict: Resource health information.
        """
        resource_data = {}
        if resource_type == "asn":
            url = f"https://irrexplorer.nlnog.net/api/prefixes/asn/AS{resource}"
        elif resource_type == "prefix":
            url = f"https://irrexplorer.nlnog.net/api/prefixes/prefix/{resource}"
        with requests.Session() as session:
            response = session.get(url, timeout=30)
        if response.status_code == 200:
            data = json.loads(response.text)
            if resource_type == "asn":
                direct_origin = data["directOrigin"]
            elif resource_type == "prefix":
                direct_origin = data
            for each in direct_origin:
                resource_data[each["prefix"]] = {
                    "origin": each["bgpOrigins"],
                    "status": each["messages"],
                    "score": each["goodnessOverall"],
                }
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return resource_data

    def pdb_ixps_pfxs(self):
        """
        Return IXP prefixes from PeeringDB.

        Returns:
            list: List of IXP prefixes.
        """
        url = "https://www.peeringdb.com/api/ixpfx"
        with requests.Session() as session:
            if PDB_USERNAME != "" and PDB_PASSWORD != "":
                session.auth = (PDB_USERNAME, PDB_PASSWORD)
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = []
            for each in data["data"]:
                prefix = each["prefix"]
                result.append(prefix)
        elif response.status_code == 429:
            print("ERROR | PeeringDB rate-limit.")
            sys.exit(1)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return sorted(result)

    def pdb_asn_info(self, asn):
        """
        Return ASN info on PeeringDB.

        Args:
            asn (str): ASN number.

        Returns:
            list: List of ASN information.
        """
        url = f"https://www.peeringdb.com/api/net?asn={asn}"
        with requests.Session() as session:
            if PDB_USERNAME != "" and PDB_PASSWORD != "":
                session.auth = (PDB_USERNAME, PDB_PASSWORD)
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = []
            for each in data["data"]:
                selected = (
                    "Name: " + each["name"],
                    "Aka: " + each["aka"],
                    "Website: " + each["website"],
                    "ASN: " + str(each["asn"]),
                    "LookingGlass: " + each["looking_glass"],
                    "RouteServer " + each["route_server"],
                    "IRR AS-SET: " + each["irr_as_set"],
                    "Type: " + each["info_type"],
                    "IPv4 Prefixes: " + str(each["info_prefixes4"]),
                    "IPv6 Prefixes: " + str(each["info_prefixes6"]),
                    "Traffic: " + each["info_traffic"],
                    "Ratio: " + each["info_ratio"],
                    "Scope: " + each["info_scope"],
                    "Unicast: " + str(each["info_unicast"]),
                    "Multicast: " + str(each["info_multicast"]),
                    "IPv6: " + str(each["info_ipv6"]),
                    "Never via RS: " + str(each["info_never_via_route_servers"]),
                    "Notes: " + each["notes"],
                    "Policy url: " + each["policy_url"],
                    "Policy: " + each["policy_general"],
                    "Policy locations: " + each["policy_locations"],
                    "Policy Ratio Requirement: " + str(each["policy_ratio"]),
                    "Policy Contracts: " + each["policy_contracts"],
                )
                result.append(selected)
        elif response.status_code == 429:
            print("ERROR | PeeringDB rate-limit.")
            sys.exit(1)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def pdb_asn_ixps_ips(self, asn):
        """
        Return ASN IPs allocated on IXPs from PeeringDB.

        Args:
            asn (str): ASN number.

        Returns:
            list: List of ASN IPs allocated on IXPs.
        """
        url = f"https://www.peeringdb.com/api/netixlan?asn={asn}"
        with requests.Session() as session:
            if PDB_USERNAME != "" and PDB_PASSWORD != "":
                session.auth = (PDB_USERNAME, PDB_PASSWORD)
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            ixps = []
            for each in data["data"]:
                selected = (
                    each["name"],
                    " | Speed: ",
                    each["speed"],
                    " | IP4: ",
                    each["ipaddr4"],
                    " | IP6: ",
                    each["ipaddr6"],
                    " | RS: ",
                    each["is_rs_peer"],
                )
                ixps.append(selected)
        elif response.status_code == 429:
            print("ERROR | PeeringDB rate-limit.")
            sys.exit(1)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return ixps

    def pdb_asn_contacts(self, asn):
        """
        Return ASN contacts from PeeringDB.

        Args:
            asn (str): ASN number.

        Returns:
            list: List of ASN contacts.
        """
        url = f"https://www.peeringdb.com/api/netixlan?asn={asn}"
        with requests.Session() as session:
            if PDB_USERNAME != "" and PDB_PASSWORD != "":
                session.auth = (PDB_USERNAME, PDB_PASSWORD)
            response = session.get(url)
        netid = []
        if response.status_code == 200:
            data = json.loads(response.text)
            for each in data["data"]:
                selected = each["net_id"]
                netid.append(selected)
            netid = sorted(set(netid))
        elif response.status_code == 429:
            print("ERROR | PeeringDB rate-limit.")
            sys.exit(1)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        result = []
        for each in netid:
            url = f"https://www.peeringdb.com/api/poc?net_id={each}"
            with requests.Session() as session:
                if PDB_USERNAME != "" and PDB_PASSWORD != "":
                    session.auth = (PDB_USERNAME, PDB_PASSWORD)
                response = session.get(url)
            if response.status_code == 200:
                data = json.loads(response.text)
                for contact in data["data"]:
                    selected = (
                        "Role: " + contact["role"],
                        "Name: " + contact["name"],
                        "Phone: " + contact["phone"],
                        "Email: " + contact["email"],
                        "URL " + contact["url"],
                    )
                    result.append(selected)
            elif response.status_code == 429:
                print("ERROR | PeeringDB rate-limit.")
                sys.exit(1)
            else:
                print("ERROR | HTTP status != 200")
                sys.exit(1)
        return result

    def pdb_ixps_by_cc(self, ccode):
        """
        Return IXPs by country code iso-3166-1 alpha-2 from PeeringDB.

        Args:
            ccode (str): Country code iso-3166-1 alpha-2.

        Returns:
            list: List of IXPs in the specified country.
        """
        url = f"https://www.peeringdb.com/api/ix?country={ccode}"
        with requests.Session() as session:
            if PDB_USERNAME != "" and PDB_PASSWORD != "":
                session.auth = (PDB_USERNAME, PDB_PASSWORD)
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = []
            for each in data["data"]:
                selected = (
                    "Name: " + each["name"],
                    "Long_name: " + each["name_long"],
                    "City: " + each["city"],
                    "Country: " + each["country"],
                    "Continent: " + each["region_continent"],
                    "Notes: " + each["notes"],
                    "Unicast: " + str(each["proto_unicast"]),
                    "Multicast: " + str(each["proto_multicast"]),
                    "IPv6: " + str(each["proto_ipv6"]),
                    "URL: " + each["website"],
                    "URL Stats: " + each["url_stats"],
                    "Tech Email: " + each["tech_email"],
                    "Tech Phone: " + each["tech_phone"],
                    "Policy Email: " + each["policy_email"],
                    "Policy Phone: " + each["policy_phone"],
                    "Networks[ASN]: " + str(each["net_count"]),
                )
                result.append(selected)
        elif response.status_code == 429:
            print("ERROR | PeeringDB rate-limit.")
            sys.exit(1)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def tc_bogons_pfxs(self, url):
        """
        Return a list of bogons prefixes.

        Args:
            url (str): URL to fetch bogons prefixes.

        Returns:
            list: List of bogons prefixes.
        """
        url = f"{url}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = response.text
            result = []
            for line in data.splitlines():
                if not re.match(r"^#", line) and not re.match(r"^\s*$", line):
                    result.append(line)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def bv_asn_upstreams(self, asn):
        """
        Return ASN upstreams from BGPView.

        Args:
            asn (str): ASN number.

        Returns:
            list: List of ASN upstreams.
        """
        url = f"https://api.bgpview.io/asn/{asn}/upstreams"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = data["data"]
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def bv_asn_downstreams(self, asn):
        """
        Return ASN downstreams from BGPView.

        Args:
            asn (str): ASN number.

        Returns:
            list: List of ASN downstreams.
        """
        url = f"https://api.bgpview.io/asn/{asn}/downstreams"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = data["data"]
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def bv_asn_whois(self, asn):
        """
        Return ASN whois information from BGPView.

        Args:
            asn (str): ASN number.

        Returns:
            dict: ASN whois information.
        """
        url = f"https://api.bgpview.io/asn/{asn}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = data["data"]
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def bv_pfx_whois(self, pfx):
        """
        Return prefix whois information from BGPView.

        Args:
            pfx (str): IP prefix.

        Returns:
            dict: Prefix whois information.
        """
        url = f"https://api.bgpview.io/prefix/{pfx}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            result = data["data"]
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def ii_ip_whois(self, ipaddr):
        """
        Return IP whois information from ipinfo.io.

        Args:
            ipaddr (str): IP address.

        Returns:
            dict: IP whois information.
        """
        url = f"https://ipinfo.io/{ipaddr}"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            result = json.loads(response.text)
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return result

    def ntt_bogons_asn(self):
        """
        Return ASN bogons list and examples from NTT.

        Returns:
            str: ASN bogons list and examples.
        """
        url = "http://as2914.net/bogon_asns/configuration_examples.txt"
        with requests.Session() as session:
            response = session.get(url)
        if response.status_code == 200:
            data = response.text
        else:
            print("ERROR | HTTP status != 200")
            sys.exit(1)
        return data

    def list_unique(self, list_l):
        """
        Return unique elements from a list.

        Args:
            list_l (list): Input list.

        Returns:
            list: List containing unique elements.
        """
        ulist = []
        for item in list_l:
            if item not in ulist:
                ulist.append(item)
        return ulist

    def ripe_bv_pfxs_aspath_length(self, asn, threshold, asprepend):
        """
        Check AS path and generate a summary analysis for first, second, third, non-transit, transit, and location.

        Args:
            asn (str): ASN number.
            threshold (int): Threshold value for AS path length.
            asprepend (str): Whether to consider AS path prepending.

        Returns:
            tuple: Tuple containing summary analysis for AS paths.
        """
        tuple_lpa = []
        first_asn = []
        second_asn = []
        third_asn = []
        direct = []
        prefixes = self.ripe_asn_announced_pfx(asn)
        for prefix in prefixes:
            lgs = self.ripe_ris_lg(prefix, "as_path")
            size = []
            for ris in lgs:
                size.append(len(ris))
            msize = max(size)
            for ris in lgs:
                nlri = lgs[ris]
                for pfx in nlri:
                    attributes = nlri[pfx]
                    for attribute in attributes:
                        attributenoprep = None
                        apl = None
                        if asprepend == "n":
                            attribute = " ".join(self.list_unique(attribute.split()))
                            apl = len(attribute.split())
                        elif asprepend == "y":
                            attributenoprep = " ".join(
                                self.list_unique(attribute.split())
                            )
                            apl = len(attributenoprep.split())
                        if apl >= int(threshold):
                            entry = (
                                f"{ris:<{msize}}",
                                " | ",
                                pfx,
                                " | ",
                                attribute,
                            )
                            if asprepend == "n":
                                if apl <= 0:
                                    first_asn = []
                                    second_asn = []
                                    third_asn = []
                                    direct = []
                                elif apl <= 1:
                                    first_asn.append(attribute.split()[0])
                                    second_asn = []
                                    third_asn = []
                                    direct.append(attribute.split()[-1])
                                elif apl == 2:
                                    first_asn.append(attribute.split()[0])
                                    second_asn = []
                                    third_asn = []
                                    direct.append(attribute.split()[-2])
                                elif apl == 3:
                                    first_asn.append(attribute.split()[0])
                                    second_asn.append(attribute.split()[1])
                                    third_asn = []
                                    direct.append(attribute.split()[-2])
                                else:
                                    first_asn.append(attribute.split()[0])
                                    second_asn.append(attribute.split()[1])
                                    third_asn.append(attribute.split()[2])
                                    direct.append(attribute.split()[-2])
                            elif asprepend == "y":
                                if apl <= 0:
                                    first_asn = []
                                    second_asn = []
                                    third_asn = []
                                    direct = []
                                elif apl == 1:
                                    first_asn.append(attributenoprep.split()[0])
                                    second_asn = []
                                    third_asn = []
                                    direct.append(attributenoprep.split()[-1])
                                elif apl == 2:
                                    first_asn.append(attributenoprep.split()[0])
                                    second_asn = []
                                    third_asn = []
                                    direct.append(attributenoprep.split()[-2])
                                elif apl == 3:
                                    first_asn.append(attributenoprep.split()[0])
                                    second_asn.append(attributenoprep.split()[1])
                                    third_asn = []
                                    direct.append(attributenoprep.split()[-2])
                                else:
                                    first_asn.append(attributenoprep.split()[0])
                                    second_asn.append(attributenoprep.split()[1])
                                    third_asn.append(attributenoprep.split()[2])
                                    direct.append(attributenoprep.split()[-2])
                            tuple_lpa.append(entry)
        asns = []
        upstreams = self.bv_asn_upstreams(asn)
        for upstream in upstreams["ipv4_upstreams"]:
            asn_ups = str(upstream["asn"])
            asns.append(asn_ups)
        for upstream in upstreams["ipv6_upstreams"]:
            asn_ups = str(upstream["asn"])
            asns.append(asn_ups)
        upstreams_s = sorted(set(asns))
        transit_m = set(upstreams_s).intersection(set(direct))
        nontransit_m = set(direct).difference(set(upstreams_s))
        nontransit = list(nontransit_m)
        transit = list(transit_m)
        return tuple_lpa, first_asn, second_asn, third_asn, nontransit, transit, direct

    def ripe_bv_upstreams_transient_path(self, asn):
        """
        Return ASN upstreams on a transient path.

        Args:
            asn (str): ASN number.

        Returns:
            tuple: Tuple containing upstreams on a transient path.
        """
        data = self.ripe_bv_pfxs_aspath_length(asn, 0, "n")
        upstreams = sorted(set(data[5]))
        nlri = data[0]
        transient_paths = []
        transient_upstreams = []
        aspaths = []
        full_aspaths = []
        all_locations = []
        for each in nlri:
            aspath = each[-1]
            aspath_l = aspath.split()
            for as_hop in aspath_l:
                full_aspaths.append(as_hop)
            location = each[0]
            all_locations.append(location)
            del aspath_l[-2:]
            match = set(upstreams).intersection(set(aspath_l))
            if match:
                transient_paths.append(each)
                transient_upstreams.append(sorted(match))
                for eachas in aspath_l:
                    aspaths.append(eachas)
        return (
            transient_paths,
            transient_upstreams,
            aspaths,
            full_aspaths,
            all_locations,
        )

    def ripe_bv_pfxs_aspath_length_summary(
        self,
        tuple_lpa,
        first_asns,
        second_asns,
        third_asns,
        nontransit,
        transit,
        direct,
    ):
        """
        Create AS path summary.

        Args:
            tuple_lpa (list): List of tuples containing AS path details.
            first_asns (list): List of first ASNs.
            second_asns (list): List of second ASNs.
            third_asns (list): List of third ASNs.
            nontransit (list): List of non-transit ASNs.
            transit (list): List of transit ASNs.
            direct (list): List of direct ASNs.

        Returns:
            tuple: Tuple containing AS path summary.
        """
        locations = []
        for item in tuple_lpa:
            print("".join(map(str, item)))
            locations.append(item[0])
        locations_u = self.list_unique(locations)
        locations_dict = {}
        for location in locations_u:
            loc = locations.count(location)
            locations_dict[location] = loc
        uniq_first_asn = sorted(set(first_asns))
        uniq_second_asn = sorted(set(second_asns))
        uniq_third_asn = sorted(set(third_asns))
        uniq_nontransit = sorted(set(nontransit))
        uniq_transit = sorted(set(transit))
        first_asn = {}
        second_asn = {}
        third_asn = {}
        nontransit = {}
        transit = {}
        for each in uniq_first_asn:
            rcount = first_asns.count(each)
            first_asn[each] = rcount
        for each in uniq_second_asn:
            rcount = second_asns.count(each)
            second_asn[each] = rcount
        for each in uniq_third_asn:
            rcount = third_asns.count(each)
            third_asn[each] = rcount
        for each in uniq_nontransit:
            rcount = direct.count(each)
            nontransit[each] = rcount
        for each in uniq_transit:
            rcount = direct.count(each)
            transit[each] = rcount
        first_asn_d = sorted(first_asn.items(), reverse=True, key=lambda x: x[1])
        second_asn_d = sorted(second_asn.items(), reverse=True, key=lambda x: x[1])
        third_asn_d = sorted(third_asn.items(), reverse=True, key=lambda x: x[1])
        nontransit_d = sorted(nontransit.items(), reverse=True, key=lambda x: x[1])
        transit_d = sorted(transit.items(), reverse=True, key=lambda x: x[1])
        locations_d = sorted(locations_dict.items(), reverse=True, key=lambda x: x[1])
        return (
            locations_d,
            first_asn_d,
            second_asn_d,
            third_asn_d,
            nontransit_d,
            transit_d,
        )
