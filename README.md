# peering_buddy

Peering Buddy is just putting a bunch of API queries together with some logic, making our life "easier".

### install
````
git clone git@github.com:kiraum/peering_buddy.git
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
````

### configuration

PeeringDB apply an aggressive rate-limit for anonymous requests, so if you are facing "ERROR | PeeringDB rate-limit.", please configure add your PeeringDB user/password to pbuddy/config.py:
````
PDB_USERNAME = "Your_User!"
PDB_PASSWORD = "Your_Pass!"
````
PeeringDB still apply rate-limit for authenticated requests, but the valeus are more than enough for mostly of the cases. If you want to understand more about, check the current (PeeringDB configurations](https://github.com/peeringdb/peeringdb/blob/master/mainsite/settings/__init__.py#L302).

### use it
````
% ./peering_buddy.py
usage: peering_buddy.py [-h] [-av ASN] [-ap ASN] [-ar ASN] [-lg PREFIX] [-al ASN] [-as ASN] [-au ASN] [-tm INTEGER] [-ti INTEGER] [-ta INTEGER] [-ao ASN] [-ac ASN] [-pa ASN THRESHOLD PREPEND[y|n]] [-tu ASN] [-gu ASN] [-gd ASN] [-gw [ASN|PREFIX]] [-wi IP]
                        [-aa ASN] [-ip] [-ai ASN] [-ii ASN] [-gc ASN] [-cc ASN] [-gl] [-bo] [-b4] [-b6] [-ba] [-nv]

Peering Buddy - Helping you dig data from internet for better decisions!

optional arguments:
  -h, --help                                                                           show this help message and exit
  -av ASN, --asn-visibility ASN                                                        [RIPE] Check ASN visibility RIPE RIS sensors.
  -ap ASN, --asn-announced-pfxs ASN                                                    [RIPE] Check ASN announced prefixes to internet.
  -ar ASN, --asn-roa-validation ASN                                                    [RIPE] Check ASN RPKI/ROA validation for announced prefixes.
  -lg PREFIX, --looking-glass PREFIX                                                   [RIPE] Get prefix using RIPE RIS as Looking Glass.
  -al ASN, --aspath-length-overview ASN                                                [RIPE] Check AS-Path length overview.
  -as ASN, --aspath-lenghth-stripped ASN                                               [RIPE] Check AS-Path length stripped [no as-prepend].
  -au ASN, --aspath-lenghth-unstripped ASN                                             [RIPE] Check AS-Path length unstripped [with as-prepend].
  -tm INTEGER, --threshold-max INTEGER                                                 [RIPE][as|au] Threshold [>=] to be used with -as and -au for max.
  -ti INTEGER, --threshold-min INTEGER                                                 [RIPE][as|au] Threshold [>=] to be used with -as and -au for min.
  -ta INTEGER, --threshold-avg INTEGER                                                 [RIPE][as|au] Threshold [>=] to be used with -as and -au for avg.
  -ao ASN, --asn-overview ASN                                                          [RIPE] Check ASN public resources overview.
  -ac ASN, --asn-announce-consistency ASN                                              [RIPE][BGPView][IPInfo] Check ASN announces consistency.
  -pa ASN THRESHOLD PREPEND[y|n], --asn-pfxs-aspath-length ASN THRESHOLD PREPEND[y|n]  [RIPE][BGPView] Check ASN prefixes where as-path length >= threshold.
  -tu ASN, --asn-upstreams-transient ASN                                               [RIPE][BGPView] Check ASN upstreams on transient paths.
  -gu ASN, --asn-upstreams ASN                                                         [BGPView] Get ASN upstreams.
  -gd ASN, --asn-downstreams ASN                                                       [BGPView] Get ASN downstreams.
  -gw [ASN|PREFIX], --whois [ASN|PREFIX]                                               [BGPView] Get ASN/Prefix whois information.
  -wi IP, --whois-ip IP                                                                [IPInfo] Get IP whois information.
  -aa ASN, --asset ASN                                                                 [PeeringDB][RIPE] Check ASN AS-SET and expand it. Limited to RIPE ASNs.
  -ip, --pdb-ixp-pfxs                                                                  [PeeringDB] Get IXPs prefixes.
  -ai ASN, --pdb-asn-info ASN                                                          [PeeringDB] Get ASN information on PeeringDB.
  -ii ASN, --pdb-asn-ips ASN                                                           [PeeringDB] Get ASN IPS allocated on IXPs.
  -gc ASN, --pdb-asn-contact ASN                                                       [PeeringDB] Get ASN contact.
  -cc ASN, --pdb-ixp-bycc ASN                                                          [PeeringDB] Get IXPs by Country Code [iso-3166-1 alpha-2].
  -gl, --lgs                                                                           [Team Cymrus] Check a list of public LookingGlass.
  -bo, --bogons                                                                        [Team Cymrus] Get ip4 bogons list.
  -b4, --bogons-v4                                                                     [Team Cymrus] Get ip4 full (+unallocated) bogons list.
  -b6, --bogons-v6                                                                     [Team Cymrus] Get ip6 full (+unallocated) bogons list.
  -ba, --bogons-asn                                                                    [NTT] Get ASN bogons list/examples.
  -nv, --non-verbose                                                                   Remove human-like text to the output.
````

## usage examples
````
% ./peering_buddy.py -av 3333
================================================================================
=> Visibilit percentage (RIS point of view) 3333 :
================================================================================
Visibility for v4: 99.46236559139786%
Visibility for v6: 100.0%
================================================================================
````

````
% ./peering_buddy.py -ap 3333
================================================================================
=> We are seeing the prefixes being announced to the internet for the ASN 3333 :
================================================================================
[
    "193.0.0.0/21",
    "193.0.10.0/23",
    "193.0.12.0/23",
    "193.0.18.0/23",
    "193.0.20.0/23",
    "193.0.22.0/23",
    "2001:67c:2e8::/48"
]
================================================================================
````

````
% ./peering_buddy.py -ar 3333
================================================================================
=> We are validating the prefixes announced by the ASN 3333 :
================================================================================
Prefix 193.0.0.0/21 is valid
Prefix 193.0.10.0/23 is valid
Prefix 193.0.12.0/23 is valid
Prefix 193.0.18.0/23 is valid
Prefix 193.0.20.0/23 is valid
Prefix 193.0.22.0/23 is valid
Prefix 2001:67c:2e8::/48 is valid
================================================================================
````

````
% ./peering_buddy.py -lg 193.0.0.0/21 
================================================================================
=> Looking glass results for the prefix 193.0.0.0/21 :
================================================================================
[
    {
        "rrc": "RRC00",
        "location": "Amsterdam, Netherlands",
        "peers": [
            {
                "asn_origin": "3333",
                "as_path": "34854 3333",
                "community": "34854:1001",
                "last_updated": "2023-06-10T05:56:34",
                "prefix": "193.0.0.0/21",
                "peer": "2.56.11.1",
                "origin": "IGP",
                "next_hop": "2.56.11.1",
                "latest_time": "2023-06-13T19:37:15"
            },
            {
                "asn_origin": "3333",
                "as_path": "59919 12779 3333",
                "community": "12779:10301 12779:20301 12779:65097",
                "last_updated": "2023-05-05T02:06:13",
                "prefix": "193.0.0.0/21",
                "peer": "5.178.95.254",
                "origin": "IGP",
                "next_hop": "5.178.95.254",
                "latest_time": "2023-06-13T19:37:14"
            },
...
            {
                "asn_origin": "3333",
                "as_path": "201333 6762 3333",
                "community": "6762:30 6762:13100",
                "last_updated": "2023-06-05T03:48:28",
                "prefix": "193.0.0.0/21",
                "peer": "217.29.67.74",
                "origin": "IGP",
                "next_hop": "217.29.67.74",
                "latest_time": "2023-06-13T19:37:15"
            }
        ]
    }
]
================================================================================
````

````
% ./peering_buddy.py -al 3333
================================================================================
=> AS-Path length overview for the ASN 3333 :
================================================================================
Maximum AS-PATH Stripped [ignore as-prepend] =>  7
Minimum AS-PATH Stripped [ignore as-prepend] =>  1
Average AS-PATH Stripped [ignore as-prepend] =>  3.13
Maximum AS-PATH Unstripped [considering as-prepend] =>  7
Minimum AS-PATH Unstripped [considering as-prepend] =>  1
Average AS-PATH Unstripped [considering as-prepend] =>  3.15
================================================================================
````

````
% ./peering_buddy.py -as 3333
================================================================================
=> AS-Path length (min, max and avg - stripping as-prepends) for the ASN 3333 :
================================================================================
[
    "RIPE-NCC Multihop, Amsterdam, Netherlands",
    {
        "sum": 1322,
        "min": 1,
        "max": 6,
        "avg": 3.672222222222222
    },
    "LINX / LONAP, London, United Kingdom",
    {
        "sum": 831,
        "min": 2,
        "max": 4,
        "avg": 2.9055944055944054
    },
    "AMS-IX / NL-IX, Amsterdam, Netherlands",
    {
        "sum": 746,
        "min": 2,
        "max": 4,
        "avg": 2.4220779220779223
    },
    "CIXP, Geneva, Switzerland",
    {
        "sum": 131,
        "min": 2,
        "max": 4,
        "avg": 2.7291666666666665
    },
    "VIX, Vienna, Austria",
    {
        "sum": 183,
        "min": 2,
        "max": 4,
        "avg": 2.5774647887323945
    },
    "DIX-IE / JPIX, Tokyo, Japan",
    {
        "sum": 120,
        "min": 3,
        "max": 7,
        "avg": 4.285714285714286
    },
    "Netnod, Stockholm, Sweden",
    {
        "sum": 173,
        "min": 2,
        "max": 4,
        "avg": 2.746031746031746
    },
    "MIX, Milan, Italy",
    {
        "sum": 329,
        "min": 2,
        "max": 4,
        "avg": 2.963963963963964
    },
    "NYIIX, New York City, New York, US",
    {
        "sum": 248,
        "min": 2,
        "max": 4,
        "avg": 3.492957746478873
    },
    "DE-CIX, Frankfurt, Germany",
    {
        "sum": 929,
        "min": 2,
        "max": 4,
        "avg": 2.9492063492063494
    },
    "MSK-IX, Moscow, Russian Federation",
    {
        "sum": 140,
        "min": 2,
        "max": 4,
        "avg": 2.857142857142857
    },
    "PAIX, Palo Alto, California, US",
    {
        "sum": 161,
        "min": 2,
        "max": 4,
        "avg": 3.22
    },
    "PTTMetro, Sao Paulo, Brazil",
    {
        "sum": 591,
        "min": 2,
        "max": 6,
        "avg": 3.436046511627907
    },
    "NOTA, Miami, Florida, US",
    {
        "sum": 37,
        "min": 2,
        "max": 3,
        "avg": 2.466666666666667
    },
    "Catnix, Barcelona, Spain",
    {
        "sum": 21,
        "min": 3,
        "max": 3,
        "avg": 3.0
    },
    "SwissIX, Zurich, Switzerland",
    {
        "sum": 520,
        "min": 2,
        "max": 4,
        "avg": 2.857142857142857
    },
    "France-IX, Paris, France",
    {
        "sum": 550,
        "min": 2,
        "max": 5,
        "avg": 3.197674418604651
    },
    "InterLAN, Bucharest, Romania",
    {
        "sum": 135,
        "min": 3,
        "max": 5,
        "avg": 4.090909090909091
    },
    "Equinix SG, Singapore, Singapore",
    {
        "sum": 211,
        "min": 2,
        "max": 4,
        "avg": 3.0142857142857142
    },
    "LACNIC Multihop, Montevideo, Uruguay",
    {
        "sum": 275,
        "min": 2,
        "max": 7,
        "avg": 3.4375
    },
    "RIPE-NCC Multihop, Amsterdam, Netherlands",
    {
        "sum": 1210,
        "min": 2,
        "max": 5,
        "avg": 3.4375
    },
    "UAE-IX, Dubai, UAE",
    {
        "sum": 88,
        "min": 2,
        "max": 4,
        "avg": 3.142857142857143
    }
]
================================================================================
````

````
% ./peering_buddy.py -au 3333
================================================================================
=> AS-Path length (min, max and avg - unstripping as-prepends) for the ASN 3333 :
================================================================================
[
    "RIPE-NCC Multihop, Amsterdam, Netherlands",
    {
        "sum": 1342,
        "min": 1,
        "max": 7,
        "avg": 3.727777777777778
    },
    "LINX / LONAP, London, United Kingdom",
    {
        "sum": 831,
        "min": 2,
        "max": 4,
        "avg": 2.9055944055944054
    },
    "AMS-IX / NL-IX, Amsterdam, Netherlands",
    {
        "sum": 746,
        "min": 2,
        "max": 4,
        "avg": 2.4220779220779223
    },
    "CIXP, Geneva, Switzerland",
    {
        "sum": 131,
        "min": 2,
        "max": 4,
        "avg": 2.7291666666666665
    },
    "VIX, Vienna, Austria",
    {
        "sum": 183,
        "min": 2,
        "max": 4,
        "avg": 2.5774647887323945
    },
    "DIX-IE / JPIX, Tokyo, Japan",
    {
        "sum": 120,
        "min": 3,
        "max": 7,
        "avg": 4.285714285714286
    },
    "Netnod, Stockholm, Sweden",
    {
        "sum": 173,
        "min": 2,
        "max": 4,
        "avg": 2.746031746031746
    },
    "MIX, Milan, Italy",
    {
        "sum": 335,
        "min": 2,
        "max": 5,
        "avg": 3.018018018018018
    },
    "NYIIX, New York City, New York, US",
    {
        "sum": 254,
        "min": 2,
        "max": 5,
        "avg": 3.5774647887323945
    },
    "DE-CIX, Frankfurt, Germany",
    {
        "sum": 941,
        "min": 2,
        "max": 6,
        "avg": 2.9873015873015873
    },
    "MSK-IX, Moscow, Russian Federation",
    {
        "sum": 140,
        "min": 2,
        "max": 4,
        "avg": 2.857142857142857
    },
    "PAIX, Palo Alto, California, US",
    {
        "sum": 161,
        "min": 2,
        "max": 4,
        "avg": 3.22
    },
    "PTTMetro, Sao Paulo, Brazil",
    {
        "sum": 591,
        "min": 2,
        "max": 6,
        "avg": 3.436046511627907
    },
    "NOTA, Miami, Florida, US",
    {
        "sum": 37,
        "min": 2,
        "max": 3,
        "avg": 2.466666666666667
    },
    "Catnix, Barcelona, Spain",
    {
        "sum": 21,
        "min": 3,
        "max": 3,
        "avg": 3.0
    },
    "SwissIX, Zurich, Switzerland",
    {
        "sum": 520,
        "min": 2,
        "max": 4,
        "avg": 2.857142857142857
    },
    "France-IX, Paris, France",
    {
        "sum": 550,
        "min": 2,
        "max": 5,
        "avg": 3.197674418604651
    },
    "InterLAN, Bucharest, Romania",
    {
        "sum": 141,
        "min": 3,
        "max": 5,
        "avg": 4.2727272727272725
    },
    "Equinix SG, Singapore, Singapore",
    {
        "sum": 211,
        "min": 2,
        "max": 4,
        "avg": 3.0142857142857142
    },
    "LACNIC Multihop, Montevideo, Uruguay",
    {
        "sum": 275,
        "min": 2,
        "max": 7,
        "avg": 3.4375
    },
    "RIPE-NCC Multihop, Amsterdam, Netherlands",
    {
        "sum": 1239,
        "min": 2,
        "max": 7,
        "avg": 3.5198863636363638
    },
    "UAE-IX, Dubai, UAE",
    {
        "sum": 88,
        "min": 2,
        "max": 4,
        "avg": 3.142857142857143
    }
]
================================================================================
````

````
% ./peering_buddy.py -ao 3333
================================================================================
=> Public Internet resources overview for the ASN 3333 :
================================================================================
{
    "first_seen": {
        "prefix": "193.0.0.0/22",
        "origin": "3333",
        "time": "2000-08-18T08:00:00"
    },
    "last_seen": {
        "prefix": "193.0.18.0/23",
        "origin": "3333",
        "time": "2023-06-13T08:00:00"
    },
    "visibility": {
        "v4": {
            "ris_peers_seeing": 370,
            "total_ris_peers": 372
        },
        "v6": {
            "ris_peers_seeing": 371,
            "total_ris_peers": 371
        }
    },
    "announced_space": {
        "v4": {
            "prefixes": 6,
            "ips": 4608
        },
        "v6": {
            "prefixes": 1,
            "48s": 1
        }
    },
    "observed_neighbours": 857,
    "resource": "3333",
    "query_time": "2023-06-13T08:00:00"
}
================================================================================
````

````
% ./peering_buddy.py -ac 3333
================================================================================
=> ASN announces consistency for the ASN 3333 :
================================================================================
Prefix: 193.0.0.0/21 | Whois: True | IRR: ['RIPE'] | BGP: True | RPKI: valid => Announce looks good.
Prefix: 193.0.10.0/23 | Whois: True | IRR: ['RIPE'] | BGP: True | RPKI: valid => Announce looks good.
Prefix: 193.0.12.0/23 | Whois: True | IRR: ['RIPE'] | BGP: True | RPKI: valid => Announce looks good.
Prefix: 193.0.18.0/23 | Whois: True | IRR: ['RIPE'] | BGP: True | RPKI: valid => Announce looks good.
Prefix: 193.0.20.0/23 | Whois: True | IRR: ['RIPE'] | BGP: True | RPKI: valid => Announce looks good.
Prefix: 193.0.22.0/23 | Whois: True | IRR: ['RIPE'] | BGP: True | RPKI: valid => Announce looks good.
Prefix: 2001:67c:2e8::/48 | Whois: True | IRR: ['RIPE'] | BGP: True | RPKI: valid => Announce looks good.
================================================================================
````

````
% ./peering_buddy.py -pa 3333 6 n
================================================================================
=> Getting prefixes for the ASN 3333 where the AS-Path is greater than 6 and not considering as-prepend :
================================================================================
Montevideo, Uruguay         | 193.0.0.0/21 | 46997 201106 50131 36236 3257 1103 3333
Tokyo, Japan                | 193.0.0.0/21 | 4777 2500 7660 22388 11537 1103 3333
Montevideo, Uruguay         | 193.0.10.0/23 | 46997 201106 50131 36236 2914 12859 3333
Tokyo, Japan                | 193.0.10.0/23 | 4777 2500 7660 22388 11537 1103 3333
Montevideo, Uruguay         | 193.0.12.0/23 | 46997 201106 50131 36236 3257 1103 3333
Tokyo, Japan                | 193.0.12.0/23 | 4777 2500 7660 22388 11537 1103 3333
Montevideo, Uruguay         | 193.0.18.0/23 | 46997 201106 50131 36236 3257 1103 3333
Tokyo, Japan                | 193.0.18.0/23 | 4777 2500 7660 22388 11537 1103 3333
Montevideo, Uruguay         | 193.0.20.0/23 | 46997 201106 50131 36236 3257 1103 3333
Tokyo, Japan                | 193.0.20.0/23 | 4777 2500 7660 22388 11537 1103 3333
Montevideo, Uruguay         | 193.0.22.0/23 | 46997 201106 50131 36236 3257 1103 3333
Tokyo, Japan                | 193.0.22.0/23 | 4777 2500 7660 22388 11537 1103 3333
Sao Paulo, Brazil           | 2001:67c:2e8::/48 | 28571 1251 20080 11537 1103 3333
================================================================================
================================================================================
Summary => format [ ASN:COUNTER ]:
================================================================================
First ASN (the other end ASN):  ['46997:6', '4777:6', '28571:1']

Second ASN (the other end upstream):  ['201106:6', '2500:6', '1251:1']

Third ASN (trying to find a common ASN on the path):  ['50131:6', '7660:6', '20080:1']

Non transit peers directly attached to ASN 3333 : []

Transit upstreams for the ASN 3333 : ['1103:12', '12859:1']

By locations:
Montevideo, Uruguay        : 6
Tokyo, Japan               : 6
Sao Paulo, Brazil          : 1
================================================================================
````

````
% ./peering_buddy.py -tu 3333
================================================================================
=> Checking for upstreams on transient paths for the ASN 3333 :
================================================================================
Amsterdam, Netherlands      | 2001:67c:2e8::/48 | 1273 20562 1103 3333
Paris, France               | 2001:67c:2e8::/48 | 50628 1273 20562 1103 3333
================================================================================
Transient upstreams for the ASN 3333 [ Upstream transient ASN => Number of times this ASN was matched on the AS-Path => Total AS-Paths number seeing this ASN => Percentage ]:
AS 1273 => 2 => 128 => 1.56 %

By locations [ Location => Number of transient upstreams ASNs on this location  => Total NLRI number seeing this location => Percentage ]:
Amsterdam, Netherlands      => 1 => 315 => 0.32 %
Paris, France               => 1 => 179 => 0.56 %
================================================================================
````

````
% ./peering_buddy.py -gu 3333
================================================================================
=> ASN  3333  upstreams are:
================================================================================
{
    "ipv4_upstreams": [
        {
            "asn": 1273,
            "name": "CW",
            "description": "Vodafone Group PLC",
            "country_code": "EU"
        },
        {
            "asn": 12859,
            "name": "NL-BIT",
            "description": "BIT BV",
            "country_code": "NL"
        },
        {
            "asn": 1103,
            "name": "SURFNET-NL",
            "description": "SURFnet, The Netherlands",
            "country_code": "NL"
        },
        {
            "asn": 1239,
            "name": "SPRINTLINK",
            "description": "Sprint",
            "country_code": "US"
        }
    ],
    "ipv6_upstreams": [
        {
            "asn": 12859,
            "name": "NL-BIT",
            "description": "BIT BV",
            "country_code": "NL"
        },
        {
            "asn": 1103,
            "name": "SURFNET-NL",
            "description": "SURFnet, The Netherlands",
            "country_code": "NL"
        },
        {
            "asn": 6939,
            "name": "HURRICANE",
            "description": "Hurricane Electric LLC",
            "country_code": "US"
        }
    ],
    "ipv4_graph": "https://api.bgpview.io/assets/graphs/AS3333_IPv4.svg",
    "ipv6_graph": "https://api.bgpview.io/assets/graphs/AS3333_IPv6.svg",
    "combined_graph": "https://api.bgpview.io/assets/graphs/AS3333_Combined.svg"
}
================================================================================
````

````
% ./peering_buddy.py -gd 3333
================================================================================
=> ASN  3333  downstreams are:
================================================================================
{
    "ipv4_downstreams": [
        {
            "asn": 2121,
            "name": "RIPE-MEETING-AS",
            "description": "RIPE NCC Training Services & RIPE Meetings",
            "country_code": "NL"
        }
    ],
    "ipv6_downstreams": [
        {
            "asn": 2121,
            "name": "RIPE-MEETING-AS",
            "description": "RIPE NCC Training Services & RIPE Meetings",
            "country_code": "NL"
        }
    ]
}
================================================================================
````

````
% ./peering_buddy.py -gw 3333
================================================================================
=> ASN  3333  information:
================================================================================
{
    "asn": 3333,
    "name": "RIPE-NCC-AS",
    "description_short": "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)",
    "description_full": [
        "Reseaux IP Europeens Network Coordination Centre (RIPE NCC)",
        "RIPE NCC Operations"
    ],
    "country_code": "NL",
    "website": "http://www.ripe.net",
    "email_contacts": [
        "peering@verizonbusiness.com",
        "peering@alsatis.com"
    ],
    "abuse_contacts": [],
    "looking_glass": null,
    "traffic_estimation": "1-5Gbps",
    "traffic_ratio": "Balanced",
    "owner_address": [
        "P.O. Box 10096",
        "1001 EB",
        "Amsterdam",
        "NETHERLANDS"
    ],
    "rir_allocation": {
        "rir_name": "RIPE",
        "country_code": "NL",
        "date_allocated": "1994-05-19 00:00:00",
        "allocation_status": "allocated"
    },
    "iana_assignment": {
        "assignment_status": null,
        "description": null,
        "whois_server": null,
        "date_assigned": null
    },
    "date_updated": "2023-05-28 08:05:46"
}
================================================================================
````

````
% ./peering_buddy.py -wi 6.6.6.6
================================================================================
=> Prefix  6.6.6.6  information:
================================================================================
{
    "ip": "6.6.6.6",
    "city": "Sierra Vista",
    "region": "Arizona",
    "country": "US",
    "loc": "31.5587,-110.3441",
    "postal": "85613",
    "timezone": "America/Phoenix",
    "readme": "https://ipinfo.io/missingauth"
}
================================================================================
````

````
% ./peering_buddy.py -aa 3333
================================================================================
=> ASN 3333 => AS-SET AS-RIPENCC expanded to:
================================================================================
{
    "AS-RIPENCC": [
        "AS3333",
        "AS2121",
        "AS12654"
    ]
}
================================================================================
````

````
% ./peering_buddy.py -ip
================================================================================
=> IXPs prefixes:
================================================================================
1.7.246.0/24
1.7.247.0/24
100.128.0.0/24
101.203.104.0/24
101.203.72.0/24
101.203.73.0/24
101.203.74.0/24
101.203.75.0/24
101.203.76.0/24
101.203.77.0/24
101.203.78.0/24
101.203.80.0/23
101.203.86.0/23
101.203.88.0/22
101.251.128.0/22
101.97.43.0/24
103.101.136.0/24
103.101.137.0/26
103.104.146.0/24
...
92.119.248.0/22
93.159.151.0/24
94.137.48.0/24
94.137.63.0/24
================================================================================
````

````
% ./peering_buddy.py -ai 3333
================================================================================
=> ASN  3333  info/summary:
================================================================================
[
    [
        "Name: RIPE NCC",
        "Aka: R\u00e9seaux IP Europ\u00e9ens Network Coordination Centre",
        "Website: http://www.ripe.net",
        "ASN: 3333",
        "LookingGlass: ",
        "RouteServer ",
        "IRR AS-SET: AS-RIPENCC",
        "Type: Non-Profit",
        "IPv4 Prefixes: 30",
        "IPv6 Prefixes: 20",
        "Traffic: 1-5Gbps",
        "Ratio: Balanced",
        "Scope: Global",
        "Unicast: True",
        "Multicast: False",
        "IPv6: True",
        "Never via RS: False",
        "Notes: ",
        "Policy url: ",
        "Policy: Selective",
        "Policy locations: Not Required",
        "Policy Ratio Requirement: False",
        "Policy Contracts: Not Required"
    ]
]
================================================================================
````

````
% ./peering_buddy.py -ii 3333
================================================================================
=> Allocated IXPs IPs for the ASN  3333 :
================================================================================
NL-ix: Main | Speed: 10000 | IP4: 193.239.117.25 | IP6: 2001:7f8:13::a500:3333:1 | RS: True
AMS-IX | Speed: 10000 | IP4: 80.249.208.68 | IP6: 2001:7f8:1::a500:3333:1 | RS: True
AMS-IX | Speed: 10000 | IP4: 80.249.208.71 | IP6: 2001:7f8:1::a500:3333:2 | RS: True
NL-ix: Main | Speed: 10000 | IP4: 193.239.118.84 | IP6: 2001:7f8:13::a500:3333:2 | RS: True
================================================================================
````

````
% ./peering_buddy.py -gc 3257
================================================================================
=> ASN  3257  contacts:
================================================================================
[
    [
        "Role: NOC",
        "Name: GTT NOC (outside the USA)",
        "Phone: +442074894200",
        "Email: noc@gtt.net",
        "URL "
    ],
    [
        "Role: NOC",
        "Name: GTT NOC (USA & Canada)",
        "Phone: +18005831388",
        "Email: noc@gtt.net",
        "URL "
    ],
    [
        "Role: Policy",
        "Name: Peering",
        "Phone: ",
        "Email: peering@gtt.net",
        "URL "
    ],
    [
        "Role: Sales",
        "Name: Sales",
        "Phone: ",
        "Email: sales@gtt.net",
        "URL "
    ],
    [
        "Role: Public Relations",
        "Name: Marketing",
        "Phone: ",
        "Email: marketing@gtt.net",
        "URL "
    ]
]
================================================================================
````

````
% ./peering_buddy.py -cc nl 
================================================================================
=> IXPs available on  nl :
================================================================================
[
    [
        "Name: AMS-IX",
        "Long_name: Amsterdam Internet Exchange",
        "City: Amsterdam",
        "Country: NL",
        "Continent: Europe",
        "Notes: ",
        "Unicast: True",
        "Multicast: False",
        "IPv6: True",
        "URL: http://www.ams-ix.net/",
        "URL Stats: https://www.ams-ix.net/statistics/",
        "Tech Email: noc@ams-ix.net",
        "Tech Phone: +31205141717",
        "Policy Email: info@ams-ix.net",
        "Policy Phone: +31203058999",
        "Networks[ASN]: 829"
    ],
    [
        "Name: NL-ix",
        "Long_name: Neutral Internet Exchange",
        "City: Amsterdam, Rotterdam, Brussels, Antwerp, Luxembourg, Frankfurt, D\u00fcsseldorf, Berlin, London, Copenhagen, Paris, Marseille",
        "Country: NL",
        "Continent: Europe",
        "Notes: ",
        "Unicast: True",
        "Multicast: False",
        "IPv6: True",
        "URL: https://www.nl-ix.net/",
        "URL Stats: https://www.nl-ix.net/locations/",
        "Tech Email: support@nl-ix.net",
        "Tech Phone: +31703120710",
        "Policy Email: ",
        "Policy Phone: +31703120710",
        "Networks[ASN]: 441"
    ],
    [
        "Name: NDIX",
        "Long_name: Nederlands Duitse Internet Exchange",
        "City: Enschede / M\u00fcnster",
        "Country: NL",
        "Continent: Europe",
        "Notes: ",
        "Unicast: True",
        "Multicast: True",
        "IPv6: True",
        "URL: http://www.ndix.net",
        "URL Stats: ",
        "Tech Email: noc@ndix.net",
        "Tech Phone: +31537114177",
        "Policy Email: Sales@ndix.net",
        "Policy Phone: +31537114150",
        "Networks[ASN]: 16"
    ],
...
    [
        "Name: VoIP IX",
        "Long_name: ",
        "City: Amsterdam",
        "Country: NL",
        "Continent: Europe",
        "Notes: VoIPIX is an Internet exchange (IX) dedicated to the VOIP ecosystem. We provide a neutral and carrier-neutral platform for VOIP providers to exchange traffic. We believe there should be a single place where you can find and locate your peers.",
        "Unicast: True",
        "Multicast: False",
        "IPv6: True",
        "URL: https://www.voip-ix.net",
        "URL Stats: ",
        "Tech Email: peer@voip-ix.net",
        "Tech Phone: ",
        "Policy Email: policy@voip-ix.net",
        "Policy Phone: ",
        "Networks[ASN]: 2"
    ]
]
================================================================================
````

````
% ./peering_buddy.py -gl
================================================================================
=> List of public looking glass.
================================================================================
route-views6.routeviews.org => 128.223.51.112
route-views.kixp.routeviews.org => 196.6.220.44
route-server.opentransit.net => 193.251.142.112
route-server.cbbtier3.att.net => 12.0.1.28
route-server.as5388.net => 195.92.201.108
routeserver7.sentex.ca => 216.18.63.214
route-server.colt.net => 212.74.64.138
routeserver9.sentex.ca => 144.85.10.248
routeserver10.sentex.ca => 209.1.220.16
loop0.route-server.phx1.gblx.net => 67.17.81.28
route-server.west.bb.allstream.net => 209.82.88.118
================================================================================
````

````
% ./peering_buddy.py -bo
================================================================================
=> IPv4 bogons list:
================================================================================
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
================================================================================
````

````
% ./peering_buddy.py -b4 
================================================================================
=> IPv4 full (+unallocated) bogons list:
================================================================================
0.0.0.0/8
10.0.0.0/8
23.135.225.0/24
23.151.160.0/24
23.154.233.0/24
27.98.192.0/20
27.112.96.0/22
27.123.224.0/22
27.124.64.0/20
27.126.156.0/22
36.50.0.0/19
36.50.32.0/22
36.50.37.0/24
36.50.38.0/23
36.50.40.0/21
36.50.48.0/23
36.50.51.0/24
...
216.40.66.0/23
216.40.68.0/22
216.40.72.0/21
216.40.80.0/20
220.158.148.0/22
223.130.8.0/22
223.165.0.0/22
224.0.0.0/4
240.0.0.0/4
================================================================================
````

````
% ./peering_buddy.py -b6
================================================================================
=> IPv6 full (+unallocated) bogons list:
================================================================================
::/10
40::/11
60::/14
64::/17
64:8000::/18
64:c000::/19
64:e000::/20
64:f000::/21
64:f800::/22
64:fc00::/23
64:fe00::/24
64:ff00::/25
64:ff80::/28
64:ff90::/29
...
2d00::/8
2e00::/7
3000::/4
4000::/2
8000::/1
================================================================================
````

````
% ./peering_buddy.py -ba
================================================================================
=> Bogons ASN list:
================================================================================
Bogon ASN Filter Policy Configuration Examples
----------------------------------------------

Date: Wed Sep 26 09:12:37 EDT 2018

Contact: Job Snijders <job@ntt.net>, Jared Mauch <jared@puck.nether.net>

Background:

    https://ripe72.ripe.net/wp-content/uploads/presentations/151-RIPE72_bogon_ASNs_JobSnijders.pdf
    https://ripe72.ripe.net/archives/video/193/
    http://mailman.nlnog.net/pipermail/nlnog/2016-May/002584.html
    http://mailman.nanog.org/pipermail/nanog/2016-June/086078.html

Juniper:
========

    policy-options {
        as-path-group bogon-asns {
            /* RFC7607 */
            as-path zero ".* 0 .*";
            /* RFC 4893 AS_TRANS */
            as-path as_trans ".* 23456 .*";
...
    ip as-path access-list 99 permit _(429[0-3][0-9][0-9][0-9][0-9][0-9][0-9])_|_(4294[0-8][0-9][0-9][0-9][0-9][0-9])_
    ip as-path access-list 99 permit _(42949[0-5][0-9][0-9][0-9][0-9])_|_(429496[0-6][0-9][0-9][0-9])_
    ip as-path access-list 99 permit _(4294967[0-1][0-9][0-9])_|_(42949672[0-8][0-9])_|_(429496729[0-4])_

    route-map ebgp-in deny 1
      match as-path 99

================================================================================
````
