"""Static catalog data for the simulated enterprise: names, netblocks, external services.

The GeoIP table is synthetic: prefixes and ASNs approximate well-known providers so that the
telemetry looks realistic, but the data is only meant for simulation.
"""

from __future__ import annotations

from dataclasses import dataclass

FIRST_NAMES = [
    "Andrei",
    "Ana",
    "Mihai",
    "Maria",
    "Alexandru",
    "Elena",
    "Ion",
    "Ioana",
    "Cristian",
    "Andreea",
    "Dragos",
    "Adriana",
    "Bogdan",
    "Diana",
    "Stefan",
    "Laura",
    "Vlad",
    "Irina",
    "Radu",
    "Alina",
    "George",
    "Raluca",
    "Florin",
    "Simona",
    "Paul",
    "Oana",
    "Tudor",
    "Bianca",
    "Victor",
    "Carmen",
    "Daniel",
    "Roxana",
    "Lucian",
    "Monica",
    "Sorin",
    "Gabriela",
    "Mark",
    "Emma",
    "Lukas",
    "Sofia",
    "Thomas",
    "Julia",
    "David",
    "Sarah",
    "Peter",
    "Anna",
    "Marco",
    "Chiara",
    "Pierre",
    "Claire",
    "James",
    "Olivia",
    "Daniela",
    "Catalin",
    "Teodora",
    "Razvan",
    "Iulia",
    "Sebastian",
    "Larisa",
    "Ovidiu",
]

LAST_NAMES = [
    "Popescu",
    "Ionescu",
    "Popa",
    "Pop",
    "Radu",
    "Dumitru",
    "Stan",
    "Stoica",
    "Gheorghe",
    "Matei",
    "Ciobanu",
    "Rusu",
    "Munteanu",
    "Constantin",
    "Marin",
    "Florea",
    "Tudor",
    "Moldovan",
    "Lungu",
    "Dinu",
    "Barbu",
    "Nistor",
    "Ilie",
    "Toma",
    "Sandu",
    "Cristea",
    "Mihai",
    "Neagu",
    "Coman",
    "Serban",
    "Muller",
    "Schmidt",
    "Weber",
    "Rossi",
    "Bianchi",
    "Martin",
    "Bernard",
    "Smith",
    "Brown",
    "Jones",
    "Garcia",
    "Lopez",
    "Novak",
    "Horvat",
    "Kovacs",
    "Nagy",
    "Varga",
    "Petrov",
    "Ivanova",
    "Andersen",
    "Jensen",
    "Visser",
    "Bakker",
    "Moreau",
    "Dubois",
    "Trandafir",
    "Enache",
    "Vasile",
    "Lazar",
    "Oprea",
]


@dataclass(frozen=True, slots=True)
class Netblock:
    cidr: str
    country: str
    city: str
    lat: float
    lon: float
    asn: int
    org: str
    category: str  # isp, mobile, cloud, cdn, hosting, anonymizer, corporate


NETBLOCKS: list[Netblock] = [
    # Residential and mobile ISPs (home workers, travellers).
    Netblock("86.120.0.0/16", "RO", "Cluj-Napoca", 46.77, 23.60, 8708, "RCS & RDS", "isp"),
    Netblock("79.112.0.0/16", "RO", "Bucharest", 44.43, 26.10, 8708, "RCS & RDS", "isp"),
    Netblock("5.12.0.0/16", "RO", "Bucharest", 44.43, 26.10, 8708, "RCS & RDS", "isp"),
    Netblock("188.24.0.0/16", "RO", "Cluj-Napoca", 46.77, 23.60, 9050, "Telekom Romania", "isp"),
    Netblock("37.120.0.0/16", "RO", "Bucharest", 44.43, 26.10, 9050, "Telekom Romania", "mobile"),
    Netblock("91.64.0.0/16", "DE", "Berlin", 52.52, 13.40, 3209, "Vodafone Germany", "isp"),
    Netblock("90.84.0.0/16", "FR", "Paris", 48.86, 2.35, 3215, "Orange France", "isp"),
    Netblock("81.96.0.0/16", "GB", "London", 51.51, -0.13, 5089, "Virgin Media", "isp"),
    Netblock("73.0.0.0/16", "US", "New York", 40.71, -74.01, 7922, "Comcast", "isp"),
    Netblock("93.40.0.0/16", "IT", "Milan", 45.46, 9.19, 12874, "Fastweb", "isp"),
    Netblock("88.0.0.0/16", "ES", "Madrid", 40.42, -3.70, 3352, "Telefonica Spain", "isp"),
    Netblock("84.24.0.0/16", "NL", "Amsterdam", 52.37, 4.90, 33915, "Ziggo", "isp"),
    # Office egress (corporate NAT).
    Netblock(
        "193.226.51.0/24", "RO", "Cluj-Napoca", 46.77, 23.60, 64512, "Example Corp", "corporate"
    ),
    Netblock("82.77.140.0/24", "RO", "Bucharest", 44.43, 26.10, 64512, "Example Corp", "corporate"),
    # Cloud, SaaS and CDNs.
    Netblock("20.190.128.0/18", "US", "Redmond", 47.67, -122.12, 8075, "Microsoft", "cloud"),
    Netblock("52.96.0.0/14", "IE", "Dublin", 53.34, -6.26, 8075, "Microsoft", "cloud"),
    Netblock("13.107.4.0/24", "US", "Redmond", 47.67, -122.12, 8068, "Microsoft", "cloud"),
    Netblock("20.42.0.0/16", "US", "Boydton", 36.67, -78.39, 8075, "Microsoft", "cloud"),
    Netblock("142.250.0.0/15", "US", "Mountain View", 37.42, -122.08, 15169, "Google", "cloud"),
    Netblock("140.82.112.0/20", "US", "San Francisco", 37.77, -122.42, 36459, "GitHub", "cloud"),
    Netblock("3.120.0.0/14", "DE", "Frankfurt", 50.11, 8.68, 16509, "Amazon", "cloud"),
    Netblock("52.216.0.0/15", "US", "Ashburn", 39.04, -77.49, 16509, "Amazon", "cloud"),
    Netblock("104.16.0.0/13", "US", "San Francisco", 37.77, -122.42, 13335, "Cloudflare", "cdn"),
    Netblock("151.101.0.0/16", "US", "San Francisco", 37.77, -122.42, 54113, "Fastly", "cdn"),
    Netblock("170.114.0.0/16", "US", "San Jose", 37.34, -121.89, 30103, "Zoom", "cloud"),
    Netblock("13.108.0.0/14", "US", "San Francisco", 37.77, -122.42, 14340, "Salesforce", "cloud"),
    Netblock("104.192.136.0/21", "US", "Ashburn", 39.04, -77.49, 133530, "Atlassian", "cloud"),
    # Secure access service edge (ZTNA): remote staff egress after a move to it (scenario S1).
    Netblock("165.225.0.0/17", "DE", "Frankfurt", 50.11, 8.68, 22616, "Zscaler", "cloud"),
    # Hosting providers: used by developers (staging, mirrors) and by attackers.
    Netblock("159.89.0.0/16", "DE", "Frankfurt", 50.11, 8.68, 14061, "DigitalOcean", "hosting"),
    Netblock("95.216.0.0/16", "FI", "Helsinki", 60.17, 24.94, 24940, "Hetzner", "hosting"),
    Netblock("51.75.0.0/16", "FR", "Roubaix", 50.69, 3.17, 16276, "OVH", "hosting"),
    Netblock("45.32.0.0/16", "US", "Piscataway", 40.55, -74.46, 20473, "Vultr", "hosting"),
    Netblock("193.106.191.0/24", "RU", "Moscow", 55.76, 37.62, 49505, "Selectel", "hosting"),
    Netblock("103.75.0.0/16", "SG", "Singapore", 1.35, 103.82, 63949, "Akamai Linode", "hosting"),
    Netblock(
        "185.220.100.0/22", "DE", "Berlin", 52.52, 13.40, 60729, "Tor exit relays", "anonymizer"
    ),
    # Consumer VPN exits (privacy-minded staff), indistinguishable by ASN from rented servers.
    Netblock("89.36.76.0/22", "RO", "Bucharest", 44.43, 26.10, 9009, "M247", "hosting"),
    Netblock("146.70.0.0/16", "DE", "Frankfurt", 50.11, 8.68, 9009, "M247 Europe", "hosting"),
    Netblock(
        "185.156.172.0/22", "NL", "Amsterdam", 52.37, 4.90, 60068, "Datacamp Limited", "hosting"
    ),
]
CONSUMER_VPN_BLOCKS = ["89.36.76.0/22", "146.70.0.0/16", "185.156.172.0/22"]


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    name: str
    netblock: str  # CIDR from NETBLOCKS
    ports: tuple[int, ...]
    popularity: float  # relative share of benign web traffic
    n_ips: int = 6
    bytes_scale: float = 1.0  # multiplier of typical response sizes


SERVICES: list[ServiceSpec] = [
    ServiceSpec("o365", "52.96.0.0/14", (443,), 30, 12, 1.0),
    ServiceSpec("azure-ad", "20.190.128.0/18", (443,), 8, 6, 0.3),
    ServiceSpec("teams", "52.96.0.0/14", (443,), 14, 8, 1.5),
    ServiceSpec("windows-update", "13.107.4.0/24", (443, 80), 3, 4, 8.0),
    ServiceSpec("defender-cloud", "20.42.0.0/16", (443,), 0, 4, 0.2),
    ServiceSpec("google", "142.250.0.0/15", (443,), 18, 10, 1.0),
    ServiceSpec("github", "140.82.112.0/20", (443, 22), 5, 4, 2.0),
    ServiceSpec("slack", "3.120.0.0/14", (443,), 7, 6, 0.6),
    ServiceSpec("aws-console", "3.120.0.0/14", (443,), 2, 4, 0.8),
    ServiceSpec("s3-backup", "52.216.0.0/15", (443,), 0, 3, 1.0),
    ServiceSpec("cloudflare-cdn", "104.16.0.0/13", (443,), 12, 12, 1.2),
    ServiceSpec("fastly-cdn", "151.101.0.0/16", (443,), 8, 8, 1.2),
    ServiceSpec("zoom", "170.114.0.0/16", (443, 8801), 5, 6, 2.0),
    ServiceSpec("salesforce", "13.108.0.0/14", (443,), 5, 4, 0.7),
    ServiceSpec("atlassian", "104.192.136.0/21", (443,), 5, 4, 0.7),
    ServiceSpec("dev-staging", "159.89.0.0/16", (443, 22), 1.5, 4, 1.0),
    ServiceSpec("package-mirror", "95.216.0.0/16", (443,), 1.5, 3, 3.0),
]

ROLE_APPS: dict[str, str] = {
    # SSO application -> service providing it
    "o365": "o365",
    "teams": "teams",
    "github": "github",
    "slack": "slack",
    "aws-console": "aws-console",
    "salesforce": "salesforce",
    "zoom": "zoom",
    "jira": "atlassian",
    "azure-portal": "azure-ad",
    "workday": "o365",
    "sap": "o365",
    "zendesk": "cloudflare-cdn",
    "hubspot": "cloudflare-cdn",
}

DESKTOP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Microsoft Teams/25.8 Chrome/130.0.0.0 Safari/537.36",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.18925; Pro)",
]
MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
    "Outlook-iOS/2.0",
    "Mozilla/5.0 (Linux; Android 15; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
]
