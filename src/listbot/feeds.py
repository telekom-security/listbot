from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    tag: str
    parser: str = "generic"
    max_network_hosts: int = 65_536
    max_range_hosts: int = 65_536
    usage_class: str = "unknown"


@dataclass(frozen=True)
class FeedNotice:
    source: str
    purpose: str
    license_terms: str


DEFAULT_SURICATA_VERSION = "8.0.0"
ET_SID_MAP_URL_TEMPLATE = (
    "https://rules.emergingthreats.net/open/"
    "suricata-{version}/rules/sid-msg.map"
)

ABUSECH_TERMS = "abuse.ch Terms of Use; no separate SPDX-style data license stated."
FIREHOL_MIRROR_TERMS = "FireHOL aggregate/mirror; upstream list licenses may vary."
NO_EXPLICIT_LICENSE = "No explicit feed license found."
TOR_TERMS = "Tor Project exit-list service; no explicit data license found on the feed endpoint."
APPROVED_FEED_USAGE_CLASSES = frozenset({"unrestricted", "non_commercial", "restricted", "unknown"})

APPROVED_IPREP_TAGS = frozenset(
    {
        "C2 server",
        "anonymizer",
        "attack source",
        "bad reputation",
        "bitcoin node",
        "bot activity",
        "botnet C2",
        "comment spam",
        "compromised",
        "forum spammer",
        "form spammer",
        "ftp abuse",
        "mail abuse",
        "malware host",
        "malware infra",
        "mass scanner",
        "open proxy",
        "scan source",
        "service abuse",
        "sip abuse",
        "spam network",
        "ssh abuse",
        "threat IOC",
        "tor exit",
        "web abuse",
        "web attacker",
        "web harvester",
        "web blacklist",
        "web scanner",
    }
)

CVE_NOTICE = FeedNotice(
    source="Emerging Threats Open sid-msg.map",
    purpose="SID to CVE/CAN lookup data.",
    license_terms="ET Open license file: older SID ranges are GPLv2; Emerging Threats SID ranges are BSD.",
)

FEED_NOTICES: dict[str, FeedNotice] = {
    "feodotracker": FeedNotice(
        "abuse.ch Feodo Tracker",
        "Botnet C2 IP blocklist.",
        "abuse.ch Terms of Use; Feodo documents vendor use for commercial and non-commercial purposes.",
    ),
    "threatfox_ip_port_recent": FeedNotice(
        "abuse.ch ThreatFox",
        "Recent ip:port malware infrastructure and botnet C2 IOCs.",
        ABUSECH_TERMS,
    ),
    "neo23x0_c2": FeedNotice(
        "Neo23x0 signature-base",
        "C2 indicators from the public signature-base IOC set.",
        "Detection Rule License 1.1.",
    ),
    "cybercrime_tracker": FeedNotice(
        "CyberCrime Tracker",
        "Cybercrime and malware infrastructure indicators.",
        NO_EXPLICIT_LICENSE,
    ),
    "firehol_webclient": FeedNotice(
        "FireHOL webclient",
        "Malware infrastructure destinations a web client should not contact.",
        "FireHOL aggregate/mirror; upstream list licenses may vary. FireHOL asks users to check each source site.",
    ),
    "et_compromised": FeedNotice(
        "Emerging Threats compromised IPs",
        "Compromised hosts from Emerging Threats.",
        "Emerging Threats/Proofpoint terms; blockrules feed has no explicit license header.",
    ),
    "maltrail_mass_scanner": FeedNotice(
        "Maltrail mass scanners",
        "Static mass-scanner indicators.",
        "MIT.",
    ),
    "tor_bulk_exit": FeedNotice(
        "Tor bulk exit list",
        "Current Tor exits.",
        TOR_TERMS,
    ),
    "tor_exit_addresses": FeedNotice(
        "Tor exit addresses",
        "TorDNSEL-style exit address data.",
        TOR_TERMS,
    ),
    "firehol_dm_tor": FeedNotice(
        "FireHOL dm_tor",
        "FireHOL-hosted Tor exit snapshot.",
        "FireHOL mirror; upstream license/terms depend on the original Tor-related source.",
    ),
    "firehol_proxylists": FeedNotice(
        "FireHOL proxylists",
        "Open proxy list snapshot.",
        "FireHOL mirror; upstream proxy-list licenses may vary or be unstated.",
    ),
    "firehol_proxyrss": FeedNotice(
        "FireHOL proxyrss",
        "Open proxy RSS snapshot.",
        "FireHOL mirror; upstream proxy-list licenses may vary or be unstated.",
    ),
    "firehol_proxyspy": FeedNotice(
        "FireHOL proxyspy",
        "ProxySpy-derived open proxy list.",
        "FireHOL mirror; upstream proxy-list licenses may vary or be unstated.",
    ),
    "firehol_web_proxies": FeedNotice(
        "FireHOL RI web proxies",
        "Open web proxy indicators.",
        "FireHOL mirror; upstream proxy-list licenses may vary or be unstated.",
    ),
    "firehol_socks_proxy": FeedNotice(
        "FireHOL socks proxy",
        "Open SOCKS proxy indicators.",
        "FireHOL mirror; upstream proxy-list licenses may vary or be unstated.",
    ),
    "firehol_sslproxies": FeedNotice(
        "FireHOL SSL proxies",
        "Open SSL proxy indicators.",
        "FireHOL mirror; upstream proxy-list licenses may vary or be unstated.",
    ),
    "spys": FeedNotice("spys.me proxy list", "Open proxy list.", NO_EXPLICIT_LICENSE),
    "firehol_botscout": FeedNotice(
        "FireHOL BotScout",
        "BotScout spammer snapshot.",
        "FireHOL mirror; upstream BotScout terms apply, explicit feed license not stated in the mirrored file.",
    ),
    "sblam": FeedNotice(
        "Sblam blacklist",
        "HTTP/form spam sources.",
        "No explicit feed license found; feed labels the data as HTTP/form spam sources.",
    ),
    "firehol_bitcoin": FeedNotice(
        "FireHOL bitcoin nodes",
        "Bitcoin node enrichment data, not necessarily malicious.",
        FIREHOL_MIRROR_TERMS,
    ),
    "firehol_cruzit": FeedNotice(
        "FireHOL CruzIT",
        "Web attack sources.",
        "FireHOL mirror; upstream source license/terms may vary or be unstated.",
    ),
    "firehol_mwdomainlist": FeedNotice(
        "FireHOL malwaredomainlist",
        "Malware host IP indicators.",
        "FireHOL mirror; upstream source license/terms may vary or be unstated.",
    ),
    "firehol_dshield": FeedNotice(
        "FireHOL DShield 30d",
        "DShield scan-source netset snapshot.",
        "FireHOL mirror of DShield-derived data; DShield publishes CC BY-NC-SA 2.5 terms on its direct feed.",
    ),
    "firehol_darklist": FeedNotice(
        "FireHOL darklist.de",
        "Generic blacklisted attack sources from darklist.de.",
        "FireHOL mirror; no explicit darklist.de feed license found in the mirrored file.",
    ),
    "binary_defense_banlist": FeedNotice(
        "Binary Defense ATIF",
        "Public bad-reputation banlist.",
        "Public use only; commercial resale or fee-based services are prohibited in the feed header.",
    ),
    "firehol_blocklist_de_apache": FeedNotice(
        "FireHOL blocklist.de apache",
        "blocklist.de Apache and web-service abuse sources.",
        "FireHOL mirror of blocklist.de apache feed; blocklist.de export terms apply.",
    ),
    "firehol_blocklist_de_bots": FeedNotice(
        "FireHOL blocklist.de bots",
        "blocklist.de bot activity sources.",
        "FireHOL mirror of blocklist.de bots feed; blocklist.de export terms apply.",
    ),
    "firehol_blocklist_de_ftp": FeedNotice(
        "FireHOL blocklist.de ftp",
        "blocklist.de FTP abuse sources.",
        "FireHOL mirror of blocklist.de FTP feed; blocklist.de export terms apply.",
    ),
    "firehol_blocklist_de_imap": FeedNotice(
        "FireHOL blocklist.de imap",
        "blocklist.de IMAP abuse sources.",
        "FireHOL mirror of blocklist.de IMAP feed; blocklist.de export terms apply.",
    ),
    "firehol_blocklist_de_mail": FeedNotice(
        "FireHOL blocklist.de mail",
        "blocklist.de mail abuse sources.",
        "FireHOL mirror of blocklist.de mail feed; blocklist.de export terms apply.",
    ),
    "firehol_blocklist_de_sip": FeedNotice(
        "FireHOL blocklist.de sip",
        "blocklist.de SIP/VoIP abuse sources.",
        "FireHOL mirror of blocklist.de SIP feed; blocklist.de export terms apply.",
    ),
    "firehol_blocklist_de_ssh": FeedNotice(
        "FireHOL blocklist.de ssh",
        "blocklist.de SSH abuse sources.",
        "FireHOL mirror of blocklist.de SSH feed; blocklist.de export terms apply.",
    ),
    "firehol_blocklist_de": FeedNotice(
        "FireHOL blocklist.de",
        "Reported service abuse sources.",
        "FireHOL mirror of blocklist.de all feed; blocklist.de export terms apply.",
    ),
    "cinsscore": FeedNotice(
        "CINS Score",
        "Bad reputation badguys list.",
        "Public CINS Army list; no explicit feed license found.",
    ),
    "greensnow": FeedNotice("GreenSnow", "Generic attack-source blacklist.", "Public blacklist; no explicit feed license found."),
    "rutgers": FeedNotice("Rutgers DROP attackers", "Generic DROP attack sources.", NO_EXPLICIT_LICENSE),
    "dshield": FeedNotice(
        "DShield block list",
        "Top scan-source subnets, parsed from start/end ranges.",
        "Creative Commons BY-NC-SA 2.5 per feed header.",
    ),
    "ipsum_level3": FeedNotice(
        "IPsum level 3",
        "IPs seen on at least three source lists.",
        "Unlicense/public-domain dedication.",
    ),
    "firehol_abusers_30d": FeedNotice(
        "FireHOL abusers 30d",
        "Recent web abuse aggregate.",
        "FireHOL aggregate/mirror; upstream licenses vary.",
    ),
    "firehol_php_commenters_30d": FeedNotice(
        "FireHOL Project Honey Pot commenters 30d",
        "Project Honey Pot comment spam sources seen in the last 30 days.",
        "FireHOL mirror; Project Honey Pot terms may apply; explicit feed license not stated in the mirrored file.",
    ),
    "firehol_php_dictionary_30d": FeedNotice(
        "FireHOL Project Honey Pot dictionary 30d",
        "Project Honey Pot directory and dictionary attack sources seen in the last 30 days.",
        "FireHOL mirror; Project Honey Pot terms may apply; explicit feed license not stated in the mirrored file.",
    ),
    "firehol_php_harvesters_30d": FeedNotice(
        "FireHOL Project Honey Pot harvesters 30d",
        "Project Honey Pot web harvester sources seen in the last 30 days.",
        "FireHOL mirror; Project Honey Pot terms may apply; explicit feed license not stated in the mirrored file.",
    ),
    "firehol_php_spammers_30d": FeedNotice(
        "FireHOL Project Honey Pot spammers 30d",
        "Project Honey Pot form spammer sources seen in the last 30 days.",
        "FireHOL mirror; Project Honey Pot terms may apply; explicit feed license not stated in the mirrored file.",
    ),
    "firehol_stopforumspam_30d": FeedNotice(
        "FireHOL StopForumSpam 30d",
        "Forum spammer IPs seen in the last 30 days.",
        "FireHOL mirror; StopForumSpam terms may apply; explicit feed license not stated in the mirrored file.",
    ),
    "firehol_stopforumspam_toxic": FeedNotice(
        "FireHOL StopForumSpam toxic",
        "StopForumSpam networks with large amounts of spambots.",
        "FireHOL mirror; StopForumSpam terms may apply; explicit feed license not stated in the mirrored file.",
    ),
    "firehol_cleantalk": FeedNotice(
        "FireHOL CleanTalk",
        "CleanTalk form spammer snapshot.",
        "FireHOL mirror; upstream CleanTalk terms apply, explicit feed license not stated in the mirrored file.",
    ),
    "myip": FeedNotice(
        "MyIP blacklist",
        "Website firewall blacklist archive.",
        "MyIP.ms publishes the download for website firewall use; no explicit data license found.",
    ),
    "bitwire_outbound": FeedNotice(
        "Bitwire IP blocklist",
        "Aggregated outbound blocklist.",
        "Aggregated data is CC BY-NC-SA 4.0 and subject to original provider licenses; Bitwire code is MIT.",
    ),
    "botvrij": FeedNotice(
        "Botvrij IOC list",
        "Threat IOC destination IPs.",
        "Botvrij describes the data as open-source IOCs; no explicit SPDX-style data license found.",
    ),
    "alienvault_reputation": FeedNotice(
        "AlienVault reputation",
        "AlienVault IP reputation database.",
        "AlienVault/LevelBlue OTX terms may apply; no explicit license in the feed header.",
    ),
    "turris": FeedNotice(
        "Turris Sentinel Greylist",
        "Turris Sentinel service-abuse greylist data.",
        "CC BY-NC-SA 4.0; commercial offerings require contacting CZ.NIC.",
    ),
    "firehol_anonymous": FeedNotice(
        "FireHOL anonymous",
        "Aggregate anonymizer list including Tor and open proxy sources.",
        "FireHOL aggregate/mirror; upstream anonymizer-list licenses may vary.",
    ),
}

# Feed order is meaningful: if an IP appears in multiple feeds, the first tag wins.
IPREP_FEEDS: tuple[Feed, ...] = (
    Feed(
        "feodotracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "botnet C2",
        usage_class="unrestricted",
    ),
    Feed(
        "threatfox_ip_port_recent",
        "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "malware infra",
    ),
    Feed(
        "neo23x0_c2",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt",
        "C2 server",
    ),
    Feed(
        "cybercrime_tracker",
        "https://cybercrime-tracker.net/all.php",
        "malware infra",
    ),
    Feed(
        "firehol_webclient",
        "https://iplists.firehol.org/files/firehol_webclient.netset",
        "malware infra",
    ),
    Feed(
        "et_compromised",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "compromised",
    ),
    Feed(
        "maltrail_mass_scanner",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/data/mass_scanner.txt",
        "mass scanner",
        usage_class="unrestricted",
    ),
    Feed(
        "tor_bulk_exit",
        "https://check.torproject.org/torbulkexitlist",
        "tor exit",
    ),
    Feed(
        "tor_exit_addresses",
        "https://check.torproject.org/exit-addresses",
        "tor exit",
    ),
    Feed(
        "firehol_dm_tor",
        "https://iplists.firehol.org/files/dm_tor.ipset",
        "tor exit",
    ),
    Feed(
        "firehol_proxylists",
        "https://iplists.firehol.org/files/proxylists_30d.ipset",
        "open proxy",
    ),
    Feed(
        "firehol_proxyrss",
        "https://iplists.firehol.org/files/proxyrss_30d.ipset",
        "open proxy",
    ),
    Feed(
        "firehol_proxyspy",
        "https://iplists.firehol.org/files/proxyspy_30d.ipset",
        "open proxy",
    ),
    Feed(
        "firehol_web_proxies",
        "https://iplists.firehol.org/files/ri_web_proxies_30d.ipset",
        "open proxy",
    ),
    Feed(
        "firehol_socks_proxy",
        "https://iplists.firehol.org/files/socks_proxy_30d.ipset",
        "open proxy",
    ),
    Feed(
        "firehol_sslproxies",
        "https://iplists.firehol.org/files/sslproxies_30d.ipset",
        "open proxy",
    ),
    Feed("spys", "https://spys.me/proxy.txt", "open proxy"),
    Feed(
        "firehol_botscout",
        "https://iplists.firehol.org/files/botscout_30d.ipset",
        "form spammer",
    ),
    Feed("sblam", "https://sblam.com/blacklist.txt", "form spammer"),
    Feed(
        "firehol_bitcoin",
        "https://iplists.firehol.org/files/bitcoin_nodes_30d.ipset",
        "bitcoin node",
    ),
    Feed(
        "firehol_cruzit",
        "https://iplists.firehol.org/files/cruzit_web_attacks.ipset",
        "web attacker",
    ),
    Feed(
        "firehol_mwdomainlist",
        "https://iplists.firehol.org/files/malwaredomainlist.ipset",
        "malware host",
    ),
    Feed(
        "firehol_dshield",
        "https://iplists.firehol.org/files/dshield_30d.netset",
        "scan source",
        usage_class="non_commercial",
    ),
    Feed(
        "firehol_darklist",
        "https://iplists.firehol.org/files/darklist_de.netset",
        "attack source",
        max_network_hosts=200_000,
    ),
    Feed(
        "binary_defense_banlist",
        "https://www.binarydefense.com/banlist.txt",
        "bad reputation",
        usage_class="restricted",
    ),
    Feed(
        "firehol_blocklist_de_apache",
        "https://iplists.firehol.org/files/blocklist_de_apache.ipset",
        "web attacker",
    ),
    Feed(
        "firehol_blocklist_de_bots",
        "https://iplists.firehol.org/files/blocklist_de_bots.ipset",
        "bot activity",
    ),
    Feed(
        "firehol_blocklist_de_ftp",
        "https://iplists.firehol.org/files/blocklist_de_ftp.ipset",
        "ftp abuse",
    ),
    Feed(
        "firehol_blocklist_de_imap",
        "https://iplists.firehol.org/files/blocklist_de_imap.ipset",
        "mail abuse",
    ),
    Feed(
        "firehol_blocklist_de_mail",
        "https://iplists.firehol.org/files/blocklist_de_mail.ipset",
        "mail abuse",
    ),
    Feed(
        "firehol_blocklist_de_sip",
        "https://iplists.firehol.org/files/blocklist_de_sip.ipset",
        "sip abuse",
    ),
    Feed(
        "firehol_blocklist_de_ssh",
        "https://iplists.firehol.org/files/blocklist_de_ssh.ipset",
        "ssh abuse",
    ),
    Feed(
        "firehol_blocklist_de",
        "https://iplists.firehol.org/files/blocklist_de.ipset",
        "service abuse",
    ),
    Feed("cinsscore", "https://cinsscore.com/list/ci-badguys.txt", "bad reputation"),
    Feed("greensnow", "http://blocklist.greensnow.co/greensnow.txt", "attack source"),
    Feed("rutgers", "https://report.cs.rutgers.edu/DROP/attackers", "attack source"),
    Feed(
        "dshield",
        "https://feeds.dshield.org/block.txt",
        "scan source",
        parser="dshield",
        usage_class="non_commercial",
    ),
    Feed(
        "ipsum_level3",
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "bad reputation",
        usage_class="unrestricted",
    ),
    Feed(
        "firehol_php_commenters_30d",
        "https://iplists.firehol.org/files/php_commenters_30d.ipset",
        "comment spam",
    ),
    Feed(
        "firehol_php_dictionary_30d",
        "https://iplists.firehol.org/files/php_dictionary_30d.ipset",
        "web scanner",
    ),
    Feed(
        "firehol_php_harvesters_30d",
        "https://iplists.firehol.org/files/php_harvesters_30d.ipset",
        "web harvester",
    ),
    Feed(
        "firehol_php_spammers_30d",
        "https://iplists.firehol.org/files/php_spammers_30d.ipset",
        "form spammer",
    ),
    Feed(
        "firehol_stopforumspam_30d",
        "https://iplists.firehol.org/files/stopforumspam_30d.ipset",
        "forum spammer",
    ),
    Feed(
        "firehol_stopforumspam_toxic",
        "https://iplists.firehol.org/files/stopforumspam_toxic.netset",
        "spam network",
    ),
    Feed(
        "firehol_abusers_30d",
        "https://iplists.firehol.org/files/firehol_abusers_30d.netset",
        "web abuse",
    ),
    Feed(
        "firehol_cleantalk",
        "https://iplists.firehol.org/files/cleantalk_30d.ipset",
        "form spammer",
    ),
    Feed("myip", "https://myip.ms/files/blacklist/general/full_blacklist_database.zip", "web blacklist"),
    Feed(
        "bitwire_outbound",
        "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt",
        "bad reputation",
        usage_class="non_commercial",
    ),
    Feed("botvrij", "https://www.botvrij.eu/data/ioclist.ip-dst.raw", "threat IOC"),
    Feed(
        "alienvault_reputation",
        "https://reputation.alienvault.com/reputation.generic",
        "bad reputation",
    ),
    Feed(
        "turris",
        "https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv",
        "service abuse",
        usage_class="non_commercial",
    ),
    Feed(
        "firehol_anonymous",
        "https://iplists.firehol.org/files/firehol_anonymous.netset",
        "anonymizer",
    ),
)
