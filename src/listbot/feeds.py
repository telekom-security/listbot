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


DEFAULT_SURICATA_VERSION = "8.0.0"
ET_SID_MAP_URL_TEMPLATE = (
    "https://rules.emergingthreats.net/open/"
    "suricata-{version}/rules/sid-msg.map"
)

# Feed order is meaningful: if an IP appears in multiple feeds, the first tag wins.
IPREP_FEEDS: tuple[Feed, ...] = (
    Feed(
        "feodotracker",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "malware",
    ),
    Feed(
        "threatfox_ip_port_recent",
        "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "malware",
    ),
    Feed(
        "neo23x0_c2",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt",
        "known c2",
    ),
    Feed(
        "cybercrime_tracker",
        "https://cybercrime-tracker.net/all.php",
        "C2 server",
    ),
    Feed(
        "firehol_webclient",
        "https://iplists.firehol.org/files/firehol_webclient.netset",
        "malware",
    ),
    Feed(
        "et_compromised",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "compromised",
    ),
    Feed(
        "maltrail_mass_scanner",
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt",
        "mass scanner",
    ),
    Feed(
        "tor_bulk_exit",
        "https://check.torproject.org/torbulkexitlist",
        "tor exit node",
    ),
    Feed(
        "tor_exit_addresses",
        "https://check.torproject.org/exit-addresses",
        "tor exit node",
    ),
    Feed(
        "firehol_dm_tor",
        "https://iplists.firehol.org/files/dm_tor.ipset",
        "tor exit node",
    ),
    Feed(
        "firehol_proxylists",
        "https://iplists.firehol.org/files/proxylists_30d.ipset",
        "anonymizer",
    ),
    Feed(
        "firehol_proxyrss",
        "https://iplists.firehol.org/files/proxyrss_30d.ipset",
        "anonymizer",
    ),
    Feed(
        "firehol_proxyspy",
        "https://iplists.firehol.org/files/proxyspy_30d.ipset",
        "anonymizer",
    ),
    Feed(
        "firehol_web_proxies",
        "https://iplists.firehol.org/files/ri_web_proxies_30d.ipset",
        "anonymizer",
    ),
    Feed(
        "firehol_socks_proxy",
        "https://iplists.firehol.org/files/socks_proxy_30d.ipset",
        "anonymizer",
    ),
    Feed(
        "firehol_sslproxies",
        "https://iplists.firehol.org/files/sslproxies_30d.ipset",
        "anonymizer",
    ),
    Feed("spys", "https://spys.me/proxy.txt", "anonymizer"),
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
        "known attacker",
    ),
    Feed(
        "firehol_mwdomainlist",
        "https://iplists.firehol.org/files/malwaredomainlist.ipset",
        "known attacker",
    ),
    Feed(
        "firehol_dshield",
        "https://iplists.firehol.org/files/dshield_30d.netset",
        "known attacker",
    ),
    Feed(
        "firehol_darklist",
        "https://iplists.firehol.org/files/darklist_de.netset",
        "known attacker",
        max_network_hosts=200_000,
    ),
    Feed(
        "binary_defense_banlist",
        "https://www.binarydefense.com/banlist.txt",
        "known attacker",
    ),
    Feed("blocklist", "https://lists.blocklist.de/lists/all.txt", "known attacker"),
    Feed("cinsscore", "https://cinsscore.com/list/ci-badguys.txt", "known attacker"),
    Feed("greensnow", "http://blocklist.greensnow.co/greensnow.txt", "known attacker"),
    Feed("rutgers", "https://report.cs.rutgers.edu/DROP/attackers", "known attacker"),
    Feed("spamlist", "https://www.ipspamlist.com/public_feeds.csv", "form spammer"),
    Feed(
        "dshield",
        "https://feeds.dshield.org/block.txt",
        "known attacker",
        parser="dshield",
    ),
    Feed(
        "ipsum_level3",
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "bad reputation",
    ),
    Feed(
        "firehol_abusers_30d",
        "https://iplists.firehol.org/files/firehol_abusers_30d.netset",
        "abuse",
    ),
    Feed(
        "firehol_cleantalk",
        "https://iplists.firehol.org/files/cleantalk_30d.ipset",
        "abuse",
    ),
    Feed("myip", "https://myip.ms/files/blacklist/general/full_blacklist_database.zip", "bot, crawler"),
    Feed(
        "bitwire_outbound",
        "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt",
        "bad reputation",
    ),
    Feed("botvrij", "https://www.botvrij.eu/data/ioclist.ip-dst.raw", "bad reputation"),
    Feed(
        "alienvault_reputation",
        "https://reputation.alienvault.com/reputation.generic",
        "bad reputation",
    ),
    Feed(
        "turris",
        "https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv",
        "bad reputation",
    ),
)
