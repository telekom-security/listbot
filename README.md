# listbot

<p align="center">
  <img src="assets/listbot-logo.png" alt="listbot logo" width="520">
</p>

`listbot` builds compact Logstash-style YAML translation maps for two common
security enrichment jobs:

- `cve.yaml`: Emerging Threats SID to CVE/CAN lookup data
- `iprep.yaml`: IPv4 reputation data from public OSINT feeds

Each output is also written as a bzip2-compressed copy, so the default result is:

- `cve.yaml`
- `cve.yaml.bz2`
- `iprep.yaml`
- `iprep.yaml.bz2`

The project used to be shell-heavy. It now runs as a Python CLI managed by
Astral `uv`, with native parsers for text, CSV-like files, gzip, zip, CIDR
ranges, and DShield-style start/end ranges.

## Usage

Create the Python 3.14 virtual environment and install dependencies:

```bash
uv sync --python 3.14
```

### Option 1: Run through `uv`

Use this when you do not want to activate the virtual environment manually.
`uv run` starts the command inside the project environment.

Generate both maps in the current directory:

```bash
uv run listbot gen-all --output-dir .
```

Generate one map at a time:

```bash
uv run listbot gen-cve --output-dir .
uv run listbot gen-iprep --output-dir .
```

Run the automation command with sanity thresholds, logs, optional publishing,
and optional Pushover notification:

```bash
uv run listbot run --output-dir .
uv run listbot run --output-dir . --publish-dir /root/listbot --git-push
```

Pushover is optional. Set `PUSHOVER_TOKEN` and `PUSHOVER_USER`, or pass
`--pushover-token` and `--pushover-user`.

### Option 2: Activate `.venv`

Use this when you prefer the shorter `listbot ...` command during an interactive
session or in a shell script that already activates the environment.

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Generate both maps in the current directory:

```bash
listbot gen-all --output-dir .
```

Generate one map at a time:

```bash
listbot gen-cve --output-dir .
listbot gen-iprep --output-dir .
```

Run the automation command with sanity thresholds, logs, optional publishing,
and optional Pushover notification:

```bash
listbot run --output-dir .
listbot run --output-dir . --publish-dir /root/listbot --git-push
```

You can leave the environment with:

```bash
deactivate
```

## Commands

### `gen-all`

Builds `cve.yaml` and `iprep.yaml` in one command. This is the normal command
for local use and scheduled generation when you only want the files.

```bash
listbot gen-all --output-dir /var/lib/listbot
```

Useful options:

- `--workers 8`: number of concurrent IP feed downloads
- `--timeout 30`: HTTP timeout in seconds
- `--suricata-version 8.0.0`: Emerging Threats Open ruleset version
- `--cve-url URL`: explicit `sid-msg.map` override

### `gen-cve`

Builds only the CVE map:

```bash
listbot gen-cve --output-dir .
```

The parser keeps the legacy scalar YAML format. If one SID contains multiple
CVE/CAN references, the first reference in source order wins, so values stay as
single strings.

### `gen-iprep`

Builds only the IP reputation map:

```bash
listbot gen-iprep --output-dir .
```

The parser validates IPv4 addresses with Python's `ipaddress` module and only
writes globally routable IPv4 addresses. This avoids false matches from comments
or version-like strings in feed metadata.

### `run`

Builds both maps, checks minimum counts, writes `run.log` or `error.log`, and
can publish the four generated files to another Git working tree.

```bash
listbot run \
  --output-dir /var/lib/listbot/build \
  --publish-dir /srv/listbot-artifacts \
  --git-push
```

Default success thresholds:

- CVE mappings: more than `5000`
- IP reputation mappings: more than `200000`

Override them with `--min-cve` and `--min-iprep`.

## Terminal Output

`listbot` uses Rich for colored terminal output:

- progress bars for download, parse, and write phases
- colored success/error summaries
- output file locations
- feed success/failure counts
- a table of the largest feed contributions

The generated YAML and `.bz2` files are unchanged by the terminal UI.

## Output Format

The YAML files intentionally use the same scalar mapping style as the legacy
generator:

```yaml
"2000016": "CAN-2004-0120"
"1.2.3.4": "known attacker"
```

The files are sorted by key and deduplicated. For duplicate IPs across feeds,
the first matching feed in `src/listbot/feeds.py` wins.

## Feed Policy

The default feed set is public OSINT only:

- no API keys
- no paid feeds
- no default feeds that require authentication
- dead or deprecated historical feeds removed

The IP reputation feeds are configured in `src/listbot/feeds.py`. A feed entry
contains the feed name, URL, output tag, parser style, and expansion limits for
CIDR/range data. Feed order matters: the first feed that contributes an IP wins
the tag for that IP.

Feed data is not relicensed by this project. The license/terms column records
what upstream currently publishes or what is visible in the feed itself. If no
explicit feed license was found, the table says so instead of guessing.

| Feed ID | Source | Tag | Purpose and notes | Upstream license / terms |
| --- | --- | --- | --- | --- |
| `feodotracker` | [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/downloads/ipblocklist.txt) | `malware` | Botnet C2 IP blocklist. | [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/); Feodo documents vendor use for commercial and non-commercial purposes. |
| `threatfox_ip_port_recent` | [abuse.ch ThreatFox](https://threatfox.abuse.ch/export/csv/ip-port/recent/) | `malware` | Recent `ip:port` malware and botnet C2 IOCs. | [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/); no separate SPDX-style data license stated. |
| `neo23x0_c2` | [Neo23x0 signature-base](https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt) | `known c2` | C2 indicators from the public signature-base IOC set. | [Detection Rule License 1.1](https://raw.githubusercontent.com/Neo23x0/signature-base/master/LICENSE). |
| `cybercrime_tracker` | [CyberCrime Tracker](https://cybercrime-tracker.net/all.php) | `C2 server` | C2 and malware infrastructure indicators. | No explicit feed license found. |
| `firehol_webclient` | [FireHOL webclient](https://iplists.firehol.org/files/firehol_webclient.netset) | `malware` | Destinations a web client should not contact. | FireHOL aggregate/mirror; upstream list licenses may vary. FireHOL asks users to check each source site. |
| `et_compromised` | [Emerging Threats compromised IPs](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | `compromised` | Compromised hosts from Emerging Threats. | Emerging Threats/Proofpoint terms; the blockrules feed has no explicit license header. ET Open rules are GPLv2/BSD by SID range. |
| `maltrail_mass_scanner` | [Maltrail mass scanners](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt) | `mass scanner` | Static mass-scanner indicators. | [MIT](https://raw.githubusercontent.com/stamparm/maltrail/master/LICENSE). |
| `tor_bulk_exit` | [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) | `tor exit node` | Current Tor exit nodes. | Tor Project exit-list service; no explicit data license found on the feed endpoint. |
| `tor_exit_addresses` | [Tor exit addresses](https://check.torproject.org/exit-addresses) | `tor exit node` | TorDNSEL-style exit address data. | Tor Project exit-list service; no explicit data license found on the feed endpoint. |
| `firehol_dm_tor` | [FireHOL dm_tor](https://iplists.firehol.org/files/dm_tor.ipset) | `tor exit node` | FireHOL-hosted Tor exit snapshot. | FireHOL mirror; upstream license/terms depend on the original Tor-related source. |
| `firehol_proxylists` | [FireHOL proxylists](https://iplists.firehol.org/files/proxylists_30d.ipset) | `anonymizer` | Public proxy list snapshot. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_proxyrss` | [FireHOL proxyrss](https://iplists.firehol.org/files/proxyrss_30d.ipset) | `anonymizer` | Public proxy RSS snapshot. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_proxyspy` | [FireHOL proxyspy](https://iplists.firehol.org/files/proxyspy_30d.ipset) | `anonymizer` | ProxySpy-derived proxy list. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_web_proxies` | [FireHOL RI web proxies](https://iplists.firehol.org/files/ri_web_proxies_30d.ipset) | `anonymizer` | Web proxy indicators. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_socks_proxy` | [FireHOL socks proxy](https://iplists.firehol.org/files/socks_proxy_30d.ipset) | `anonymizer` | SOCKS proxy indicators. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_sslproxies` | [FireHOL SSL proxies](https://iplists.firehol.org/files/sslproxies_30d.ipset) | `anonymizer` | SSL proxy indicators. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `spys` | [spys.me proxy list](https://spys.me/proxy.txt) | `anonymizer` | Public proxy list. | No explicit feed license found. |
| `firehol_botscout` | [FireHOL BotScout](https://iplists.firehol.org/files/botscout_30d.ipset) | `form spammer` | BotScout spammer snapshot. | FireHOL mirror; upstream BotScout terms apply, explicit feed license not stated in the mirrored file. |
| `sblam` | [Sblam blacklist](https://sblam.com/blacklist.txt) | `form spammer` | HTTP/form spam sources. | No explicit feed license found; feed labels the data as HTTP/form spam sources. |
| `firehol_bitcoin` | [FireHOL bitcoin nodes](https://iplists.firehol.org/files/bitcoin_nodes_30d.ipset) | `bitcoin node` | Bitcoin node enrichment data, not necessarily malicious. | FireHOL mirror; upstream source license/terms may vary. |
| `firehol_cruzit` | [FireHOL CruzIT](https://iplists.firehol.org/files/cruzit_web_attacks.ipset) | `known attacker` | Web attack sources. | FireHOL mirror; upstream source license/terms may vary or be unstated. |
| `firehol_mwdomainlist` | [FireHOL malwaredomainlist](https://iplists.firehol.org/files/malwaredomainlist.ipset) | `known attacker` | Malware-domain-derived IP indicators. | FireHOL mirror; upstream source license/terms may vary or be unstated. |
| `firehol_dshield` | [FireHOL DShield 30d](https://iplists.firehol.org/files/dshield_30d.netset) | `known attacker` | DShield attacker netset snapshot. | FireHOL mirror of DShield-derived data; DShield publishes CC BY-NC-SA 2.5 terms on its direct feed. |
| `firehol_darklist` | [FireHOL darklist.de](https://iplists.firehol.org/files/darklist_de.netset) | `known attacker` | SSH fail2ban reporting from darklist.de. | FireHOL mirror; no explicit darklist.de feed license found in the mirrored file. |
| `binary_defense_banlist` | [Binary Defense ATIF](https://www.binarydefense.com/banlist.txt) | `known attacker` | Public banlist. | Public use only; commercial resale or fee-based services are prohibited in the feed header. |
| `blocklist` | [blocklist.de all](https://lists.blocklist.de/lists/all.txt) | `known attacker` | Reported service attackers. | blocklist.de export terms: provided as-is, used at your own risk; no explicit data license found. |
| `cinsscore` | [CINS Score](https://cinsscore.com/list/ci-badguys.txt) | `known attacker` | Badguys list. | Public CINS Army list; no explicit feed license found. |
| `greensnow` | [GreenSnow](http://blocklist.greensnow.co/greensnow.txt) | `known attacker` | Known attacker list. | Public blacklist; no explicit feed license found. |
| `rutgers` | [Rutgers DROP attackers](https://report.cs.rutgers.edu/DROP/attackers) | `known attacker` | Attackers from Rutgers DROP. | No explicit feed license found. |
| `spamlist` | [IPSpamList public feed](https://www.ipspamlist.com/public_feeds.csv) | `form spammer` | Public spam source feed. The feed currently describes itself as a non-updated sample. | No explicit feed license found. |
| `dshield` | [DShield block list](https://feeds.dshield.org/block.txt) | `known attacker` | Top attacking subnets, parsed from start/end ranges. | [Creative Commons BY-NC-SA 2.5](http://creativecommons.org/licenses/by-nc-sa/2.5/) per feed header. |
| `ipsum_level3` | [IPsum level 3](https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt) | `bad reputation` | IPs seen on at least three source lists. | [Unlicense/public-domain dedication](https://raw.githubusercontent.com/stamparm/ipsum/master/LICENSE). |
| `firehol_abusers_30d` | [FireHOL abusers 30d](https://iplists.firehol.org/files/firehol_abusers_30d.netset) | `abuse` | Recent abuse-tracking aggregate. | FireHOL aggregate/mirror; upstream licenses vary. |
| `firehol_cleantalk` | [FireHOL CleanTalk](https://iplists.firehol.org/files/cleantalk_30d.ipset) | `abuse` | CleanTalk abuse snapshot. | FireHOL mirror; upstream CleanTalk terms apply, explicit feed license not stated in the mirrored file. |
| `myip` | [MyIP blacklist](https://myip.ms/files/blacklist/general/full_blacklist_database.zip) | `bot, crawler` | Bot and crawler blacklist archive. | MyIP.ms publishes the download for website firewall use; no explicit data license found. |
| `bitwire_outbound` | [Bitwire IP blocklist](https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt) | `bad reputation` | Aggregated outbound blocklist. | Aggregated data is [CC BY-NC-SA 4.0](https://github.com/bitwire-it/ipblocklist#license) and subject to original provider licenses; Bitwire code is MIT. |
| `botvrij` | [Botvrij IOC list](https://www.botvrij.eu/data/ioclist.ip-dst.raw) | `bad reputation` | Destination IOC IPs. | Botvrij describes the data as open-source IOCs; no explicit SPDX-style data license found. |
| `alienvault_reputation` | [AlienVault reputation](https://reputation.alienvault.com/reputation.generic) | `bad reputation` | AlienVault IP reputation database. | AlienVault/LevelBlue OTX terms may apply; no explicit license in the feed header. |
| `turris` | [Turris Sentinel Greylist](https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv) | `bad reputation` | Turris Sentinel Greylist data. | [CC BY-NC-SA 4.0](https://view.sentinel.turris.cz/greylist-data/LICENSE.txt); commercial offerings require contacting CZ.NIC. |

The CVE map uses Emerging Threats Open `sid-msg.map`. The ET Open license file
states that older SID ranges are GPLv2 and Emerging Threats SID ranges are BSD;
the generated `cve.yaml` only contains SID-to-CVE/CAN lookup values extracted
from that map.

## Development

Run tests:

```bash
uv run pytest
```

Confirm the Python runtime:

```bash
uv run python --version
```

Check the CLI:

```bash
uv run listbot --help
uv run listbot gen-all --help
```

Run a live generation into a temporary directory. With an activated `.venv`, you
can drop the `uv run` prefix here as shown in the usage section above.

```bash
tmpdir="$(mktemp -d)"
uv run listbot gen-all --output-dir "$tmpdir"
ls -lh "$tmpdir"
```

## Notes

- The tool currently supports IPv4 only, matching the original generator.
- Generated YAML and `.bz2` files are build artifacts, not source files.


## License

`listbot` code is licensed under GPL-3.0-only. See `LICENSE`.

The generated maps are derived from third-party OSINT feeds. Those feed terms
remain governed by their upstream providers.
