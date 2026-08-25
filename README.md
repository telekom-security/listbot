# listbot

<p align="center">
  <img src="assets/listbot-logo.png" alt="listbot logo" width="520">
</p>

`listbot` builds compact Logstash-style YAML translation maps for two common
security enrichment jobs:

- `cve.yaml`: Emerging Threats SID to CVE/CAN lookup data
- `iprep.yaml`: IPv4 reputation data from public OSINT feeds

Each map is also written as a bzip2-compressed copy, so the generated map
artifact set is:

- `cve.yaml`
- `cve.yaml.bz2`
- `iprep.yaml`
- `iprep.yaml.bz2`
- `NOTICE`

When logging is enabled, `run` also writes `run.log`; failed logged runs are
also appended to `error.log`.

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
uv run listbot run --output-dir .
```

Generate one map at a time:

```bash
uv run listbot gen-cve --config config.toml --output-dir .
uv run listbot gen-iprep --config config.toml --output-dir .
```

Run any command with a TOML config:

```bash
uv run listbot run --config config.toml --output-dir .
```

### Option 2: Activate `.venv`

Use this when you prefer the shorter `listbot ...` command during an interactive
session or in a shell script that already activates the environment.

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Generate both maps in the current directory:

```bash
listbot run --output-dir .
```

Generate one map at a time:

```bash
listbot gen-cve --config config.toml --output-dir .
listbot gen-iprep --config config.toml --output-dir .
```

Run any command with a TOML config:

```bash
listbot run --config config.toml --output-dir .
```

You can leave the environment with:

```bash
deactivate
```

### Option 3: Docker / Docker Compose

Build a local image:

```bash
docker build -t listbot:local .
```

Run the default combined build. The container writes artifacts to `./output`
and keeps the download cache in `./.cache/listbot`:

```bash
mkdir -p output .cache/listbot
docker run --rm \
  -v "$PWD/config.toml:/config/listbot.toml:ro" \
  -v "$PWD/output:/data" \
  -v "$PWD/.cache/listbot:/cache/listbot" \
  listbot:local
```

Run a single command through the same image:

```bash
docker run --rm \
  -v "$PWD/config.toml:/config/listbot.toml:ro" \
  -v "$PWD/output:/data" \
  -v "$PWD/.cache/listbot:/cache/listbot" \
  listbot:local gen-iprep --config /config/listbot.toml --output-dir /data --cache-dir /cache/listbot
```

With Docker Compose:

```bash
mkdir -p output .cache/listbot
docker compose run --rm listbot
```

To remove the one-off container and then clean up the Compose project network
and any named Compose volumes after a successful run:

```bash
docker compose run --rm listbot && docker compose down -v
```

In the provided `docker-compose.yml`, `output` and `.cache/listbot` are
bind-mounted host directories, so `down -v` does not delete those directories or
their generated files. It only removes Docker-managed resources created by
Compose.

The image runs as UID/GID `1000` by default so bind-mounted output files are
usable on typical Linux developer machines. Build with explicit IDs if your
host user differs:

```bash
LISTBOT_UID="$(id -u)" LISTBOT_GID="$(id -g)" docker compose build
```

## Commands

### `run`

Builds `cve.yaml`, `iprep.yaml`, their compressed `.bz2` copies, and `NOTICE`
in one command. With the shipped defaults it also performs threshold checks and
writes logs. This is the normal command for local use and scheduled generation.

```bash
listbot run --output-dir /var/lib/listbot
```

Useful options:

- `--config config.toml`: load command defaults from an explicit TOML config file
- `--workers 8`: number of concurrent IP feed downloads
- `--timeout 30`: HTTP timeout in seconds
- `--suricata-version 8.0.0`: Emerging Threats Open ruleset version
- `--cve-url URL`: explicit `sid-msg.map` override
- `--cache` / `--no-cache`: enable or disable the local raw-download cache
- `--cache-dir PATH`: cache directory for feed payloads and metadata
- `--cache-max-age 6h`: refresh cache entries after this age; supports `m`, `h`, `d`
- `--feed-usage-profile all|commercial|non-commercial`: filter IPREP feeds by usage profile
- `--check-thresholds`: enable minimum count checks
- `--min-cve 5000`: minimum CVE mappings for a checked run
- `--min-iprep 500000`: minimum IP reputation mappings for a checked run
- `--log-dir PATH`: write `run.log` or `error.log` and enable checks
- `--no-log`: disable logging configured in `--config`

### `gen-cve`

Builds only the CVE map:

```bash
listbot gen-cve --config config.toml --output-dir .
```

The command uses the same default cache as `run`. Use `--no-cache` for a live
download or override the cache location with `--cache-dir`. If `./config.toml`
exists, it is loaded automatically; use `--config` to select another file.
`--feed-usage-profile` is accepted for config consistency, but CVE generation
does not use IP reputation feeds.

The parser keeps the legacy scalar YAML format. If one SID contains multiple
CVE/CAN references, the first reference in source order wins, so values stay as
single strings.

### `gen-iprep`

Builds only the IP reputation map:

```bash
listbot gen-iprep --config config.toml --output-dir .
```

The command uses the same default cache as `run`. Use `--no-cache` for live feed
downloads or override the cache age with `--cache-max-age`. If `./config.toml`
exists, it is loaded automatically; use `--config` to select another file.
Use `--feed-usage-profile` to restrict active feeds to a commercial,
non-commercial, or all-feeds profile.

The parser validates IPv4 addresses with Python's `ipaddress` module and only
writes globally routable IPv4 addresses. This avoids false matches from comments
or version-like strings in feed metadata.

By default, `run` uses threshold checks and logging because both the built-in
defaults and the shipped `config.toml` enable them. A checked run passes when
each generated count reaches at least its configured minimum. Default thresholds:

- CVE mappings: at least `5000`
- IP reputation mappings: at least `500000`

Override them with `--min-cve` and `--min-iprep`. For artifact-only runs, set
`[thresholds].enabled = false` and `[logging].enabled = false` in a config file.
`--no-log` disables configured logging, but threshold checks can still be active.

`listbot` does not publish, push, or notify by itself. External jobs can watch
or copy `--output-dir` when they need to move artifacts into another system.

### Config

All commands load `./config.toml` automatically when it exists. You can point to
a different TOML file with `--config`. No legacy config names are searched. CLI
options override config values.

Excerpt:

```toml
[run]
output_dir = "."
workers = 8
timeout = 30.0
suricata_version = "8.0.0"
# cve_url = "https://example.test/sid-msg.map"

[cache]
enabled = true
cache_dir = ".cache/listbot"
cache_max_age = "6h"

[feeds]
# all, commercial, or non-commercial.
# all is an operational choice, not a legal clearance.
usage_profile = "all"

[feeds.iprep]
# The real config.toml lists every IPREP feed explicitly.
# A loaded config must contain every known feed ID with a boolean value.
feodotracker = true
firehol_blocklist_de_ssh = true
firehol_stopforumspam_30d = true
firehol_anonymous = true

[thresholds]
enabled = true
min_cve = 5000
min_iprep = 500000

[logging]
enabled = true
# dir = "/var/log/listbot"
```

Caching is enabled by default for `run`, `gen-cve`, and `gen-iprep`. A valid
cache entry avoids a network request and reuses the raw upstream payload. When a
cache entry is older than `cache_max_age`, listbot deletes it before attempting a
fresh download. There is no stale fallback: if the refresh fails, the feed is
handled like any other failed download. Cache durations must be positive values
with `m`, `h`, or `d` suffixes, for example `30m`, `6h`, or `2d`.

Logging also enables threshold checks. If `logging.dir` is omitted, logs are written
to `output_dir`. `run.log` is an additive history of all logged runs; failed
runs are also appended to `error.log`. Threshold failures are shown as a
dedicated Rich panel and logged with actual count, configured minimum, and
missing count.

The repository includes a commented `config.toml` with all configurable
settings, so local scheduled runs can be adjusted without keeping the README
open next to the terminal.

The `[feeds.iprep]` section is intentionally strict. When a config file is
loaded, every known IP reputation feed must be present as `true` or `false`.
Unknown feed IDs and missing feed IDs are rejected so feed changes are explicit.
Without a config file, listbot uses the built-in default feed set.

The global `[feeds].usage_profile` filter is applied after the individual
feed booleans:

- `commercial`: only feeds classified as explicitly commercial/permissive
- `non-commercial`: commercial/permissive feeds plus explicitly non-commercial feeds
- `all`: every enabled feed, including unclear or restricted upstream terms

This profile is a conservative technical policy, not legal advice. The generated
`NOTICE` remains the source record for upstream terms, retrieval timestamps, and
derived-data attribution.

## Terminal Output

`listbot` uses Rich for colored terminal output:

- progress bars for download, parse, and write phases
- colored success/error summaries
- output file locations
- feed success/failure counts
- a complete feed contribution table sorted by added indicators, including failed feeds

The generated YAML and `.bz2` files are unchanged by the terminal UI.

## Output Format

The YAML files intentionally use the same scalar mapping style as the legacy
generator:

```yaml
"2000016": "CAN-2004-0120"
"1.2.3.4": "attack source"
```

The files are sorted by key and deduplicated. For duplicate IPs across feeds,
the first matching feed in `src/listbot/feeds.py` wins.

Every map build also writes a `NOTICE` file next to the generated maps. It
records the feed source, configured and final URL, retrieval timestamp,
license/terms note, extracted/added row counts, and states that the YAML maps
are derived data from third-party OSINT feeds.

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

`config.toml` controls which default IP reputation feeds are active. The
`[feeds.iprep]` section is explicit by design: every feed ID must be present, so
operators can review new sources before running scheduled builds.

`[feeds].usage_profile` adds a second, global filter for environments with
different usage requirements. The filter is intentionally defensive: feeds
without explicit licensing or terms are treated as `unknown` and are only used
with `all`.

Tags are short analyst-facing labels intended for Kibana dashboards. Specific
tags are preferred when a feed states a concrete behavior such as C2, scanning,
open proxies, service abuse, or form spam. `attack source` is used for generic
attack-focused feeds where the upstream data does not support a narrower claim.
`anonymizer` is enrichment context, not a malware or attack assertion.

Feed data is not relicensed by this project. The license/terms column records
what upstream currently publishes or what is visible in the feed itself. If no
explicit feed license was found, the table says so instead of guessing.

Usage classes used by the profile filter:

- `unrestricted`: used by `commercial`, `non-commercial`, and `all`
- `non_commercial`: used by `non-commercial` and `all`
- `restricted`: used only by `all`
- `unknown`: used only by `all`

Initial conservative classification:

- `unrestricted`: `feodotracker`, `maltrail_mass_scanner`, `ipsum_level3`
- `non_commercial`: `firehol_dshield`, `dshield`, `bitwire_outbound`, `turris`
- `restricted`: `binary_defense_banlist`
- `unknown`: all other IP reputation feeds

| Feed ID | Source | Tag | Purpose and notes | Upstream license / terms |
| --- | --- | --- | --- | --- |
| `feodotracker` | [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/downloads/ipblocklist.txt) | `botnet C2` | Botnet C2 IP blocklist. | [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/); Feodo documents vendor use for commercial and non-commercial purposes. |
| `threatfox_ip_port_recent` | [abuse.ch ThreatFox](https://threatfox.abuse.ch/export/csv/ip-port/recent/) | `malware infra` | Recent `ip:port` malware infrastructure and botnet C2 IOCs. | [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/); no separate SPDX-style data license stated. |
| `neo23x0_c2` | [Neo23x0 signature-base](https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt) | `C2 server` | C2 indicators from the public signature-base IOC set. | [Detection Rule License 1.1](https://raw.githubusercontent.com/Neo23x0/signature-base/master/LICENSE). |
| `cybercrime_tracker` | [CyberCrime Tracker](https://cybercrime-tracker.net/all.php) | `malware infra` | Cybercrime and malware infrastructure indicators. | No explicit feed license found. |
| `firehol_webclient` | [FireHOL webclient](https://iplists.firehol.org/files/firehol_webclient.netset) | `malware infra` | Malware infrastructure destinations a web client should not contact. | FireHOL aggregate/mirror; upstream list licenses may vary. FireHOL asks users to check each source site. |
| `et_compromised` | [Emerging Threats compromised IPs](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | `compromised` | Compromised hosts from Emerging Threats. | Emerging Threats/Proofpoint terms; the blockrules feed has no explicit license header. ET Open rules are GPLv2/BSD by SID range. |
| `maltrail_mass_scanner` | [Maltrail mass scanners](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt) | `mass scanner` | Static mass-scanner indicators. | [MIT](https://raw.githubusercontent.com/stamparm/maltrail/master/LICENSE). |
| `tor_bulk_exit` | [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) | `tor exit` | Current Tor exits. | Tor Project exit-list service; no explicit data license found on the feed endpoint. |
| `tor_exit_addresses` | [Tor exit addresses](https://check.torproject.org/exit-addresses) | `tor exit` | TorDNSEL-style exit address data. | Tor Project exit-list service; no explicit data license found on the feed endpoint. |
| `firehol_dm_tor` | [FireHOL dm_tor](https://iplists.firehol.org/files/dm_tor.ipset) | `tor exit` | FireHOL-hosted Tor exit snapshot. | FireHOL mirror; upstream license/terms depend on the original Tor-related source. |
| `firehol_proxylists` | [FireHOL proxylists](https://iplists.firehol.org/files/proxylists_30d.ipset) | `open proxy` | Open proxy list snapshot. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_proxyrss` | [FireHOL proxyrss](https://iplists.firehol.org/files/proxyrss_30d.ipset) | `open proxy` | Open proxy RSS snapshot. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_proxyspy` | [FireHOL proxyspy](https://iplists.firehol.org/files/proxyspy_30d.ipset) | `open proxy` | ProxySpy-derived open proxy list. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_web_proxies` | [FireHOL RI web proxies](https://iplists.firehol.org/files/ri_web_proxies_30d.ipset) | `open proxy` | Open web proxy indicators. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_socks_proxy` | [FireHOL socks proxy](https://iplists.firehol.org/files/socks_proxy_30d.ipset) | `open proxy` | Open SOCKS proxy indicators. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `firehol_sslproxies` | [FireHOL SSL proxies](https://iplists.firehol.org/files/sslproxies_30d.ipset) | `open proxy` | Open SSL proxy indicators. | FireHOL mirror; upstream proxy-list licenses may vary or be unstated. |
| `spys` | [spys.me proxy list](https://spys.me/proxy.txt) | `open proxy` | Open proxy list. | No explicit feed license found. |
| `firehol_botscout` | [FireHOL BotScout](https://iplists.firehol.org/files/botscout_30d.ipset) | `form spammer` | BotScout spammer snapshot. | FireHOL mirror; upstream BotScout terms apply, explicit feed license not stated in the mirrored file. |
| `sblam` | [Sblam blacklist](https://sblam.com/blacklist.txt) | `form spammer` | HTTP/form spam sources. | No explicit feed license found; feed labels the data as HTTP/form spam sources. |
| `firehol_bitcoin` | [FireHOL bitcoin nodes](https://iplists.firehol.org/files/bitcoin_nodes_30d.ipset) | `bitcoin node` | Bitcoin node enrichment data, not necessarily malicious. | FireHOL mirror; upstream source license/terms may vary. |
| `firehol_cruzit` | [FireHOL CruzIT](https://iplists.firehol.org/files/cruzit_web_attacks.ipset) | `web attacker` | Web attack sources. | FireHOL mirror; upstream source license/terms may vary or be unstated. |
| `firehol_mwdomainlist` | [FireHOL malwaredomainlist](https://iplists.firehol.org/files/malwaredomainlist.ipset) | `malware host` | Malware host IP indicators. | FireHOL mirror; upstream source license/terms may vary or be unstated. |
| `firehol_dshield` | [FireHOL DShield 30d](https://iplists.firehol.org/files/dshield_30d.netset) | `scan source` | DShield scan-source netset snapshot. | FireHOL mirror of DShield-derived data; DShield publishes CC BY-NC-SA 2.5 terms on its direct feed. |
| `firehol_darklist` | [FireHOL darklist.de](https://iplists.firehol.org/files/darklist_de.netset) | `attack source` | Generic blacklisted attack sources from darklist.de. | FireHOL mirror; no explicit darklist.de feed license found in the mirrored file. |
| `binary_defense_banlist` | [Binary Defense ATIF](https://www.binarydefense.com/banlist.txt) | `bad reputation` | Public bad-reputation banlist. | Public use only; commercial resale or fee-based services are prohibited in the feed header. |
| `firehol_blocklist_de_apache` | [FireHOL blocklist.de apache](https://iplists.firehol.org/files/blocklist_de_apache.ipset) | `web attacker` | blocklist.de Apache and web-service abuse sources. | FireHOL mirror of blocklist.de apache feed; blocklist.de export terms apply. |
| `firehol_blocklist_de_bots` | [FireHOL blocklist.de bots](https://iplists.firehol.org/files/blocklist_de_bots.ipset) | `bot activity` | blocklist.de bot activity sources. | FireHOL mirror of blocklist.de bots feed; blocklist.de export terms apply. |
| `firehol_blocklist_de_ftp` | [FireHOL blocklist.de ftp](https://iplists.firehol.org/files/blocklist_de_ftp.ipset) | `ftp abuse` | blocklist.de FTP abuse sources. | FireHOL mirror of blocklist.de FTP feed; blocklist.de export terms apply. |
| `firehol_blocklist_de_imap` | [FireHOL blocklist.de imap](https://iplists.firehol.org/files/blocklist_de_imap.ipset) | `mail abuse` | blocklist.de IMAP abuse sources. | FireHOL mirror of blocklist.de IMAP feed; blocklist.de export terms apply. |
| `firehol_blocklist_de_mail` | [FireHOL blocklist.de mail](https://iplists.firehol.org/files/blocklist_de_mail.ipset) | `mail abuse` | blocklist.de mail abuse sources. | FireHOL mirror of blocklist.de mail feed; blocklist.de export terms apply. |
| `firehol_blocklist_de_sip` | [FireHOL blocklist.de sip](https://iplists.firehol.org/files/blocklist_de_sip.ipset) | `sip abuse` | blocklist.de SIP/VoIP abuse sources. | FireHOL mirror of blocklist.de SIP feed; blocklist.de export terms apply. |
| `firehol_blocklist_de_ssh` | [FireHOL blocklist.de ssh](https://iplists.firehol.org/files/blocklist_de_ssh.ipset) | `ssh abuse` | blocklist.de SSH abuse sources. | FireHOL mirror of blocklist.de SSH feed; blocklist.de export terms apply. |
| `firehol_blocklist_de` | [FireHOL blocklist.de all](https://iplists.firehol.org/files/blocklist_de.ipset) | `service abuse` | Reported service abuse sources. | FireHOL mirror of blocklist.de all feed; blocklist.de export terms apply. |
| `cinsscore` | [CINS Score](https://cinsscore.com/list/ci-badguys.txt) | `bad reputation` | Bad reputation badguys list. | Public CINS Army list; no explicit feed license found. |
| `greensnow` | [GreenSnow](http://blocklist.greensnow.co/greensnow.txt) | `attack source` | Generic attack-source blacklist. | Public blacklist; no explicit feed license found. |
| `rutgers` | [Rutgers DROP attackers](https://report.cs.rutgers.edu/DROP/attackers) | `attack source` | Generic DROP attack sources. | No explicit feed license found. |
| `dshield` | [DShield block list](https://feeds.dshield.org/block.txt) | `scan source` | Top scan-source subnets, parsed from start/end ranges. | [Creative Commons BY-NC-SA 2.5](http://creativecommons.org/licenses/by-nc-sa/2.5/) per feed header. |
| `ipsum_level3` | [IPsum level 3](https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt) | `bad reputation` | IPs seen on at least three source lists. | [Unlicense/public-domain dedication](https://raw.githubusercontent.com/stamparm/ipsum/master/LICENSE). |
| `firehol_php_commenters_30d` | [FireHOL Project Honey Pot commenters 30d](https://iplists.firehol.org/files/php_commenters_30d.ipset) | `comment spam` | Project Honey Pot comment spam sources seen in the last 30 days. | FireHOL mirror; Project Honey Pot terms may apply; explicit feed license not stated in the mirrored file. |
| `firehol_php_dictionary_30d` | [FireHOL Project Honey Pot dictionary 30d](https://iplists.firehol.org/files/php_dictionary_30d.ipset) | `web scanner` | Project Honey Pot directory and dictionary attack sources seen in the last 30 days. | FireHOL mirror; Project Honey Pot terms may apply; explicit feed license not stated in the mirrored file. |
| `firehol_php_harvesters_30d` | [FireHOL Project Honey Pot harvesters 30d](https://iplists.firehol.org/files/php_harvesters_30d.ipset) | `web harvester` | Project Honey Pot web harvester sources seen in the last 30 days. | FireHOL mirror; Project Honey Pot terms may apply; explicit feed license not stated in the mirrored file. |
| `firehol_php_spammers_30d` | [FireHOL Project Honey Pot spammers 30d](https://iplists.firehol.org/files/php_spammers_30d.ipset) | `form spammer` | Project Honey Pot form spammer sources seen in the last 30 days. | FireHOL mirror; Project Honey Pot terms may apply; explicit feed license not stated in the mirrored file. |
| `firehol_stopforumspam_30d` | [FireHOL StopForumSpam 30d](https://iplists.firehol.org/files/stopforumspam_30d.ipset) | `forum spammer` | Forum spammer IPs seen in the last 30 days. | FireHOL mirror; StopForumSpam terms may apply; explicit feed license not stated in the mirrored file. |
| `firehol_stopforumspam_toxic` | [FireHOL StopForumSpam toxic](https://iplists.firehol.org/files/stopforumspam_toxic.netset) | `spam network` | StopForumSpam networks with large amounts of spambots. | FireHOL mirror; StopForumSpam terms may apply; explicit feed license not stated in the mirrored file. |
| `firehol_abusers_30d` | [FireHOL abusers 30d](https://iplists.firehol.org/files/firehol_abusers_30d.netset) | `web abuse` | Recent web abuse aggregate. | FireHOL aggregate/mirror; upstream licenses vary. |
| `firehol_cleantalk` | [FireHOL CleanTalk](https://iplists.firehol.org/files/cleantalk_30d.ipset) | `form spammer` | CleanTalk form spammer snapshot. | FireHOL mirror; upstream CleanTalk terms apply, explicit feed license not stated in the mirrored file. |
| `myip` | [MyIP blacklist](https://myip.ms/files/blacklist/general/full_blacklist_database.zip) | `web blacklist` | Website firewall blacklist archive. | MyIP.ms publishes the download for website firewall use; no explicit data license found. |
| `bitwire_outbound` | [Bitwire IP blocklist](https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt) | `bad reputation` | Aggregated outbound blocklist. | Aggregated data is [CC BY-NC-SA 4.0](https://github.com/bitwire-it/ipblocklist#license) and subject to original provider licenses; Bitwire code is MIT. |
| `botvrij` | [Botvrij IOC list](https://www.botvrij.eu/data/ioclist.ip-dst.raw) | `threat IOC` | Threat IOC destination IPs. | Botvrij describes the data as open-source IOCs; no explicit SPDX-style data license found. |
| `alienvault_reputation` | [AlienVault reputation](https://reputation.alienvault.com/reputation.generic) | `bad reputation` | AlienVault IP reputation database. | AlienVault/LevelBlue OTX terms may apply; no explicit license in the feed header. |
| `turris` | [Turris Sentinel Greylist](https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv) | `service abuse` | Turris Sentinel service-abuse greylist data. | [CC BY-NC-SA 4.0](https://view.sentinel.turris.cz/greylist-data/LICENSE.txt); commercial offerings require contacting CZ.NIC. |
| `firehol_anonymous` | [FireHOL anonymous](https://iplists.firehol.org/files/firehol_anonymous.netset) | `anonymizer` | Large anonymizer aggregate including Tor and open proxy sources; enrichment context, not a malware assertion. | FireHOL aggregate/mirror; upstream anonymizer-list licenses may vary. |

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
uv run listbot run --help
```

Run a live generation into a temporary directory. With an activated `.venv`, you
can drop the `uv run` prefix here as shown in the usage section above.

```bash
tmpdir="$(mktemp -d)"
uv run listbot run --output-dir "$tmpdir"
ls -lh "$tmpdir"
```

## Notes

- The tool currently supports IPv4 only, matching the original generator.
- Generated YAML and `.bz2` files are build artifacts, not source files.


## License

`listbot` code is licensed under GPL-3.0-only. See `LICENSE`.

The generated maps are derived from third-party OSINT feeds. Those feed terms
remain governed by their upstream providers.
