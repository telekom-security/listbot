#!/bin/bash
myIPREPMAP="iprep.yaml"
myRED="[0;31m"
myGREEN="[0;32m"
myBLUE="[0;34m"
myWHITE="[0;0m"

# Prepare for new files
rm -rf *.raw *.yaml.tmp iprep.yaml

### Define repeating commands as functions
# Download only if host is up, file is newer and follow redirects
fuCURL () {
local myFILE=$1
local myURL=$2
local myHOST=$(echo $2 | cut -d "/" -f3)

  echo -n "[ Now checking host ] [$myBLUE $myHOST $myWHITE] "
  curl --connect-timeout 5 -IsS $myHOST 2>&1>/dev/null
  if [ $? -eq 0 ];
    then
      echo "[$myGREEN OK $myWHITE]"
      echo -n "[ Now downloading ] [$myBLUE $myURL $myWHITE] "
      curl -fLso $myFILE -z $myFILE $myURL
        if [ $? -eq 0 ];
          then
            echo "[$myGREEN OK $myWHITE]"
          else
            echo "[$myRED ERROR $myWHITE]"
        fi
    else
      echo "[$myRED ERROR $myWHITE]"
  fi
}

# Only match lines with CIDR addresses, unzip if necessary
# Duplicates will be eliminated for the final translation map!
fuMATCHCIDR () {
local myFILE=$1

  if [ -f $myFILE ];
    then
      myZIP=$(file $myFILE | grep -o "Zip\|gz" | uniq)
      if [ "$myZIP" == "Zip" ];
        then
          unzip -p $myFILE | grep -o -P "\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b" | xargs -I '{}' prips '{}'
      elif [ "$myZIP" == "gz" ];
        then
          gunzip -c -f $myFILE | grep -o -P "\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b" | xargs -I '{}' prips '{}'
        else
          grep -o -P "\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b" $myFILE | xargs -I '{}' prips '{}'
      fi
  fi
}

# Only match lines with IPv4 addresses, unzip if necessary
# Duplicates will be eliminated for the final translation map!
fuMATCHIP () {
local myFILE=$1

  if [ -f $myFILE ];
    then
      myZIP=$(file $myFILE | grep -o "Zip\|gz" | uniq)
      if [ "$myZIP" == "Zip" ];
        then
          unzip -p $myFILE | grep -o -P "\b(?:\d{1,3}\.){3}\d{1,3}\b"
      elif [ "$myZIP" == "gz" ];
        then
          gunzip -c -f $myFILE | grep -o -P "\b(?:\d{1,3}\.){3}\d{1,3}\b"
        else
          grep -o -P "\b(?:\d{1,3}\.){3}\d{1,3}\b" $myFILE
      fi
  fi
}

### Define download function
fuDOWNLOAD () {
local myURL=$1
local myTAG=$2
local myTMPFILE="$3.tmp"
local myYAMLFILE="$3.raw"

  fuCURL $myTMPFILE $myURL
  fuMATCHCIDR $myTMPFILE | awk '{ print "\""$1"\": \"" "'"$myTAG"'" "\"" }' > $myYAMLFILE
  fuMATCHIP $myTMPFILE | awk '{ print "\""$1"\": \"" "'"$myTAG"'" "\"" }' >> $myYAMLFILE
  mySIZE=$(wc -l < $myYAMLFILE)
    if [ "$mySIZE" != "0" ]
      then
        echo "[ Control output ] [$myBLUE $(head -n 1 $myYAMLFILE) $myWHITE]"
      else
        echo "[ Control output ] [$myRED EMPTY FILE $myWHITE]"
    fi
}

# Download reputation lists
fuDOWNLOAD "https://reputation.alienvault.com/reputation.generic" "bad reputation" "alienvault"
fuDOWNLOAD "https://raw.githubusercontent.com/Neo23x0/signature-base/39787aaefa6b70b0be6e7dcdc425b65a716170ca/iocs/otx-c2-iocs.txt" "malware" "alienvault"
fuDOWNLOAD "https://www.badips.com/get/list/any/2?age=90d" "known attacker" "badips"
fuDOWNLOAD "http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt" "C2 server" "bambenek"
fuDOWNLOAD "https://lists.blocklist.de/lists/all.txt" "known attacker" "blocklist"
fuDOWNLOAD "https://iplists.firehol.org/files/bitcoin_nodes_30d.ipset" "bitcoin node" "firehol_bitcoin"
fuDOWNLOAD "https://iplists.firehol.org/files/botscout_30d.ipset" "form spammer" "firehol_botscout"
fuDOWNLOAD "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cruzit_web_attacks.ipset" "known attacker" "firehol_cruzit"
fuDOWNLOAD "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malwaredomainlist.ipset" "known atttacker" "firehol_mwdomainlist"
fuDOWNLOAD "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxylists_30d.ipset" "anonymizer" "firehol_proxylists"
fuDOWNLOAD "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyrss_30d.ipset" "anonymizer" "firehol_proxyrss"
fuDOWNLOAD "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyspy_30d.ipset" "anonymizer" "firehol_proxyspy"
fuDOWNLOAD "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ri_web_proxies_30d.ipset" "anonymizer" "firehol_web_proxies"
fuDOWNLOAD "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy_30d.ipset" "anonymizer" "firehol_socks_proxy"
fuDOWNLOAD "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslproxies_30d.ipset" "anonymizer" "firehol_sslproxies"
fuDOWNLOAD "https://iplists.firehol.org/files/cleantalk_30d.ipset" "abuse" "firehol_cleantalk"
fuDOWNLOAD "https://iplists.firehol.org/files/dshield_30d.netset" "known attacker" "firehol_cleantalk"
fuDOWNLOAD "https://iplists.firehol.org/files/darklist_de.netset" "known attacker" "firehol_darklist"
fuDOWNLOAD "https://iplists.firehol.org/files/dm_tor.ipset" "tor exit node" "firehol_dm_tor"
fuDOWNLOAD "http://danger.rulez.sk/projects/bruteforceblocker/blist.php" "known attacker" "rulez"
fuDOWNLOAD "http://cinsscore.com/list/ci-badguys.txt" "known attacker" "cinsscore"
fuDOWNLOAD "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist" "malware" "feodotracker"
fuDOWNLOAD "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt" "compromised" "et_compromised"
fuDOWNLOAD "http://blocklist.greensnow.co/greensnow.txt" "known attacker" "greensnow"
fuDOWNLOAD "http://www.nothink.org/blacklist/blacklist_malware_irc.txt" "malware" "nothink"
fuDOWNLOAD "http://spys.me/proxy.txt" "anonymizer" "spys"
fuDOWNLOAD "http://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt" "ransomware" "ransomwaretracker"
fuDOWNLOAD "https://report.cs.rutgers.edu/DROP/attackers" "known attacker" "rutgers"
fuDOWNLOAD "http://sblam.com/blacklist.txt" "form spammer" "sblam"
fuDOWNLOAD "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv" "C2 server" "sslbl"
fuDOWNLOAD "http://www.talosintelligence.com/feeds/ip-filter.blf" "bad reputation" "talos"
fuDOWNLOAD "https://check.torproject.org/exit-addresses" "tor exit node" "torexit"
fuDOWNLOAD "https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv" "tor exit node" "torip"
fuDOWNLOAD "https://www.turris.cz/greylist-data/greylist-latest.csv" "bad reputation" "turris"
fuDOWNLOAD "https://zeustracker.abuse.ch/blocklist.php?download=badips" "malware" "zeustracker"
fuDOWNLOAD "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt" "mass scanner" "maltrail_mass_scanner"
fuDOWNLOAD "https://myip.ms/files/blacklist/general/full_blacklist_database.zip" "bot, crawler" "myip"
fuDOWNLOAD "http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz" "spam" "nix"
fuDOWNLOAD "http://www.urlvir.com/export-ip-addresses/" "malware" "urlvir"
fuDOWNLOAD "https://threatintel.stdominics.sa.edu.au/droplist_high_confidence.txt" "known attacker" "threatintel"
fuDOWNLOAD "https://sslbl.abuse.ch/blacklist/dyre_sslipblacklist_aggressive.csv" "C2 server" "dyre"
fuDOWNLOAD "http://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt" "known attacker" "charles"
fuDOWNLOAD "https://zerodot1.gitlab.io/CoinBlockerLists/MiningServerIPList.txt" "mining node" "coinblocker"
fuDOWNLOAD "http://www.botvrij.eu/data/ioclist.ip-dst.raw" "bad reputation" "botvrij"
fuDOWNLOAD "http://www.ipspamlist.com/public_feeds.csv" "known attacker" "spamlist"

# Generate logstash translation map for ip reputation lookup
echo -n "[ Building translation map ] "
cat *.raw > $myIPREPMAP.tmp
# Remove duplicates
sort -u $myIPREPMAP.tmp > $myIPREPMAP
bzip2 -f -k -9 $myIPREPMAP
echo "[$myGREEN DONE $myWHITE]"
