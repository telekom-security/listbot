#!/bin/bash

####################################################
#
# This is just an example on how to automate listbot
# Make sure to adjust paths to your needs
# Do not run from within the local GitHub repo
#
####################################################

myHOME=$(pwd)
myDATE=$(date)

# Build CVE Translation Map
/opt/listbot/gen_cve_map.sh 2>&1 > $myHOME/cve_log.txt &

# Build IP Rep. Translation Map
/opt/listbot/gen_iprep_map.sh 2>&1 > $myHOME/iprep_log.txt &

# Wait for background jobs to finish
wait

# Sanity Check
myCVE=$(grep -c "CVE\|CAN" < cve.yaml)
myIPREP=$(grep -c -P "\b(?:\d{1,3}\.){3}\d{1,3}\b" < iprep.yaml)

if [ $myCVE -gt 5000 ] && [ $myIPREP -gt 200000 ];
  then
    myMESSAGE="$myDATE: $myCVE IDs, $myIPREP reps - OK."
    echo "$myMESSAGE" >> $myHOME/run.log
    cp *.bz2 *.yaml /root/listbot/

    # Push to Github
    cd /root/listbot/
    git add *.bz2 *.yaml 2>&1 >> $myHOME/run.log
    git commit -m "\"Include $myCVE CVE IDs, $myIPREP reputations\"" 2>&1 >> $myHOME/run.log
    git push ssh://git@github.com/dtag-dev-sec/listbot.git 2>&1 >> $myHOME/run.log
  else
    myMESSAGE="$myDATE: $myCVE IDs, $myIPREP reps - ERROR."
    echo "$myMESSAGE" >> $myHOME/error.log
fi

cd $myHOME

# Send Pushover
curl -s \
  --form-string "token=<your.token.without.brackets.here>" \
  --form-string "user=<your.user.without.brackets.here>" \
  --form-string "message=$myMESSAGE" \
  https://api.pushover.net/1/messages.json

echo

