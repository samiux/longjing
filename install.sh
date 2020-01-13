#!/bin/bash
#
# Installer script
# Author      : Samiux
# Website     : https://www.infosec-ninjas.com
# Blog        : https://samiux.blogspot.com
# Date        : MAR 04, 2019
# Version     : 0.10.5
#

# check if root
if [ "$(id -u)" != "0" ]; then
	echo "Sorry, you don't have root privileges to run this script."
	exit 1
fi

# check if version 0.10.3 (or older) is running or not
if [ -f /lib/systemd/system/longjing.service ]
then
        sudo systemctl stop longjing.service
fi

# copy config.conf file
if ! [ -f /etc/longjing/config.conf ]
then
	sudo mkdir -p /etc/longjing
        sudo cp config.conf /etc/longjing
fi

# read config.conf
. /etc/longjing/config.conf

# copy waf_dl.service
if [ -f /lib/systemd/system/longjing.service ]
then
	sudo rm /lib/systemd/system/longjing.service
fi
sudo touch /lib/systemd/system/longjing.service
sudo cat >>/lib/systemd/system/longjing.service <<END

[Unit]
Description=Longjing WAF Daemon
Wants=network.target syslog.target
After=network.target syslog.target

[Service]
Type=simple
ExecStart=/root/anaconda3/bin/mitmdump -p $PORT --set stream_large_bodies=1k --set block_global=false -s /etc/longjing/longjing.py -m transparent -q $CERT
ExecStartPre=/etc/longjing/port-redirect
ExecStopPre=/etc/longjing/port-resume
Restart=always
RestartSec=600
StartLimitIntervalSec=3600
StartLimitBurst=6

[Install]
WantedBy=multi-user.target
END

# copy related files
sudo cp *.py /etc/longjing/
sudo cp *.pickle /etc/longjing/
sudo cp port-re* /etc/longjing/
sudo cp *.sh /etc/longjing/
sudo cp index.html /etc/longjing/
sudo cp INSTALL /etc/longjing/

# start services
sudo systemctl daemon-reload
sudo systemctl enable longjing.service
sudo systemctl restart longjing.service

# completed
echo ""
echo "Install completed!"
echo "Copy 'index.html' to the Web root directory!"
echo ""
