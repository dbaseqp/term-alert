#!/bin/bash

YUM_CMD=$(which yum)
APT_GET_CMD=$(which apt-get)

if [[ ! -z $YUM_CMD ]]; then
    yum install epel-release python-urwid python3 python3-pip git -y
elif [[ ! -z $APT_GET_CMD ]]; then
    apt-get update -y 
    apt-get install python3 python3-pip git python-urwid -y
else
    echo "installation failed"
    exit 1;
fi

pip3 install urwid
git clone https://github.com/dbaseqp/term-alert
cd term-alert
