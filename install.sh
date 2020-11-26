#!/bin/bash

clear

sudo apt-get update
sudo apt-get install python3 python3-pip -y
sudo apt-get install libssl-dev libcurl4-openssl-dev libsqlite3-dev -y

sudo python3 setup.py build
sudo python3 setup.py install

python3 -m pip install pysqlite3 tqdm

chmod +x -R examples/

echo -e "\n\n~ Done & Dusted! ~\n"
