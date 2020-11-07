#! /bin/bash
if [ "$EUID" -ne 0 ]
  then echo "[-] Please run as root"
  exit
fi

sudo apt update
sudo apt install -y docker.io
sudo systemctl enable docker --now
