# WiGLE Wardriving mobile app assistant
[In Russian](README_ru.md)
## Overview
The program complements the functionality of the WiGLE Wardriving mobile application by collecting additional information about devices (where available) such as WPS version, manufacturer, model, serial number, etc. into a local SQLite database.
## Purpose
The program can be used for research purposes to collect public information about wireless access points from the air.
## Requirements
- [Python 3.8](https://www.python.org/) or above
- [iw](https://wireless.wiki.kernel.org/en/users/documentation/iw)

## Installation in [Termux](https://play.google.com/store/apps/details?id=com.termux)
Requires root access or SELinux in permissive mode
```
pkg install python git root-repo tsu
pkg install iw
git clone https://github.com/drygdryg/wigle_companion.git
cd wigle_companion/
```
If SELinux is in permissive mode, then you can run the program as a regular user:
```
python main.py -i wlan0
```
If you get an error while running the script in the above way, then run as superuser:
```
sudo python main.py -i wlan0
```

## Usage
```
$ python main.py --help
usage: main.py [-h] -i INTERFACE [-m {real,dump}] [-d DELAY] [-f DB_FILE]

WiGLE Wardriving application assistant (Android).This program uses iw for scanning Wi-Fi networks and obtaining info about vendor, model, serial number etc.
(WSC) and writes it to the local database (SQLite)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Name of the wireless interface for scanning
  -m {real,dump}, --mode {real,dump}
                        Network scan mode: real — real scanning (requires superuser access), dump — dumping the results of previous scans (no root required,
                        if SELinux is permissive). Default: dump
  -d DELAY, --delay DELAY
                        Delay between scans (in seconds). Default: 1.5
  -f DB_FILE, --db-file DB_FILE
                        SQLite database for saving results. Default: networks.db
  -q, --quiet           Print less information to stdout

Example: main.py -i wlan0 -d 3

```
