# Помощник мобильного приложения WiGLE
## Описание
Программа дополняет функционал мобильного приложения WiGLE Wardriving, собирая такую дополнительную информацию о устройствах (где доступно), как версия WPS, производитель, модель, серийный номер и др. в локальную базу данных SQLite.
## Предназначение
Программа может использоваться в исследовательских целях для сбора открытой информации о беспроводных точках доступа из эфира.
## Требования
- [Python 3.8](https://www.python.org/) и выше
- [iw](https://wireless.wiki.kernel.org/en/users/documentation/iw)

## Установка в [Termux](https://play.google.com/store/apps/details?id=com.termux)
Требуется корневой доступ либо SELinux в режиме permissive
```
pkg install python git root-repo tsu
pkg install iw
git clone https://github.com/drygdryg/wigle_companion.git
cd wigle_companion/
```
Если SELinux в разрешительном режиме, то можно запустить программу от обычного пользователя:
```
python main.py -i wlan0
```
Если запуская скрипт вышеприведённым способом вы получаете ошибку, то запустите от суперпользователя:
```
sudo python main.py -i wlan0
```

## Использование
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
