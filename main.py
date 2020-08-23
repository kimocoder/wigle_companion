# -*- coding: utf-8 -*-
import subprocess
import re
import codecs


class WiFiScanner():
    """iw-based Wi-Fi networks scanner"""
    def __init__(self, interface):
        self.interface = interface

    def scan(self, dump_only=False):
        '''Parsing iw scan results'''
        def handle_network(line, result, networks):
            networks.append(
                    {
                        'Security type': 'Unknown',
                        'WPS': False,
                        'WPS state': False,
                        'WPS locked': False,
                        'Response type': False,
                        'UUID': '',
                        'Manufacturer': '',
                        'Model': '',
                        'Model number': '',
                        'Serial number': '',
                        'Primary device type': '',
                        'Device name': '',
                        'Config methods': []
                     }
                )
            networks[-1]['BSSID'] = result.group(1).upper()

        def handle_essid(line, result, networks):
            d = result.group(1)
            networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_level(line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'Privacy' in result.group(2):
                    sec = 'WEP'
                else:
                    sec = 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN':
                    sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handle_wps(line, result, networks):
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsState(line, result, networks):
            networks[-1]['WPS state'] = int(result.group(1))

        def handle_wpsLocked(line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handle_responseType(line, result, networks):
            networks[-1]['Response type'] = int(result.group(1))

        def handle_uuid(line, result, networks):
            d = result.group(1)
            networks[-1]['UUID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_manufacturer(line, result, networks):
            d = result.group(1)
            networks[-1]['Manufacturer'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_model(line, result, networks):
            d = result.group(1)
            networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_modelNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_serialNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Serial number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_primaryDeviceType(line, result, networks):
            networks[-1]['Primary device type'] = result.group(1)

        def handle_deviceName(line, result, networks):
            d = result.group(1)
            networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='ignore')

        def handle_configMethods(line, result, networks):
            networks[-1]['Config methods'] = result.group(1).split(', ')

        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
            re.compile(r' [*] Wi-Fi Protected Setup State: (\d)'): handle_wpsState,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
            re.compile(r' [*] Response Type: (\d)'): handle_responseType,
            re.compile(r' [*] UUID: (.*)'): handle_uuid,
            re.compile(r' [*] Manufacturer: (.*)'): handle_manufacturer,
            re.compile(r' [*] Model: (.*)'): handle_model,
            re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
            re.compile(r' [*] Serial Number: (.*)'): handle_serialNumber,
            re.compile(r' [*] Primary Device Type: (.*)'): handle_primaryDeviceType,
            re.compile(r' [*] Device name: (.*)'): handle_deviceName,
            re.compile(r' [*] Config methods: (.*)'): handle_configMethods
        }

        cmd = 'iw dev {} scan'.format(self.interface)
        if dump_only:
            cmd += ' dump'
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, encoding='utf-8')
        lines = proc.stdout.splitlines()
        networks = []

        for line in lines:
            if line.startswith('command failed:'):
                print(line)
                return False
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        # Filtering non-WPS networks
        networks = list(filter(lambda x: bool(x['WPS']), networks))
        if not networks:
            return False
        return networks


if __name__ == '__main__':
    import argparse
    import sqlite3
    import time
    import atexit

    parser = argparse.ArgumentParser(
        description='Ассистент мобильного приложения WiGLE (Android).'
        'Использует iw для сканирования Wi-Fi сетей и получения информации о производителе, модели и пр. (WSC) и записывает информацию в локальную БД (SQLite)',
        epilog='Пример использования: %(prog)s -i wlan0 -d 3')

    parser.add_argument(
        '-i', '--interface',
        type=str,
        required=True,
        help='Имя беспроводного интерфейса для сканирования'
        )
    parser.add_argument(
        '-m', '--mode',
        type=str,
        choices=['real', 'dump'],
        default='dump',
        help='Метод сканирования: real — настоящее сканирование,\
        dump — использование результатов предыдущих сканирований.\
        По умолчанию: %(default)s'
        )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=1.5,
        help='Задержка между сканированием. По умолчанию: %(default)s'
        )
    parser.add_argument(
        '-f', '--db-file',
        type=str,
        default='networks.db',
        help='База данных SQLite для сохранения результатов. По умолчанию: %(default)s'
        )

    args = parser.parse_args()
    conn = sqlite3.connect(args.db_file)

    def cleanup():
        conn.commit()
        conn.close()

    atexit.register(cleanup)

    conn.execute('''CREATE TABLE IF NOT EXISTS "network" (
    "bssid" TEXT NOT NULL UNIQUE,
    "essid" TEXT,
    "security"  TEXT,
    "wps_version"   TEXT,
    "wps_state" INTEGER,
    "wps_locked"    INTEGER,
    "response_type" INTEGER,
    "uuid"  TEXT,
    "manufacturer"  TEXT,
    "model" TEXT,
    "model_number"  TEXT,
    "serial_number" TEXT,
    "primary_device_type"   TEXT,
    "device_name"   TEXT,
    "config_methods"    TEXT,
    PRIMARY KEY("bssid")
);''')

    scanner = WiFiScanner(args.interface)

    while True:
        if args.mode == 'real':
            results = scanner.scan()
        else:
            results = scanner.scan(dump_only=True)
        if not results:
            continue

        for network in results:
            if network['WPS'] and network['Model'] and network['Manufacturer']:
                conn.execute(
                    'INSERT OR IGNORE INTO network \
                    (bssid, essid, security, wps_version, wps_state, wps_locked, response_type, uuid, manufacturer, model, model_number, serial_number, primary_device_type, device_name, config_methods)\
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (
                        network['BSSID'], network['ESSID'], network['Security type'], network['WPS'], network['WPS state'], network['WPS locked'],
                        network['Response type'], network['UUID'], network['Manufacturer'], network['Model'], network['Model number'],
                        network['Serial number'], network['Primary device type'], network['Device name'], ', '.join(network['Config methods']))
                )
                conn.commit()

        time.sleep(args.delay)
