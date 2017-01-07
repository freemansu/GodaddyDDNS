"""
Copyright 2017 [Su Yu, yusu.work@gmail.com]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import json
import logging
from logging.config import dictConfig

import requests

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,  # this fixes the problem

    'formatters': {
        'standard': {
            'format': '%(levelname) -3s %(asctime)s %(module)s:%(lineno)s %(funcName)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default'],
            'level': 'INFO',
            'propagate': True
        }
    }
})
logger = logging.getLogger(__name__)


def load_config(filename):
    fp = open(filename)
    return json.load(fp)


def set_dns_record(config, public_ip):
    api_key = config['api_key']
    api_secret = config['api_secret']
    domain = config['domain']
    url = 'https://api.godaddy.com/v1/domains/{domain}/records/{type}/{name}'.format(domain=domain, type='A',
                                                                                     name='ddns')
    header = {'Authorization': 'sso-key {API_KEY}:{API_SECRET}'.format(API_KEY=api_key, API_SECRET=api_secret)}
    data = [
        {
            "type": "A",
            "name": "ddns",
            "data": public_ip,
            "ttl": 600
        }
    ]

    logger.info("OK")
    response = requests.put(url=url, json=json.dumps(data, sort_keys=False), headers=header)
    print response.text


def get_public_ip():
    urls = [
        'https://api.ipify.org',
        'http://ipv4bot.whatismyipaddress.com/',
        'http://ipinfo.io/ip',
    ]

    ips = []
    for url in urls:
        ip = requests.get(url).text
        ips.append(ip.strip())

    return max(ips, key=ips.count)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A Godaddy API Based Dynamic DNS')
    parser.add_argument('-c', dest='config_file', default='config.json',
                        help='set the config file (default: config.json)')

    args = parser.parse_args()
    config = load_config(args.config_file)
    public_ip = get_public_ip()
    set_dns_record(config, public_ip)
