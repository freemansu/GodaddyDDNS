'''
Copyright 2017 [Su Yu, yusu.work@gmail.com]

Licensed under the Apache License, Version 2.0 (the 'License');
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an 'AS IS' BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
import sys
import argparse
import json
import logging
from logging.config import dictConfig

import requests


class DDNS:
    def __init__(self, api_key, api_secret, domain, sub_domain):
        self.api_key = api_key
        self.api_secret = api_secret
        self.domain = domain
        self.sub_domain = sub_domain
        self.public_ip = None

    def __get_public_ip(self):
        public_ip_api_urls = [
            'https://api.ipify.org',
            'http://ipv4bot.whatismyipaddress.com/',
            'http://ipinfo.io/ip',
        ]

        public_ips = []
        for url in public_ip_api_urls:
            try:
                public_ip = requests.get(url).text
                public_ips.append(public_ip.strip())
            except requests.exceptions.RequestException as e:
                logger.warning('can not get public ip from {url}: {info}'.format(url=url, info=e))

        if len(public_ips) == 0:
            logger.error('can not get public ip')

        self.public_ip = max(public_ips, key=public_ips.count)

    def set_dns_record(self):
        self.__get_public_ip()

        url = 'https://api.godaddy.com/v1/domains/{domain}/records/{type}/{name}' \
            .format(domain=self.domain, type='A', name=self.sub_domain)

        header = {
            'Authorization': 'sso-key {API_KEY}:{API_SECRET}'.format(API_KEY=self.api_key, API_SECRET=self.api_secret),
            'Content-Type': 'application/json'
        }
        public_ip = self.public_ip.encode('ascii', 'ignore')
        payload = [{
            "type": 'A',
            "name": 'ddns',
            "data": public_ip,
            "ttl": 600
        }]

        try:
            response = requests.put(url=url, json=json.dumps(payload), headers=header)
            if response.status_code is not 200:
                logger.error('call goadddy api error: {info}'.format(info=response.text))
                sys.exit(1)
        except requests.exceptions.RequestException as e:
            logger.error('can not set ddns record for {sub_domain}: {info}'.format(sub_domain=self.sub_domain, info=e))
            sys.exit(1)


if __name__ == '__main__':
    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': False,

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

    parser = argparse.ArgumentParser(description='A Godaddy API Based Dynamic DNS')
    parser.add_argument('-c', dest='config_file', default='config.json',
                        help='set the config file (default: config.json)')

    args = parser.parse_args()
    try:
        config = json.load(open(args.config_file))
    except Exception as e:
        logger.error(
            'can not load config file -  {config_file}, info: {info}'.format(config_file=args.config_file, info=e))
        sys.exit(1)

    try:
        api_key = config['api_key']
        api_secret = config['api_secret']
        domain = config['domain']
        sub_domain = config['sub_domain']
    except Exception as e:
        logger.error('config error, info: {info}'.format(info=e))
        sys.exit(1)

    DDNS(api_key=api_key, api_secret=api_secret, domain=domain, sub_domain=sub_domain).set_dns_record()
    logger.info('set ddns record success, have fun!')
