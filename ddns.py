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

import requests
import json


def load_config(file):
    fp = open(file)
    config = json.load(fp)
    return config


def set_dns_record(config, public_ip):
    api_key = config['api_key']
    api_secret = config['api_secret']
    domain = config['domain']
    url = 'https://api.godaddy.com/v1/domains/{domain}/records/{type}/{name}'.format(domain=domain, type='A', name='ddns')
    header = {'Authorization': 'sso-key {API_KEY}:{API_SECRET}'.format(API_KEY=api_key, API_SECRET=api_secret)}
    data = [
        {
            "type": "A",
            "name": "ddns",
            "data": public_ip,
            "ttl": 600
        }
    ]

    jsonData = json.dumps(data, sort_keys=False)
    response = requests.put(url=url, json=jsonData, headers=header)
    print response.text


def is_subdomain_exists(subdomain):
    api_key = config['api_key']
    api_secret = config['api_secret']
    url = 'https://api.godaddy.com/v1/domains/{domain}/records/{type}/{name}'.format(domain=subdomain, type='A', name='ddns')
    header = {'Authorization': 'sso-key {API_KEY}:{API_SECRET}'.format(API_KEY=api_key, API_SECRET=api_secret)}

    response = requests.get(url=url, headers=header)
    return response.text != u'[]'


def get_public_ip():
    urls = [
        'https://api.ipify.org',
        'http://ipv4bot.whatismyipaddress.com/',
        'http://ipinfo.io/ip',
    ]

    ips = []
    for url in urls:
        ip = requests.get(url).text
        ips.append(ip)

    return max(ips, key=ips.count)


if __name__ == '__main__':
    config = load_config('config.json')
    is_subdomain_exists(config['domain'])
    public_ip = get_public_ip()
    set_dns_record(config, public_ip)
