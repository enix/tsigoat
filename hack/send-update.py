#!/usr/bin/python

import os
import glob
import dns.name
import dns.rdataclass
import dns.query
import dns.rrset
import dns.update
import dns.tsigkeyring
from sys import exit
from time import sleep
from pprint import pprint

SERVER=("127.0.0.1", 53000)
KEYRING=".keyring"
KEY_NAME="ed25519"
HMAC_ALG="hmac-sha256"

if not os.path.isdir(KEYRING):
    print("Not a directory: {}".format(KEYRING))
    exit(1)

keys = {}
for filepath in glob.iglob(os.path.join(KEYRING, '*.private')):
    if not os.path.islink(filepath):
        continue
    kname = os.path.basename(filepath).split('.')[0]
    with open(filepath, 'r') as f:
        for line in f.readlines():
            if line.startswith('PrivateKey: '):
                keys[kname] = line.split(':')[1][1:]

print("Found {} private keys:".format(len(keys.keys())))
pprint(keys)
print("Building keyring...")
keyring = dns.tsigkeyring.from_text(keys)

def update(zone_class, zone):
    return dns.update.Update(zone, zone_class, keyring, dns.name.from_text(KEY_NAME), HMAC_ALG)

def query(update):
    response = dns.query.udp(update, SERVER[0], port=SERVER[1])
    if response.rcode() == dns.rcode.NOERROR:
        print("OK")
    else:
        print(f"Failed: {dns.rcode.to_text(response.rcode())}")

while True:
    print("add 1")
    u = update(dns.rdataclass.IN, 'example.org')
    u.add('loop', 600, dns.rdatatype.TXT, 'hello broken world #1')
    query(u)
    sleep(2)

    print("add 2")
    u = update(dns.rdataclass.IN, 'example.org')
    u.add('loop', 30, dns.rdatatype.TXT, 'hello broken world #2')
    query(u)
    sleep(2)

    print("add A+B")
    u = update(dns.rdataclass.IN, 'example.org')
    u.add('loop', 30, dns.rdatatype.TXT, '"hello whole world #1"')
    u.add('loop', 30, dns.rdatatype.TXT, '"hello whole world #2"')
    query(u)
    sleep(2)

    print("del A")
    u = update(dns.rdataclass.IN, 'example.org')
    u.delete('loop', dns.rdatatype.TXT, '"hello whole world #1"')
    query(u)
    sleep(2)

    print("del 1+2")
    u = update(dns.rdataclass.IN, 'example.org')
    u.delete('loop', dns.rdatatype.TXT, 'hello broken world #1')
    u.delete('loop', dns.rdatatype.TXT, 'hello broken world #2')
    query(u)
    sleep(2)

    print("del *")
    u = update(dns.rdataclass.IN, 'example.org')
    u.delete('loop', dns.rdatatype.TXT)
    query(u)
    sleep(2)

    sleep(10)
