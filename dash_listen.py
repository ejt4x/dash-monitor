#!/usr/bin/env python3

from scapy.all import *
import logging as log
import requests
import os
import sys
from config import ifttt_key, macs, interface

ifttt_url = 'https://maker.ifttt.com/trigger/{event}/with/key/{key}'

log.basicConfig(level=log.INFO)

def button_pressed(event):
    request_url = ifttt_url.format(event=event, key=ifttt_key)
    log.debug("URL = {url}".format(url=request_url))
    r = requests.get(request_url)
    if r.status_code != requests.codes.ok:
        log.error("Bad response: {resp}".format(resp=r.text))
    else:
        log.info("Event {event} triggered successfully".format(event=event))

def check_arp(pkt):
    if ARP in pkt:
        pkt.show()
        src = pkt['ARP'].hwsrc
        if src in macs:
            log.debug("Button pressed: {event} event triggering".format(event=macs[src]))
            button_pressed(macs[src])
        else:
            log.debug("{src} not in macs".format(src=src))

def root(): 
    return os.geteuid() == 0

def main():
    if not root():
        log.error("Must be root to run this script, exiting")
        sys.exit(1)
    else:
        log.debug("You are root")

    log.info('Waiting for arp packets...')

    bpf = " or ".join("ether src host {ehost}".format(ehost=mac) for mac in macs)
    log.debug("Filter: " + bpf)
    while True:
        sniff(iface=interface, filter=bpf, prn = check_arp, count=3 )
        log.debug("reloading")

if __name__ == "__main__": main()
