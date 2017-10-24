#!/usr/bin/python

# INSTALL:
#   sudo apt-get install python-scapy
# RUN:
#   sudo /usr/bin/python ./pping.py

import sys, Queue, threading
from scapy import all as S

IFACE_LIST = 'wlan0','lo'


# pylint:disable=E1101
def run_ping(iface, out_q):
    host = '8.8.8.8'
    pkt = S.Ether()/S.IP(dst=host, ttl=(1,3))/S.ICMP() 
    ans,_unans = S.srp(pkt, iface=iface, timeout=2) 
    out_q.put( (iface,ans) )


result_q = Queue.Queue()
for iface in IFACE_LIST:
    threading.Thread(
        target=run_ping, args=(iface, result_q)
    ).start()

for t in threading.enumerate():
    if t != threading.current_thread():
        t.join()

print 'result:', dict( [
    result_q.get()
    for _ in range(result_q.qsize())
    ] )
