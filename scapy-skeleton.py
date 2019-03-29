from scapy.all import *
import pandas as pd
import numpy as np
import sys
import socket
import os
import csv

def fields_extraction(x):
    print(x.sprintf('{IP:%IP.src%,%IP.dst%,%IP.len%,%IP.proto%,}'
        '{TCP:%TCP.sport%,%TCP.dport%,}'
        '{UDP:%UDP.sport%,%UDP.dport%}'))

    print(x.summary())

    #use x.time for time information on the pkts

pkts = sniff(prn = fields_extraction, count = 10)
#pkts[0].show()

"""

make new list for each packet filled with important packet info + analysis on IP.len

for loop that pairs together members of new list

"""

""" example of how to reference values in packets """
print("PROTOCOL USED IN FIRST PACKET: %s" % pkts[0].sprintf('IP:%IP.proto%,'))

""" fake labels for csv file columns, we'll need to assign these one at a time """
headers = []
for i in range(len(pkts[0])):
    headers.append(i+1)

""" will hold every row for pktData.csv, starting with labels """
csvData = [headers, [], []]

""" writes csvData to pktData.csv """
with open('pktData.csv', 'w') as csvFile:
    writer = csv.writer(csvFile)
    writer.writerows(csvData)
