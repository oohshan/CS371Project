from scapy.all import *
import pandas as pd
import numpy as np
import sys
import socket
import os
import csv

label = sys.argv[1:]

def fields_extraction(x):
    #print(x.sprintf('{IP:%IP.src%,%IP.dst%,%IP.len%,%IP.proto%,}'
        #'{TCP:%TCP.sport%,%TCP.dport%,}'
        #'{UDP:%UDP.sport%,%UDP.dport%}'))
    print(x.summary())

    #use x.time for time information on the pkts

pkts = sniff(prn = fields_extraction, count = 10)
#pkts[0].show()

flowList = []
for i in range(len(pkts)):
    flowList.append([])

    flowList[i].append(pkts[i].proto)
    flowList[i].append(pkts[i].sprintf('%IP.src%'))
    flowList[i].append(pkts[i].sprintf('%IP.dst%'))
    flowList[i].append(pkts[i].sport)
    flowList[i].append(pkts[i].dport)
    flowList[i].append(pkts[i].len)
    flowList[i].append(label)

headers = ['proto', 'IP src', 'IP dest', 'src port', 'dest port', 'packet len', 'label']
csvData = []


""" writes csvData to pktData.csv """
with open('pktData.csv', 'a') as csvFile:
    if os.stat("pktData.csv").st_size == 0:
        csvData.append(headers)

    for j in range(7):
        csvData.append(flowList[j])
        
    writer = csv.writer(csvFile)
    writer.writerows(csvData)

csvFile.close()
