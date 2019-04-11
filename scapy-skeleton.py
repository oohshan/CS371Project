from scapy.all import *
import pandas as pd
import numpy as np
import sys
import socket
import os
import csv
#take in label as command line argument
label = int(sys.argv[1])
numPackets = 500

def fields_extraction(x):
    print(x.summary())

pkts = sniff(prn = fields_extraction, count = numPackets)

#flow class, holds IP addresses and ports of packet in flow
class flow:
    def __init__(self, pkt, id):
        self.pkt = pkt
        self.setIdentifiers()
        self.id = id
    #dictionary of identifiers set in initialization
    def setIdentifiers(self):
        #dictionary of tuples for each value
        self.identifiers = {
            'IP': (self.pkt[0], self.pkt[1]),
            'ports': (self.pkt[2], self.pkt[3]),
        }
    #gets a new packet passed in, and checks if the packet's values are in the dictionary
    #for IP addresses and ports
    def checkConnections(self, pkt):
        if (pkt[0] in self.identifiers['IP'] and pkt[1] in self.identifiers['IP']):
            if (pkt[2] in self.identifiers['ports'] and pkt[3] in self.identifiers['ports']):
                return True

        return False
#lists to hold packet info we want and to hold unique flow instances
pktList = []
flowList = []
for i in range(len(pkts)):
    #wrapped in try/except to handle any extraneous packets
    try:
        #append a new list to pktList, then fill the new list with relevant packet info
        pktList.append([])
        pktList[i].append(pkts[i].sprintf('%IP.src%'))
        pktList[i].append(pkts[i].sprintf('%IP.dst%'))
        pktList[i].append(pkts[i].sport)
        pktList[i].append(pkts[i].dport)
        #assign UDP as 0
        if pkts[i].proto == 17:
            pktList[i].append(0)
        #assign TCP as 1
        if pkts[i].proto == 6:
            pktList[i].append(1)
        pktList[i].append(pkts[i].len)
        pktList[i].append(label)
        #if no flows identified yet, add the first packet as first flow
        if flowList == None:
            newFlow = flow(pktList[i], 1)
            flowList.append(newFlow)
            #add flow id as a new value at the end of the packet
            pktList[i].append(0)
        else:
            #found flag holds if the current packet is found to be in an existing flow; initialized to false
            found = False
            #loop through existing flows checking if current packet has the same identifiers
            for j in flowList:
                if j.checkConnections(pktList[i]):
                    #if a connection is found, change flag to true and save location of flow that relates
                    found = True
                    loc = j
            #if no connections found, make a new flow with the packet
            if not found:
                newFlow = flow(pktList[i], len(flowList) + 1)
                flowList.append(newFlow)
                #add new flow id to the end of the packet
                pktList[i].append(len(flowList))
            #if the connection is found, add the correct flow id to the end of the packet
            else:
                pktList[i].append(loc.id)
    #if error has occurred it results in empty packet in pktList, so find it and delete it
    except:
        for packet in pktList:
            if packet is None:
                del pktList[packet]
        continue


#name file saved depending on the amount of packets we're reading
fileName = str(numPackets) + 'pktData.csv'

csvData = []
with open(fileName, 'a') as file:
    for j in range(numPackets):
        csvData.append(pktList[j])
    #use writer and writerows to write all of our csvData to file
    writer = csv.writer(file)
    writer.writerows(csvData)
file.close()
