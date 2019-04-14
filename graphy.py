import csv
import numpy as np
import matplotlib.pyplot as plt

lengths0 = []
lengths1 = []
lengths2 = []
lengths3 = []

ttl0 = []
ttl1 = []
ttl2 = []
ttl3 = []

def listAvg(list):
    if len(list) != 0:
        return sum(list) / len(list)
    else:
        return 0

with open('500pktData.csv', 'r') as file:
    reader = csv.reader(file, delimiter=',')

    for row in reader:
        #assign label for each new row to hold data in separate lists
        currentLabel = int(row[8])

        if currentLabel == 0:
            lengths0.append(int(row[5]))
            ttl0.append(int(row[6]))

        elif currentLabel == 1:
            lengths1.append(int(row[5]))
            ttl1.append(int(row[6]))

        elif currentLabel == 2:
            lengths2.append(int(row[5]))
            ttl2.append(int(row[6]))

        elif currentLabel == 3:
            lengths3.append(int(row[5]))
            ttl3.append(int(row[6]))

""" GRAPH OF LENGTHS """
plt.title('Average Lengths')
plt.bar('Web Browsing' ,listAvg(lengths0))
plt.bar('Video Streaming', listAvg(lengths1))
plt.bar('Video Call' ,listAvg(lengths2))
plt.bar('Downloading', listAvg(lengths3))
plt.ylabel('Average Byte Length')
plt.xlabel('Label')
plt.show()

""" GRAPH of TTL """
plt.title('Average TTL Values')
plt.bar('Web Browsing', listAvg(ttl0))
plt.bar('Video Streaming', listAvg(ttl1))
plt.bar('Video Call', listAvg(ttl2))
plt.bar('Downloading', listAvg(ttl3))
plt.ylabel('Average Hops')
plt.xlabel('Label')
plt.show()
