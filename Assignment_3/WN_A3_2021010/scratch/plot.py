import pandas as pd
import matplotlib.pyplot as plt

latencies_ofdma = pd.read_csv('ofdma.txt', header=None, names=['latency(OFDMA)'])
latencies_ofdm = pd.read_csv("ofdm.txt", header=None, names=['latency(OFDM)'])

plt.figure(1)  
plt.boxplot(latencies_ofdma['latency(OFDMA)'])
plt.title('Plot of OFDMAs Latency Packets')
plt.ylabel('Latency')
plt.show()

plt.figure(2)  
plt.boxplot(latencies_ofdm['latency(OFDM)'])
plt.title('Plot of OFDMs Latency Packets')
plt.ylabel('Latency')
plt.show()