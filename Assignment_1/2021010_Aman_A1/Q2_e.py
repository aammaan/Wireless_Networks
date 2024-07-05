
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import rdpcap

pcap_file = "/Users/aman/Desktop/2021010_Aman_A1/pcap_trace1 (1).pcap"  
packets = rdpcap(pcap_file)

time_intervals = []
aggregate_throughput = []

window_size = 2  

window_start_time = 0
window_end_time = window_size
window_bytes = 0

ft = packets[0].time

for packet in packets:
    packet_length = len(packet)
    print(packet_length)

    packet_time = packet.time - ft
    # print(packet_time)

    if packet_time < window_end_time:
        window_bytes += packet_length
    else:
        eight=8
        throughput_bps = (window_bytes * eight) / window_size
        time_intervals.append(window_end_time - window_size / 2)
        aggregate_throughput.append(throughput_bps)

        while packet_time >= window_end_time:
            window_start_time += window_size
            window_end_time += window_size

        window_bytes = packet_length

plt.figure(figsize=(12, 6))
plt.plot(time_intervals, aggregate_throughput, label= "Aggregate Throughput (bps)")
plt.xlabel("Time ")
plt.ylabel("Throughput (bps)")

plt.show()
