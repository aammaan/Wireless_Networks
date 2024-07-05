from scapy.all import *
import matplotlib.pyplot as plt

def calc_latency(pkts):
    rel_pkts = []
    for i in range(1, len(pkts)):
        if pkts[i].haslayer(UDP) and pkts[i][UDP].sport == 9:
            rel_pkts.append(pkts[i])

    latencies = []
    for i in range(1, len(rel_pkts)):
        latency = (rel_pkts[i].time - rel_pkts[i - 1].time) * 1000
        latencies.append(latency)

    mean_latency = sum(latencies) / len(latencies) if len(latencies) > 0 else 0

    return mean_latency, latencies

def main():
    pkt1 = rdpcap('a-8-0.pcap')
    pkt2 = rdpcap('b-3-0.pcap')
    pkt3 = rdpcap('c-2-0.pcap')

    mean1, lat1 = calc_latency(pkt1)
    mean2, lat2 = calc_latency(pkt2)
    mean3, lat3 = calc_latency(pkt3)

    with open('report.txt', 'w') as rep_file:
        rep_file.write(f'Mean Latency for Client 1: {mean1} ms\n')
        rep_file.write(f'Mean Latency for Client 2: {mean2} ms\n')
        rep_file.write(f'Mean Latency for Client 3: {mean3} ms\n')

    plt.figure(figsize=(10, 6))
    plt.scatter(range(len(lat1)), lat1, label='Client 1 Latency', marker='o')
    plt.scatter(range(len(lat2)), lat2, label='Client 2 Latency', marker='x')
    plt.scatter(range(len(lat3)), lat3, label='Client 3 Latency', marker='s')
    plt.xlabel('Packet Index')
    plt.ylabel('Latency (ms)')
    plt.legend()
    plt.title('Latency for Received Packets (Scatter Plot)')
    plt.grid(True)
    plt.savefig('latency_scatter_plot.png')
    plt.show()

if __name__ == '__main__':
    main()
