import pyshark
import matplotlib.pyplot as plt

# Define the paths to the pcap files for each client
pcap1 = '/Users/aman/Downloads/ns-allinone-3.39/ns-3.39/scratch/a_2-8-0.pcap'
pcap2 = '/Users/aman/Downloads/ns-allinone-3.39/ns-3.39/scratch/b_2-3-0.pcap'
pcap3 = '/Users/aman/Downloads/ns-allinone-3.39/ns-3.39/scratch/c_2-2-0.pcap'

# Function to calculate throughput from a pcap file
def calc_throughput(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    total_bytes = 0
    total_packets = 0
    start_time = None
    end_time = None

    # Calculate total bytes and find start and end time
    for packet in capture:
        packet_size = int(packet.length)
        total_bytes += packet_size
        total_packets += 1
        if start_time is None:
            start_time = float(packet.sniff_timestamp)
        end_time = float(packet.sniff_timestamp)

    if start_time is None or end_time is None:
        return 0, 0

    duration = end_time - start_time

    # Check if duration is greater than zero to avoid division by zero
    if duration > 0:
        throughput_bps = (total_bytes * 8) / duration
    else:
        throughput_bps = 0

    return throughput_bps, duration

# Calculate throughput and duration for each client
throughput1, duration1 = calc_throughput(pcap1)
throughput2, duration2 = calc_throughput(pcap2)
throughput3, duration3 = calc_throughput(pcap3)

# Print the calculated throughput and duration for each client
print("Client 1 Throughput: {:.2f} bps".format(throughput1))
print("Client 1 Duration: {:.2f} seconds".format(duration1))
print("Client 2 Throughput: {:.2f} bps".format(throughput2))
print("Client 2 Duration: {:.2f} seconds".format(duration2))
print("Client 3 Throughput: {:.2f} bps".format(throughput3))
print("Client 3 Duration: {:.2f} seconds".format(duration3))

# Plot throughput over time for Client 1
if duration1 > 0:
    capture1 = pyshark.FileCapture(pcap1)
    timestamps1 = [float(packet.sniff_timestamp) for packet in capture1]
    sizes1 = [int(packet.length) for packet in capture1]
    throughput_over_time1 = [sum(sizes1[:i+1]) * 8 / (t - timestamps1[0]) for i, t in enumerate(timestamps1)]
else:
    throughput_over_time1 = []

plt.figure(figsize=(10, 5))
plt.plot(timestamps1, throughput_over_time1, label='Client 1 Throughput')
plt.xlabel('Time (s)')
plt.ylabel('Throughput (bps)')
plt.title('Throughput Over Time for Client 1')
plt.legend()
plt.grid(True)

# Plot throughput over time for Client 2
if duration2 > 0:
    capture2 = pyshark.FileCapture(pcap2)
    timestamps2 = [float(packet.sniff_timestamp) for packet in capture2]
    sizes2 = [int(packet.length) for packet in capture2]
    throughput_over_time2 = [sum(sizes2[:i+1]) * 8 / (t - timestamps2[0]) for i, t in enumerate(timestamps2)]
else:
    throughput_over_time2 = []

plt.figure(figsize=(10, 5))
plt.plot(timestamps2, throughput_over_time2, label='Client 2 Throughput')
plt.xlabel('Time (s)')
plt.ylabel('Throughput (bps)')
plt.title('Throughput Over Time for Client 2')
plt.legend()
plt.grid(True)

# Plot throughput over time for Client 3
if duration3 > 0:
    capture3 = pyshark.FileCapture(pcap3)
    timestamps3 = [float(packet.sniff_timestamp) for packet in capture3]
    sizes3 = [int(packet.length) for packet in capture3]
    throughput_over_time3 = [sum(sizes3[:i+1]) * 8 / (t - timestamps3[0]) for i, t in enumerate(timestamps3)]
else:
    throughput_over_time3 = []

plt.figure(figsize=(10, 5))
plt.plot(timestamps3, throughput_over_time3, label='Client 3 Throughput')
plt.xlabel('Time (s)')
plt.ylabel('Throughput (bps)')
plt.title('Throughput Over Time for Client 3')
plt.legend()
plt.grid(True)

# Show the plots
plt.show()
