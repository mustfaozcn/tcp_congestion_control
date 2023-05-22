import matplotlib.pyplot as plt
from scapy.all import *
from collections import defaultdict

def get_packet_info(packets):
    data = defaultdict(list)
    last_seq_num = None

    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            data['seq_nums'].append(tcp_layer.seq)
            data['ack_nums'].append(tcp_layer.ack)
            data['lengths'].append(len(packet))
            data['times'].append(float(packet.time))

            # Check for missing sequence numbers
            if last_seq_num is not None and data['seq_nums'][-1] != last_seq_num + data['lengths'][-2]:
                try:
                    data['dropped_packets'][data['times'][-1]] += 1
                except TypeError:
                    data['dropped_packets'] = defaultdict(int)
                    data['dropped_packets'][data['times'][-1]] += 1

            last_seq_num = tcp_layer.seq

            options = packet[TCP].options
            for option in options:
                if option[0] == 'Timestamp':
                    data['cwnd'].append(packet[TCP].window)
                    data['rtt'].append(packet.time - option[1][0])
                    break

    return data

def plot_graphs(data):
    graphs = [('seq_nums', 'Sequence Numbers Over Time', 'Sequence Number'),
              ('ack_nums', 'ACK Numbers Over Time', 'ACK Number'),
              ('lengths', 'Packet Lengths Over Time', 'Packet Length'),
              ('dropped_packets', 'Dropped Packets Over Time', 'Number of Dropped Packets'),
              ('cwnd', 'Congestion Window Size Over Time', 'Window Size'),
              ('rtt', 'Round-Trip Time Over Time', 'RTT')]

    for key, title, ylabel in graphs:
        plt.figure()
        if key == 'dropped_packets':
            plt.plot(list(data[key].keys()), list(data[key].values()), label=key)
        else:
            plt.plot(data['times'][:len(data[key])], data[key], label=key)
        plt.xlabel('Time')
        plt.ylabel(ylabel)
        plt.title(title)
        plt.show()

def compute_metrics(data):
    total_packets = len(data['seq_nums'])
    total_dropped_packets = sum(data['dropped_packets'].values())
    packet_loss_rate = total_dropped_packets / total_packets

    total_bytes = sum(data['lengths'])
    total_time = data['times'][-1] - data['times'][0]
    throughput = total_bytes / total_time

    avg_rtt = sum(data['rtt']) / len(data['rtt'])

    print(f"Packet Loss Rate: {packet_loss_rate * 100:.2f}%")
    print(f"Throughput: {throughput / 1024:.2f} KB/s")
    print(f"Average RTT: {avg_rtt:.2f} ms")


packets = rdpcap('output.pcap')
data = get_packet_info(packets)
plot_graphs(data)
compute_metrics(data)
