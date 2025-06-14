import time
from collections import Counter, defaultdict
from threading import Thread
import matplotlib.pyplot as plt
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sniff

protocol_counter = Counter()
ip_counter = Counter()
port_counter = Counter()
packet_times = []

# Anomaly detection threshold (packets/sec from one IP)
ANOMALY_THRESHOLD = 20
ip_packet_times = defaultdict(list)


def packet_handler(pkt):
    if IP in pkt:
        proto = None
        sport = None
        dport = None

        if TCP in pkt:
            proto = 'TCP'
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = 'UDP'
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            proto = 'ICMP'
        else:
            proto = pkt[IP].proto

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Update counters
        protocol_counter.update([proto])
        ip_counter.update([src_ip, dst_ip])
        if sport is not None:
            port_counter.update([sport])
        if dport is not None:
            port_counter.update([dport])

        now = time.time()
        packet_times.append(now)
        ip_packet_times[src_ip].append(now)

        recent_packets = [t for t in ip_packet_times[src_ip] if now - t < 1]
        ip_packet_times[src_ip] = recent_packets  # prune old
        if len(recent_packets) > ANOMALY_THRESHOLD:
            print(f"ALERT: High traffic from IP {src_ip} - {len(recent_packets)} packets/sec")


def sniff_packets():
    sniff(prn=packet_handler, store=False)


def live_plot():
    plt.ion()
    fig, axs = plt.subplots(3, 1, figsize=(10, 12))

    while True:
        # Plot protocol counts
        axs[0].clear()
        protocols = [str(p) for p in protocol_counter.keys()]
        counts = [protocol_counter[p] for p in protocol_counter.keys()]
        axs[0].bar(protocols, counts, color='skyblue')
        axs[0].set_title('Packets by Protocol')
        axs[0].set_ylabel('Count')

        # Plot top 10 IPs by count
        axs[1].clear()
        top_ips = ip_counter.most_common(10)
        if top_ips:
            ips, counts_ip = zip(*top_ips)
            axs[1].barh(ips, counts_ip, color='lightgreen')
        axs[1].set_title('Top 10 IP Addresses')
        axs[1].set_xlabel('Packet Count')

        # Plot top 10 Ports by count
        axs[2].clear()
        top_ports = port_counter.most_common(10)
        if top_ports:
            ports, counts_port = zip(*top_ports)
            axs[2].barh([str(p) for p in ports], counts_port, color='salmon')
        axs[2].set_title('Top 10 Ports')
        axs[2].set_xlabel('Packet Count')

        plt.tight_layout()
        plt.pause(2)  # update every 2 seconds


def main():
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    sniffer_thread = Thread(target=sniff_packets, daemon=True)
    sniffer_thread.start()

    try:
        live_plot()
    except KeyboardInterrupt:
        print("\nStopping...")


if __name__ == '__main__':
    main()
