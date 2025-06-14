# 🔍 Network Packet Sniffer & Visualizer

A real-time **network packet sniffer and visualizer** built in pure Python using **Scapy** and **Matplotlib**. This tool captures network packets, analyzes traffic by protocol, IP, and port, and includes basic anomaly detection (e.g., detecting high-frequency packets from a single IP).

---

## 📌 Features

- ✅ Captures live network traffic using Scapy
- 📊 Real-time visualizations of:
  - Protocol distribution (TCP, UDP, ICMP)
  - Top source/destination IPs
  - Top communication ports
- 🚨 Basic anomaly detection:
  - Alerts if a single IP exceeds a defined packet-per-second threshold

---

## 🛠 Requirements

- Python 3.7+
- Dependencies:
  ```bash
  pip install scapy matplotlib
⚠️ On Windows, you must install Npcap to enable packet sniffing with Scapy.

🚀 How to Run
Clone or download this repository.

Run the script with admin/root privileges:

bash

python packet_sniffer.py
You’ll see three live plots:

Packets by protocol

Top 10 IP addresses

Top 10 ports

Stop the program anytime with Ctrl + C.

⚙️ Customization
Anomaly threshold:
Adjust the packet rate threshold in the script:

python

ANOMALY_THRESHOLD = 20  # packets per second per IP
Plot refresh rate:
Set how often plots update:

python

plt.pause(2)  # in seconds
🧠 How It Works
Uses scapy.sniff() to capture all packets.

Filters for IP packets and extracts:

Source/destination IPs

Source/destination ports

Protocol type (TCP/UDP/ICMP)

Updates counters in real-time for visual analysis.

Uses matplotlib to render plots dynamically.

Tracks packet rates from each IP to flag suspicious activity.

📊 Sample Use Cases
Network traffic analysis

Intrusion detection experiments

Cybersecurity learning tool

Teaching networking fundamentals

⚠️ Limitations
Requires admin/root privileges

May miss some traffic if used on wireless interfaces (depends on OS + hardware)

Basic anomaly detection (not a replacement for IDS/IPS)

📄 License
This project is licensed under the MIT License.

🙋‍♂️ Contributions
Pull requests and suggestions are welcome! Open an issue or fork and improve the project.

🔗 Acknowledgments
Scapy – for packet sniffing and protocol dissection

Matplotlib – for data visualization

