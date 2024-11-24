from flask import Flask, render_template, jsonify
from scapy.all import sniff, Packet, Ether, IP, TCP, UDP
import threading

app = Flask(__name__)
packets = []  # List to store captured packets
capturing = False  # Flag to control packet capture


def packet_sniffer(packet):
    """Callback function to process each captured packet."""
    global packets
    if packet.haslayer(IP):
        packet_info = {
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": packet[IP].proto,
            "len": len(packet),
        }
        packets.append(packet_info)


def start_sniffing():
    """Start packet sniffing."""
    global capturing
    capturing = True
    sniff(prn=packet_sniffer, store=False, stop_filter=lambda x: not capturing)


@app.route("/")
def index():
    """Home page displaying captured packets."""
    return render_template("index.html")


@app.route("/start_capture", methods=["POST"])
def start_capture():
    """Start capturing network traffic."""
    global capturing
    if not capturing:
        threading.Thread(target=start_sniffing, daemon=True).start()
        return jsonify({"status": "Capture started"})
    return jsonify({"status": "Already capturing"})


@app.route("/stop_capture", methods=["POST"])
def stop_capture():
    """Stop capturing network traffic."""
    global capturing
    capturing = False
    return jsonify({"status": "Capture stopped"})


@app.route("/get_packets")
def get_packets():
    """Retrieve captured packets."""
    return jsonify(packets)


if __name__ == "__main__":
    app.run(debug=True)
