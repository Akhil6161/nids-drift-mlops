import csv
import os
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP

from src.live.flow_builder import Flow, get_flow_key
from src.live.predictor import NIDSPredictor


# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = r"\Device\NPF_{227451D9-9718-4DD5-B69C-9ECA99233158}"

PREDICT_AFTER_PACKETS = 5
PREDICT_EVERY_PACKETS = 5

LOG_FILE = "logs/nids_predictions.csv"

# IMPORTANT:
# This module processes actual packets captured from the
# configured network interface.
TRAFFIC_SOURCE = "LIVE"


# ============================================================
# GLOBAL STATE
# ============================================================

flows = {}

predictor = NIDSPredictor()

total_predictions = 0
benign_predictions = 0
attack_predictions = 0
highest_attack_probability = 0.0


# ============================================================
# CSV LOGGING
# ============================================================

def log_prediction(flow, result):

    log_directory = os.path.dirname(LOG_FILE)

    if log_directory:
        os.makedirs(
            log_directory,
            exist_ok=True,
        )

    file_exists = os.path.exists(LOG_FILE)

    with open(
        LOG_FILE,
        "a",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.writer(file)

        if not file_exists:

            writer.writerow([
                "timestamp",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "packets",
                "bytes",
                "prediction",
                "label",
                "attack_probability",
                "source",
            ])

        writer.writerow([
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol,
            flow.total_packets,
            flow.total_bytes,
            result["prediction"],
            result["label"],
            result["attack_probability"],
            TRAFFIC_SOURCE,
        ])


# ============================================================
# IP LAYER
# ============================================================

def get_ip_layer(packet):

    if IP in packet:
        return packet[IP]

    if IPv6 in packet:
        return packet[IPv6]

    return None


# ============================================================
# TRANSPORT INFORMATION
# ============================================================

def get_transport_info(packet):

    if TCP in packet:

        return (
            int(packet[TCP].sport),
            int(packet[TCP].dport),
            6,
        )

    if UDP in packet:

        return (
            int(packet[UDP].sport),
            int(packet[UDP].dport),
            17,
        )

    return None


# ============================================================
# TCP FLAGS
# ============================================================

def get_tcp_flags(packet):

    if TCP not in packet:
        return 0

    return int(packet[TCP].flags)


# ============================================================
# TCP WINDOW
# ============================================================

def get_tcp_window(packet):

    if TCP not in packet:
        return 0

    try:
        return int(packet[TCP].window)

    except Exception:
        return 0


# ============================================================
# HEADER LENGTH
# ============================================================

def get_header_length(packet):

    if TCP in packet:

        if IP in packet:

            ip_header_length = int(
                packet[IP].ihl or 5
            ) * 4

        elif IPv6 in packet:

            ip_header_length = 40

        else:

            ip_header_length = 0

        tcp_header_length = int(
            packet[TCP].dataofs or 5
        ) * 4

        return (
            ip_header_length
            + tcp_header_length
        )

    if UDP in packet:

        if IP in packet:

            ip_header_length = int(
                packet[IP].ihl or 5
            ) * 4

        elif IPv6 in packet:

            ip_header_length = 40

        else:

            ip_header_length = 0

        return (
            ip_header_length
            + 8
        )

    return 0


# ============================================================
# PREDICTION
# ============================================================

def predict_flow(flow):

    global total_predictions
    global benign_predictions
    global attack_predictions
    global highest_attack_probability

    features = flow.to_features()

    result = predictor.predict(features)

    log_prediction(
        flow,
        result,
    )

    total_predictions += 1

    if result["label"] == "BENIGN":

        benign_predictions += 1

    else:

        attack_predictions += 1

    probability = float(
        result["attack_probability"]
    )

    if probability > highest_attack_probability:

        highest_attack_probability = probability

    print()
    print("=" * 60)

    if result["label"] == "BENIGN":

        print("NIDS RESULT - BENIGN")

    else:

        print("NIDS RESULT - ATTACK")

    print("=" * 60)

    print(
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    print()

    print(
        f"{flow.src_ip}:{flow.src_port}"
        f" -> "
        f"{flow.dst_ip}:{flow.dst_port}"
    )

    print(
        f"Protocol: {flow.protocol}"
    )

    print(
        f"Packets: {flow.total_packets}"
    )

    print(
        f"Bytes: {flow.total_bytes}"
    )

    print(
        f"Prediction: {result['label']}"
    )

    print(
        f"Attack probability: "
        f"{probability:.2%}"
    )

    print(
        f"Traffic source: {TRAFFIC_SOURCE}"
    )

    print("=" * 60)


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(packet):

    try:

        ip_layer = get_ip_layer(packet)

        if ip_layer is None:
            return

        transport = get_transport_info(packet)

        if transport is None:
            return

        src_port, dst_port, protocol = transport

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        timestamp = float(packet.time)

        length = len(packet)

        tcp_flags = get_tcp_flags(packet)

        tcp_window = get_tcp_window(packet)

        header_length = get_header_length(packet)

        forward_key, backward_key = get_flow_key(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        )

        if forward_key in flows:

            flow = flows[forward_key]

            direction = "forward"

        elif backward_key in flows:

            flow = flows[backward_key]

            direction = "backward"

        else:

            flow = Flow(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
            )

            flows[forward_key] = flow

            direction = "forward"

        flow.add_packet(
            timestamp=timestamp,
            length=length,
            direction=direction,
            tcp_flags=tcp_flags,
            header_length=header_length,
            tcp_window=tcp_window,
        )

        packet_count = flow.total_packets

        if packet_count >= PREDICT_AFTER_PACKETS:

            packets_after_start = (
                packet_count
                - PREDICT_AFTER_PACKETS
            )

            if (
                packets_after_start
                % PREDICT_EVERY_PACKETS
                == 0
            ):

                predict_flow(flow)

    except Exception as e:

        print(
            "[Packet processing error]",
            str(e),
        )


# ============================================================
# FINAL SUMMARY
# ============================================================

def print_summary():

    print()
    print("=" * 60)
    print("NIDS CAPTURE SUMMARY")
    print("=" * 60)

    print(
        f"Flows observed        : {len(flows)}"
    )

    print(
        f"Total predictions     : {total_predictions}"
    )

    print(
        f"BENIGN predictions    : {benign_predictions}"
    )

    print(
        f"ATTACK predictions    : {attack_predictions}"
    )

    print(
        f"Highest attack probability: "
        f"{highest_attack_probability:.2%}"
    )

    print()

    print(
        f"Traffic source        : {TRAFFIC_SOURCE}"
    )

    if os.path.exists(LOG_FILE):

        print(
            f"Predictions saved to  : {LOG_FILE}"
        )

    else:

        print(
            "Predictions saved to  : None"
        )

    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("NIDS - LIVE NETWORK INTRUSION DETECTION")
    print("=" * 60)

    print()

    print("Traffic source:")
    print(TRAFFIC_SOURCE)

    print()

    print("Interface:")
    print(INTERFACE)

    print()

    print("Packet limit:")
    print("CONTINUOUS")

    print()

    print(
        "Prediction starts after:",
        PREDICT_AFTER_PACKETS,
        "packets",
    )

    print(
        "Prediction interval:",
        PREDICT_EVERY_PACKETS,
        "packets",
    )

    print()

    print("CSV log:")
    print(LOG_FILE)

    print()

    print("Starting continuous live capture...")
    print("Press Ctrl+C to stop.")
    print()

    try:

        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False,
        )

    except KeyboardInterrupt:

        print()
        print("Capture stopped by user.")

    except Exception as e:

        print()
        print(
            "[Capture error]",
            str(e),
        )

    print()
    print("=" * 60)
    print("NIDS CAPTURE STOPPED")
    print("=" * 60)

    print_summary()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()