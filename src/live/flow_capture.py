from collections import defaultdict
from datetime import datetime

from scapy.all import IP, IPv6, TCP, UDP, sniff


INTERFACE = r"\Device\NPF_{227451D9-9718-4DD5-B69C-9ECA99233158}"

flows = defaultdict(
    lambda: {
        "first_seen": None,
        "last_seen": None,
        "forward_packets": 0,
        "backward_packets": 0,
        "forward_bytes": 0,
        "backward_bytes": 0,
    }
)


def get_packet_info(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

        if TCP in packet:
            protocol = 6
        elif UDP in packet:
            protocol = 17
        else:
            return None

    else:
        return None

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    else:
        source_port = 0
        destination_port = 0

    return (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
        len(packet),
    )


def process_packet(packet):
    info = get_packet_info(packet)

    if info is None:
        return

    (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
        packet_length,
    ) = info

    forward_key = (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
    )

    backward_key = (
        destination_ip,
        destination_port,
        source_ip,
        source_port,
        protocol,
    )

    if forward_key in flows:
        flow_key = forward_key
        direction = "forward"

    elif backward_key in flows:
        flow_key = backward_key
        direction = "backward"

    else:
        flow_key = forward_key
        direction = "forward"

    now = datetime.now()

    if flows[flow_key]["first_seen"] is None:
        flows[flow_key]["first_seen"] = now

    flows[flow_key]["last_seen"] = now

    if direction == "forward":
        flows[flow_key]["forward_packets"] += 1
        flows[flow_key]["forward_bytes"] += packet_length

    else:
        flows[flow_key]["backward_packets"] += 1
        flows[flow_key]["backward_bytes"] += packet_length


def print_flow_summary():
    print()
    print("=" * 70)
    print("LIVE FLOW SUMMARY")
    print("=" * 70)

    print("Active flows:", len(flows))
    print()

    for number, (key, flow) in enumerate(flows.items(), start=1):

        source_ip, source_port, destination_ip, destination_port, protocol = key

        duration = (
            flow["last_seen"] - flow["first_seen"]
        ).total_seconds()

        total_packets = (
            flow["forward_packets"]
            + flow["backward_packets"]
        )

        total_bytes = (
            flow["forward_bytes"]
            + flow["backward_bytes"]
        )

        print(f"Flow {number}")
        print("-" * 70)
        print(
            f"{source_ip}:{source_port}"
            f" -> "
            f"{destination_ip}:{destination_port}"
        )
        print("Protocol:", protocol)
        print("Duration:", duration, "seconds")
        print("Forward packets:", flow["forward_packets"])
        print("Backward packets:", flow["backward_packets"])
        print("Total packets:", total_packets)
        print("Forward bytes:", flow["forward_bytes"])
        print("Backward bytes:", flow["backward_bytes"])
        print("Total bytes:", total_bytes)
        print()


if __name__ == "__main__":

    print("=" * 70)
    print("NIDS - LIVE FLOW CAPTURE")
    print("=" * 70)
    print()
    print("Capturing 100 live packets...")
    print("Please generate some normal network activity.")
    print()

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        count=100,
        store=False,
    )

    print_flow_summary()