from scapy.all import sniff, IP, IPv6, TCP, UDP
from datetime import datetime

from flow_builder import Flow, get_flow_key


INTERFACE = r"\Device\NPF_{227451D9-9718-4DD5-B69C-9ECA99233158}"

flows = {}


def process_packet(packet):

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        protocol = packet[IPv6].nh

    else:
        return

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:
        return

    timestamp = datetime.now().timestamp()
    length = len(packet)

    forward_key, backward_key = get_flow_key(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
    )

    if forward_key in flows:

        flow = flows[forward_key]

        flow.add_packet(
            timestamp,
            length,
            "forward",
        )

    elif backward_key in flows:

        flow = flows[backward_key]

        flow.add_packet(
            timestamp,
            length,
            "backward",
        )

    else:

        flow = Flow(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        )

        flow.add_packet(
            timestamp,
            length,
            "forward",
        )

        flows[forward_key] = flow


def main():

    print("=" * 60)
    print("NIDS - LIVE FLOW CAPTURE")
    print("=" * 60)

    print(f"Interface: {INTERFACE}")
    print("Capturing 50 packets...")
    print()

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        count=50,
        store=False,
    )

    print()
    print("=" * 60)
    print("FLOW CAPTURE COMPLETE")
    print("=" * 60)

    print(f"Flows created: {len(flows)}")
    print()

    for number, flow in enumerate(
        flows.values(),
        start=1,
    ):

        print(f"Flow {number}")
        print("-" * 60)

        summary = flow.summary()

        print(
            f"{summary['src_ip']}:{summary['src_port']} "
            f"-> "
            f"{summary['dst_ip']}:{summary['dst_port']}"
        )

        print(f"Protocol: {summary['protocol']}")
        print(f"Duration: {summary['duration']:.6f} seconds")
        print(
            f"Forward packets: "
            f"{summary['forward_packets']}"
        )
        print(
            f"Backward packets: "
            f"{summary['backward_packets']}"
        )
        print(
            f"Total packets: "
            f"{summary['total_packets']}"
        )
        print(
            f"Forward bytes: "
            f"{summary['forward_bytes']}"
        )
        print(
            f"Backward bytes: "
            f"{summary['backward_bytes']}"
        )
        print(
            f"Total bytes: "
            f"{summary['total_bytes']}"
        )

        print()


if __name__ == "__main__":
    main()