from scapy.all import *
from scapy.layers.inet import ICMP
import sys


def main():
    """
    Main function for decoding hidden hex chunks from ICMP packets and reconstructing an image
    :return: None
    """
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <pcapng>")
        sys.exit(1)
    pcap = sys.argv[1]
    if not os.path.exists(pcap):
        print("Pcapng does not exist")
        sys.exit(1)
    packets = rdpcap(pcap)
    data = ""
    for p in packets:
        if ICMP in p:
            if p[ICMP].type == 0:
                data += p[ICMP].load.hex()[-32:]
    with open("generated.png", "wb") as f:
        f.write(bytes.fromhex(data))


if __name__ == "__main__":
    main(
