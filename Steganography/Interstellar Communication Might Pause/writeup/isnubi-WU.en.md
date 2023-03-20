# Interstellar Communication Might Pause

So we have a .pcap file which contains a lot of ICMP packets.
Nothing seems particularly abnormal, but considering the quantity of packets, we can say that something is hidden in this communication.

## Analysis of the .pcap file

We come in Python, with Scapy, to recover the packets.
```python
from scapy.all import *
from scapy.layers.inet import ICMP

pcap = "dump.pcap"

print(rdpcap(pcap))
```
```python
<dump.pcap: TCP:0 UDP:0 ICMP:12082 Other:0>
```
We come in Python, with Scapy, to recover the packets.

## Packet analysis

So, for each packet, we will retrieve the payload of the packet that may contain data.
We will only look at one type of packet (Request or Reply) to avoid duplicate data.
```python
from scapy.all import *
from scapy.layers.inet import ICMP

pcap = "dump.pcap"
for p in rdpcap(pcap):
    if ICMP in p:
        if p[ICMP].type == 0:
            print(p[ICMP].load.hex()
```

## Recovery of fragements
By searching a little, we realize that 16 bytes that can look like data fragements are added at the end of each payload.
So we will get these 16 bytes fragements and put them in a row.
```python
from scapy.all import *
from scapy.layers.inet import ICMP

pcap = "dump.pcap"
data = ""
for p in rdpcap(pcap):
    if ICMP in p:
        if p[ICMP].type == 0:
            data += p[ICMP].load.hex()[-32:]
```
## Reconstitution of the data
We end up with a long string of hexadecimal characters.

By looking at the first fragmentation of 16 bytes, we realize that the first 8 bytes correspond to the signature of a PNG file (89504E470D0A1A0A).

We will then come to reconstruct an image in PNG format using the hexadecimal character string.
```python
from scapy.all import *
from scapy.layers.inet import ICMP

pcap = "dump.pcap"
data = ""
for p in rdpcap(pcap):
    if ICMP in p:
        if p[ICMP].type == 0:
            data += p[ICMP].load.hex()[-32:]

with open("generated.png", "wb") as f:
    f.write(bytes.fromhex(data))
```

We then find an image on which a flag is present.
