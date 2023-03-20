# Interstellar Communication Might Pause

On a donc un fichier .pcap qui contient beaucoup de paquets ICMP.
Rien ne parait particulièrement anormal, mais au vu de la quantité de paquet, on peut se dire que quelque chose se cache dans cette communication.

## Etude du fichier .pcap

On vient en Python, avec Scapy, récupérer les paquets.
```python
from scapy.all import *
from scapy.layers.inet import ICMP

pcap = "dump.pcap"

print(rdpcap(pcap))
```
```python
<dump.pcap: TCP:0 UDP:0 ICMP:12082 Other:0>
```
On voit qu'il n'y a que des paquets ICMP dans notre fichier .pcap.

## Analyse des paquets

On va donc, pour chaque paquet, récupérer la payload du paquet pouvant, possiblement, contenir de la donnée.
On ne regardera qu'un type de paquet (Request ou Reply) pour ne pas avoir les données en double.
```python
from scapy.all import *
from scapy.layers.inet import ICMP

pcap = "dump.pcap"
for p in rdpcap(pcap):
    if ICMP in p:
        if p[ICMP].type == 0:
            print(p[ICMP].load.hex()
```
## Récupération des fragements
En cherchant un peu, on se rend compte que 16 octets pouvant ressembler à des fragements de données sont ajoutés à la fin de chaque payload.
On va donc récupérer ces fragements de 16 octets et les mettre à la suite.
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
## Reconstitution de la donnée
On se retrouve alors avec une longue chaîne de caractères héxadécimaux.

En regardant le premier fragement de 16 octets, on se rend compte que les 8 premiers octets correspondent à la signature d'un fichier PNG (89504E470D0A1A0A).

On va alors venir reconstruire une image au format PNG à l'aide de la chaîne de caractères héxadécimaux.
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

On retrouve alors une image sur laquelle un flag est présent.
