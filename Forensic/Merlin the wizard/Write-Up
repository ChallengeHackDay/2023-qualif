Résolution :
Ce challenge de Forensic / Reverse avait pour objectif de travailler avec le malware Merlin, qui est un agent de C2 développé en Go. 
Pour le savoir, il suffisait de chercher "Merlin malware" sur Google, ce qui nous amenait vers le github du serveur Merlin. Seulement ici, il s'agisssait d'un agent Merlin, et non pas du serveur. 
Quelques recherches plus tard, on trouvait assez facilement le code source de Merlin. Dans le main.go, une description de toute les options est disponible, mais un attire notre attention : 
```go
flag.StringVar(&psk, "psk", psk, "Pre-Shared Key used to encrypt initial communications")
```

D'après le code source, la clé de chiffrement était stockée dans la variable 'psk'. 
Si on fait un strings | grep psk sur le binaire, on trouvait une ligne de compilation : 
```bash
build   -ldflags="-X \"main.payloadID=41ec9d05-f479-4440-bd96-f12e3cb1834b\" -X \"main.profile=http\" -X \"main.url=http://127.0.0.1:80/data\" -X \"main.psk=yDqoTzYhqkOadpoU4WS7wUBDJZZlsLEayL6ElxetWIc=\" -X \"main.useragent=Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko\" -X \"main.sleep=10s\" -X \"main.skew=2300\" -X \"main.killdate=1709769600\" -X \"main.maxretry=7\" -X \"main.padding=4096\" -X \"main.verbose=False\" -X \"main.debug=False\" -H=windowsgui -s -w -buildid="
```
On trouvait dans cette ligne la variable psk qui avat été setté : yDqoTzYhqkOadpoU4WS7wUBDJZZlsLEayL6ElxetWIc=, qui était le flag.


Neutralisation du binaire : 
Pas d'inquiétude, comme on peut le voir dans la ligne de compilation, l'agent C2 pointe vers 127.0.0.1 ;)
