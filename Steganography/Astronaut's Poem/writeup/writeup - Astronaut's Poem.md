# Write up

Le challenge prend la forme d’un poème dans lequel une valeur a été cachée. 

Pour mieux appréhender le challenge, il est utile de s'intéresser aux métadonnées. Un lien vers https://esolangs.org/wiki/Poetic peut y être trouvé. Le langage du poème peut ainsi être facilement identifié comme le langage ésotérique poetic. Depuis cette source, un lien vers [l’interpréteur officiel de ce langage](https://web.archive.org/web/20210506123139/https://mcaweb.matc.edu/winslojr/vicom128/final/tio/index.html) doit être découvert.

Une fois sur la page, il suffit de coller le poème dans l’interpréteur pour obtenir le second indice. Attention, l'exécution dépend de la longueur des mots, une erreur de retranscription peut donc s’avérer fatale.

![image](https://user-images.githubusercontent.com/94687077/227499678-4437ab7d-5638-4715-b15f-afa377df62b5.png)

*L’indice indique que la valeur que l’on recherche peut-être décelée à la ligne 10 du poème.*

**"Drove by our curiosity, I found my way: patrolling our spacecraft. You remembered wishes of hope. I am close to succeeding."**

On sait que les instructions dépendent de la longueur des mots, il faut alors mener un travail de traduction.
La suite ainsi obtenue est telle que : 5 2 3 9 1 5 2 3 10 3 10 3 10 6 2 4 1 2 5 2 0.

Afin de comprendre ce qui est fait, on identifie chacune des instructions. Ainsi, après s’être positionné et avoir ajouté neuf - 5 2 3 9 - on entre dans une boucle - 1 -  que l’on initialise - 5 2 - dans lequel on additionne trois fois dix - 3 10 3 10 3 10 - . Une fois la somme faite, on revient à la position originelle pour décrémenter la valeur précédemment initialisée : neuf - 6 2 4 1 - avant de fermer la boucle - 2 -.

![image](https://user-images.githubusercontent.com/94687077/227500230-21d83f35-64b4-4cc5-9cc0-cc77926c90d8.png)

La suite, - 5 2 - n’importe pas, le zéro quant à lui marque la fin d'exécution. On a donc retrouvé la valeur cachée, 270, le numéro d’un NGC.

Or, [NGC 270](https://fr.wikipedia.org/wiki/NGC_270) est une galaxie située dans la constellation de la **Baleine**. 

**Donc le flag est HACKDAY{baleine}**
