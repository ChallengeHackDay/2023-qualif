# Write up

Le programme suivant va s’occuper de la vérification du mot de passe :
```python
for (unit8_t i = 0; i > sizeof(correct_passwd); i ++){
	if (correct_passwd[i] != passwd[i] ){
    	passbad = 1;
    	break;
	}
}```


Ce programme est sensible à l’attaque SPA car si la lettre n’est pas correcte, le temps d'exécution va être plus long car on met la variable “passbad” à 1 et on break. Pour savoir quel est le bon octet de clé testé, on va fixer un octet précis, mettons le 1er. Si l’octet n’est pas le bon, la consommation sera plus “faible” que si il est bon, car le break aura lieu plus tôt. Dans ce cas, si on est sur le bon octet, on aura une courbe qui a shifter vers la droite par rapport aux autres. Il suffit alors de tester les 36 possibilités et de regarder sur quel octet on observe le shift.


Pour réaliser l’attaque Simple Power Analysis à partir des enregistrements, on peut utiliser le programme suivant. Celui-ci va afficher sur des cinq graphiques contenant chacun 30 courbes représentant les 36 caractères de la liste “trylist” (alphabet et nombre). 

```python
import matplotlib.pyplot as plt
import numpy as np

trylist = "abcdefghijklmnopqrstuvwxyz0123456789"
clk_freq = 7500000
delta_t =  1/float(clk_freq)
files = ["SPA_first.npy", "SPA_second.npy", "SPA_third.npy", "SPA_fourth.npy", "SPA_five.npy"]
traces = np.zeros((5, len(trylist), 800))

if __name__ ==  "__main__":
	for i in range(5):
    	with open(files[i], 'rb') as f:
        	for j in range(len(trylist)):
            	traces [i,j] = np.load(f)

            	plt.plot(traces[i,j], label=trylist[j])
            	plt.legend()
        	plt.show()
```


Ce programme nous donne le résultat suivant : (voir photo demo.png)


On observe sur le graphique qu’une des courbes est décalée par rapport à la masse. Il faut alors identifier la lettre associée pour découvrir petit à petit le mot de passe. 
Ici, nous sommes confrontés à un problème, l’affichage ne possède que 10 couleurs alors que nous avons 36 caractères. L’objectif est alors de prendre les 26 premiers caractères, et d’observer si on a le shift ou non. Si on l’a, c’est que la clé se trouve dans les 26 premiers, sinon c’est qu'il est dans les 10 derniers. On continue ainsi de remonter jusqu'à trouver le bon caractère. 

On obtient le mot de passe : h0px3

**donc le flag à construire est HACKDAY{h0px3}**
