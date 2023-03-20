if __name__ == "__main__":
   #Chargement des fichiers contenant les différentes mesures
   with open('DPA.npy', 'rb') as f:
       trace_array = np.load(f) #L'ensemble des mesures
       textin_array = np.load(f) #Le texte entrant en clair que la puce va chiffrer
       known_keys = np.load(f) #L'ensemble des clés utilisées pour chaque mesure
       #On a utilisée la même clée pour toute les mesures et on essaie de la retrouver
   true_key = known_keys[0] #On connait la vrai clé et c'est la même partout. Elle servira pour vérifier le résultat
   print(true_key)
   num_trace = np.shape(trace_array)[0] #le nombre de courbe enregistrée


   for i in range(16):
       moy_array = []
       for key_hypothesis in range(255):
           zero = []
           uns = []
           for k in range(800):
               b = point_of_attack(textin_array[k][i], key_hypothesis)
               if b % 2 == 0:
                   zero.append(trace_array[k])
               else:
                   uns.append(trace_array[k])
       average0 = np.mean(zero, 0)
       average1 = np.mean(uns, 0)
       diff = np.abs(average1 - average0)


       moy_array.append(np.max(diff))
   plt.plot(moy_array)
   plt.show()
