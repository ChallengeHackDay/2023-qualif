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
