import pandas as pd
import numpy as np

df = pd.read_csv("/Users/aman/Desktop/q2.csv")

d = {}

for i in range(len(df.index)):
    
    src_mac = df.iat[i,2]
    rate = df.iat[i,7]
    rate = int(rate.split()[0])
    if src_mac not in d:
        d[src_mac] = [rate]
    else:
        d[src_mac].append(rate)
        

for i in d:
    print(f"{i} : {np.mean(d[i])}")
    
    
    
