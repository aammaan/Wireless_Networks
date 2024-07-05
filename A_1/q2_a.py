import pandas as pd
import numpy as np

df = pd.read_csv("/Users/aman/Desktop/q2.csv")

d = set()

for i in range(len(df.index)):
    
    
    src_mac = df.iat[i,2]
    rate = df.iat[i,6]
    d.add(src_mac)
    d.add(rate)
    
    
        
print(f"Number of Unique MAC Addresses: {len(d)}")
    
    
d = set()

for i in range(len(df.index)):
    
    
    src_mac = df.iat[i,2]
    d.add(src_mac)

    
    
        
print(f"Number of clients: {len(d)}")
    
    
