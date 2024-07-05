import pandas as pd

df = pd.read_csv("/Users/aman/Desktop/q3_c.csv",encoding='latin')

ctr = 0

for i in df.index:
    ctr += 1
    
print("udp/quic packets ",ctr)