import pandas as pd

df = pd.read_csv("/Users/aman/Desktop/q3_b.csv")

ctr = 0
for i in df.index:
    ctr += 1
    
print("tcp packets ",ctr)