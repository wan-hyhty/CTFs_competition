i = 0
while (1):
    if ((i & 127) == 0 and (i & 65280) >> 8 == 66):
        print(i)
        break
    
    i+=1
