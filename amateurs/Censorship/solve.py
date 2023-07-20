str = "exec('print(flag)')"
res = ""
for i in str:
    res += f"chr({ord(i)})+"
print(res)