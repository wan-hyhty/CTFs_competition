#!/usr/local/bin/python3
# flag = "fakeflag"
from flag import flag
for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            # print(code)
            if "flag" in code or "e" in code or "t" in code or "\\" in code:
                raise ValueError("invalid input")
            exec(eval(code))
        except Exception as err:
            print(err)
