```python
import math

def is_prime(n):
    if n <= 1:
        return False
    elif n == 2:
        return True
    elif n % 2 == 0:
        return False

    # Check odd divisors up to sqrt(n)
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False

    return True


for i in range(100000000):
    a1 = i * i
    v6 = 0
    v5 = 1
    v3 = a1
    while v3 != 0:
        v6 += v3 % 10 * v5
        v3 //= 10
        v5 *= 10
        v4 = v6 + v3
        if v6 >= v3:
            break
        if v4 == i and is_prime(v6):
            print(a1, v6)
            break
```
