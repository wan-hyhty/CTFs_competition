def alpha(a, b):
    if a < b:
        return alpha(b, a)
    
    if a % b == (a ^ a):
        return b
    
    return alpha(b, a % b)

def beta(x, y, z):
    ans = 1
    
    if y & 1 != 0:
        ans = x
    
    while y != 0:
        y >>= 1
        x = (x * x) % z
        
        if y & 1 != 0:
            ans = (ans * x) % z
    
    return ans

def gamma(n):
    for i in range(2, n+1):
        if alpha(i, n) == 1:
            if beta(i, n-1, n) != 1:
                return 0
    
    return 1

def init(n):
    check = True if gamma(n) == 1 else False
    
    if check:
        print("YES")
    else:
        print("NO")
def main():
    for i in range(18446744073709551430, 18446744073709551521):
        print(i)
        init(i)
        print("---")
main()