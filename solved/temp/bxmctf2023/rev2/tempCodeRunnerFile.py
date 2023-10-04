print("Error. Login Required.")
print("Please enter the corresponding passcodesto proceed.")
with open('primes.txt', 'r') as file:
    content = file.read()
numbers = [int(num) for num in content.split()]
# a = int(input("Enter 'a': "))
# b = int(input("Enter 'b': "))
# c = int(input("Enter 'c': "))
# d = int(input("Enter 'd': "))

# x = manipulate(str(a))
# y = manipulate(str(b))
# z = manipulate(str(c))
# w = manipulate(str(d))
print(numbers)
# token = manipulate(str(x + y + z + w))
# print("ctf{" + str(token) + "}")