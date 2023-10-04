flag = "ctf{i wonder what the flag is}"

def checkpass(lis):
  if lis == [ord(e) for e in flag]:
    print("You are now authorized!")
    # TODO grant access
  else:
    print("Incorrect password!")

def main():
  inp = input("Enter a Python list: ")
  lis = eval(inp)
  if type(lis) != list:
    print("That's not a list")
    return
  for i in lis:
    print(f"You entered: {i}")
  checkpass(lis)

main()
