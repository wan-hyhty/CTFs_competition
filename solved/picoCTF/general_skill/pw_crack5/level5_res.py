import hashlib
#flag_enc = open('level5.flag.txt.enc', 'rb').read()
#correct_pw_hash = open('level5.hash.bin', 'rb').read()

correct_pw_hash = open('level5.hash.bin', 'rb').read()
list_pw = open('dictionary.txt', 'rb').read()

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

for i in list_pw:
    if('0000' in str(i) == 'True'):
        print(i)
print("end")
        


