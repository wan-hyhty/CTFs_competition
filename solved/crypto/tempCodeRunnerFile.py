from Crypto.PublicKey import RSA

f = open('privacy_enhanced_mail.pem','r').read()
flag = RSA.importKey(f)

print(flag.d)