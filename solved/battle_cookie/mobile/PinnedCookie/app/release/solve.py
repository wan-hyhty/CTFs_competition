import base64
array_str = "MBw6FDdZBT4wRzkQMB0jYEc8EUUDLQwjPiE8LR0TDw=="
decoded_str = base64.b64decode(array_str)
byte_arr = bytearray(decoded_str)
# byte_str = string.encode('utf-8')
# for i in range(len(byte_arr)):
#     byte_arr[i] = byte_arr[i] ^ byte_str[i % len(byte_str)]
# byte_arr.decode('utf-8')
byte_str = "this as java.lang.String).getBytes(charset)"
for i in range(len(byte_arr)):
    byte_arr[i] = byte_arr[i] ^ ord(byte_str[i % len(byte_str)])
print(byte_arr)