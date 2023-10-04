import hashlib


def md5sum(b: bytes):
    return hashlib.md5(b).digest()[:3]


printable = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '.']


for a in printable:
    for b in printable:
        for c in printable:
            for d in printable:
                for e in printable:
                    for f in printable:
                        s = b"cat "
                        s = s+bytes(a, 'utf-8')+bytes(b, 'utf-8') + bytes(c, 'utf-8') + bytes(d, 'utf-8') + bytes(
                            e, 'utf-8') + bytes(f,'utf-8')
                        if md5sum(s).hex() == '76cbad':
                            print(s)
