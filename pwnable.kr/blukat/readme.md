# blukat
- Một bài troll, mục đích chỉ là nhắc ta lưu ý về phân quyền group
```
blukat@pwnable:~$ id
uid=1104(blukat) gid=1104(blukat) groups=1104(blukat),1105(blukat_pwn)
```
```
blukat@pwnable:~$ cat password
cat: password: Permission denied # real pass
```

```
blukat@pwnable:~$ ./blukat
guess the password!
cat: password: Permission denied
congrats! here is your flag: Pl3as_DonT_Miss_youR_GrouP_Perm!!
```