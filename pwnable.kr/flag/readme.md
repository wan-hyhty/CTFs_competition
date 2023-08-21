# flag
## Phân tích
- Bài này reverse tuy nhiên có vẻ đã bị nén bằng upx
- Để giải nén `./upx-4.0.2-amd64_linux/upx <tên file>`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *dest; // [rsp+8h] [rbp-8h]

  puts("I will malloc() and strcpy the flag there. take it.", argv, envp);
  dest = (char *)malloc(100LL);
  strcpy(dest, flag);
  return 0;
}
```

- Chương trình copy flag vào dest

## Khai thác

```.rodata:0000000000496628 aUpxSoundsLikeA db 'UPX...? sounds like a delivery service :)',0```