# printfail
## IDA
```c
int __fastcall run_round(_DWORD *a1)
{
  memset(buf, 0, sizeof(buf));
  fflush(stdout);
  if ( !fgets(buf, 512, stdin) )
    return 0;
  *a1 = strlen(buf) <= 1;
  return printf(buf);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("I'll let you make one printf call. You control the format string. No do-overs.");
  v4 = 1;
  while ( v4 )
  {
    if ( !(unsigned int)run_round(&v4) )
      return 0;
    if ( v4 )
      puts("...That was an empty string. Come on, you've at least gotta try!\nOkay, I'll give you another chance.");
  }
  return 0;
}
```

## Định hướng
Sau khi được các anh hint thì ta có lỗi fmt dùng con trỏ stack để thay đổi dữ liệu. Đoạn bug ở đây: