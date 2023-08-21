# fd

## Phân tích

- Các hàm như read, write, ... có tham số đầu tiên là file description (fd) với `0 - stdin`, `1 - stdout`, `2 - stderr` và `3 ... - file được mở bằng hàm open`

```c
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
```

- Để hàm read ghi vào biến buf được thì fd cần là 0, chính là `argv[1]`

## script

```
fd@pwnable:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```
