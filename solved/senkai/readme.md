# House of Enherjar

## Introduction

- Kĩ thuật House of Enherjar sẽ sử dụng off-by-one null byte để ow bit inuse của chunk thành non-inuse và set pre_size, từ đó khi free chunk đó vào unsorted bin, nó sẽ consolidate khiến overlap chunk xảy ra.

## Principle

### Backward merge operation

- Khi free một chunk vào unsorted bin

```c
/* consolidate backward */

if (!prev_inuse(p)) {

    prevsize = prev_size(p);

    size += prevsize;

    p = chunk_at_offset(p, -((long) prevsize));
unlink (off, p, bck, fwd);
        }
```

- Hiểu đơn giản là nếu bit inuse = 0, nó sẽ merge một lượng bằng presize phía bên trên.
  ![Alt text](image.png)
- Khi này nó có một số security check
  - Đầu tiên khi merge lên trên, khi này chunk cũ và phần được merge là 1 chunk, khi đó security check đầu tiên sẽ là check
  ```
  if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");
  ```
  - Thứ hai là `P->fd->bk == P and P->bk->fd == P`
    ![Alt text](image-1.png)

### Example
- Giả sử ta setup như sau
![Alt text](image-2.png)
- Khi ta free chunk 1, free sẽ thấy bit inuse tắt, khi này nó sẽ unlink và mer với fake chunk và free, khi ấy chunk trong bin là chunk fake (chunk fake merge với chunk 1) và khi này ta có overlap chunk