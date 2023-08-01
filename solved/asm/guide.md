constants
<name> equ <value>
MYCONST equ 10
myStrLen equ $ - myStr
Initialized Variables

- Nằm trong section .data
  <name> <type> <magnitude>
  type: db (1byte), dw (2b), dd(4b), dq (8b)
  - db (1 byte): Đây là kiểu dữ liệu dùng để lưu trữ một byte (8 bit) dữ liệu. Byte này có thể chứa một giá trị số nguyên có dấu hoặc không dấu, một ký tự ASCII hoặc một địa chỉ bộ nhớ.
  - dw (2 bytes): Đây là kiểu dữ liệu dùng để lưu trữ một từ (16 bit) dữ liệu. Từ này có thể chứa một giá trị số nguyên có dấu hoặc không dấu, một ký tự Unicode hoặc một địa chỉ bộ nhớ.
  - dd (4 bytes): Đây là kiểu dữ liệu dùng để lưu trữ một double word (32 bit) dữ liệu. Double word này có thể chứa một giá trị số nguyên có dấu hoặc không dấu, một địa chỉ bộ nhớ hay một số thực đơn giản.
  - dq (8 bytes): Đây là kiểu dữ liệu dùng để lưu trữ một quad word (64 bit) dữ liệu. Quad word này có thể chứa một giá trị số nguyên có dấu hoặc không dấu, một địa chỉ bộ nhớ hay một số thực đơn giản.

sqrTwo dd 1.4142
age db 10

- Moving date (mov)

  - có thể chuyển giữ 2 biến, 2 thanh ghi, 1thanh ghi 1 biến, không thể giữa 2 địa chỉ với nhau
    mov eax, ebx

- Conversion Instructions
  Trong lập trình assembly, các lệnh chuyển đổi kiểu dữ liệu (Conversion Instructions) được sử dụng để chuyển đổi giá trị của một biến hoặc thanh ghi sang một kiểu dữ liệu khác. Các lệnh này giúp bạn thực hiện các phép tính và thao tác dữ liệu trên các kiểu dữ liệu khác nhau.

Một số lệnh chuyển đổi kiểu dữ liệu phổ biến trong assembly như sau:

    MOVZX: Lệnh này được sử dụng để mở rộng một giá trị byte hoặc word thành một giá trị double word trong thanh ghi.
    MOVSX: Lệnh này được sử dụng để mở rộng một giá trị byte hoặc word thành một giá trị double word với dấu trong thanh ghi.
    CVTSI2SD: Lệnh này được sử dụng để chuyển đổi một giá trị integer sang một giá trị double precision.
    CVTSD2SI: Lệnh này được sử dụng để chuyển đổi một giá trị double precision sang một giá trị integer.
    FILD: Lệnh này được sử dụng để chuyển đổi một giá trị integer sang một giá trị floating-point.
    FIST: Lệnh này được sử dụng để chuyển đổi một giá trị floating-point sang một giá trị integer.
    XORPD: Lệnh này được sử dụng để thực hiện phép XOR trên hai giá trị double precision.
    XORPS: Lệnh này được sử dụng để thực hiện phép XOR trên hai giá trị floating-point.

- Narrowing Conversions
  Trong lập trình assembly, Narrowing Conversions (chuyển đổi thu hẹp) là quá trình chuyển đổi giá trị của một biến hoặc thanh ghi từ kiểu dữ liệu lớn hơn sang kiểu dữ liệu nhỏ hơn. Quá trình này có thể gây mất mát dữ liệu và sai sót tính toán, do đó bạn cần phải cẩn thận khi sử dụng các lệnh chuyển đổi thu hẹp.
  mov rbx, 10

  ```
  Lệnh "mov rbx, 10" trong lập trình assembly sẽ sao chép giá trị 10 vào thanh ghi RBX. Tuy nhiên, việc sao chép giá trị integer 10 vào thanh ghi RBX được xem là một chuyển đổi thu hẹp vì kiểu dữ liệu của giá trị integer 10 (4 byte) lớn hơn kiểu dữ liệu của thanh ghi RBX (8 byte).

  Trong trường hợp này, lệnh "mov rbx, 10" sẽ sao chép giá trị 10 vào 4 byte thấp của thanh ghi RBX, và các 4 byte cao của thanh ghi RBX sẽ được giữ nguyên giá trị của nó. Do đó, việc sao chép giá trị integer 10 vào thanh ghi RBX có thể gây mất mát dữ liệu và sai sót tính toán trong một số trường hợp.
  ```

    mov al,bl
