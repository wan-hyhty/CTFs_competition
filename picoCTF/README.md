# basic-file-exploit
<details> <summary> basic-file-exploit </summary>
  
  [file c](https://github.com/wan-hyhty/CTFs_competition/blob/main/picoCTF/source/basic-file-exploit.c)
  chương trình cho ta đoạn chương trình C, ta chú ý đoạn thực thi flag  
```c
  static void data_read() {
  char entry[4];
  long entry_number;
  char output[100];
  int r;

  memset(output, '\0', 100);
  
  printf("Please enter the entry number of your data:\n");
  r = tgetinput(entry, 4);
  // Timeout on user input
  if(r == -3)
  {
    printf("Goodbye!\n");
    exit(0);
  }
  
  if ((entry_number = strtol(entry, NULL, 10)) == 0) {
    puts(flag);
    fseek(stdin, 0, SEEK_END);
    exit(0);
  }

  entry_number--;
  strncpy(output, data[entry_number], input_lengths[entry_number]);
  puts(output);
}
```
  Khi thực thi đến đoạn "entry number of your data" ta phải thoả điều kiện strtol(entry, NULL, 10) == 0 thì sẽ in được flag
  > Sau khi tìm hiểu thì hàm *strtol* sẽ chuyển đổi một phần của chuỗi ban đầu trong str thành một giá trị long int tương ứng với cơ số base đã cho, mà phải là 2, 8, …, 36, hoặc là giá trị đặc biệt 0.
  > Ở đây chương trình chuyển đổi chuỗi của ta thành cơ số 10, nghĩa là nếu ta nhập số thì sẽ chuyển được về số tương ứng
  > ví dụ: chuỗi '10' thì strtol sẽ trả giá trị là 10, chuỗi '10 abc' sẽ trả là 10, tất nhiên nếu ta nhập chuỗi không chứa số thì strtol sẽ trả giá trị 0 và thoả điều kiện để in flag  
```
Hi, welcome to my echo chamber!
Type '1' to enter a phrase into our database
Type '2' to echo a phrase in our database
Type '3' to exit the program
1
1
Please enter your data:
qqqqq
qqqqq
Please enter the length of your data:
5
5
Your entry number is: 1
Write successful, would you like to do anything else?
2
2
Please enter the entry number of your data:
q
q
picoCTF{M4K3_5UR3_70_CH3CK_Y0UR_1NPU75_1B9F5942}
```
</details>
