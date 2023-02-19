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
  
</details>
