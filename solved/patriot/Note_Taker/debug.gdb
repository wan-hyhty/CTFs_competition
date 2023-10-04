file note_keep_arm
set architecture aarch64
target remote localhost:1234
b*main
b*create_note+244
b*0x0000005500001020
c