#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// gcc -fstack-protector-all -o aftermath aftermath.c

#define MAX_NOTES 10
#define MAX_NOTE_SIZE 0xff


struct Note {
	int size;
	char* note;
};

struct Note* note_storage[MAX_NOTES];


void error(char* err_msg) {
	puts(err_msg);
	exit(1);
}

int get_int() {
	char buf[8];
	unsigned int res = fgets(buf, 8, stdin);
	if (res == 0) {
		error("invalid int");
	}
	return atoi(&buf);

}

unsigned int count_notes() {
	for (int i = 0; i < MAX_NOTES; i++) {
		if (note_storage[i] == NULL) return i;
	}
	return MAX_NOTES;
}


void add_note() {
	unsigned int note_count = count_notes();
	if (note_count == MAX_NOTES) {
		puts("Max note capacity reached");
		return;
	}

	struct Note* note = (struct Note*) malloc(sizeof(struct Note));
	note_storage[note_count] = note;

	printf("Size: ");
	int size = get_int();

	if (abs(size) >= MAX_NOTE_SIZE) {
		error("Notes that big are currently not supported!");
	} else if (size == 0) {
		error("Can't store nothing");
	}

	char* data = (char*) malloc(abs(size));
	printf("Note: ");
	fgets(data, abs(size), stdin);
	note->size = size;
	note->note = data;

	puts("Note added!");
}

void read_note() {
	printf("Index: ");
	unsigned int index = get_int();
	unsigned int count = count_notes();

	if (index < count) {
		struct Note* cnote = note_storage[index];
		printf("Note: ");
		printf(cnote->note);
	} else {
		error("Note does not exist!");
	}
}

void edit_note() {
	char edit_buf[MAX_NOTE_SIZE];

	printf("Index: ");
	unsigned int index = get_int();
	unsigned int count = count_notes();

	if (index < count) {
		struct Note* cnote = note_storage[index];
		printf("New Note: ");
		read(0, edit_buf, cnote->size);
		strncpy(cnote->note, edit_buf, abs(cnote->size));
	} else {
		error("Note does not exist!");
	}
}

void menu() {
	puts("1. Add note");
	puts("2. Read note");
	puts("3. Edit note");
	puts("4. Exit");

	printf("> ");
}



int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	puts("******** Insane note book app trust me ********");
	
	while (1) {
		menu();
		unsigned int choice = get_int();
		if (choice == 1) {
			add_note();
		} else if (choice == 2) {
			read_note();
		} else if (choice == 3) {
			edit_note();
		} else if (choice == 4) {
			return 0;
		} else {
			error("invalid choice");
		}
	}
}