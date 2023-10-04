#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PREV_INUSE 1

struct struct_book{
	long long int *book;
	unsigned long long int length;
};

struct struct_book books[5];

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void add()
{
	unsigned int size, idx;
	char *b;

	printf("Book index: ");
	scanf("%u", &idx);
	if (idx>=5)
		puts("Cannot manage more than 5 books!");
	else
	{
		printf("Length of book name: ");
		scanf("%u", &(books[idx].length));
		if (books[idx].length > 0x500)
			puts("Length too long!");
		else
		{
			b = malloc(books[idx].length);
			printf("Book name: ");
			size = read(0, b, books[idx].length);
			b[size] = '\0';
			books[idx].book = (long long int*)b;
		}
	}
}

void view()
{
	unsigned int idx;

	printf("Book index: ");
	scanf("%u", &idx);
	if ((idx>=5) || (books[idx].book==NULL))
		puts("Invalid!");
	else
		printf("Book name: %s\n", books[idx].book);
	if (books[idx].length==0)
		books[idx].book = NULL;
}

void edit()
{
	unsigned int size, idx;
	char *b;

	printf("Book index: ");
	scanf("%u", &idx);
	if ((idx>=5) || (books[idx].book==NULL))
		puts("Invalid!");
	else
	{
		printf("Book name: ");
		b = (char *)books[idx].book;
		size = read(0, b, books[idx].length);
		b[size] = '\0';
		books[idx].book = (long long int*)b;
	}
}

int checkbackward(long long int *b)
{
	return b[-1] & PREV_INUSE;
}

int checkforward(long long int *b)
{
	if (b[-1]>0x10000)
		return 1;
	else
		return b[ (long long int)((b[-1] & 0xfffffff0) - 8)/8 ] & PREV_INUSE;
}


void delete()
{
	unsigned int idx, cforward = 0, cbackward = 0;

	printf("Book index: ");
	scanf("%u", &idx);
	if ((idx>=5) || (books[idx].book==NULL))
		puts("Invalid!");
	else
	{
		if (!checkbackward(books[idx].book))
			cbackward = 1;
		if (!checkforward(&books[idx].book[ (long long int)(books[idx].book[-1] & 0xfffffff0)/8 ]))
			cforward = 1;
		free(books[idx].book);
		if (!cbackward || !cforward)
		{
			books[idx].book = NULL;
		}
		books[idx].length = 0;
	}
}


int main()
{
	int option;

	init();

	puts("----------------------------------------------------------------------------------------");
	puts("| Heap consolidation can be used to overwrite data of another chunk                    |");
	puts("| This challenge require you to do forward and backward consolidation at the same time |");
	puts("----------------------------------------------------------------------------------------");

	while (1)
	{
		puts("1. Add book");
		puts("2. View book");
		puts("3. Edit book");
		puts("4. Delete book");
		puts("5. Exit");
		printf("> ");
		scanf("%d", &option);

		if (option==2)
			view();
		else if (option==4)
			delete();
		else if (option==3)
			edit();
		else if (option==1)
			add();
		else
			exit(0);
	}

	return 0;
}