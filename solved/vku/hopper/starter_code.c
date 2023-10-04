#include <stdio.h>
#include <stdlib.h>

short hash(unsigned char * s){

	unsigned short h = 0;

	//TODO Complete me!

	return h;

}

int main(int argc, char * argv[]){

	for(int i =1;i<argc;i++)
		printf("hash(\"%s\")=0x%04hx\n",argv[1], hash(argv[i]));
}
