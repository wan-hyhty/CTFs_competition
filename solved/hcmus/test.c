#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define ARG "cat /home/iflow/flag"
#define MAX 3

int main(short argc, char **argv)
{
        char *helper[] = {"strlen", "atoi", "printf", "puts"};
        void (*callable_funcs[])(char *) = {strlen, atoi, printf, puts};
        void (*uncallable_funcs[])(char *) = {system};
        short i, pos = 0;

        setresuid(geteuid(), geteuid(), geteuid());

        for (i = 1; i < argc; i++) {
                pos += strlen(argv[i]);
        }

        if (pos <= MAX) {
                (callable_funcs[MAX-1])("Calling ");
                (callable_funcs[MAX-1])(helper[pos]);
                (callable_funcs[MAX-1])(".\n");
                (callable_funcs[pos])(ARG);
        } else {
                (callable_funcs[MAX])("Out of bounds !\n");
        }

        return 0;
}