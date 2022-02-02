#include <stdio.h>

void bar()
{
    printf(" World!\n");
}

void foo()
{
    printf("Hello,");
    bar();
}

int main()
{
    foo();
    return 0;
}