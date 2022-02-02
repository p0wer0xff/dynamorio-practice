#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Argument missing\n");
        return 1;
    }
    if (strlen(argv[1]) != 4)
    {
        printf("Incorrect\n");
        return 1;
    }
    if (argv[1][0] == 'b')
    {
        if (argv[1][1] == 'a')
        {
            if (argv[1][2] == 'd')
            {
                if (argv[1][3] == '!')
                {
                    printf("Correct\n");
                    return 0;
                }
            }
        }
    }
    printf("Incorrect!\n");
    return 1;
}