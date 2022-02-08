#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

int main(int argc, char *argv[])
{
    FILE *file;
    char line[100];
    file = fopen("/proc/self/status", "r");
    if (file == NULL)
        return -1; /* Failure to open /proc/self/stat -- very unlikely */
    while (fgets(line, sizeof(line), file) != NULL)
    {
        char *tail;
        char *key;
        char *value;
        tail = strchr(line, '\n');
        if (tail != NULL)
            *tail = '\0'; /* remove the trailing '\n' */
        tail = strchr(line, ':');
        if (tail != NULL)
        {
            tail[0] = '\0';
            key = strdup(line);
            if (key == NULL)
                continue;
            tail += 1;
            while ((tail[0] != '\0') && (isspace((int)tail[0]) != 0))
                tail++;
            value = strdup(tail);
            if (value != NULL)
            {
                if (strcmp("SigCgt", key) == 0)
                {
                    if (strcmp("0000000000000000", value) == 0)
                    {
                        printf("Running normally\n");
                    }
                    else
                    {
                        printf("Running with DBI\n");
                    }
                }
                free(value);
            }
            free(key);
        }
    }
}