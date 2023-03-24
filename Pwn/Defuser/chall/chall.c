#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define ALLOC_MAX 7
#define TCACHE_MAX 1032
#define INPUT_LEN 14

int main(void) {
    void* allocated[ALLOC_MAX] = {0};
    int sizes[ALLOC_MAX] = {0};
    char rememberedName[INPUT_LEN] = {0};

    while (true) {
        printf("\n----- DEFUSER -----\n\n");
        char choice[INPUT_LEN];
        printf("1. Put a patch\n2. Edit a patch\n3. Remove a patch\n4. Greet me\n5. Exit the defuser\n> ");
        fflush(stdout);
        fgets(choice, INPUT_LEN, stdin);

        if (strcmp(choice, "1\n") == 0) {
            char slot[INPUT_LEN];
            printf("In what slot?\n> ");
            fflush(stdout);
            fgets(slot, INPUT_LEN, stdin);

            int slotInt = atoi(slot);
            if (slotInt <= 0 || slotInt > ALLOC_MAX) {
                printf("This slot is not in the allowed range (1 - %d)\n", ALLOC_MAX);
                continue;
            }

            slotInt--;

            char size[INPUT_LEN];
            printf("What size?\n> ");
            fflush(stdout);
            fgets(size, INPUT_LEN, stdin);

            int sizeInt = atoi(size);
            if (sizeInt <= 0 || sizeInt > TCACHE_MAX) {
                printf("This size is not in the allowed range (1 - %d)\n", TCACHE_MAX);
                continue;
            }

            allocated[slotInt] = malloc(sizeInt);
            sizes[slotInt] = sizeInt;
            printf("Patch created!\n");
            printf("Enter the payload to put in the patch\n> ");
            fflush(stdout);
            fgets(allocated[slotInt], sizeInt, stdin);
        }

        else if (strcmp(choice, "2\n") == 0) {
            char slot[INPUT_LEN];
            printf("In what slot?\n> ");
            fflush(stdout);
            fgets(slot, INPUT_LEN, stdin);

            int slotInt = atoi(slot);
            if (slotInt <= 0 || slotInt > ALLOC_MAX) {
                printf("This slot is not in the allowed range (1 - %d)\n", ALLOC_MAX);
                continue;
            }

            slotInt--;

            if (allocated[slotInt] == NULL) {
                printf("This slot has no patch yet\n");
                continue;
            }

            printf("Enter the payload to put in the patch\n> ");
            fflush(stdout);
            fgets(allocated[slotInt], sizes[slotInt], stdin);

            printf("Patch edited!\n");
        }

        else if (strcmp(choice, "3\n") == 0) {
            char slot[INPUT_LEN];
            printf("In what slot?\n> ");
            fflush(stdout);
            fgets(slot, INPUT_LEN, stdin);

            int slotInt = atoi(slot);
            if (slotInt <= 0 || slotInt > ALLOC_MAX) {
                printf("This slot is not in the allowed range (1 - %d)\n", ALLOC_MAX);
                continue;
            }

            slotInt--;

            free(allocated[slotInt]);
            printf("Patch removed!\n");
        }

        else if (strcmp(choice, "4\n") == 0) {
            if (strlen(rememberedName) > 0) {
                printf("I remember you, ");
                printf(rememberedName);
                continue;
            }

            printf("What's your name, dear defuser?\n> ");
            fflush(stdout);
            
            char name[INPUT_LEN];
            fgets(name, INPUT_LEN, stdin);

            if (strchr(name, 'n') != NULL) {
                printf("I don't like people with a n in their name :)\n");
                continue;
            }

            printf("I will remember you, ");
            printf(name);

            strncpy(rememberedName, name, INPUT_LEN);
        }

        else if (strcmp(choice, "5\n") == 0) {
            printf("You close the defuser and pray...\n");
            break;
        }

        else {
            printf("Invalid choice\n");
        }
    }

    return 0;
}