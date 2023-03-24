#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

#define PARTS_LEN 4
#define PARTS_COUNT 4

char slogan[] = "STANDING HERE, I REALIZE YOU ARE JUST LIKE ME, TRYING TO MAKE HISTORY. BUT WHO'S TO JUDGE THE RIGHT FROM WRONG? WHEN OUR GUARD IS DOWN, I THINK WE'LL BOTH AGREE THAT VIOLENCE BREEDS VIOLENCE. BUT IN THE END, IT HAS TO BE THIS WAY."; // just an easter egg :)

int encSerial[PARTS_COUNT * PARTS_LEN] = { 15045, 10184, 15551, 15132, 4470, 12015, 13811, 15857, 4387, 14257, 9156, 4736, 4986, 7872, 2274, 1959 };

int main(void) {
    char serial[100];
    printf("Please enter your serial code, son:\n");
    fgets(serial, 100, stdin);

    bool success = true;

    if (strlen(serial) == 20 && serial[4] == '-' && serial[9] == '-' && serial[14] == '-' && serial[19] == '\n') {
        char first_part[PARTS_LEN + 1];
        strncpy(first_part, serial, PARTS_LEN);
        first_part[PARTS_LEN] = '\0';

        char second_part[PARTS_LEN + 1];
        strncpy(second_part, serial + PARTS_LEN + 1, PARTS_LEN);
        second_part[PARTS_LEN] = '\0';

        char third_part[PARTS_LEN + 1];
        strncpy(third_part, serial + 2 * (PARTS_LEN + 1), PARTS_LEN);
        third_part[PARTS_LEN] = '\0';

        char fourth_part[PARTS_LEN + 1];
        strncpy(fourth_part, serial + 3 * (PARTS_LEN + 1), PARTS_LEN);
        fourth_part[PARTS_LEN] = '\0';

        char parts[PARTS_COUNT * PARTS_LEN + 1];
        strcpy(parts, first_part);
        strcat(parts, second_part);
        strcat(parts, third_part);
        strcat(parts, fourth_part);

        int processed[PARTS_COUNT * PARTS_LEN];
        int mod = PARTS_COUNT * PARTS_LEN;

        for (int i = 0; i < PARTS_COUNT * PARTS_LEN; i++) {
            char code = parts[i];
            int next_code = parts[(i + 1) % mod];
            int next_next_code = parts[(i + 2) % mod];

            processed[i] = 2 * code * code - 5 * next_code + 3 * next_next_code;
        }

        for (int i = 0; i < PARTS_COUNT * PARTS_LEN; i++) {
            if (processed[i] != encSerial[i]) {
                success = false;
                break;
            }
        }
    }
    else {
        success = false;
    }

    if (success) {
        printf("Serial code accepted. The firmware is now enabled.\n");
    }
    else {
        printf("You can't hurt this firmware, Jack.\n");
    }

    return 0;
}