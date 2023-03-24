#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#define INPUT_SIZE 100

bool should_exit = false;

int main(void) {
    printf("PARROT SIMULATOR\n");
    while (!should_exit) {
        char input[INPUT_SIZE];
        printf("*The parrot stares at you, waiting for something*\n> ");
        fflush(stdout);
        fgets(input, INPUT_SIZE, stdin);
        printf(input);
    }
    return 0;
}

// add the needed gadgets for the execve syscall, to simplify the challenge
void s() {
    asm(
        ".intel_syntax noprefix;"
        "syscall;"
        "pop rdx;"
        "pop rax;"
        "ret;"
    );
}