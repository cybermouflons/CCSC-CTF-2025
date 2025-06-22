#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

// --------------------------------------------------- SETUP

void init_buffering() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

// --------------------------------------------------- FUNCTIONS

void emergency_override() {
    printf("Emergency override activated. Escape pod launched!\n");
    system("/bin/cat flag.txt");
}

int main() {
    init_buffering();
	

    char param_buf[20];
    long target_addr;    
    char value[4];       
    int station_id = 101;

    puts("=== Space Station Control Panel ===");
    puts("Welcome. Adjust system parameters carefully.");
    printf("Station ID: %d\n", station_id); 

    puts("\nParameter value");
    read(0, value, 4); 

    puts("===============");

    puts("Target");
    read(0, param_buf, 9); 
    target_addr = atol(param_buf); 

    puts("===============");

    
    *(int*)target_addr = *(int*)value; 

    puts("Adjustment complete. System stable... hopefully.");
    exit(0);
}
