#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void init() {
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

void send_log() {
    printf("Transmitting log... nominal.\n");
    exit(0);
}

void emergency_broadcast() {
    printf("EMERGENCY BROADCAST TRIGGERED. Accessing core systems...\n");
    system("/bin/sh"); 
}


struct transmitter {
    char data[24];
    void (*send)();  
};

int main() {
    init();
    

    
    char *log = malloc(24); 
    if (!log) {
        puts("Log allocation failed. Aborting.");
        exit(1);
    }


    struct transmitter *tx = malloc(32); 
    if (!tx) {
        puts("Transmitter allocation failed. Aborting.");
        exit(1);
    }
    
    
    memset(tx->data, 0, 24);
    tx->send = send_log;

    puts("=== Space Log Recorder ===");
    puts("Record your mission log.");

    
    printf("Enter log entry: ");
    read(0, log, 25); 
    

    size_t *metadata = (size_t *)((char *)tx - sizeof(size_t)); 
    size_t chunk_size = *metadata & ~0x7;

    
    printf("Enter data: ");
    read(0, tx->data, chunk_size - 18); 
     
    puts("Sending log...");
    tx->send();

    free(log);
    log = NULL;
    free(tx);
    tx = NULL;
    return 0;
}