#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <assert.h>
#include <unistd.h>

// #define ENABLE_LOGGING

#ifdef ENABLE_LOGGING
  // If ENABLE_LOGGING is defined, LOG expands to a printf call.
  // The ##__VA_ARGS__ handles cases where no variable arguments are provided,
  // preventing a trailing comma issue (common extension).
  #define LOG(format, ...) printf(format, ##__VA_ARGS__)
#else
  // If ENABLE_LOGGING is not defined, LOG expands to a do-nothing statement.
  // Using do {} while(0) ensures it acts like a single statement and avoids
  // potential syntax issues (e.g., in if/else blocks without braces).
  #define LOG(format, ...) do { } while(0)
#endif


#define MEMORY_SIZE (2 * 1024 * 1024) // 2 MB
uint8_t * memory;
size_t current_used_memory;
struct MainStruct;

typedef struct Callbacks {
    void * initMemory;
    void * cleanMemory;
} Callbacks;

Callbacks callbacks;

typedef struct BStruct {
    Callbacks * memoryCallbacks;
    uint32_t STATUS_OK;
    uint32_t STATUS_ERROR;
    uint64_t should_run;
    void (* callback)(struct MainStruct *);
} BStruct;


typedef struct MainStruct {

    uint8_t input[0x100];
    BStruct * bstruct;
    uint8_t deadbeef[0x3000];

} MainStruct;


/* Apply the constructor attribute so that it is executed before main() */
void initMemory(void) __attribute__ ((constructor));
/* Apply the destructor attribute to cleanupFunction() so that it is executed after main() */
void cleanupFunction(void) __attribute__ ((destructor));

void initMemory(void) {

    setvbuf(stdout, NULL, _IONBF, 0); 
    setvbuf(stderr, NULL, _IONBF, 0); 

    LOG("init code before main()\n");
    memory = mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    current_used_memory = 0;

    LOG("memory was allocated at %p\n", memory);
}

void cleanupFunction(void) {
    LOG("cleanup code after main()\n");
    munmap(memory, MEMORY_SIZE);
}


void * my_malloc(size_t size) {
    if (current_used_memory + size >= MEMORY_SIZE) {
        return NULL;
    }

    uint8_t * ptr = &memory[current_used_memory];
    current_used_memory += size;

    LOG("Allocating %zu bytes of memory at %p\n", size, ptr);

    return (void *)ptr;
}


/**
 * @brief Displays a menu with predefined options and gets the user's integer choice.
 *
 * Prints the following menu:
 * 1. Update your token
 * 2. Check authentication status
 * 3. Authenticate
 * 4. Exit
 *
 * Prompts the user to enter a choice and reads an integer.
 * Includes basic input validation to ensure an integer is entered.
 * Clears the input buffer after reading to prevent issues with subsequent inputs.
 *
 * @return The integer choice entered by the user. Returns -1 on input error
 * after multiple failed attempts (though the loop currently retries indefinitely).
 * Consider adding a maximum retry limit if needed.
 */
int display_menu_and_get_choice(void) {
    int choice = 0;
    int scanf_result = 0;

    // Print the menu options
    printf("\n--- Menu ---\n");
    printf("1. Update your token\n");
    printf("2. Check authentication status\n");
    printf("3. Authenticate\n");
    printf("4. Exit\n");
    printf("------------\n");

    // Loop until valid integer input is received
    while (1) {
        printf("Enter your choice (1-4): ");

        // Attempt to read an integer
        scanf_result = scanf("%d", &choice);

        // Check if scanf successfully read an integer
        if (scanf_result == 1) {
            // Clear the rest of the input buffer (up to newline or EOF)
            int c;
            while ((c = getchar()) != '\n' && c != EOF);

            // Optional: Validate if the choice is within the expected range (1-4)
            if (choice >= 1 && choice <= 4) {
                 return choice; // Return the valid choice
            } else {
                printf("Invalid choice. Please enter a number between 1 and 4.\n");
                continue;
            }
            // If not validating range here, just return the integer read
            return choice;

        } else {
            // Input was not a valid integer
            printf("Invalid input. Please enter a number.\n");
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue;

        }
    }
}

MainStruct * init() {

    my_malloc(0x40);

    BStruct * bstruct = (BStruct *)my_malloc(sizeof(BStruct));
    bstruct->memoryCallbacks = &callbacks;
    bstruct->STATUS_OK = 0x2000;
    bstruct->STATUS_ERROR = 0x3000;

    MainStruct * mainStruct = (MainStruct *)my_malloc(sizeof(MainStruct));
    mainStruct->bstruct = bstruct;

    return mainStruct;
}


void read_memory(uint8_t * buffer) {
    printf("Please enter your token: ");
    fflush(stdout);
    read(0, buffer, 0x120);
}


void check_auth(MainStruct * mainStruct) {

    uint32_t errorCode = mainStruct->bstruct->STATUS_ERROR;

    if (errorCode == 0x2000) {
        printf("You are authenticated\n");
    } else if (errorCode == 0x3000) {
        printf("There was an error\n");
    } else {
        printf("There was an unknown error of type %#x", errorCode);
    }
}


void authenticate(MainStruct * mainStruct) {

    BStruct * bstruct = mainStruct->bstruct;

    if (bstruct != NULL && bstruct->should_run && bstruct->callback != NULL) {
        bstruct->callback(mainStruct);
    }
}


int main(int argc, char ** argv) {

    MainStruct * mainStruct = init();

    int user_choice;

    do {
        user_choice = display_menu_and_get_choice();

        switch (user_choice) {
            case 1: {
                printf("\n-> Action: Updating token...\n");
                read_memory(mainStruct->input);
                break;
            }
            case 2:
                printf("\n-> Action: Checking authentication status...\n");
                // Add code to check status here
                check_auth(mainStruct);
                break;
            case 3:
                printf("\n-> Action: Authenticating...\n");
                authenticate(mainStruct);
                // Add code to authenticate here
                break;
            case 4:
                printf("\n-> Action: Exiting program.\n");
                break; // Exit the switch
            default:
                // This case handles integers outside 1-4 if range validation
                // is not done within display_menu_and_get_choice
                printf("\nInvalid choice [%d]. Please try again.\n", user_choice);
        }

    } while (user_choice != 4); // Loop until the user chooses to exit


    return 0;
}
