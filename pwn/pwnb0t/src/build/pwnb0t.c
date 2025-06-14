#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int banner() {
    printf("+-----------------------------+\n");
    printf("|                             |\n");
    printf("|           _____             |\n");
    printf("|           |___|             |\n");
    printf("|           :$ $:             |\n");
    printf("|          _`~^~` _           |\n");
    printf("|        /'   ^   '\\          |\n");
    printf("|        PwnB0t 1024          |\n");
    printf("+-----------------------------+\n");

    printf("Data management - pwnB0t 1024\n");
    return 0;
}



// Read number - input
int read_num(){

  	int num;
  	char buf[32];
  	size_t size = sizeof(buf);
    
  	memset(buf, 0, size);
  	fgets(buf,31,stdin);
  	num = atoi(buf);
    
  	return num;

}

void VIP() {
// 4 1073742080
	int v1 = 0;
	int v2 = 0;
	puts("Welcome the VIP section!\nEnable VIP service via two number insertion");
	printf("First number: ");
	scanf("%d", &v1);
	getchar();
	printf("Second number: ");
	scanf("%d", &v2);
	getchar();
	if(v1 > 1 && v2 > 1024 && v1*v2 == 1024) {
		printf("VIP ID number: %p\n", &puts);
	}else {
		puts("We will contact soon..");
	}

}


int main(int argc, char *argv[]){

  	char* vals[20];
  	int index = 0;
	banner();
 	while (true) {
		puts("--------------------");
    		puts("1) Capture data chunk");
    		puts("2) Release data");
    		puts("3) Quit");
		puts("--------------------");
    		printf("\npwn@b0t:~$ ");
		fflush(stdout);
		int num = read_num();
    		switch(num) {
    			case 1:
      			printf("Size: ");
			fflush(stdout);
			if(index < 0x20){
      				int size = read_num();
				if(size < 1033){
      					char* point = malloc(size);
      					vals[index] = point;

      					if(vals[index] == (char *)0x0) {
        					puts("Request failed");
      					}
      					else {
        					printf("Data: ");
						fflush(stdout);
        					fgets(vals[index],0x10,stdin);
        					index++;
					}
				}
				else {
					puts("Size error");
				}
      			}	
			else {
				puts("Max number reached!");
				exit(1337);
			}
			break;

    			case 2:
      				printf("Index: ");
				fflush(stdout);
      				int s = read_num();
				if(vals[s] == (char *)0x0) {
                                	puts("Already released!");
                                }	
      				free(vals[s]);
				break;
			case 3:
				printf("Goodbye!\n");
				exit(1337);
    			case 256:
				VIP();
				break;
			default:
				printf("Invalid option!\n");
				break;
    		}
	}

 

  	return 0;

}
