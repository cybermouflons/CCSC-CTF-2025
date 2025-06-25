#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void decode(char *enc, char *msg, char* key) {
	size_t len = strlen(enc);
	size_t keylen = strlen(key);
	for (size_t i = 0; i < len; i++) {
		msg[i] = enc[i] ^ key[i % keylen];
	}
	msg[len] = '\0';
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("[!] Usage: %s <key>\n", argv[0]);
		return 1;
	}
	
	char dynamic_key[] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x00};
	char encrypted_key[] = %ENCRYPTED_KEY%; //{ ... , 0x00};
	char decrypted_key[%ENCRYPTED_KEY_LEN%];
	char encrypted_flag[] = %ENCRYPTED_FLAG%; //{ ... , 0x00};
	char decrypted_flag[%ENCRYPTED_FLAG_LEN%];

	size_t len = strlen(argv[1]);
	if (len < 5) {
		printf("[!] Input key is too small\n");
		return 0;
	}
	for (int i = 0; i < len; i = i + 5) {
		decode(dynamic_key, dynamic_key, argv[1] + i);	
	}
	decode(encrypted_key, decrypted_key, dynamic_key);
	
	printf("[.] Decrypting ...\n");
	decode(encrypted_flag, decrypted_flag, decrypted_key);
	printf("[.] Here is your flag: %s\n", decrypted_flag);

	return 0;
}
