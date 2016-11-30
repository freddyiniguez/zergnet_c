#include <stdio.h>
#include "zergnet.h"
 
 int encryption_with_public_key(char* msg){
	printf("Hello, encryption! %s", msg);
    return 20;
}


int decryption_with_private_key(char* msg){
    printf("Hello, decryption! %s", msg);
    return 20;
}
