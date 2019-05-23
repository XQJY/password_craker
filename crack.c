#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <sys/stat.h>
#include "proj-2_sha256.h"

#define  PASS_LENGTH 6

typedef struct {
    BYTE data[SHA256_BLOCK_SIZE];
    int index;
    int cracked;
} HASH;

struct node {
    BYTE b1;
    BYTE b2;
    struct node *next;
};

struct node *addNode(struct node *head, BYTE b1, BYTE b2) {
    struct node *current = head;
    //search if the node exists
    while (current != NULL) {
        if (current->b1 == b1 && current->b2 == b2) {
            return NULL;
        }
        current = current->next;
    }
    current = (struct node *) malloc(sizeof(struct node));
    current->b1 = b1;
    current->b2 = b2;
    current->next = head;
    return current;
}

void clearNodes(struct node *head) {
    struct node *current = head;
    while (current != NULL) {
        head = current->next;
        free(current);
        current = head;
    }
}

//check if a word is a digital or letter
int isDL(BYTE l) {
    if (l >= 48 && l <= 57) return 1;
    if (l >= 65 && l <= 90) return 1;
    if (l >= 97 && l <= 122) return 1;
    return 0;
}

//change the capitalisation
BYTE caps(BYTE l) {
    if (l >= 65 && l <= 90) return l + 32;
    if (l >= 97 && l <= 122) return l - 32;
    else return l;
}

//common substitution for a word
BYTE subs(BYTE l) {
    // a -> @
    if (l == 65 || l == 97) return 64;
    // b -> 8
    if (l == 66 || l == 98) return 56;
    // c -> (
    if (l == 67 || l == 99) return 40;
    // d -> 6
    if (l == 68 || l == 100) return 54;
    // e -> 3
    if (l == 69 || l == 101) return 51;
    // f -> #
    if (l == 70 || l == 102) return 35;
    // g -> 9
    if (l == 71 || l == 103) return 57;
    // h -> #
    if (l == 72 || l == 104) return 35;
    // i -> !
    if (l == 73 || l == 105) return 33;
    // k -> <
    if (l == 75 || l == 107) return 60;
    // l -> 1
    if (l == 76 || l == 108) return 49;
    // n -> ^
    if (l == 78 || l == 110) return 94;
    // o -> 0
    if (l == 79 || l == 111) return 48;
    // q -> 9
    if (l == 81 || l == 113) return 57;
    // s -> $
    if (l == 83 || l == 115) return 36;
    // t -> +
    if (l == 84 || l == 116) return 43;
    // v -> <
    if (l == 87 || l == 119) return 60;
    // x -> %
    if (l == 88 || l == 120) return 37;
    // y -> ?
    if (l == 89 || l == 121) return 63;
    return l;
}


void guess(HASH *dataset, BYTE attempt[], int start, int size) {
    int i;
    BYTE buf[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, attempt, strlen((const char*)attempt));
    sha256_final(&ctx, buf);

    for (i = start; i < size; i++) {
        if (!dataset[i].cracked) {
            if (!memcmp(dataset[i].data, buf, SHA256_BLOCK_SIZE)) {
                printf("%s %d\n", attempt, dataset[i].index);
                dataset[i].cracked = 1;
                break;
            }
        }
    }
}

int searchCompleted(HASH *dataset, int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (dataset[i].cracked == 0) return 0;
    }
    return 1;
}


void mode1() {
    int i, j, i1, i2, i3, i4, i5, i6;
    int secret_size = 30;
    BYTE buffer[20];
    HASH dataset[secret_size];
    struct node *head = NULL;
    struct node *curr = NULL;

    //import 2 hashsets
    FILE *fp = fopen("pwd4sha256", "rb");
    for (i = 0; i < 10; i++) {
        for (j = 0; j < SHA256_BLOCK_SIZE; j++) {
            dataset[i].data[j] = (BYTE) fgetc(fp);
        }
        dataset[i].index = i + 1;
        dataset[i].cracked = 0;
    }

    fclose(fp);

    fp = fopen("pwd6sha256", "rb");
    for (i = 10; i < 30; i++) {
        for (j = 0; j < SHA256_BLOCK_SIZE; j++) {
            dataset[i].data[j] = (BYTE) fgetc(fp);
        }
        dataset[i].index = i + 1;
        dataset[i].cracked = 0;
    }
    fclose(fp);

    // 1 Plain Dictionary Search & save first 2 letters
    fp = fopen("proj-2_common_passwords.txt", "r");
    while ((fgets((char*)buffer, 20, fp)) != NULL) {
        //convert \n to \0
        buffer[strlen((const char*)buffer) - 1] = '\0';
        //set the max length to 6
        buffer[6] = '\0';
        //only guess string length greater than 4
        if (strlen((const char*)buffer) >= 4) {
            curr = addNode(head, buffer[0], buffer[1]);
            if (curr != NULL) head = curr;
            guess(dataset, buffer, 0, secret_size);
        }
    }
    fclose(fp);

    // 2 Enhanced Dictionary attack for password of 4
    // Keep first 2 Character (Simple capitalisation/substitution are tried) and try letter & digits for the other 2 Character
    if (!searchCompleted(dataset, 10)) {
        BYTE temp;
        curr = head;
        //limit the max length to 4
        buffer[4] = '\0';
        //No worries about the list
        while (curr != NULL) {
            buffer[0] = curr->b1;
            buffer[1] = curr->b2;
            for (i3 = 48; i3 <= 122; i3++)
                for (i4 = 48; i4 <= 122; i4++) {
                    if (isDL(i3) && isDL(i4)) {
                        // Standard attempt
                        buffer[2] = i3;
                        buffer[3] = i4;
                        guess(dataset, buffer, 0, 10);
                        // Try Capitalising first letter
                        temp = buffer[0];
                        buffer[0] = caps(buffer[0]);
                        guess(dataset, buffer, 0, 10);
                        // Try Substituting first letter
                        buffer[0] = subs(temp);
                        guess(dataset, buffer, 0, 10);
                        // Try Substituting the second letter
                        buffer[0] = temp;
                        temp = buffer[1];
                        buffer[1] = subs(buffer[1]);
                        guess(dataset, buffer, 0, 10);
                        // Try Capitalising the second letter
                        buffer[1] = caps(temp);
                        guess(dataset, buffer, 0, 10);
                        // Restore
                        buffer[1] = temp;
                    }
                }
            curr = curr->next;
            if (searchCompleted(dataset, 10)) break;
        }
    }

    clearNodes(head);

    // 3 Exhaustive search for 4 letter words
    if (!searchCompleted(dataset, 10)) {
        //set the max length to 4
        buffer[4] = '\0';
        for (i1 = 32; i1 <= 126; i1++)
            for (i2 = 32; i2 <= 126; i2++)
                for (i3 = 32; i3 <= 126; i3++)
                    for (i4 = 32; i4 <= 126; i4++) {
                        buffer[0] = i1;
                        buffer[1] = i2;
                        buffer[2] = i3;
                        buffer[3] = i4;
                        guess(dataset, buffer, 0, 10);
                        if (searchCompleted(dataset, 10)) break;
                    }
    }

    // 4 Enhanced Dictionary attack for password of 6
    // Keep first 4 Character (Simple capitalisation/substitution are tried) and try every character for the other 2 Character
    if (!searchCompleted(dataset, 30)) {
        BYTE temp1;
        BYTE temp2;
        fp = fopen("proj-2_common_passwords.txt", "r");
        while ((fgets((char*)buffer, 20, fp)) != NULL) {
            //convert \n to \0
            buffer[strlen((const char*)buffer) - 1] = '\0';
            if (strlen((const char*)buffer) >= 4) {
                buffer[6] = '\0';
                for (i5 = 32; i5 <= 126; i5++)
                    for (i6 = 32; i6 <= 126; i6++) {
                        if (isDL(i5) && isDL(i6)) {
                            // Standard attempt
                            buffer[4] = i5;
                            buffer[5] = i6;
                            guess(dataset, buffer, 10, 30);
                            // Try Capitalising every letter
                            for (i = 0; i < 4; i++) {
                                temp1 = buffer[i];
                                buffer[i] = caps(temp1);
                                guess(dataset, buffer, 10, 30);
                                buffer[i] = temp1;
                            }
                            // Try Substituting every letter
                            for (i = 0; i < 4; i++) {
                                temp1 = buffer[i];
                                buffer[i] = subs(temp1);
                                guess(dataset, buffer, 10, 30);
                                buffer[i] = temp1;
                            }

                            // Try Capitalising the first letter & Substitute any letter
                            temp1 = buffer[0];
                            buffer[0] = caps(temp1);
                            for (i = 1; i < 4; i++) {
                                temp2 = buffer[i];
                                buffer[i] = subs(temp2);
                                guess(dataset, buffer, 10, 30);
                                buffer[i] = temp2;
                            }
                            buffer[0] = temp1;
                        }
                    }
            }
            if (searchCompleted(dataset, 30)) return;
        }
        fclose(fp);
    }

    // 5 Exhaustive search for 6 letter words, only search lower-case secrets
    if (!searchCompleted(dataset, 30)) {
        //Set the max length to 6
        buffer[6] = '\0';
        for (i1 = 97; i1 <= 122; i1++)
            for (i2 = 97; i2 <= 122; i2++)
                for (i3 = 97; i3 <= 122; i3++)
                    for (i4 = 97; i4 <= 122; i4++)
                        for (i5 = 97; i5 <= 122; i5++)
                            for (i6 = 97; i6 <= 122; i6++) {
                                buffer[0] = i1;
                                buffer[1] = i2;
                                buffer[2] = i3;
                                buffer[3] = i4;
                                buffer[4] = i5;
                                buffer[5] = i6;
                                guess(dataset, buffer, 10, 30);
                                if (searchCompleted(dataset, 30)) return;
                            }
    }

    // 6 Notice, we don't go through all tokens of 6, cuz it will take too much time
}

void mode2(char *nums) {
    int i, i1, i2, i3, i4, i5, i6;
    long count = 0;
    long max = atol(nums);
    BYTE buffer[20];
    struct node *head = NULL;
    struct node *curr = NULL;

    //Generate password length of 4
    //NOTICE: this generator may generate duplicate key, but don't affect the performance too much
    if (PASS_LENGTH == 4) {
        // 1 Plain Dictionary Search
        FILE *fp = fopen("proj-2_common_passwords.txt", "r");
        while ((fgets((char*)buffer, 20, fp)) != NULL && count < max) {
            //convert \n to \0
            buffer[strlen((const char*)buffer) - 1] = '\0';
            if (strlen((const char*)buffer) >= 4) {
                //set the max length to 4
                buffer[4] = '\0';
                curr = addNode(head, buffer[0], buffer[1]);
                if (curr != NULL) head = curr;
                if (strlen((const char*)buffer) >= 4 && buffer[3] != '\n') {
                    printf("%s\n", buffer);
                    count++;
                }
            }
        }
        fclose(fp);

        // 2 Enhanced Dictionary attack for password of 4
        // Keep first 2 Character (Simple capitalisation/substitution are tried) and try letter & digits for the other 2 Character
        BYTE temp;
        curr = head;
        //set the max length to 4
        buffer[4] = '\0';
        while (curr != NULL && count < max) {
            buffer[0] = curr->b1;
            buffer[1] = curr->b2;
            for (i3 = 48; i3 <= 126; i3++)
                for (i4 = 48; i4 <= 126; i4++) {
                    if (isDL(i3) && isDL(i4)) {
                        // Standard attempt
                        buffer[2] = i3;
                        buffer[3] = i4;
                        if (count < max) {
                            printf("%s\n", buffer);
                            count++;
                        } else return;
                        // Try Capitalising first letter
                        temp = buffer[0];
                        buffer[0] = caps(buffer[0]);
                        if (count < max) {
                            printf("%s\n", buffer);
                            count++;
                        } else return;
                        // Try Substituting first letter
                        buffer[0] = subs(temp);
                        if (count < max) {
                            printf("%s\n", buffer);
                            count++;
                        } else return;
                        // Try Substituting the second letter
                        buffer[0] = temp;
                        temp = buffer[1];
                        buffer[1] = subs(buffer[1]);
                        if (count < max) {
                            printf("%s\n", buffer);
                            count++;
                        } else return;
                        // Try Capitalising the second letter
                        buffer[1] = caps(temp);
                        if (count < max) {
                            printf("%s\n", buffer);
                            count++;
                        } else return;
                        // Restore
                        buffer[1] = temp;
                    }
                }
            curr = curr->next;
        }
        clearNodes(head);


        // 3 Exhaustive search for 4 letter words
        //set the max length to 4
        buffer[4] = '\0';
        for (i1 = 32; i1 <= 126; i1++)
            for (i2 = 32; i2 <= 126; i2++)
                for (i3 = 32; i3 <= 126; i3++)
                    for (i4 = 32; i4 <= 126; i4++) {
                        buffer[0] = i1;
                        buffer[1] = i2;
                        buffer[2] = i3;
                        buffer[3] = i4;
                        if (count < max) {
                            printf("%s\n", buffer);
                            count++;
                        } else return;
                    }
    }

    if (PASS_LENGTH == 6) {
        // 1 Plain Dictionary Search & save first 2 letters
        FILE *fp = fopen("proj-2_common_passwords.txt", "r");
        while ((fgets((char*)buffer, 20, fp)) != NULL && count < max) {
            //convert \n to \0
            buffer[strlen((const char*)buffer) - 1] = '\0';
            if (strlen((const char*)buffer) >= 6) {
                //set the max length to 6
                buffer[6] = '\0';
                printf("%s\n", buffer);
                count++;
            }
        }
        fclose(fp);
        
        // 2 Exhaustive search for 6 letter words, only search all digit secrets
        //set the max length to 6
        buffer[6] = '\0';
        for (i1 = 48; i1 <= 57; i1++)
            for (i2 = 48; i2 <= 57; i2++)
                for (i3 = 48; i3 <= 57; i3++)
                    for (i4 = 48; i4 <= 57; i4++)
                        for (i5 = 48; i5 <= 57; i5++)
                            for (i6 = 48; i6 <= 57; i6++) {
                                buffer[0] = i1;
                                buffer[1] = i2;
                                buffer[2] = i3;
                                buffer[3] = i4;
                                buffer[4] = i5;
                                buffer[5] = i6;
                                if (count < max) {
                                    printf("%s\n", buffer);
                                    count++;
                                } else return;
                            }
        
        // 3 Exhaustive search for 6 letter words, only search lower-case secrets
        //set the max length to 6
        buffer[6] = '\0';
        for (i1 = 97; i1 <= 122; i1++)
            for (i2 = 97; i2 <= 122; i2++)
                for (i3 = 97; i3 <= 122; i3++)
                    for (i4 = 97; i4 <= 122; i4++)
                        for (i5 = 97; i5 <= 122; i5++)
                            for (i6 = 97; i6 <= 122; i6++) {
                                buffer[0] = i1;
                                buffer[1] = i2;
                                buffer[2] = i3;
                                buffer[3] = i4;
                                buffer[4] = i5;
                                buffer[5] = i6;
                                if (count < max) {
                                    printf("%s\n", buffer);
                                    count++;
                                } else return;
                            }
        
        // 2 Enhanced Dictionary attack for password of 6
        // Keep first 4 Character (Simple capitalisation/substitution are tried) and try every character for the other 2 Character

        BYTE temp;
        BYTE temp2;
        fp = fopen("proj-2_common_passwords.txt", "r");
        while ((fgets((char*)buffer, 20, fp)) != NULL && count < max) {
            //convert \n to \0
            buffer[strlen((const char*)buffer) - 1] = '\0';
            if (strlen((const char*)buffer) >= 4) {
                //set the max length to 6
                buffer[6] = '\0';
                for (i5 = 32; i5 <= 126; i5++)
                    for (i6 = 32; i6 <= 126; i6++) {
                        if (isDL(i5) && isDL(i6)) {
                            // Standard attempt
                            buffer[4] = i5;
                            buffer[5] = i6;
                            if (count < max) {
                                printf("%s\n", buffer);
                                count++;
                            } else return;
                            // Try Capitalising every letter
                            for (i = 0; i < 4; i++) {
                                temp = buffer[i];
                                buffer[i] = caps(temp);
                                if (count < max) {
                                    printf("%s\n", buffer);
                                    count++;
                                } else return;
                                buffer[i] = temp;
                            }
                            // Try Substituting every letter
                            for (i = 0; i < 4; i++) {
                                temp = buffer[i];
                                buffer[i] = subs(temp);
                                if (count < max) {
                                    printf("%s\n", buffer);
                                    count++;
                                } else return;
                                buffer[i] = temp;
                            }

                            // Try Capitalising the first letter & Substitute any letter
                            temp = buffer[0];
                            buffer[0] = caps(temp);
                            for (i = 1; i < 4; i++) {
                                temp2 = buffer[i];
                                buffer[i] = subs(temp2);
                                if (count < max) {
                                    printf("%s\n", buffer);
                                    count++;
                                } else return;
                                buffer[i] = temp2;
                            }
                            buffer[0] = temp;
                        }
                    }
            }
        }
        fclose(fp);

        //Go through all tokens of 6, cuz it will take too much time
        //set the max length to 6
        buffer[6] = '\0';
        for (i1 = 32; i1 <= 126; i1++)
            for (i2 = 32; i2 <= 126; i2++)
                for (i3 = 32; i3 <= 126; i3++)
                    for (i4 = 32; i4 <= 126; i4++)
                        for (i5 = 32; i5 <= 126; i5++)
                            for (i6 = 32; i6 <= 126; i6++) {
                                buffer[0] = i1;
                                buffer[1] = i2;
                                buffer[2] = i3;
                                buffer[3] = i4;
                                buffer[4] = i5;
                                buffer[5] = i6;
                                if (count < max) {
                                    printf("%s\n", buffer);
                                    count++;
                                } else return;
                            }
    }
}

void mode3(char *passwords, char *hashes) {
    int i, j;
    int secret_size;
    BYTE buffer[20];

    //import hashes and calculate the secret size
    FILE *fp = fopen(hashes, "rb");
    struct stat st;
    stat(hashes, &st);
    secret_size = st.st_size / SHA256_BLOCK_SIZE;
    HASH dataset[secret_size];

    for (i = 0; i < secret_size; i++) {
        for (j = 0; j < SHA256_BLOCK_SIZE; j++) {
            dataset[i].data[j] = (BYTE) fgetc(fp);
        }
        dataset[i].index = i + 1;
        dataset[i].cracked = 0;
    }
    fclose(fp);

    //Check passwords
    fp = fopen(passwords, "r");
    while ((fgets((char*)buffer, 20, fp)) != NULL) {
        //convert \n to \0
        buffer[strlen((const char*)buffer) - 1] = '\0';
        guess(dataset, buffer, 0, secret_size);

    }
}

    int main(int argc, char *argv[]) {
        if (argc < 2) {
            mode1();
        } else if (argc < 3) {
            mode2(argv[1]);
        } else {
            mode3(argv[1], argv[2]);
        }
        return 0;
    }