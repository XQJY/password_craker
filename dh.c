//
// Created by scott on 19-5-13.
//

/* A simple client program for server.c

   To compile: gcc client.c -o client

   To run: start the server, then the client */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <math.h>
#include <netdb.h>
#include <unistd.h>

//Calculates g^b mod p
//Basis: (A*B mod p) = ((A mod P) * (B mod P)) mod P
int imod (int g ,int b, int p){

    int temp = g % p;
    int i;

    for (i = 1; i < b; i++) {
        temp = ((temp % p)*(g % p)) % p;
    }

    return temp;
}

int main(int argc, char ** argv)
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent * server;

    char buffer[256];
    char b_hex[3];
    int b;
    int g = 15;
    int p = 97;

    portno = 7800;

    FILE *fp;
    fp = popen("openssl sha256 dh.c", "r");
    if(fgets(buffer,sizeof(buffer),fp)==NULL){
      printf("Read sha of the dh.c Failed.");
    };
    pclose(fp);
    b_hex[0] = *(strstr(buffer, "= ") + 2);
    b_hex[1] = *(strstr(buffer, "= ") + 3);
    b_hex[2] = '\0';
    b = strtoll(b_hex, NULL, 16);
    printf("The b is chosen: %d\n",b);



    /* Translate host name into peer's IP address ;
     * This is name translation service by the operating system
     */
    server = gethostbyname("172.26.37.44");

    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    /* Building data structures for socket */

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    bcopy(server->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr, server->h_length);

    serv_addr.sin_port = htons(portno);

    /* Create TCP socket -- active open
    * Preliminary steps: Setup: creation of active open socket
    */

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(0);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR connecting");
        exit(0);
    }

    /* Do processing
    */

    // 1 Send the username

    printf("Sending username...\n");

    bzero(buffer, 256);

    strcpy(buffer,"junyiw7\n");

    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(0);
    }

    bzero(buffer, 256);

    n = read(sockfd, buffer, 255);

    if (n < 0)
    {
        perror("ERROR reading from socket");
        exit(0);
    }

    printf("%s", buffer);

    int gamodp = atoi(buffer);

    // 2 Send g^b mod p

    int gbmodp = imod(g, b, p);

    printf("Sending g^b mod p = %d .\n",gbmodp);

    bzero(buffer, 256);

    sprintf(buffer, "%d\n", gbmodp);

    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(0);
    }

    printf("%s\n", buffer);

    // 3 Send (g^b)^a mod p

    int gbamodp =  imod(gamodp, b, p);

    printf("Sending (g^b)^a mod p = %d .\n",gbamodp);

    bzero(buffer, 256);

    sprintf(buffer, "%d\n", gbamodp);

    n = write(sockfd, buffer, strlen(buffer));

    if (n < 0)
    {
        perror("ERROR writing to socket");
        exit(0);
    }

    bzero(buffer, 256);

    n = read(sockfd, buffer, 255);

    if (n < 0)
    {
        perror("ERROR reading from socket");
        exit(0);
    }

    printf("%s\n", buffer);

    return 0;
}