#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define DEST_PORT 12345  // Fixed port

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Destination_IP>\n", argv[0]);
        exit(1);
    }

    const char* dest_ip = argv[1];

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); exit(1); }

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DEST_PORT);
    if (inet_pton(AF_INET, dest_ip, &dest.sin_addr) <= 0) {
        perror("Invalid IP address"); exit(1);
    }

    char msg[64];
    int counter = 0;

    while (1) {
        snprintf(msg, sizeof(msg), "sensor_data_%d", counter++);
        sendto(sockfd, msg, strlen(msg), 0, (struct sockaddr*)&dest, sizeof(dest));
        usleep(10000);  // 10ms
    }

    close(sockfd);
    return 0;
}
