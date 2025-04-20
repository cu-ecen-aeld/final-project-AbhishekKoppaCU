// udp_sender.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define DEST_IP "172.20.10.3"  // IP of RPi #2
#define DEST_PORT 12345

int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); exit(1); }

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DEST_PORT);
    inet_pton(AF_INET, DEST_IP, &dest.sin_addr);

    char msg[64];
    int counter = 0;

    while (1) {
        snprintf(msg, sizeof(msg), "sensor_data_%d", counter++);
        sendto(sockfd, msg, strlen(msg), 0, (struct sockaddr*)&dest, sizeof(dest));
        usleep(10000);  // 10ms = 10,000 µs
    }

    close(sockfd);
    return 0;
}

