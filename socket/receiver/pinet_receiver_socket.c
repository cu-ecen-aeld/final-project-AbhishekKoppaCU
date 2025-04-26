// udp_to_pinet.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define PORT 12345
#define DEVICE "/dev/pinet"

int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); exit(1); }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }

    int dev_fd = open(DEVICE, O_WRONLY);
    if (dev_fd < 0) {
        perror("open /dev/pinet"); exit(1);
    }

    printf("Listening on UDP port %d...\n", PORT);

    char buf[128];
    while (1) {
        ssize_t len = recvfrom(sockfd, buf, sizeof(buf)-1, 0, NULL, NULL);
        if (len > 0) {
            //buf[len] = '\0';
            write(dev_fd, buf, len);  // write to your char driver
        }
    }

    close(dev_fd);
    close(sockfd);
    return 0;
}

