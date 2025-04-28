// udp_to_pinet_receiver.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdint.h>  // For uint32_t

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

    uint8_t buffer[64];
    while (1) {
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            perror("recvfrom");
            break;
        }

        if (len >= sizeof(uint32_t)) { // Only handle 4 bytes (or more if future expands)
            uint32_t num;
            memcpy(&num, buffer, sizeof(uint32_t));

            // No ntohl() here because sender sends in *host byte order*
            // (your sending code doesn't do htonl before sendto)

            printf("Received value: %d (writing to /dev/pinet)\n", num);

            // Write exactly 4 bytes to /dev/pinet
            ssize_t written = write(dev_fd, &num, sizeof(num));
            if (written != sizeof(num)) {
                perror("write to /dev/pinet");
            }
        } else {
            printf("Received too few bytes: %ld bytes\n", len);
        }
    }

    close(dev_fd);
    close(sockfd);
    return 0;
}

