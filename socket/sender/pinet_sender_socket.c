#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#define DEST_PORT 12345
#define DEVICE "/dev/pinet"
#define BUF_SIZE 64

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <Destination_IP> <Interface_Name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *dest_ip = argv[1];
    const char *iface = argv[2];

    // Open character device for reading
    int dev_fd = open(DEVICE, O_RDONLY);
    if (dev_fd < 0) {
        perror("Failed to open /dev/pinet");
        exit(EXIT_FAILURE);
    }

    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        close(dev_fd);
        exit(EXIT_FAILURE);
    }

    // Bind socket to the specified interface
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0) {
        perror("setsockopt(SO_BINDTODEVICE)");
        close(sockfd);
        close(dev_fd);
        exit(EXIT_FAILURE);
    }

    // Set destination address
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DEST_PORT);
    if (inet_pton(AF_INET, dest_ip, &dest.sin_addr) <= 0) {
        perror("Invalid IP address");
        close(sockfd);
        close(dev_fd);
        exit(EXIT_FAILURE);
    }

    printf("Sender daemon started. Interface: %s, Destination: %s\n", iface, dest_ip);

    while (1) {
        char buffer[BUF_SIZE] = {0};

        ssize_t len = read(dev_fd, buffer, sizeof(buffer));
        if (len < 0) {
            perror("read from /dev/pinet");
            break;
        } else if (len == 0) {
            printf("char driver read() returned 0\n");
            usleep(10000);
            continue;
        }

        sendto(sockfd, buffer, len, 0, (struct sockaddr*)&dest, sizeof(dest));

        // Print payload as integer (assumes 4-byte int in network order)
        int value = 0;
        if (len >= 4) {
            memcpy(&value, buffer, 4);
            printf("Sent %ld bytes to %s:%d | Payload = %d\n", len, dest_ip, DEST_PORT, value);
        } else {
            printf("Sent %ld bytes to %s:%d | (Payload too short to parse as int)\n", len, dest_ip, DEST_PORT);
        }

    }

    close(sockfd);
    close(dev_fd);
    return 0;
}

