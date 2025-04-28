// udp_to_pinet_receiver.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdint.h>  // For uint32_t
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h> // for mkfifo

#define PORT 12345
#define DEVICE "/dev/pinet"
#define FIFO_PATH "/tmp/proxpipe"

int main() {
    // Setup syslog
    openlog("udp_to_pinet_receiver", LOG_PID | LOG_CONS, LOG_USER);

    // Create FIFO if it doesn't exist
    if (mkfifo(FIFO_PATH, 0666) != 0) {
        if (errno != EEXIST) {
            syslog(LOG_ERR, "Failed to create FIFO: %s", strerror(errno));
            closelog();
            return EXIT_FAILURE;
        }
    }

    // Open FIFO (retry until some reader opens it)
    int pipe_fd;
    while (1) {
        pipe_fd = open(FIFO_PATH, O_WRONLY);
        if (pipe_fd < 0) {
            syslog(LOG_ERR, "Waiting for reader to open FIFO: %s", strerror(errno));
            sleep(1); // Wait and retry
        } else {
            syslog(LOG_INFO, "FIFO opened for writing");
            break;
        }
    }

    // Setup UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        close(pipe_fd);
        closelog();
        exit(1);
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(pipe_fd);
        close(sockfd);
        closelog();
        exit(1);
    }

    // Open /dev/pinet
    int dev_fd = open(DEVICE, O_WRONLY);
    if (dev_fd < 0) {
        perror("open /dev/pinet");
        close(pipe_fd);
        close(sockfd);
        closelog();
        exit(1);
    }

    printf("Listening on UDP port %d...\n", PORT);

    uint8_t buffer[64];
    while (1) {
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            perror("recvfrom");
            break;
        }

        if (len >= sizeof(uint32_t)) {
            uint32_t num;
            memcpy(&num, buffer, sizeof(uint32_t));

            printf("Received value: %d (writing to /dev/pinet and FIFO)\n", num);

            // Write to /dev/pinet
            ssize_t written = write(dev_fd, &num, sizeof(num));
            if (written != sizeof(num)) {
                perror("write to /dev/pinet");
            }

            // Also write to /tmp/proxpipe
            written = write(pipe_fd, &num, sizeof(num));
            if (written != sizeof(num)) {
                syslog(LOG_ERR, "Failed to write to FIFO: %s", strerror(errno));
            }
        } else {
            printf("Received too few bytes: %ld bytes\n", len);
        }
    }

    // Cleanup
    close(dev_fd);
    close(pipe_fd);
    close(sockfd);
    closelog();
    return 0;
}
