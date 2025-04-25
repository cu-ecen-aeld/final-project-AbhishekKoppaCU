#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define PINET_IOCTL_SEND_SENSOR_DATA _IOW('p', 1, int)

#define SENSOR_INTERVAL_MS 10

int main()
{
    int fd;
    int sensor_value = 10;

    fd = open("/dev/pinet", O_RDWR);
    if (fd < 0) {
        perror("open failed");
        return EXIT_FAILURE;
    }

    printf("Sending sensor value = 10 every %d ms using ioctl\n", SENSOR_INTERVAL_MS);

    while (1) {
        if (ioctl(fd, PINET_IOCTL_SEND_SENSOR_DATA, &sensor_value) == -1) {
            perror("ioctl failed");
        }
        usleep(SENSOR_INTERVAL_MS * 1000); // sleep 10ms
    }

    close(fd);
    return 0;
}
