# Makefile for pinet_receiver_socket
CC = gcc
CFLAGS = -Wall -O2
TARGET = pinet_receiver

all: $(TARGET)

$(TARGET): pinet_receiver_socket.c
	$(CC) $(CFLAGS) -o $(TARGET) pinet_receiver_socket.c

clean:
	rm -f $(TARGET)

