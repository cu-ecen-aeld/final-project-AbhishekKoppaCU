# Makefile for pinet_sender_socket
CC = gcc
CFLAGS = -Wall -O2
TARGET = pinet_sender

all: $(TARGET)

$(TARGET): pinet_sender_socket.c
	$(CC) $(CFLAGS) -o $(TARGET) pinet_sender_socket.c

clean:
	rm -f $(TARGET)

