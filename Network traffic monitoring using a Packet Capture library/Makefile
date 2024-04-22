CC = gcc
CFLAGS = -Wall
LIBS = -lpcap

TARGET = pcap_ex

all: $(TARGET)

$(TARGET): pcap_ex.c
	$(CC) $(CFLAGS) -o $(TARGET) pcap_ex.c $(LIBS)

help:
	./$(TARGET) -h	

clean:
	rm -f $(TARGET)
