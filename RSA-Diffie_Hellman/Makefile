# Makefile for rsa_assign1.c and dh_assign_1.c

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall

# GMP library flag
LIBS = -lgmp

# Executable names
TARGETS = rsa_assign_1 dh_assign_1

# Source files
SRCS = rsa_assign_1.c dh_assign_1.c

# Object files
OBJS = $(SRCS:.c=.o)

all: $(TARGETS)

rsa_assign_1: rsa_assign_1.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

dh_assign_1: dh_assign_1.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGETS) $(OBJS)

.PHONY: all clean