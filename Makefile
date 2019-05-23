BIN_DIR = bin
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wpedantic

all: mkbin import dh crack

dh: dh.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $<

crack: crack.c proj-2_sha256.o
	$(CC) $(CFLAGS) crack.c $(BIN_DIR)/proj-2_sha256.o -o $(BIN_DIR)/$@ 
 
%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $(BIN_DIR)/$@ $<
 
 proj-2_sha256: proj-2_sha256.c proj-2_sha256.h 

.PHONY: clean mkbin

clean:
	rm -rf $(BIN_DIR)

mkbin:
	mkdir -p bin

import:
	cp -p proj-2_common_passwords.txt $(BIN_DIR)/proj-2_common_passwords.txt
	cp -p dh.c $(BIN_DIR)/dh.c
	cp -p pwd6sha256 $(BIN_DIR)/pwd6sha256
	cp -p pwd4sha256 $(BIN_DIR)/pwd4sha256