.POSIX:
.SUFFIXES:
CC = gcc
CFLAGS =  -O3 -fPIC
LDFLAGS = -shared -lcrypto -lssl -ldl

lib: lib.c
	$(CC) -o libtlswrap.so $(CFLAGS) lib.c $(LDFLAGS)

clean:
	rm *.so
