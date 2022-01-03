CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
TARGET   = aescbc

COMM_SOURCE = ../../common/main.c

INSTALL_DIR = /usr/local/
SOURCE_CBC   = ./aes-cbc.c
SOURCE_GCM   = ./aes-gcm.c


ifeq ($(SSL),OPENSSL)
INCLUDE   = -I../../include
LDFLAGS   = -lcrypto -lssl
CFLAGS    = -g -Wall $(INCLUDE)
else
INCLUDE   = -I../../include -I$(INSTALL_DIR)/include/wolfssl/ -include options.h
LDFLAGS   = -lwolfssl
CFLAGS    = -g -Wall $(INCLUDE)
endif

all: $(TARGET)

$(TARGET): $(SOURCE_CBC) $(SOURCE_GCM) $(COMM_SOURCE)
	$(CC) $(CFLAGS) -o aescbc $(LDFLAGS) $(COMM_SOURCE) $(SOURCE_CBC)
	$(CC) $(CFLAGS) -o aesgcm $(LDFLAGS) $(COMM_SOURCE) $(SOURCE_GCM)

clean: FORCE
	-rm -f *.o aescbc aesgcm

FORCE:
.PHONY: FORCE
