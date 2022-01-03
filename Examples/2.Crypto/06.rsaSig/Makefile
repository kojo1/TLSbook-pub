CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
TARGET   = rsa

COMM_SOURCE = ../../common/main.c

INSTALL_DIR = /usr/local/
S_SIG   = ./rsaSig.c
S_VER   = ./rsaVer.c

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

$(TARGET): $(S_SIG) $(S_VER) $(COMM_SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET)sig $(LDFLAGS) $(S_SIG) $(COMM_SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET)ver $(LDFLAGS) '-DOPEN_MODE2="rb"' $(S_VER) $(COMM_SOURCE)
clean: FORCE
	-rm -f *.o $(TARGET)

FORCE:
.PHONY: FORCE
