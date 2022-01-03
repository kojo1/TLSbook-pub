CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
TARGET   = genrsa

COMM_SOURCE = ../../common/main.c

INSTALL_DIR = /usr/local/
SOURCE   = ./genRsa.c

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

$(TARGET): $(SOURCE) $(S_VER) $(COMM_SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(LDFLAGS) '-DOPEN_MODE1="w+"' $(SOURCE) $(COMM_SOURCE)

clean: FORCE
	-rm -f *.o $(TARGET)

FORCE:
.PHONY: FORCE
