CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
TARGET   = rsa

COMM_SOURCE = ../../common/main.c

INSTALL_DIR = /usr/local/
S_ENC   = ./rsaEnc.c
S_DEC   = ./rsaDec.c

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

$(TARGET): $(S_ENC) $(S_DEC) $(COMM_SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET)enc $(LDFLAGS) $(S_ENC) $(COMM_SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET)dec $(LDFLAGS) $(S_DEC) $(COMM_SOURCE)
clean: FORCE
	-rm -f *.o $(TARGET)

FORCE:
.PHONY: FORCE
