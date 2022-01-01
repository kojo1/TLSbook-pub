CC = gcc
#CC = clang
#SSL = OPENSSL
SSL = WOLFSSL
DEBUG= no
TARGET   = sha256

COMM_SOURCE = ../../common/main.c

INSTALL_DIR = /usr/local
SOURCE      = ./sha256.c
COMM_SOURCE = ../../common/main.c
OBJ         = $(SOURCE:.c=.o)
COMM_OBJ    = $(COMM_SOURCE:.c=.o)

ifeq ($(SSL),OPENSSL)
INCLUDE   = -I../../include
LDFLAGS   = -lcrypto -lssl
CFLAGS    = -g -Wall $(INCLUDE) -DSSL_SUCCESS=1 -DSSL_FAILURE=0
else
INCLUDE   = -I../../include -I$(INSTALL_DIR)/include/wolfssl -include options.h
LDFLAGS   = -lwolfssl
CFLAGS    = -g -Wall $(INCLUDE)
endif


all: $(TARGET)

$(TARGET): $(OBJ) $(COMM_OBJ)
	$(CC) $(COMM_OBJ) $(OBJ) -o $@ $(LDFLAGS)


clean: FORCE
	-rm -f *.o $(COMM_OBJ) $(OBJ) $(TARGET)

FORCE:
.PHONY: FORCE
