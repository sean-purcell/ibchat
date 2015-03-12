DIR=crypto
SOURCES+=$(patsubst %,$(DIR)/%,crypto_layer.c handshake.c keyfile.c)

