DIR=inet
SOURCES+=$(patsubst %,$(DIR)/%,protocol.c connect.c message.c)

