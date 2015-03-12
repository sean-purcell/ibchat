DIR=util
SERVERSOURCES+=$(patsubst %,$(DIR)/%,gen_key.c)
SOURCES+=$(patsubst %,$(DIR)/%,getpass.c)

