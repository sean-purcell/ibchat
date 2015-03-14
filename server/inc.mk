DIR=server
SERVERSOURCES+=$(patsubst %,$(DIR)/%,server_main.c chat_server.c client_handler.c)

