DIR=client
FILTER=$(wildcard */*_test.c)
CLIENTSOURCES+=$(filter-out $(FILTER),$(wildcard $(DIR)/*.c)) $(DIR)/client_shake_test.c

