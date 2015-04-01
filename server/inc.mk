DIR=server
FILTER=$(wildcard */*_test.c)
SERVERSOURCES+=$(filter-out $(FILTER),$(wildcard $(DIR)/*.c))

