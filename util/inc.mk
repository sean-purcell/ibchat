DIR=util
FILTER=$(wildcard */*_test.c) $(DIR)/gen_key.c
SERVERSOURCES+=$(DIR)/gen_key.c
SOURCES+=$(filter-out $(FILTER),$(wildcard $(DIR)/*.c))

