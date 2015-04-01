DIR=crypto
FILTER=$(wildcard */*_test.c)
SOURCES+=$(filter-out $(FILTER),$(wildcard $(DIR)/*.c))

