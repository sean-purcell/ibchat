DIR=inet
FILTER=$(wildcard */*_test.c)
SOURCES+=$(filter-out $(FILTER),$(wildcard $(DIR)/*.c))

