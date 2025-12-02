# Makefile for compiling license_tool and license_valid

CC := gcc
CFLAGS := -O0 -w -g
LIBS := -L/opt/license4.0/lib/ -lconfig -ludev -luuid -lprism_md5
SRC_DIR := .
BIN_DIR := ./bin
LIB_DIR := ./lib

all: create_dirs license_tool license_valid liblicense_valid.so liblicense_valid.a

create_dirs:
	mkdir -p $(BIN_DIR) $(LIB_DIR)

license_tool: $(SRC_DIR)/license_tool.c $(SRC_DIR)/system_info.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LIBS)
	@echo "Compiled $@"

license_valid: $(SRC_DIR)/license_valid_tool.c $(SRC_DIR)/system_info.c
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^ $(LIBS)
	@echo "Compiled $@"

liblicense_valid.so: $(SRC_DIR)/license_valid.c $(SRC_DIR)/system_info.c
	$(CC) $(CFLAGS) -fPIC -shared -o $(LIB_DIR)/$@ $^ $(LIBS)
	@echo "Created shared library $@"

liblicense_valid.a: license_valid.o system_info.o
	ar -r $(LIB_DIR)/$@ $^
	@echo "Created static library $@"

license_valid.o: $(SRC_DIR)/license_valid.c
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled $@"

system_info.o: $(SRC_DIR)/system_info.c
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled $@"

clean:
	rm -rf $(BIN_DIR)/* $(LIB_DIR)/* *.o
	@echo "Cleaned up binaries and libraries"


