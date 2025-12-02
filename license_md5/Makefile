CC      := gcc
CFLAGS  := -O0 -g
LDFLAGS := -shared -fpic
TARGET_STATIC := libprism_md5.a
TARGET_DYNAMIC := libprism_md5_d.so
BUILD_DIR := ./lib
INSTALL_PATH_FILE := record_path.txt
CLEAN_PATH_FILE := clean_path.txt

SOURCE := stegano.c encrypt.c ice.c compress.c encode.c
OBJS_STATIC := $(patsubst %.c, %.o, $(SOURCE))
OBJS_DYNAMIC := $(patsubst %.c, %.o, $(SOURCE))

# 默认目标
all: $(BUILD_DIR)/$(TARGET_STATIC) $(BUILD_DIR)/$(TARGET_DYNAMIC)

# 静态库目标
$(BUILD_DIR)/$(TARGET_STATIC): $(OBJS_STATIC)
	@mkdir -p $(BUILD_DIR)
	ar -r $@ $^

# 动态库目标
$(BUILD_DIR)/$(TARGET_DYNAMIC): $(OBJS_DYNAMIC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJS_DYNAMIC)

# 编译对象文件（静态库）
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

# 编译对象文件（动态库需要 -fPIC）
%.o: %.c
	$(CC) -c $(CFLAGS) -fPIC $< -o $@

# 记录安装路径
ifneq ($(prefix),)
	$(shell mkdir -p $(shell dirname $(INSTALL_PATH_FILE)))
	$(shell mkdir -p $(prefix))
	$(shell realpath $(prefix) > $(INSTALL_PATH_FILE))
	$(shell cp $(INSTALL_PATH_FILE) $(CLEAN_PATH_FILE))
endif

# 安装库文件到记录的路径
install:
	@if [ -f $(INSTALL_PATH_FILE) ]; then \
		INSTALL_PATH=$$(cat $(INSTALL_PATH_FILE)); \
		mkdir -p $$INSTALL_PATH; \
		cp $(BUILD_DIR)/$(TARGET_STATIC) $(BUILD_DIR)/$(TARGET_DYNAMIC) $$INSTALL_PATH; \
		echo "Installed to $$INSTALL_PATH"; \
	else \
		echo "No installation path recorded. Please run 'make prefix=./path/to/install' first."; \
	fi

# 清理构建文件
clean:
	rm -f *.o $(BUILD_DIR)/$(TARGET_STATIC) $(BUILD_DIR)/$(TARGET_DYNAMIC)
	@if [ -f $(INSTALL_PATH_FILE) ]; then \
		cp $(INSTALL_PATH_FILE) $(CLEAN_PATH_FILE); \
		rm -f $(INSTALL_PATH_FILE); \
		echo "Removed $(INSTALL_PATH_FILE) and saved to $(CLEAN_PATH_FILE)"; \
	else \
		echo "No install path file to clean."; \
	fi

# 清理安装路径中的库文件
clean_install:
	@if [ -f $(CLEAN_PATH_FILE) ]; then \
		make clean; \
		INSTALL_PATH=$$(cat $(CLEAN_PATH_FILE)); \
		rm -rf $$INSTALL_PATH/$(TARGET_STATIC) $$INSTALL_PATH/$(TARGET_DYNAMIC); \
		rm -f $(CLEAN_PATH_FILE); \
		echo "Removed installed files from $$INSTALL_PATH and deleted $(CLEAN_PATH_FILE)"; \
	else \
		echo "No recorded install path. Nothing to clean."; \
	fi



