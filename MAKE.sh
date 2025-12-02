#!/bin/bash

THREADS_NUM="8"

# 定义压缩包密码
PASSWORD="prism@123"

# 定义输出压缩包名称
OUTPUT_ZIP="install.zip"

# 定义需要压缩的文件，使用相对路径而不是整个目录
FILES="./install.tgz ./install-dependency/install_engine.sh"

# 定义全局变量，表示 /opt/license4.0/lib 路径
LICENSE_PATH="/opt/license4.0/lib"

# 发布或罐装前打包，程序安装路径
BASE_PATH="$(pwd)/install"

# 规则路径
RULES_PATH="/var/lib/prism/rules"

# 配置路径
CONF_PATH="/etc/prism"

# PID 文件
PID_FILE="/var/run/prism.pid"

# log 目录
LOG_PATH="/var/log/prism/"

# 小流量测试机配置
MIN_CONF_PATH="./etc/release-min/"

# 大流量测试机配置
MAX_CONF_PATH="./etc/release-max/"

# 旧的 suricata 配置路径
OLD_CONF_PATH="/etc/suricata"

# 全局计时器
start_time=""

# 压缩函数
zip_files() {
    local password="$1"
    local output_zip="$2"
    shift 2
    local files="$@"

    # 使用 zip 命令打包并加密，-j 参数去掉路径信息，只打包文件
    zip -j -P "$password" "$output_zip" $files

    # 检查 zip 命令是否成功
    if [ $? -eq 0 ]; then
        echo "压缩成功，生成文件: $output_zip"
    else
        echo "压缩失败"
        return 1
    fi
}

creating_license_package() {
    # 删除旧的 license_so 目录
    rm -rf ./license_so* 1>/dev/null 2>&1

    # 创建新的 license_so 目录
    mkdir ./license_so

    # 复制 prism_lib64.conf 文件到 /etc/ld.so.conf.d/
    cp -f ./license_tools/ld_conf/prism_lib64.conf /etc/ld.so.conf.d/
    ldconfig

    # 编译并安装 license_md5
    cd license_md5
    make clean
    make prefix="$LICENSE_PATH"
    make install
    cd ..

    # 编译 license_tools
    cd license_tools
    make clean
    make

    # 复制相关文件到 $LICENSE_PATH 和 ../license_so 目录
    cp -f ./lib/liblicense_valid.so "$LICENSE_PATH"
    cp -f "$LICENSE_PATH/liblicense_valid.so" ../license_so
    cp -f "$LICENSE_PATH/libprism_md5_d.so" ../license_so
    cp -f license_template/license.cfg ../license_so
    cp -rf ./bin ../license_so
    cp -f ./ld_conf/prism_lib64.conf ../license_so
    cd ..

    # 创建压缩文件 license_so.tgz
    tar -zcvf license_so.tgz license_so
}

# 定义一个函数，结束脚本，计算编译耗时
finish() {
    end_time=$(date +%s)
    elapsed_time=$((end_time - start_time))
    
    # 将秒数转换为分钟和秒钟
    minutes=$((elapsed_time / 60))
    seconds=$((elapsed_time % 60))
	
    echo -e "---------------- 编译耗时: ${minutes}:${seconds} ----------------\n"
}

# 定义一个函数，将单个文件转换为 UTF-8 编码
convert_to_utf8() {
    local file="$1"
    # 将文件转换为 UTF-8 编码，并覆盖原文件
    iconv -f "$(file -bi "$file" | awk -F "=" '{print $2}')" -t utf-8 "$file" -o "$file.tmp" && mv "$file.tmp" "$file"
    echo "已将 $file 转换为 UTF-8"
}

# 定义一个函数，遍历当前目录及其子目录中的所有 .c、.h、.rs 文件，并转换编码
process_files() {
    find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.rs" \) | while read -r file; do
        convert_to_utf8 "$file"
    done
}

# 定义一个函数，将所有 .sh 脚本文件赋予 755 权限
set_sh_permissions() {
    find . -type f -name "*.sh" | while read -r script; do
        chmod 755 "$script"
        echo "已将 $script 设置为 755 权限"
    done
}

# 定义一个函数，显示当前内存使用情况
show_memory_usage() {
    echo "当前内存使用情况："
    free -h
}

# 定义一个函数，清理内存缓存
clear_memory_cache() {
    echo "清理内存缓存..."
    sync
    echo 3 > /proc/sys/vm/drop_caches
    echo "内存缓存已清理"
}

# 初始化函数
init() {
	local param=$1

	# 根据命令行判断编译方式
	case "$param" in
		release-min)
		;;
		release-min-asan)
		;;
		release-max)
		;;
		release-max-asan)
		;;
		debug)
		;;
		debug-asan)
		;;
		*)
		echo -e "Usage: $0 {release-min|release-min-asan|release-max|release-max-asan|debug|debug-asan}"
		exit 1
		;;
	esac

	# 编译计时开始
	start_time=$(date +%s)
	
	# 所有文件转换成 utf-8
	process_files

	# 所有 shell 脚本赋予可执行权限
	set_sh_permissions

    echo "--------------------清理 前 内存使用--------------------"
    show_memory_usage
	
	# 清理内存缓存
	clear_memory_cache

    echo "--------------------清理 后 内存使用--------------------"
    show_memory_usage
	
	sleep 5
	
	echo -e "-------- Start compiling --------\n"
	# 删除 suricata 进程的 PID 文件，防止上次异常终止的 PID 文件阻止本次进程启动
	rm -f ${PID_FILE}
	
	# 清理代码覆盖率中间文件和日志
	cd ./src
	rm -rf *.gcov test.info result *.gcda *.gcno
	cd ..

	# 清理旧日志
	rm -rf /SE/log/debug_log.txt 1>/dev/null 2>&1
	rm -rf ${LOG_PATH}* 1>/dev/null 2>&1

	# 删除旧的目标文件等
	make clean 1>/dev/null 2>&1

	# 同步所有文件时间为当前时间，防止编译不全
	find ./ * | xargs touch

	# 重新构建 Makefile
	autoreconf -ivf --warnings=all 1>/dev/null
	automake 1>/dev/null
	
	# 创建当前安装目录
	rm -rf ${BASE_PATH} 1>/dev/null 2>&1
	rm -rf ${BASE_PATH}.tgz 1>/dev/null 2>&1
	rm -rf ${BASE_PATH}.zip 1>/dev/null 2>&1
	mkdir ${BASE_PATH}
	
	# 创建必要的目录
	mkdir -p /var/log/prism 1>/dev/null 2>&1
	mkdir -p /var/run/prism 1>/dev/null 2>&1
	
	# 在初始化时创建 license 包，不用到处加代码
	creating_license_package
}

# release-max 编译
release-max() {
	echo -e "-------- Execute release-max compilation. --------\n"
	
	# 构建编译环境
	CFLAGS="-D_GNU_SOURCE" ./configure \
	--disable-gccmarch-native \
	--prefix=/usr/ \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-clang=/usr/bin/clang \
	--with-libevent \
	--enable-lua \
	--enable-geoip \
	--enable-rust \
	--enable-pfring \
	--enable-nfq \
	--enable-nfqueue \
	--enable-dpdk \
	--enable-hyperscan \
	--enable-ebpf \
	--enable-ebpf-build \
	--enable-hiredis

	# 删除旧的可执行文件
	rm -f /usr/bin/prism-engine 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginectl 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginesc 1>/dev/null 2>&1
	rm -f /usr/bin/prism-engine-update 1>/dev/null 2>&1
	
	# 删除旧的 yaml 文件
	rm -f ${CONF_PATH}/prism-ids.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ips.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ids-pcap.yaml 1>/dev/null 2>&1
	
	# 编译
	make -j ${THREADS_NUM}

	# 判断编译是否成功
	if [ $? -eq 0 ];then
		cp -d ./libhtp/htp/.libs/* /lib64
		make install 1>/dev/null
		make install-conf 1>/dev/null
		#make install-full 1>/dev/null		
		
		# 删除新生成的配置目录
		rm -rf ${OLD_CONF_PATH}
		
		# 拷贝配置文件和规则文件到安装包对应目录
		mkdir -p ${BASE_PATH}/usr/bin 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/usr/lib 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/etc/prism 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/rules 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/lib64 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/script 1>/dev/null 2>&1
		cp -f ./etc/classification.config ${BASE_PATH}/etc/prism
		cp -f ${MAX_CONF_PATH}prism-i* ${BASE_PATH}/etc/prism
		cp -f ./etc/threshold.config ${BASE_PATH}/etc/prism
		cp -f ./etc/reference.config ${BASE_PATH}/etc/prism
		cp -f ./rules/prism.rules ${BASE_PATH}/rules
		cp -d ./libhtp/htp/.libs/libhtp* ${BASE_PATH}/lib64
		cp -rf ./install-dependency/* ${BASE_PATH}/script
		rm -f ${BASE_PATH}/script/install_engine.sh
		rm -f ${BASE_PATH}/script/BIND.sh
		mv ${BASE_PATH}/script/BIND_MAX.sh ${BASE_PATH}/script/BIND.sh
		cp -f ./src/.libs/suricata ${BASE_PATH}/usr/bin/prism-engine
		cp -f /usr/bin/suricatactl ${BASE_PATH}/usr/bin/prism-enginectl
		cp -f /usr/bin/suricatasc ${BASE_PATH}/usr/bin/prism-enginesc
		cp -f /usr/bin/suricata-update ${BASE_PATH}/usr/bin/prism-engine-update
		cp -f /usr/lib/libhtp* ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/pkgconfig ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/suricata ${BASE_PATH}/usr/lib
		
		# 拷贝配置文件和规则
		mkdir -p ${CONF_PATH} 1>/dev/null 2>&1
		mkdir -p ${RULES_PATH}  1>/dev/null 2>&1		
		cp -f ./etc/classification.config ${CONF_PATH}
		cp -f ${MIN_CONF_PATH}prism-i* ${CONF_PATH}
		cp -f ./etc/threshold.config ${CONF_PATH}
		cp -f ./etc/reference.config ${CONF_PATH}
		cp -f ./rules/prism.rules ${RULES_PATH}
		cp -rf ./install-dependency/* ${CONF_PATH}
		rm -f ${CONF_PATH}/install_engine.sh
		
		# 最终使用的可执行文件名称
		mv /usr/bin/suricata /usr/bin/prism-engine
		mv /usr/bin/suricatactl /usr/bin/prism-enginectl
		mv /usr/bin/suricatasc /usr/bin/prism-enginesc
		mv /usr/bin/suricata-update /usr/bin/prism-engine-update
		
		# 压缩安装包
		tar -zcvf install.tgz ./install

		# 带密码压缩升级包
		zip_files "$PASSWORD" "$OUTPUT_ZIP" $FILES
		
		echo -e "\n------ The release-max version is compiled and installed successfully ------\n"
	else
		echo -e "\n------ The release-max version failed to compile !!! ------\n"
	fi
}

# release-max-asan 编译
release-max-asan() {
	echo -e "-------- Execute the release-max-asan compilation. --------\n"

	# ASAN 选项
	SANITIZE_FLAGS=" -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer -lasan"
	
	# 构建编译环境
	CFLAGS="-D_GNU_SOURCE" ./configure \
	--disable-gccmarch-native \
	--prefix=/usr/ \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-clang=/usr/bin/clang \
	--with-libevent \
	--enable-lua \
	--enable-geoip \
	--enable-rust \
	--enable-pfring \
	--enable-nfq \
	--enable-nfqueue \
	--enable-dpdk \
	--enable-hyperscan \
	--enable-ebpf \
	--enable-ebpf-build \
	--enable-hiredis

	# 主目录 Makefile 添加 ASAN 编译选项
	sed -i "/^GCC_CFLAGS/s|$| ${SANITIZE_FLAGS}|" ./Makefile

	# 源码 Makefile 添加 ASAN 编译选项
	sed -i "/^GCC_CFLAGS/s|$| ${SANITIZE_FLAGS}|" ./src/Makefile

	# 删除旧的可执行文件
	rm -f /usr/bin/prism-engine 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginectl 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginesc 1>/dev/null 2>&1
	rm -f /usr/bin/prism-engine-update 1>/dev/null 2>&1
	
	# 删除旧的 yaml 文件
	rm -f ${CONF_PATH}/prism-ids.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ips.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ids-pcap.yaml 1>/dev/null 2>&1
	
	# 编译
	make -j ${THREADS_NUM}

	# 删除编译过程中的 asan 日志
	rm -f /var/log/prism/*
	
	# 判断编译是否成功
	if [ $? -eq 0 ];then
		cp -d ./libhtp/htp/.libs/* /lib64
		make install 1>/dev/null
		make install-conf 1>/dev/null
		#make install-full 1>/dev/null

		# 删除新生成的配置目录
		rm -rf ${OLD_CONF_PATH}
		
		# 拷贝配置文件和规则文件到安装包对应目录
		mkdir -p ${BASE_PATH}/usr/bin 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/usr/lib 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/etc/prism 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/rules 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/lib64 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/script 1>/dev/null 2>&1
		cp -f ./etc/classification.config ${BASE_PATH}/etc/prism
		cp -f ${MAX_CONF_PATH}prism-i* ${BASE_PATH}/etc/prism
		cp -f ./etc/threshold.config ${BASE_PATH}/etc/prism
		cp -f ./etc/reference.config ${BASE_PATH}/etc/prism
		cp -f ./rules/prism.rules ${BASE_PATH}/rules
		cp -d ./libhtp/htp/.libs/libhtp* ${BASE_PATH}/lib64
		cp -rf ./install-dependency/* ${BASE_PATH}/script
		rm -f ${BASE_PATH}/script/install_engine.sh
		rm -f ${BASE_PATH}/script/BIND.sh
		mv ${BASE_PATH}/script/BIND_MAX.sh ${BASE_PATH}/script/BIND.sh
		cp -f ./src/.libs/suricata ${BASE_PATH}/usr/bin/prism-engine
		cp -f /usr/bin/suricatactl ${BASE_PATH}/usr/bin/prism-enginectl
		cp -f /usr/bin/suricatasc ${BASE_PATH}/usr/bin/prism-enginesc
		cp -f /usr/bin/suricata-update ${BASE_PATH}/usr/bin/prism-engine-update
		cp -f /usr/lib/libhtp* ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/pkgconfig ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/suricata ${BASE_PATH}/usr/lib
		
		# 拷贝配置文件和规则
		mkdir -p ${CONF_PATH} 1>/dev/null 2>&1
		mkdir -p ${RULES_PATH}  1>/dev/null 2>&1		
		cp -f ./etc/classification.config ${CONF_PATH}
		cp -f ${MIN_CONF_PATH}prism-i* ${CONF_PATH}
		cp -f ./etc/threshold.config ${CONF_PATH}
		cp -f ./etc/reference.config ${CONF_PATH}
		cp -f ./rules/prism.rules ${RULES_PATH}
		cp -rf ./install-dependency/* ${CONF_PATH}
		rm -f ${CONF_PATH}/install_engine.sh
		
		# 最终使用的可执行文件名称
		mv /usr/bin/suricata /usr/bin/prism-engine
		mv /usr/bin/suricatactl /usr/bin/prism-enginectl
		mv /usr/bin/suricatasc /usr/bin/prism-enginesc
		mv /usr/bin/suricata-update /usr/bin/prism-engine-update
		
		# 压缩安装包
		tar -zcvf install.tgz ./install

		# 带密码压缩升级包
		zip_files "$PASSWORD" "$OUTPUT_ZIP" $FILES
		
		echo -e "\n------ The release-max ASAN version is compiled and installed successfully ------\n"
	else
		echo -e "\n------ The release-max ASAN version failed to compile !!! ------\n"
	fi
}

# release-min 编译
release-min() {
	echo -e "-------- Execute release-min compilation. --------\n"
	
	# 构建编译环境
	CFLAGS="-D_GNU_SOURCE" ./configure \
	--disable-gccmarch-native \
	--prefix=/usr/ \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-clang=/usr/bin/clang \
	--with-libevent \
	--enable-lua \
	--enable-geoip \
	--enable-rust \
	--enable-pfring \
	--enable-nfq \
	--enable-nfqueue \
	--enable-dpdk \
	--enable-hyperscan \
	--enable-ebpf \
	--enable-ebpf-build \
	--enable-hiredis

	# 删除旧的可执行文件
	rm -f /usr/bin/prism-engine 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginectl 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginesc 1>/dev/null 2>&1
	rm -f /usr/bin/prism-engine-update 1>/dev/null 2>&1
	
	# 删除旧的 yaml 文件
	rm -f ${CONF_PATH}/prism-ids.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ips.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ids-pcap.yaml 1>/dev/null 2>&1
	
	# 编译
	make -j ${THREADS_NUM}

	# 判断编译是否成功
	if [ $? -eq 0 ];then
		cp -d ./libhtp/htp/.libs/* /lib64
		make install 1>/dev/null
		make install-conf 1>/dev/null
		#make install-full 1>/dev/null		
		
		# 删除新生成的配置目录
		rm -rf ${OLD_CONF_PATH}
		
		# 拷贝配置文件和规则文件到安装包对应目录
		mkdir -p ${BASE_PATH}/usr/bin 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/usr/lib 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/etc/prism 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/rules 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/lib64 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/script 1>/dev/null 2>&1
		cp -f ./etc/classification.config ${BASE_PATH}/etc/prism
		cp -f ${MIN_CONF_PATH}prism-i* ${BASE_PATH}/etc/prism
		cp -f ./etc/threshold.config ${BASE_PATH}/etc/prism
		cp -f ./etc/reference.config ${BASE_PATH}/etc/prism
		cp -f ./rules/prism.rules ${BASE_PATH}/rules
		cp -d ./libhtp/htp/.libs/libhtp* ${BASE_PATH}/lib64
		cp -rf ./install-dependency/* ${BASE_PATH}/script
		rm -f ${BASE_PATH}/script/install_engine.sh
		cp -f ./src/.libs/suricata ${BASE_PATH}/usr/bin/prism-engine
		cp -f /usr/bin/suricatactl ${BASE_PATH}/usr/bin/prism-enginectl
		cp -f /usr/bin/suricatasc ${BASE_PATH}/usr/bin/prism-enginesc
		cp -f /usr/bin/suricata-update ${BASE_PATH}/usr/bin/prism-engine-update
		cp -f /usr/lib/libhtp* ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/pkgconfig ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/suricata ${BASE_PATH}/usr/lib
		
		# 拷贝配置文件和规则
		mkdir -p ${CONF_PATH} 1>/dev/null 2>&1
		mkdir -p ${RULES_PATH}  1>/dev/null 2>&1		
		cp -f ./etc/classification.config ${CONF_PATH}
		cp -f ${MIN_CONF_PATH}prism-i* ${CONF_PATH}
		cp -f ./etc/threshold.config ${CONF_PATH}
		cp -f ./etc/reference.config ${CONF_PATH}
		cp -f ./rules/prism.rules ${RULES_PATH}
		cp -rf ./install-dependency/* ${CONF_PATH}
		rm -f ${CONF_PATH}/install_engine.sh
		
		# 最终使用的可执行文件名称
		mv /usr/bin/suricata /usr/bin/prism-engine
		mv /usr/bin/suricatactl /usr/bin/prism-enginectl
		mv /usr/bin/suricatasc /usr/bin/prism-enginesc
		mv /usr/bin/suricata-update /usr/bin/prism-engine-update
		
		# 压缩安装包
		tar -zcvf install.tgz ./install

		# 带密码压缩升级包
		zip_files "$PASSWORD" "$OUTPUT_ZIP" $FILES
		
		echo -e "\n------ The release-min version is compiled and installed successfully ------\n"
	else
		echo -e "\n------ The release-min version failed to compile !!! ------\n"
	fi
}

# release-min-asan 编译
release-min-asan() {
	echo -e "-------- Execute the release-min-asan compilation. --------\n"

	# ASAN 选项
	SANITIZE_FLAGS=" -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer -lasan"
	
	# 构建编译环境
	CFLAGS="-D_GNU_SOURCE" ./configure \
	--disable-gccmarch-native \
	--prefix=/usr/ \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-clang=/usr/bin/clang \
	--with-libevent \
	--enable-lua \
	--enable-geoip \
	--enable-rust \
	--enable-pfring \
	--enable-nfq \
	--enable-nfqueue \
	--enable-dpdk \
	--enable-hyperscan \
	--enable-ebpf \
	--enable-ebpf-build \
	--enable-hiredis

	# 主目录 Makefile 添加 ASAN 编译选项
	sed -i "/^GCC_CFLAGS/s|$| ${SANITIZE_FLAGS}|" ./Makefile

	# 源码 Makefile 添加 ASAN 编译选项
	sed -i "/^GCC_CFLAGS/s|$| ${SANITIZE_FLAGS}|" ./src/Makefile

	# 删除旧的可执行文件
	rm -f /usr/bin/prism-engine 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginectl 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginesc 1>/dev/null 2>&1
	rm -f /usr/bin/prism-engine-update 1>/dev/null 2>&1
	
	# 删除旧的 yaml 文件
	rm -f ${CONF_PATH}/prism-ids.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ips.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ids-pcap.yaml 1>/dev/null 2>&1
	
	# 编译
	make -j ${THREADS_NUM}

	# 删除编译过程中的 asan 日志
	rm -f /var/log/prism/*
	
	# 判断编译是否成功
	if [ $? -eq 0 ];then
		cp -d ./libhtp/htp/.libs/* /lib64
		make install 1>/dev/null
		make install-conf 1>/dev/null
		#make install-full 1>/dev/null

		# 删除新生成的配置目录
		rm -rf ${OLD_CONF_PATH}
		
		# 拷贝配置文件和规则文件到安装包对应目录
		mkdir -p ${BASE_PATH}/usr/bin 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/usr/lib 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/etc/prism 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/rules 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/lib64 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/script 1>/dev/null 2>&1
		cp -f ./etc/classification.config ${BASE_PATH}/etc/prism
		cp -f ${MIN_CONF_PATH}prism-i* ${BASE_PATH}/etc/prism
		cp -f ./etc/threshold.config ${BASE_PATH}/etc/prism
		cp -f ./etc/reference.config ${BASE_PATH}/etc/prism
		cp -f ./rules/prism.rules ${BASE_PATH}/rules
		cp -d ./libhtp/htp/.libs/libhtp* ${BASE_PATH}/lib64
		cp -rf ./install-dependency/* ${BASE_PATH}/script
		rm -f ${BASE_PATH}/script/install_engine.sh
		cp -f ./src/.libs/suricata ${BASE_PATH}/usr/bin/prism-engine
		cp -f /usr/bin/suricatactl ${BASE_PATH}/usr/bin/prism-enginectl
		cp -f /usr/bin/suricatasc ${BASE_PATH}/usr/bin/prism-enginesc
		cp -f /usr/bin/suricata-update ${BASE_PATH}/usr/bin/prism-engine-update
		cp -f /usr/lib/libhtp* ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/pkgconfig ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/suricata ${BASE_PATH}/usr/lib
		
		# 拷贝配置文件和规则
		mkdir -p ${CONF_PATH} 1>/dev/null 2>&1
		mkdir -p ${RULES_PATH}  1>/dev/null 2>&1		
		cp -f ./etc/classification.config ${CONF_PATH}
		cp -f ${MIN_CONF_PATH}prism-i* ${CONF_PATH}
		cp -f ./etc/threshold.config ${CONF_PATH}
		cp -f ./etc/reference.config ${CONF_PATH}
		cp -f ./rules/prism.rules ${RULES_PATH}
		cp -rf ./install-dependency/* ${CONF_PATH}
		rm -f ${CONF_PATH}/install_engine.sh
		
		# 最终使用的可执行文件名称
		mv /usr/bin/suricata /usr/bin/prism-engine
		mv /usr/bin/suricatactl /usr/bin/prism-enginectl
		mv /usr/bin/suricatasc /usr/bin/prism-enginesc
		mv /usr/bin/suricata-update /usr/bin/prism-engine-update
		
		# 压缩安装包
		tar -zcvf install.tgz ./install

		# 带密码压缩升级包
		zip_files "$PASSWORD" "$OUTPUT_ZIP" $FILES
		
		echo -e "\n------ The release-min ASAN version is compiled and installed successfully ------\n"
	else
		echo -e "\n------ The release-min ASAN version failed to compile !!! ------\n"
	fi
}

# debug 编译
debug() {
	echo -e "-------- Execute debug compilation. --------\n"

	# ASAN 选项
	SANITIZE_FLAGS="-fprofile-arcs -ftest-coverage -gdwarf-2 -lgcov -lpq -g3"
	
	# 复制一个 configure
	cp -f ./configure ./configure_debug
	
	# -g -O2 替换成 -g -O0
	sed -i "s/-g -O2/-g -O0/g" ./configure_debug
	
	# -O2 替换成 -g -O0
	sed -i "s/-O2/-g -O0/g" ./configure_debug
	
	# 构建编译环境
	CFLAGS="-D_GNU_SOURCE" ./configure_debug \
	--disable-gccmarch-native \
	--prefix=/usr/ \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-clang=/usr/bin/clang \
	--with-libevent \
	--enable-lua \
	--enable-geoip \
	--enable-rust \
	--enable-pfring \
	--enable-nfq \
	--enable-nfqueue \
	--enable-dpdk \
	--enable-profiling \
	--enable-debug \
	--enable-hyperscan \
	--enable-ebpf \
	--enable-ebpf-build \
	--enable-hiredis
	rm -f ./configure_debug
	
	# 主目录 ./Makefile 中的 -g -O2 替换成 -g -O0
	sed -i "s/-g -O2/-g -O0/g" ./Makefile
	
	# 源码 Makefile 中的 -g -O2 替换成 -g -O0
	sed -i "s/-g -O2/-g -O0/g" ./src/Makefile

	# 主目录 Makefile 添加 ASAN 编译选项
	sed -i "/^GCC_CFLAGS/s|$| ${SANITIZE_FLAGS}|" ./Makefile

	# 源码 Makefile 添加 ASAN 编译选项
	sed -i "/^GCC_CFLAGS/s|$| ${SANITIZE_FLAGS}|" ./src/Makefile

	# 删除旧的可执行文件
	rm -f /usr/bin/prism-engine 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginectl 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginesc 1>/dev/null 2>&1
	rm -f /usr/bin/prism-engine-update 1>/dev/null 2>&1
	
	# 删除旧的 yaml 文件
	rm -f ${CONF_PATH}/prism-ids.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ips.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ids-pcap.yaml 1>/dev/null 2>&1

	# 编译
	make -j ${THREADS_NUM}

	# 判断编译是否成功
	if [ $? -eq 0 ];then
		cp -d ./libhtp/htp/.libs/* /lib64
		make install
		make install-conf 
		#make install-full 

		# 删除新生成的配置目录
		rm -rf ${OLD_CONF_PATH}

		# 拷贝配置文件和规则文件到安装包对应目录
		mkdir -p ${BASE_PATH}/usr/bin 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/usr/lib 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/etc/prism 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/rules 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/lib64 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/script 1>/dev/null 2>&1
		cp -f ./etc/classification.config ${BASE_PATH}/etc/prism
		cp -f ${MIN_CONF_PATH}prism-i* ${BASE_PATH}/etc/prism
		cp -f ./etc/threshold.config ${BASE_PATH}/etc/prism
		cp -f ./etc/reference.config ${BASE_PATH}/etc/prism
		cp -f ./rules/prism.rules ${BASE_PATH}/rules
		cp -d ./libhtp/htp/.libs/libhtp* ${BASE_PATH}/lib64
		cp -rf ./install-dependency/* ${BASE_PATH}/script
		rm -f ${BASE_PATH}/script/install_engine.sh
		rm -f ${BASE_PATH}/script/BIND.sh
		mv ${BASE_PATH}/script/BIND_MAX.sh ${BASE_PATH}/script/BIND.sh
		cp -f ./src/.libs/suricata ${BASE_PATH}/usr/bin/prism-engine
		cp -f /usr/bin/suricatactl ${BASE_PATH}/usr/bin/prism-enginectl
		cp -f /usr/bin/suricatasc ${BASE_PATH}/usr/bin/prism-enginesc
		cp -f /usr/bin/suricata-update ${BASE_PATH}/usr/bin/prism-engine-update
		cp -f /usr/lib/libhtp* ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/pkgconfig ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/suricata ${BASE_PATH}/usr/lib
		
		# 拷贝配置文件和规则
		mkdir -p ${CONF_PATH} 1>/dev/null 2>&1
		mkdir -p ${RULES_PATH}  1>/dev/null 2>&1		
		cp -f ./etc/classification.config ${CONF_PATH}
		cp -f ${MIN_CONF_PATH}prism-i* ${CONF_PATH}
		cp -f ./etc/threshold.config ${CONF_PATH}
		cp -f ./etc/reference.config ${CONF_PATH}
		cp -f ./rules/prism.rules ${RULES_PATH}
		cp -rf ./install-dependency/* ${CONF_PATH}
		rm -f ${CONF_PATH}/install_engine.sh
		
		# 最终使用的可执行文件名称
		mv /usr/bin/suricata /usr/bin/prism-engine
		mv /usr/bin/suricatactl /usr/bin/prism-enginectl
		mv /usr/bin/suricatasc /usr/bin/prism-enginesc
		mv /usr/bin/suricata-update /usr/bin/prism-engine-update		

		# 压缩安装包
		tar -zcvf install.tgz ./install

		# 带密码压缩升级包
		zip_files "$PASSWORD" "$OUTPUT_ZIP" $FILES
		
		echo -e "\n------ The debug version is compiled and installed successfully ------\n"
	else
		echo -e "\n------ The debug version failed to compile !!! ------\n"
	fi
}

# debug-asan 编译
debug_asan() {
	echo -e "-------- Execute the debug-asan compilation. --------\n"

	# ASAN 选项
	SANITIZE_FLAGS="-fprofile-arcs -ftest-coverage -gdwarf-2 -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer -lasan -lgcov -lpq -g3"
	
	# 复制一个 configure
	cp -f ./configure ./configure_debug
	
	# -g -O2 替换成 -g -O0
	sed -i "s/-g -O2/-g -O0/g" ./configure_debug
	
	# -O2 替换成 -g -O0
	sed -i "s/-O2/-g -O0/g" ./configure_debug
	
	# 构建编译环境
	CFLAGS="-D_GNU_SOURCE" ./configure_debug \
	--disable-gccmarch-native \
	--prefix=/usr/ \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-clang=/usr/bin/clang \
	--with-libevent \
	--enable-lua \
	--enable-geoip \
	--enable-rust \
	--enable-pfring \
	--enable-nfq \
	--enable-nfqueue \
	--enable-dpdk \
	--enable-profiling \
	--enable-debug \
	--enable-hyperscan \
	--enable-ebpf \
	--enable-ebpf-build \
	--enable-hiredis
	rm -f ./configure_debug
	
	# 主目录 ./Makefile 中的 -g -O2 替换成 -g -O0
	sed -i "s/-g -O2/-g -O0/g" ./Makefile
	
	# 源码 Makefile 中的 -g -O2 替换成 -g -O0
	sed -i "s/-g -O2/-g -O0/g" ./src/Makefile

	# 主目录 Makefile 添加 ASAN 编译选项
	sed -i "/^GCC_CFLAGS/s|$| ${SANITIZE_FLAGS}|" ./Makefile

	# 源码 Makefile 添加 ASAN 编译选项
	sed -i "/^GCC_CFLAGS/s|$| ${SANITIZE_FLAGS}|" ./src/Makefile

	# 删除旧的可执行文件
	rm -f /usr/bin/prism-engine 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginectl 1>/dev/null 2>&1
	rm -f /usr/bin/prism-enginesc 1>/dev/null 2>&1
	rm -f /usr/bin/prism-engine-update 1>/dev/null 2>&1
	
	# 删除旧的 yaml 文件
	rm -f ${CONF_PATH}/prism-ids.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ips.yaml 1>/dev/null 2>&1
	rm -f ${CONF_PATH}/prism-ids-pcap.yaml 1>/dev/null 2>&1
	
	# 编译
	make -j ${THREADS_NUM}

	# 删除编译过程中的 asan 日志
	rm -f /var/log/prism/*
	
	# 判断编译是否成功
	if [ $? -eq 0 ];then
		cp -d ./libhtp/htp/.libs/* /lib64
		make install
		make install-conf 
		#make install-full 

		# 删除新生成的配置目录
		rm -rf ${OLD_CONF_PATH}

		# 拷贝配置文件和规则文件到安装包对应目录
		mkdir -p ${BASE_PATH}/usr/bin 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/usr/lib 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/etc/prism 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/rules 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/lib64 1>/dev/null 2>&1
		mkdir -p ${BASE_PATH}/script 1>/dev/null 2>&1
		cp -f ./etc/classification.config ${BASE_PATH}/etc/prism
		cp -f ${MIN_CONF_PATH}prism-i* ${BASE_PATH}/etc/prism
		cp -f ./etc/threshold.config ${BASE_PATH}/etc/prism
		cp -f ./etc/reference.config ${BASE_PATH}/etc/prism
		cp -f ./rules/prism.rules ${BASE_PATH}/rules
		cp -d ./libhtp/htp/.libs/libhtp* ${BASE_PATH}/lib64
		cp -rf ./install-dependency/* ${BASE_PATH}/script
		rm -f ${BASE_PATH}/script/install_engine.sh
		rm -f ${BASE_PATH}/script/BIND.sh
		mv ${BASE_PATH}/script/BIND_MAX.sh ${BASE_PATH}/script/BIND.sh
		cp -f ./src/.libs/suricata ${BASE_PATH}/usr/bin/prism-engine
		cp -f /usr/bin/suricatactl ${BASE_PATH}/usr/bin/prism-enginectl
		cp -f /usr/bin/suricatasc ${BASE_PATH}/usr/bin/prism-enginesc
		cp -f /usr/bin/suricata-update ${BASE_PATH}/usr/bin/prism-engine-update
		cp -f /usr/lib/libhtp* ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/pkgconfig ${BASE_PATH}/usr/lib
		cp -rf /usr/lib/suricata ${BASE_PATH}/usr/lib
		
		# 拷贝配置文件和规则
		mkdir -p ${CONF_PATH} 1>/dev/null 2>&1
		mkdir -p ${RULES_PATH}  1>/dev/null 2>&1		
		cp -f ./etc/classification.config ${CONF_PATH}
		cp -f ${MIN_CONF_PATH}prism-i* ${CONF_PATH}
		cp -f ./etc/threshold.config ${CONF_PATH}
		cp -f ./etc/reference.config ${CONF_PATH}
		cp -f ./rules/prism.rules ${RULES_PATH}
		cp -rf ./install-dependency/* ${CONF_PATH}
		rm -f ${CONF_PATH}/install_engine.sh
		
		# 最终使用的可执行文件名称
		mv /usr/bin/suricata /usr/bin/prism-engine
		mv /usr/bin/suricatactl /usr/bin/prism-enginectl
		mv /usr/bin/suricatasc /usr/bin/prism-enginesc
		mv /usr/bin/suricata-update /usr/bin/prism-engine-update

		# 压缩安装包
		tar -zcvf install.tgz ./install

		# 带密码压缩升级包
		zip_files "$PASSWORD" "$OUTPUT_ZIP" $FILES
		
		echo -e "\n------ The debug ASAN version is compiled and installed successfully ------\n"
	else
		echo -e "\n------ The debug ASAN version failed to compile !!! ------\n"
	fi
}


# 主函数
main() {
	local param=$1

	# 初始化
	init "$param"

	# 根据命令行判断编译方式
    case "$1" in
        release-min)
            release-min
            ;;
        release-min-asan)
            release-min-asan
            ;;
        release-max)
            release-max
            ;;
        release-max-asan)
            release-max-asan
            ;;
        debug)
            debug
            ;;
        debug-asan)
            debug_asan
            ;;
        *)
            echo -e "Parameter is not correct nothing is executed !"
            exit 1
            ;;
    esac
	
	# 统计编译耗时
	finish
}

# 调用主编译并传递所有脚本参数
main "$@"
