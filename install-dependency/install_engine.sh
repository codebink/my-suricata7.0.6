#!/bin/bash

# 规则路径
RULES_PATH="/var/lib/prism/rules"

# 配置路径
CONF_PATH="/etc/prism"

# PID 文件
PID_FILE="/var/run/prism.pid"

# lib64 目录
LIB64_PATH="/lib64"

# 安装程序文件
install_file() {
    echo -e "-------- Install the executable file. --------\n"

	# 删除 prism-engine 进程的 PID 文件，防止上次异常终止的 PID 文件阻止本次进程启动
	rm -f ${PID_FILE}
	
	# 解压安装包
	tar -zxvf ./install.tgz
	
	# 分发配置文件和规则
	mkdir -p ${CONF_PATH}
	mkdir -p ${RULES_PATH}
	cp -rf ./install/etc/prism/* ${CONF_PATH}
	cp -rf ./install/rules/* ${RULES_PATH}
	cp -rf ./install/etc/prism/classification.config ${RULES_PATH}
	cp -d ./install/lib64/* ${LIB64_PATH}
	cp -rf ./install/script/* ${CONF_PATH}
	chmod 755 ${CONF_PATH}/*
	
	# 分发程序
	chmod 755 ./install/usr/bin/*
	cp -rf ./install/usr/bin/* /usr/bin/

	# 分发 动态库等
	cp -rf ./install/usr/lib/* /usr/lib/
	
	# 创建必要的目录
	mkdir -p /var/log/prism 1>/dev/null 2>&1
	mkdir -p /var/run/prism 1>/dev/null 2>&1
	
	# 判断安装是否成功
	if [ $? -eq 0 ];then
		echo -e "\n------ The executable file is installed successfully ------\n"
	else
		echo -e "\n------ Failed to install the executable file !!! ------\n"
	fi
}


# 主函数
main() {
	# 安装可执行文件
	install_file

}

# 调用主编译并传递所有脚本参数
main "$@"
