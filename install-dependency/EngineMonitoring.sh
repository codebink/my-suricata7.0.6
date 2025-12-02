#!/bin/bash

# 定义日志文件、网络接口变量和进程名称宏
NIC_NAME="enp5s0f0" # 网络镜像接口名称，打包前需要根据硬件信息配置
KAFKA_IP="127.0.0.1" # kafka 需要的 IP
KAFKA_PORT="9092" # kafka 需要的 端口
KAFKA_CONF="/etc/prism/kafka.conf" # kafka 配置，里面有 IP
HOSTS_FILE="/etc/hosts"
SENSITIVE_CONF="/etc/prism/prism_sensitive_v1/sensitive.ini" # prism_sensitive_v1 配置，里面有 IP

# 高性能线程设置用到的动态库
#PRELOAD_STR="/usr/lib64/libtcmalloc_minimal.so.4"

# 带有 ASAN 的高性能线程设置用到的动态库
PRELOAD_STR="/usr/lib/gcc/x86_64-linux-gnu/10.3.1/libasan.so:/usr/lib64/libtcmalloc_minimal.so.4"

ENGINE_LOG="/var/log/prism/engine-init.log"
ENGINE_MONITORING_PROCESS="EngineMonitoring"  # EngineMonitoring 进程名称
PRISM_ENGINE_PROCESS="prism-engine"  # prism-engine 进程名称
KAFKA_CTRL="/etc/prism/kafka_ctrl.sh"  # kafka 控制脚本路径
FLUENTBIT_CTRL="/etc/prism/fluentbit_ctrl.sh"  # fluent-bit 控制脚本路径
SENSITIVE_V1="/etc/prism/prism_sensitive_v1/sensitive_server_v1.sh"  # prism_sensitive_v1 控制脚本路径

KAFKA2TIDB_PATH="/etc/prism/kafka2tidb/"  # kafka2tidb 路径
KAFKA2TIDB_CMD="kafka2tidb"  # kafka2tidb 可执行文件

PID_FILE="/var/run/prism.pid"
YAML_FILE="/etc/prism/prism-ids.yaml"
LOG_PATH="/var/log/prism"

LONG_SLEEP_NUM=5
SLEEP_NUM=60
MAX_RETRIES=3

# kafka 启动前，替换 locolhost 的 127.0.0.1 IP 为 KAFKA_IP
update_hosts() {
  # 1) 如果已经存在同 IP + 主机名，则不做任何修改
  if grep -Eq "^${KAFKA_IP}[[:space:]]+localhost[[:space:]]+localhost.localdomain[[:space:]]+localhost4[[:space:]]+localhost4.localdomain4\$" "$HOSTS_FILE"; then
	echo "Hosts file already contains '${KAFKA_IP}   localhost localhost.localdomain localhost4 localhost4.localdomain4'."
	return
  fi

  # 2) 否则，替换匹配:
  #   ^[^[:space:]]+	 -> 行首开始, 任意非空白字符(即任意IP或hostname) 
  #   [[:space:]]+	   -> 一个或多个空白符
  #   localhost localhost.localdomain localhost4 localhost4.localdomain4 -> 这组主机名
  #   $				  -> 行尾
  #
  # 用 sed 正则替换: 将任意 IP 部分改成 $KAFKA_IP, 其余主机名保持不动
  sudo sed -i -r \
	"s@^[^[:space:]]+[[:space:]]+localhost[[:space:]]+localhost.localdomain[[:space:]]+localhost4[[:space:]]+localhost4.localdomain4\$@${KAFKA_IP}   localhost localhost.localdomain localhost4 localhost4.localdomain4@" \
	"$HOSTS_FILE"

  echo "Done updating /etc/hosts (if matching line was found)."
}

# 检查是否已经有监控脚本在运行，或者有任意程序已经启动
check_process() {
	need_monitor=false

	# 检查是否已有同名脚本运行
	process_list=$(ps axj | grep EngineMonitoring.sh | grep -v grep)
	line_count=$(echo "$process_list" | wc -l)
	ppid1=$(echo "$process_list" | sed -n '1p' | awk '{print $1}')
	ppid2=$(echo "$process_list" | sed -n '2p' | awk '{print $1}')

	echo "$(date): 检查 EngineMonitoring.sh 是否已在运行，行数: $line_count, PPID1: $ppid1, PPID2: $ppid2" >> $ENGINE_LOG

	if [ "$line_count" -ge 2 ] && [ "$ppid1" -eq 1 ] && [ "$ppid2" -eq 1 ]; then
		echo -e "$(date): 已检测到 EngineMonitoring.sh 实例正在运行。退出。 \n$process_list \nPPIDs: $ppid1, $ppid2, $line_count\n" >> $ENGINE_LOG
		exit 1
	fi

	# 检查 PRISM_ENGINE_PROCESS
	if pgrep -f "$PRISM_ENGINE_PROCESS" > /dev/null; then
		echo "$(date): 检测到 PRISM_ENGINE_PROCESS 正在运行。" >> $ENGINE_LOG
		need_monitor=true
	else
		echo "$(date): PRISM_ENGINE_PROCESS 未运行。" >> $ENGINE_LOG
	fi

	# 检查 Kafka
	kafka_status=$($KAFKA_CTRL status)
	if echo "$kafka_status" | grep -q "running"; then
		echo "$(date): 检测到 Kafka 正在运行。" >> $ENGINE_LOG
		need_monitor=true
	else
		echo "$(date): Kafka 未运行。" >> $ENGINE_LOG
	fi

	# 检查 Sensitive
	sensitive_status=$($SENSITIVE_V1 status | grep running | wc -l)
	if [ "$sensitive_status" -eq 3 ]; then
		echo "$(date): 检测到 Sensitive 所有组件正常运行 ($sensitive_status/3)。" >> $ENGINE_LOG
		need_monitor=true
	else
		echo "$(date): Sensitive 组件不完整，当前运行数量：$sensitive_status。" >> $ENGINE_LOG
	fi

	# 如果任一进程存在，调用 monitor_processes 函数
	if [ "$need_monitor" = true ]; then
		echo "$(date): 检测到需要监控的进程，开始调用 monitor_processes 函数。" >> $ENGINE_LOG
		monitor_processes
	else
		echo "$(date): 未检测到需要监控的进程，无需启动监控。" >> $ENGINE_LOG
	fi
}



# 初始化所有组件
initialize_all() {
	# 检查是否已经有监控脚本在运行，或者有任意程序已经启动
	check_process

if true; then

	# 控制每个用户可以创建的 inotify 监视实例的最大数量
	sysctl -w fs.inotify.max_user_watches=524288

	# 创建必要的目录
	mkdir -p /var/log/prism 1>/dev/null 2>&1
	mkdir -p /var/run/prism 1>/dev/null 2>&1	
	
	# 删除 PID 文件，否则进程起不来
	rm -f $PID_FILE

	# 需要执行的脚本都赋给可执行权限
	chmod 755 /etc/prism/*

	# 本身进程未存在，就可以删除日志文件
	rm -f $ENGINE_LOG

	# 初始化日志文件
	mkdir -p /var/log/prism 1>/dev/null 2>&1
	echo -e "$(date): ----------- 引擎初始化 开始 -----------\n" > $ENGINE_LOG

	# 启动前，根据网卡名称获得 bus-info: 0000:00:08.0，然后替换 /etc/prism-ids.yaml 文件中的 interface: 0000:00:07.0 和 in-iface: "网卡名称"
	BUS_INFO=$(ethtool -i "$NIC_NAME" | grep bus-info | awk '{print $2}')

	# 确保获取到了总线信息
	if [ -z "$BUS_INFO" ]; then
		echo "$(date): $NIC_NAME 的 bus-info 信息获取失败，程序退出"
		exit 1
	fi

	# 更新 YAML 文件中的内容
	sed -i \
		-e "/PrismInput0/ {s/\(interface: \)[^ #]* \(#.*PrismInput0\)/\1$BUS_INFO \2/}" \
		-e "s/in-iface: .*/in-iface: $NIC_NAME/" \
		"$YAML_FILE"
	
	# 检查 NIC_NAME 是否已被 DPDK 绑定
	if ! dpdk-devbind.py -s | grep -q "$NIC_NAME"; then
		echo -e "$(date): $NIC_NAME 已绑定到 DPDK\n" >> $ENGINE_LOG
	else
		# 绑定 DPDK 网卡
		echo -e "$(date): 绑定 DPDK 网卡 $NIC_NAME\n" >> $ENGINE_LOG
		/etc/prism/BIND.sh $NIC_NAME
		sleep 2
		if ! dpdk-devbind.py -s | grep -q "$NIC_NAME"; then
			echo -e "$(date): $NIC_NAME 已绑定到 DPDK\n" >> $ENGINE_LOG
		else
			# 绑定 DPDK 网卡失败
			echo -e "$(date): 绑定 DPDK 网卡 $NIC_NAME 失败，程序退出\n" >> $ENGINE_LOG
			exit 1
		fi
	fi
	
	# 初始化 PRISM_ENGINE_PROCESS 进程，程序启动慢么不用等，在监控循环中检查是否启动成功
	echo -e "$(date): 初始化 $PRISM_ENGINE_PROCESS\n" >> $ENGINE_LOG
	LD_PRELOAD="${PRELOAD_STR}" $PRISM_ENGINE_PROCESS -c $YAML_FILE -l $LOG_PATH --dpdk -D

	# 使用更宽松的正则表达式匹配和替换 ip 行中的 IP 地址
	sed -i -E "s/^(ip[[:space:]]*=[[:space:]]*).*/\1${KAFKA_IP}/" "$KAFKA_CONF"

	# 使用更宽松的正则表达式匹配和替换 port 行中的 IP 地址
	sed -i -E "s/^(port[[:space:]]*=[[:space:]]*).*/\1${KAFKA_PORT}/" "$KAFKA_CONF"

	# 使用更宽松的正则表达式匹配和替换 kafkaip 行中的 IP 地址
	sed -i -E "s/^(kafkaip[[:space:]]*=[[:space:]]*).*/\1${KAFKA_IP}/" "$SENSITIVE_CONF"

	# 使用更宽松的正则表达式匹配和替换 dpip 行中的 IP 地址
	#sed -i -E "s/^(dpip[[:space:]]*=[[:space:]]*).*/\1${KAFKA_IP}/" "$SENSITIVE_CONF"

	# 使用更宽松的正则表达式匹配和替换 dlip 行中的 IP 地址
	#sed -i -E "s/^(dlip[[:space:]]*=[[:space:]]*).*/\1${KAFKA_IP}/" "$SENSITIVE_CONF"
	
	# kafka 启动前，替换 locolhost 的 127.0.0.1 IP 为 KAFKA_IP
	update_hosts
	
	# 启动 kafka
	chmod 755 ${KAFKA_CTRL}
	${KAFKA_CTRL} start
	
	# 等一会 kafka
	sleep $LONG_SLEEP_NUM
	
	# 启动 fluent-bit
	chmod 755 ${FLUENTBIT_CTRL}
	${FLUENTBIT_CTRL} start
	
	# 执行 kafka2tidb
	cd ${KAFKA2TIDB_PATH}
	chmod 755 ${KAFKA2TIDB_CMD}
	nohup ./${KAFKA2TIDB_CMD} -mysql 127.0.0.1:4000@root/prism@123  -kafka ${KAFKA_IP}:9092 &
	cd -
	
	# 启动 sensitive_server_v1
	cd /etc/prism/prism_sensitive_v1/
	./sensitive_server_v1.sh start
	sleep 180
	./sensitive_server_v1.sh engine_start
	cd -
	sleep 30

fi
	
	echo -e "$(date): ----------- 引擎初始化 完成 -----------\n" >> $ENGINE_LOG
}

# 监控并重启进程
monitor_processes() {
	local prism_retries=0
	local prism_failed_logged=0

	local kafka_retries=0	
	local kafka_failed_logged=0

	local fluentbit_retries=0	
	local fluentbit_failed_logged=0

	local sensitive_retries=0	
	local sensitive_failed_logged=0
	
	# 循环监控多个进程
	while true; do
		sleep $SLEEP_NUM
		
		
		#echo -e "$(date): ----------- 循环中 -----------\n" >> $ENGINE_LOG
if true; then

		# 检查 PRISM_ENGINE_PROCESS 进程是否存在
		if ! pgrep -f "$PRISM_ENGINE_PROCESS" > /dev/null; then
			if [ $prism_retries -lt $MAX_RETRIES ]; then
				# 删除 PID 文件，否则进程起不来
				rm -f $PID_FILE
			
				echo -e "$(date): $PRISM_ENGINE_PROCESS 进程未找到。正在重启...\n" >> $ENGINE_LOG
				LD_PRELOAD="${PRELOAD_STR}" $PRISM_ENGINE_PROCESS -c $YAML_FILE -l $LOG_PATH --dpdk -D
				prism_retries=$((prism_retries + 1))
			else
				if [ $prism_failed_logged -eq 0 ]; then
					echo -e "$(date): $PRISM_ENGINE_PROCESS 进程在 $MAX_RETRIES 次尝试后仍未启动成功。\n" >> $ENGINE_LOG
					prism_failed_logged=1
				fi
			fi
		else
			prism_retries=0
			prism_failed_logged=0
		fi

		# 检查 kafka 状态
		kafka_status=$($KAFKA_CTRL status)
		if ! echo "$kafka_status" | grep -q "running"; then
			if [ $kafka_retries -lt $MAX_RETRIES ]; then
				echo -e "$(date): kafka 停止了。正在重启...\n" >> $ENGINE_LOG
				$KAFKA_CTRL restart
				kafka_retries=$((kafka_retries + 1))
			else
				if [ $kafka_failed_logged -eq 0 ]; then
					echo -e "$(date): kafka 进程在 $MAX_RETRIES 次尝试后仍未启动成功。\n" >> $ENGINE_LOG
					kafka_failed_logged=1
				fi
			fi
		else
			kafka_retries=0
			kafka_failed_logged=0
		fi

		# 检查 fluent-bit 状态
		fluentbit_status=$($FLUENTBIT_CTRL status)
		if ! echo "$fluentbit_status" | grep -q "running"; then
			if [ $fluentbit_retries -lt $MAX_RETRIES ]; then
				echo -e "$(date): fluent-bit 停止了。正在重启...\n" >> $ENGINE_LOG
				$FLUENTBIT_CTRL restart
				fluentbit_retries=$((fluentbit_retries + 1))
			else
				if [ $fluentbit_failed_logged -eq 0 ]; then
					echo -e "$(date): fluent-bit 进程在 $MAX_RETRIES 次尝试后仍未启动成功。\n" >> $ENGINE_LOG
					fluentbit_failed_logged=1
				fi
			fi
		else
			fluentbit_retries=0
			fluentbit_failed_logged=0
		fi

		# 检查 sensitive_server_v1 状态
		sensitive_status=$($SENSITIVE_V1 status | grep running | wc -l)
		if [ "$sensitive_status" -lt 4 ]; then
			if [ $sensitive_retries -lt $MAX_RETRIES ]; then
				echo -e "$(date): sensitive 停止了。正在重启...\n" >> $ENGINE_LOG
				
				# 启动 sensitive_server_v1
				cd /etc/prism/prism_sensitive_v1/
				./sensitive_server_v1.sh restart
				sleep 180 
				./sensitive_server_v1.sh engine_restart
				cd -
				sleep 30
				sensitive_retries=$((sensitive_retries + 1))
			else
				if [ $sensitive_failed_logged -eq 0 ]; then
					echo -e "$(date): sensitive 进程在 $MAX_RETRIES 次尝试后仍未启动成功。\n" >> $ENGINE_LOG
					sensitive_failed_logged=1
				fi
			fi
		else
			sensitive_retries=0
			sensitive_failed_logged=0
		fi



fi



	done
}

main() {
	# 初始化所有组件
	initialize_all

	# 延时监控，防止其他进程启动慢，造成反复拉起
	sleep $LONG_SLEEP_NUM

	# 进入监控模式
	monitor_processes
}

# 调用主函数
main "$@" &

disown
