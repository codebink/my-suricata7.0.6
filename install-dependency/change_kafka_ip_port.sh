#!/bin/bash

# 子函数：替换配置文件中的 IP 和端口，保留注释
replace_config() {
    local config_file="/etc/prism/EngineMonitoring.sh"
    local ip_value=$1
    local port_value=$2

    # 检查配置文件是否存在
    if [ ! -f "$config_file" ]; then
        echo "Error: $config_file not found!"
        exit 1
    fi

    # 如果传入了 IP，替换 KAFKA_IP
    if [ -n "$ip_value" ]; then
        sed -i -E "s/^(KAFKA_IP[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\1\"$ip_value\"/" "$config_file"
        echo "KAFKA_IP updated to $ip_value in $config_file"
    fi

    # 如果传入了端口，替换 KAFKA_PORT
    if [ -n "$port_value" ]; then
        sed -i -E "s/^(KAFKA_PORT[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\1\"$port_value\"/" "$config_file"
        echo "KAFKA_PORT updated to $port_value in $config_file"
    fi
}

# 主函数
main() {
    local ip=""
    local port=""

    # 解析传入的参数
    for arg in "$@"; do
        case $arg in
            ip=*)
                ip="${arg#*=}"
                ;;
            port=*)
                port="${arg#*=}"
                ;;
            *)
                echo "Invalid argument: $arg"
                echo "Usage: $0 [ip=<new_ip>] [port=<new_port>]"
                echo "Example: $0 ip=192.168.1.101 port=9094"
                exit 1
                ;;
        esac
    done

    # 如果既没有 IP 也没有端口，给出提示并提供示例
    if [ -z "$ip" ] && [ -z "$port" ]; then
        echo "Error: You must provide at least one parameter (ip or port)"
        echo "Usage: $0 [ip=<new_ip>] [port=<new_port>]"
        echo "Example: $0 ip=192.168.1.101 port=9094"
        exit 1
    fi

    # 调用子函数进行替换
    replace_config "$ip" "$port"
}

# 调用主函数
main "$@"




