#!/bin/bash

# 子函数：替换 NIC_NAME 的值并保留注释
replace_nic_name() {
    local nic_name=$1
    local config_file="/etc/prism/EngineMonitoring.sh"

    # 检查配置文件是否存在
    if [ ! -f "$config_file" ]; then
        echo "Error: $config_file not found!"
        exit 1
    fi

    # 使用 sed 替换 NIC_NAME 值，保留注释
    sed -i -E "s/^(NIC_NAME[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\1\"$nic_name\"/" "$config_file"
    
    echo "NIC_NAME updated to $nic_name in $config_file, comment preserved"
}

# 主函数
main() {
    # 参数校验
    if [ $# -ne 1 ]; then
        echo "Usage: $0 <new_nic_name>"
        exit 1
    fi

    # 调用子函数进行替换
    replace_nic_name "$1"
}

# 调用主函数
main "$@"



