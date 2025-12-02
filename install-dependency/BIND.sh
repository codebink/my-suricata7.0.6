#!/bin/sh

# 子函数：执行所有操作
execute_tasks() {
    # 删除 suricata 进程的 PID 文件，防止上次异常终止的 PID 文件阻止本次进程启动
    rm -f /var/run/suricata.pid

    # 进入驱动模块目录并加载内核模块
    cd /lib/modules/prism_ko
    modprobe ixgbe
    modprobe ixgbe max_vfs=2,2
    modprobe uio
    insmod igb_uio.ko intr_mode=legacy
    insmod pf_ring.ko

    # 设置大页内存
    echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

    # 循环处理所有网卡接口
    for interface_name in "$@"; do
        # 将指定的网卡接口关闭
        ifconfig $interface_name down

        # 获取网卡的PCI地址
        local pci_addr=$(ethtool -i $interface_name | grep bus-info | awk '{print $2}')

        # 绑定网卡到 igb_uio 驱动
        dpdk-devbind.py --bind=igb_uio $pci_addr
    done
}

main() {
    # 检查脚本是否接收到至少一个参数
    if [ $# -lt 1 ]; then
        echo "用法: $0 <网卡名称1> <网卡名称2> ... <网卡名称N>"
        exit 1
    fi

    # 调用子函数并传递所有参数
    execute_tasks "$@"

    # 显示当前的设备绑定状态
    dpdk-devbind.py -s

    # 显示网络硬件信息
    # lshw -C network -businfo
}

# 调用主函数
main "$@"




