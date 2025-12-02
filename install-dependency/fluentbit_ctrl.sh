#!/bin/bash

#########################################
#fluent-bit 控制脚本, start/stop/install/uninstall/status/help
#fluent-bit 依赖kafak 服务, 需要kafka 服务启动后，方可运行fluent-bit .
#########################################
. scripts/common.sh

## fluent-bit 配置 ####
prism_dir="/etc/prism"
fluentbit="/usr/bin/fluent-bit"
fluentbit_conf_dir="/usr/local/etc/fluent-bit"
fluentbit_config_file="prism_fluent.conf"
kafka_dir="/opt/kafka"
kafka_port=9092

## kafka topic 配置##
partitions_num=6
topic_flow="flow" 
topic_http="http"
topic_enginefind="EngineFind"
topic_enginecmd="EngineCmd"
topic_cmdresult="CmdResult"
topic_lists="${topic_flow} ${topic_http} ${topic_enginefind} \
    ${topic_enginecmd} ${topic_cmdresult}"





##########################
# redis 中增加命令集.
#
#########################
function redis_add_cmd()
{
    if [ -x ./scripts/process_file.sh ];then
        cd ./scripts/
        if [ -f ./systemcmdfile ];then
            ./process_file.sh systemcmdfile >/dev/null  2>&1 
        fi
        if [ -f ./enginecmdfile ];then
            ./process_file.sh enginecmdfile >/dev/null 2>&1 
        fi
        cd -
    fi
}


##########################
# fluent-bit 初始化topic
# 包括：
# 1、将engineid 发送给 EngineFInd , 用于首次服务发现
# 2、创建 六种 topic
# 3、设置topic 数据存储时长.
#########################
function topic_init()
{
    chmod +x scripts/*.sh 
    #kafka 状态.
    kafka_status
    local ret=$?
    if [ $ret -eq 2 ];then
        # 向 topic EngineFind 注册enginid ，用于首次服务发现.
        # 后继由 fluent-bit 每5分钟发送一次到 EngineFind..
        echo "register_topic_engineid"
        register_topic_engineid
    else
        echo "topic_init kafka is not running ..."
        exit 1
    fi
}



######################
# fluent-bit 删除topic
# 删除 六种 topic
######################
function local_topic_del()
{
    IFS=' ' read -r -a array <<< "${topic_lists}"
    for v in ${array[@]}; do
        if [ `kafka-topics.sh --bootstrap-server localhost:9092 --list|grep -w $v|grep -v grep` ];then
            del_topic ${v}
            echo "topic delete ${v}"
        fi
    done
    # 显示all topic
    #kafka-topics.sh --bootstrap-server localhost:9092 --list
}


###########################
# topic 创建.
# 当前创建 6种 topic.
# 该函数被移到kafka/kafka_ctrl.sh 中，fluentbit不需要改函数功能.
##########################
function local_topic_create()
{
    IFS=' ' read -r -a array <<< "${topic_lists}"
    for vs in ${array[@]};do
        if [ `kafka-topics.sh --bootstrap-server localhost:9092 --list|grep -w $vs|grep -v grep` ];then
            echo "topic ${vs} already existed "
        else
            if [ ${vs} == ${topic_flow}  ];then
                # topic  flow 创建flow 主题，和分配 5 个partitions .
                echo "local_topic_create ${vs} ${partitions_num}"
               kafka-topics.sh --bootstrap-server localhost:9092 --create --topic ${vs} --partitions ${partitions_num} --replication-factor 1 
            else
                make_topic ${vs}
            fi
            #echo "create topic $vs ok"
        fi
    done
}



#########################
# fluent-bit 安装.
#########################
function fluentbit_install()
{
    if [ -f ./fluent-bit ];then
        chmod +x ./fluent-bit
        cp -rf ./fluent-bit /usr/bin/
    else
        echo "fluentbit_install not find fluent-bit"
        exit -1
    fi
    if [ -f ./prism_fluent.conf ];then
        cp -rf ./prism_fluent.conf /etc/prism/
    else
        echo "fluentbit_install not find prism_fluent.conf"
        exit -1
    fi
    if [ -d ./scripts ];then
        cp -rf ./scripts /etc/prism/
    else
        echo "fluentbit_install not find scripts"
        exit -1
    fi
    if [ -d ./etc ];then
        cp -rf ./etc/fluent-bit /usr/local/etc/
    else
        echo "fluentbit_install not find etc/fluent-bit"
        exit -1
    fi
    echo "fluent-bit install ok "
}

#########################
# fluent-bit 卸载.
#########################
function fluentbit_uninstall()
{
    if [ -f ${fluentbit} ];then
        rm -rf ${fluentbit}
    fi
    if [ -f ${prism_dir}/${fluentbit_config_file} ];then
        rm -rf ${prism_dir}/${fluentbit_config_file} 
    fi
    if [ -d ${prism_dir}/scripts ];then
        rm -rf ${prism_dir}/scripts
    fi
    if [ -d ${prism_dir}/redis_tools ];then
        rm -rf ${prism_dir}/redis_tools
    fi

    if [ -d /usr/local/etc/fluent-bit ];then
        rm -rf /usr/local/etc/fluent-bit
    fi
    echo "fluent-bit uninstall ok "
}



########################
# fluent-bit 关闭.
#######################
function fluentbit_stop()
{
    `pidof fluent-bit |xargs kill -9 >/dev/null 2>&1` 
}

# 检查EngineCmd topic 是否存在，如果不存在则创建topic.
function check_topic_EngineCmd
{
    local topicc_name="EngineCmd"
    local topicc=`kafka-topics.sh --bootstrap-server localhost:9092 --list |grep -w $topicc_name`
    if [ $topicc ];then
        :
    else
        make_topic $topicc_name
    fi
}

########################
# fluent-bit 开启.
#######################
function fluentbit_start()
{
    echo "redis add cmd ."
    redis_add_cmd
    #设置redis engineid
    scripts/set_engineid_msg.sh >/dev/null 2>&1
    # 检查EngineCmd topic 是否存在，如果不存在则创建topic.
    check_topic_EngineCmd
    if [ -x ${fluentbit} ];then
        cd ${prism_dir}
        if [ -f "./${fluentbit_config_file}" ];then
            nohup ${fluentbit} -q -c ${fluentbit_config_file} >/dev/null 2>&1 & 
            echo "fluentbit is start running ..."
        else
            echo "./${fluentbit_config_file} not find"
        fi
        cd - >/dev/null 2>&1
    else
        echo "${fluentbit} not find"
    fi
}


##########################
# fluent-bit 状态.
#
# NOTICE:
# fluent-bit 依赖kafka 服务，必须kafka 服务先启动后，fluent-bit 才启动.
#
##########################
function fluentbit_status()
{
    #判断kafka 服务状态.
    kafka_status
    local ret=$?
    if [ $ret -eq 2 ];then
        echo "kafka is running ..."
        if [ `pidof fluent-bit` ];then
            echo "fluent-bit is running ..."
        else
            echo "fluent-bit is not running ..."
        fi
    else
        echo "kafka is not running ..."
        echo "fluent-bit is not running ..."
    fi
}


##############
#FUNC:
#  kafka 获取状态.
#
#PARAM:
#  参数1 表示状态输出. 
#
#Notice:
#  kafka 启动后，会显示2个pid, 如果是1个pid ,则认为kafka没有完全启动.
#Return:
#  2 表示启动，1 表示仅启动一个进程, 0 表示close.
###############
function kafka_status()
{
    local ll=`prog_status kafka`    
    local out=$1
    if [ $ll ];then
        show_list $ll
        res=$?
        if [ $res -eq 2 ];then
            if [ $out ] && [ $out -eq 1 ];then
                echo "kafka is running ..." 
            fi
            return 2
        else
            if [ $out ] && [ $out -eq 1 ];then
                echo "kafka current is stop, to 'kafka_ctrl.sh start' ..."
            fi
            return 1
        fi
    else
        if [ $out ] && [ $out -eq 1 ];then
            echo "kafka is stop..."
        fi
        return 0
    fi
}



function show_list()
{
    count=0
    lists=$1
    IFS=$','
    for i in $lists; do
        #echo "$i"
        count=$((count + 1)) 
    done
    return $count
}



########################
#仅仅过滤 kafka 中 server.properties 和 zookeeper.properties 这2个进程.
#
#######################
function prog_status()
{
    prog=$1
    #pids=`ps -ef|grep -w $prog|grep -v grep|awk '{print $2}'`
    pids=`ps -ef|grep -w $prog|grep -v grep| grep -P "server.properties|zookeeper.properties" |awk '{print $2}'`
    echo "${pids}" |tr "\n" ","|sed -e 's/,$/\n/'
}


##############
# 设置环境变量.
#############
function set_path_env()
{
    local flag=`cat /root/.bashrc |grep  "kafka"|grep "license"|grep "export" |grep -v grep|grep -v '\#'`
    if [ ${#flag} -lt 6 ];then
        echo 'export PATH=$PATH:/opt/kafka/bin/:/opt/license4.0/bin' >> /root/.bashrc
        source /root/.bashrc
    fi
}

function help(){
    if [ ${#} -ge 1 ];then 
        echo ${1}
    fi
    echo "ctrl fluent-bit Server"
    echo "usage:${0} [install|uninstall|start|stop|restart|status|showtopics]"
    exit -1
}

if [ ${#} -ge 1 ];then
    #set env
    set_path_env
    case ${1} in
        'install')
            fluentbit_install
            #添加 指令到redis .
            echo "redis add cmd ."
            redis_add_cmd
            #创建 topic 和设置属性.
            echo "topic init ."
            topic_init
            ;;
        'uninstall')
            fluentbit_stop
            sleep 1
            fluentbit_stop
            #删除所有 topic.
            echo "topic delete ..."
            local_topic_del
            fluentbit_uninstall
            ;;
        'restart')
            fluentbit_stop
            sleep 1
            fluentbit_stop
            fluentbit_start
            ;;
        'start')
            fluentbit_start
            ;;
        'stop')
            fluentbit_stop
            echo "fluent-bit is stop .."
            ;;
        'status')
            fluentbit_status 
            ;;
        'showtopics')
            kafka-topics.sh --bootstrap-server localhost:9092 --list
            echo "---   topic flow partitions:"
            kafka-topics.sh --describe --bootstrap-server localhost:9092 --topic flow
            ;;
        *)
            help
            ;;
    esac
else
    help 'choose param '
fi


