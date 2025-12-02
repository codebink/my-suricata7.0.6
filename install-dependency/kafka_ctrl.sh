#!/bin/bash
#set -x
kafka_dir="/opt/kafka"
kafka_port=9092
kafka_conf="./kafka.conf"

## kafka topic 配置##
partitions_num=6
topic_flow="flow" 
topic_http="http"
topic_alert="alert"
topic_enginefind="EngineFind"
topic_enginecmd="EngineCmd"
topic_cmdresult="CmdResult"
topic_lists="${topic_flow} ${topic_http} ${topic_alert} \
    ${topic_enginefind} ${topic_enginecmd} ${topic_cmdresult}"
db_lists="mysql kingbase dmdb"
#敏感数据主题 prismdlp, 组prismdlp_group.
sensitive_data="prismdlp"

. scripts/common.sh
function replace_conf()
{
    local curip=""
    local curport=""
    local curhours=""
    
    while read -r vv; do
        local key=$(echo $vv|cut -d '=' -f1)
        local value=$(echo $vv|cut -d '=' -f2)
        if [ $key == 'ip' ];then
            curip=$value
        elif [ $key == 'port' ];then
            curport=$value
        elif [ $key == 'hours' ];then
            curhours=$value
        fi
    done < $kafka_conf
    echo "$curip $curport, $curhours"

    if [ -f  $kafka_dir/config/server.properties ] && [ ! -f $kafka_dir/config/server.properties-bak ];then
        cp $kafka_dir/config/server.properties $kafka_dir/config/server.properties-bak
    elif [ ! -f  $kafka_dir/config/server.properties ];then  
        echo " $kafka_dir/config/server.properties not find"
        exit -1
    fi

    local line_number=`grep -n 'log.retention.hours=' $kafka_dir/config/server.properties |grep -v '#' |awk -F: '{print $1}'|tr "\n" ","|sed -e 's/,$/\n/'`
    if [ $line_number -ge 1 ];then
        sed -i "$line_number s/.*/log.retention.hours=$curhours/" $kafka_dir/config/server.properties
    fi

    local line_number1=`grep -n 'listeners=PLAINTEXT' $kafka_dir/config/server.properties |grep -v '#' |awk -F: '{print $1}'|tr "\n" ","|sed -e 's/,$/\n/'`
    if [ !  $line_number1 ];then
        sed -i "$ a listeners=PLAINTEXT://:$curport" $kafka_dir/config/server.properties
    fi

    local line_number2=`grep -n 'advertised.listeners=PLAINTEXT' $kafka_dir/config/server.properties |grep -v '#' |awk -F: '{print $1}'|tr "\n" ","|sed -e 's/,$/\n/'`
    if [ ! $line_number2 ];then
        sed -i "$ a advertised.listeners=PLAINTEXT://$curip:$curport" $kafka_dir/config/server.properties
    fi
}

function kafka_install()
{
    if [ `rpm -qa|grep -i kafka` ];then
        echo "kafka already install ok"
    else
        yum -y install kafka
        if [ -d ${kafka_dir} ];then
            if [ -d ${kafka_dir}/config ];then
                replace_conf
            else
                echo "kafka config dir not find"
                exit -1
            fi
            echo "kafka install ok"
        fi
    fi
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


function show_list()
{
    count=0
    lists=$1
    IFS=$','
    for i in $lists; do
        echo "$i"
        count=$((count + 1)) 
    done
    return $count
}

function open_firewall()
{
    systemctl restart firewalld.service
    result=`firewall-cmd --query-port=$kafka_port/tcp`
    if [ $result = 'yes' ];then
        echo "open firewall $kafka_port ok"
    else
        firewall-cmd --permanent --add-port=$kafka_port/tcp
        firewall-cmd --reload
    fi
}

function force_kill()
{
    IFS=$','
    local ll=`prog_status kafka`    
    #if [ $ll ];then
        for i in $ll; do
            kill -9 $i
        done
    #fi
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

######################
# fluent-bit 删除topic
# 删除 5 种 topic
######################
function local_topic_del()
{
    #删除所有非数据库的topic.
    IFS=' ' read -r -a array <<< "${topic_lists}"
    for v in ${array[@]}; do
        if [ `kafka-topics.sh --bootstrap-server localhost:9092 --list|grep -w $v|grep -v grep` ];then
            kafka-topics.sh --bootstrap-server localhost:9092 --delete --topic ${v}
            echo "topic delete ${v}"
        fi
    done
    #删除所有数据库的topic.
    IFS=' ' read -r -a array <<< "${db_lists}"
    for v in ${array[@]}; do
        if [ `kafka-topics.sh --bootstrap-server localhost:9092 --list|grep -w $v|grep -v grep` ];then
            kafka-topics.sh --bootstrap-server localhost:9092 --delete --topic ${v}
            echo "topic delete ${v}"
        fi
    done
    #删除所有敏感数据的topic. prismdlp
    if [ `kafka-topics.sh --bootstrap-server localhost:9092 --list|grep -w ${sensitive_data}|grep -v grep` ];then
        kafka-topics.sh --bootstrap-server localhost:9092 --delete --topic ${sensitive_data}
        echo "topic delete ${sensitive_data}"
    fi

    #显示all topic
    #kafka-topics.sh --bootstrap-server localhost:9092 --list
}


###########################
# topic 创建.
# 当前创建 5种 topic.
# 
##########################
function local_topic_create()
{
    IFS=' ' read -r -a array <<< "${topic_lists}"
    for vs in ${array[@]};do
        if [ `kafka-topics.sh --bootstrap-server localhost:9092 --list|grep -w $vs|grep -v grep` ];then
            echo "topic ${vs} already existed "
            if [ ${vs} == ${topic_flow}  ];then
                kafka-topics.sh --bootstrap-server localhost:9092 --topic ${vs} --alter  --partitions ${partitions_num}  >/dev/null 2>&1
            fi
        else
            if [ ${vs} == ${topic_flow}  ];then
                # topic  flow 修改 flow 主题，和分配 6 个partitions .
             #  kafka-topics.sh --bootstrap-server localhost:9092 --create --topic ${vs} --partitions ${partitions_num} --replication-factor 1 >/dev/null 2>&1 
                kafka-topics.sh --bootstrap-server localhost:9092 --topic ${vs} --alter  --partitions ${partitions_num}  >/dev/null 2>&1
            else
                #创建topic ，分区为1
               kafka-topics.sh --bootstrap-server localhost:9092 --create --topic ${vs} --partitions 1 --replication-factor 1  >/dev/null 2>&1
            fi
            echo "create topic $vs ok"
        fi
    done
}

########################
#创建消费者组db_group 和 topic db_lists
#
#######################
function topic_create_db_group()
{
    if [ `kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list |grep -w db_group` ];then
        echo "db_group already created"
    else
        IFS=' ' read -r -a array <<< "${db_lists}"
        for v in ${array[@]}; do
        if [ `kafka-topics.sh --bootstrap-server localhost:9092 --list|grep -w $v|grep -v grep` ];then
            echo "db_group topic ${v} is ok"
        else
            kafka-console-consumer.sh --bootstrap-server localhost:9092  --from-beginning --group db_group --topic ${v}  >/dev/null 2>&1 &
            echo "db_group created topic ${v} ok"
        fi
        done

    fi
}

########################
#创建消费者组flow_group 和 topic flow
#
#######################
function topic_create_flow_group()
{
    if [ `kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list |grep -w flow_group` ];then
        echo "flow_group already created"
    else
        kafka-console-consumer.sh --bootstrap-server localhost:9092  --from-beginning --group flow_group --topic flow  >/dev/null 2>&1 &
        echo "flow_group created ok"
    fi
}

########################
#创建敏感数据组 prismdlp_group 和 topic prismdlp
#
#######################
function topic_create_sensitive_group()
{
    if [ `kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list |grep -w prismdlp_group` ];then
        echo "prismdlp_group already created"
    else
        kafka-console-consumer.sh --bootstrap-server localhost:9092  --from-beginning --group prismdlp_group --topic ${sensitive_data} >/dev/null 2>&1 &
        echo "prismdlp_group created ok"
    fi
}

########################
#创建敏感数据组 alert_group 和 topic alert
#
#######################
function topic_create_alert_group()
{
    if [ `kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list |grep -w alert_group` ];then
        echo "alert_group already created"
    else
        kafka-console-consumer.sh --bootstrap-server localhost:9092  --from-beginning --group alert_group --topic ${topic_alert} >/dev/null 2>&1 &
        echo "alert_group created ok"
    fi
}

#########################
# 设置topic 属性, 数据存储保存时间 单位second.
#
# 当前设置 5种 topic 数据存储时间.
########################
function local_topic_storage_time()
{
    #set -x
    #设置topic EngineFind 数据保存时间300 秒. 
    echo "set ${topic_enginefind} storage 300 second"
    set_topic_save_time ${topic_enginefind} 300 >/dev/null 2>&1 

    #设置topic EngineCmd 数据保存时间 3600 秒.
    echo "set ${topic_enginecmd} storage 3600 second"
    set_topic_save_time ${topic_enginecmd} 3600 >/dev/null 2>&1

    #设置topic CmdResult 数据保存时间 3600 秒.
    echo "set ${topic_cmdresult} storage 3600 second"
    set_topic_save_time ${topic_cmdresult} 3600 >/dev/null 2>&1

    #设置topic flow 数据保存时间 1800 秒.
    echo "set ${topic_flow} storage 1800 second"
    set_topic_save_time ${topic_flow} 1800 >/dev/null 2>&1

    #设置topic http 数据保存时间 1800 秒.
    echo "set ${topic_http} storage 1800 second"
    set_topic_save_time ${topic_http} 1800 >/dev/null 2>&1

    #设置topic alert 数据保存时间 1800 秒.
    echo "set ${topic_alert} storage 1800 second"
    set_topic_save_time ${topic_alert} 1800 >/dev/null 2>&1

    #db
    #设置 db topic 数据保存时间1800 秒.
    IFS=' ' read -r -a array <<< "${db_lists}"
    for v in ${array[@]}; do
    echo "db topic ${v} set storage 1800 second"
    set_topic_save_time ${v} 1800 >/dev/null 2>&1
    done

    #prismdlp
    #设置 敏感数据 prismdlp topic 数据保存时间 1800 秒.
    echo "prismdlp topic ${sensitive_data} set storage 1800 second"
    set_topic_save_time ${sensitive_data} 1800 >/dev/null 2>&1

    #set +x
}


function kafka_start()
{
    #必须先删除，不然会出现启动失败
    rm -rf /tmp/kafka-logs/.lock >/dev/null 2>&1
    kafka_status
    local ret=$?
    if [ $ret -eq 2 ];then
        echo "kafka is running ..." 
        show_list $list
    elif [ $ret -eq 1 ];then
        cd $kafka_dir
        `bin/kafka-server-start.sh config/server.properties >/dev/null 2>&1 &`
        cd - >/dev/null 2>&1
    elif [ $ret -eq 0 ];then
        cd $kafka_dir
        `bin/zookeeper-server-start.sh config/zookeeper.properties >/dev/null 2>&1 &`
        sleep 20
        `bin/kafka-server-start.sh config/server.properties >/dev/null 2>&1 &`
        cd - >/dev/null  2>&1 
    fi
    open_firewall
    sleep 40
    # 创建flow_group. 和topic flow 
    topic_create_flow_group
    # 创建db_group 和 topic db_lists
    topic_create_db_group
    # 创建敏感数据 group 和 topic prismdlp
    topic_create_sensitive_group
    # 创建敏感数据 group alert 和 topic alert
    topic_create_alert_group
}

function kafka_stop()
{
    cd $kafka_dir
    bin/kafka-server-stop.sh config/server.properties
    sleep 20
    bin/zookeeper-server-stop.sh config/zookeeper.properties
    cd - >/dev/null  2>&1 
    sleep 40
    rm -rf /tmp/zookeeper 
    rm -rf /tmp/kafka-logs
}

function help(){
    if [ ${#} -ge 1 ];then 
        echo ${1}
    fi
    echo "ctrl kafka Server"
    echo "usage:${0} [install|uninstall|start|stop|restart|status|deltopics|showtopics|replace_conf]"
    exit -1
}

if [ ${#} -ge 1 ];then
    case ${1} in
        'install')
            kafka_install
            ;;
        'uninstall')
            kafka_stop
            sleep 1
            force_kill
            yum remove kafka -y
            if [ -d $kafka_dir ];then
                rm -rf $kafka_dir
            fi
            ;;
        'restart')
            kafka_stop
            kafka_start
            ;;
        'start')
            kafka_start
            sleep 3
            # 创建 5 种 topic .        
            local_topic_create
            # 设置topic 数据存储时长.
            local_topic_storage_time
            ;;
        'stop')
            kafka_stop
            echo "kafka is stop .."
            ;;
        'deltopics')
            kafka_status
            ret=$?
            if [ $ret -eq 2 ];then
                local_topic_del
                echo "kafka topic del ok"
                #kafka-topics.sh --bootstrap-server localhost:9092 --list
            else
                echo "kafka is not running ..."
            fi
            ;;
        'showtopics')
            kafka_status
            ret=$?
            if [ $ret -eq 2 ];then
                kafka-topics.sh --bootstrap-server localhost:9092 --list
                if [ `kafka-topics.sh --bootstrap-server localhost:9092 --list |grep flow` ];then
                    echo "---   topic flow partitions:"
                    kafka-topics.sh --describe --bootstrap-server localhost:9092 --topic flow
                fi
                #数据库.
                IFS=' ' read -r -a array <<< "${db_lists}"
                for v in ${array[@]}; do
                    echo "---   topic ${v} partitions :"
                    kafka-topics.sh --describe --bootstrap-server localhost:9092 --topic ${v}
                done
                echo ""
                echo "---- flow_group ---"
                kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --group flow_group
                echo "---- db_group ---"
                kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --group db_group
                #敏感数据.
                echo ""
                echo "--- sensitive topic ${sensitive_data} partitions :"
                kafka-topics.sh --describe --bootstrap-server localhost:9092 --topic ${sensitive_data}
                echo ""
                echo "----sensitive group prismdlp_group ---"
                kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --group prismdlp_group
                echo ""
                echo "----alert group alert_group ---"
                kafka-consumer-groups.sh --bootstrap-server localhost:9092 --describe --group alert_group

            else
                echo "kafka is not running ..."
            fi
            ;;
        'status')
            kafka_status 1
            ;;
        'replace_conf')
            replace_conf
            echo "replace conf ok"
            ;;
        *)
            help
            ;;
    esac
else
    help 'choose param '
fi


