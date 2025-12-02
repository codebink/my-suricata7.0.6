#ifndef __SYST_INFO__
#define __SYST_INFO__
#include <stdint.h>

#define MAX_CPU_NUM 1

//打印debug 信息.
#define DEBUG_PRINT(fmt, args...) do{ fprintf(stderr, fmt, ##args); }while(0)
extern int global_quiet; //安静模式.

//网卡信息结构体 最大支持16个网卡UUID.
typedef struct __net_iface {
#define MAX_NIC_NUM 256
    uint8_t  mask; 
   
    char (*nicptr)[64];
    char nicbuf[16448]; //最大能存 [256][64] 257个64长度字符串..
} net_iface;

//网卡信息结构体2
struct net_iface_1 {
    struct net_iface_1 *next; //指向下一个网卡信息结构体的地址
    char net_name[20];          //网卡名字
    char net_ip[16];            //网卡IP
};

//磁盘信息.最多256个磁盘UUID 信息.
struct disk_info{
#define MAX_HDD_NUM 256
    uint8_t mask; //有效存储的UUID 个数.
    char (*dinfoptr)[64];
    char dinfobuf[16448]; //最大能存 [256][64] 257个64长度字符串..
};

//读/写配置标识.
static enum __config_flag__ {
    config_read_flag = 1,
    config_write_flag,
    config_serial_flag,
    config_cpu_flag,
    config_hdd_flag,
    config_nic_flag,
    config_firsttime_flag,
    config_validday_flag,
} config_flag;

//license 获取硬件参数. 最大支持采集 1个cpu ID ,16个硬盘UUID ,3个NIC UUID. 
struct hardware_info{
    char serial[256]; //采用UUID. 表示engine ID.

    uint8_t cpumask; //表示须采集几个cpu core id.
    char cpu[MAX_CPU_NUM][64];
    uint8_t hddmask; //表示须采集几个hdd id.
    char hdd[MAX_HDD_NUM][64];
    uint8_t nicmask; //表示须采集几个nic id.
    char nic[MAX_NIC_NUM][64];

    char firsttime[32];  //20240521.
    int validday;        //days 有效天数..
};


/*********************************************************
 * @brief getCpuId     
 * @param id     存储获取到的CPU序列号的字符串变量
 * @return      
 * 0：获取成功  其他返回值：获取失败
**********************************************************/
int getCpuId(char *id);

/**********************
 *FUNC:
 * 获取CPU UUID.  * 与 dmidecode -t processor 命令获取ID 一致.
 *
 *Return 
 * 1：获取成功  其他返回值：获取失败
 * *******************/
int getCpuUUID(char *uuid) ;

/**********************************************************
 * @brief getDiskId       获取Linux下的硬盘序列号最多获取3个硬盘UUID 通过 blkid 获取. .
 * @param disk_info       硬盘ID 例：/dev/sda1 的ID, /dev/sdb1 的ID, /dev/sdc1的ID.
 * @return               
 * 0：获取成功  其他返回值：获取失败
***********************************************************/
int getDiskId(struct disk_info *dinfo);



/*************************************************************
 *FUNC:
 *  获取网卡UUID.
 *  对应命令： nmcli -g UUID,NAME conn show
 * 0：获取成功  其他返回值：获取失败
 * **********************************************************/
int getNetUUID(net_iface *get_iface);


/************************************************************
 * @brief check_nic    检测网卡是否已经插上网线
 * @param eth_name     IN 网卡名字
 * @return           
 * 0：网卡已插上网线   -1：网卡未插上网线,  其他返回值：错误
 *************************************************************/
int check_nic(const char *net_name);


/**************************************************************
 * @brief get_iface_info	   获取本地所有网卡名字和IP
 * @param netIface             网卡信息结构体指针，用户自行分配存储空间
 * @param outBuffLen           netIface分配的存储空间大小，若与实际获取到的数据总大小不一致，则将实际的总大小返回
 * @return                   
 * 0：成功
 * 1：outBuffLen与实际获取到的数据总大小不一致，将实际的大小赋值给outBuffLen并返回
 * -1：错误
 *
 * 使用步骤注意：
 * 1、malloc申请 netIface 堆内存空间，初始化 outBuffLen 变量的值
 * 2、调用一次该函数，目的是确定实际outBuffLen的大小
 * 3、判断返回值，如果返回1，则释放netIface堆内存空间，根据outBuffLen的大小重新分配堆内存空间；
 *    如果返回0，证明获取网卡信息成功，直接跳过第3、4步
 * 4、再一次调用该函数，若成功返回，则网卡信息获取完成
 * 5、遍历获取网卡信息，根据结构体的 next 指针即可遍历指向下一个网卡信息的地址，直到 next 为空
 ***************************************************************/
int get_iface_info(struct net_iface_1 *netIface, unsigned int *outBuffLen) ;

/***************
 *FUNC:
 * 获取license 中参数信息.
 * 
 *RETURN:
 * 获取到license中信息并填充struct hardware_info 结构体.
 * 0 success, other failed.
 *
 *NOTICE:
 * 默认获取当前目录下 license.cfg 文件.
 * *************/
int  get_license_info(char *file, struct hardware_info *hinfo) ;
void show_license(char *file);

/***********************
 *FUNC:
 * 保存硬件信息到license.cfg.
 *
 *
 * NOTICE:
 * 默认保存到当前目录 ./license.cfg 文件.
 * ********************/
int  set_license_info(char *file, struct hardware_info *hinfo) ;

/***************
 *FUNC:
 *  获取当前时间.
 *  格式： YYYYMMDD
 *
 * ************/
void local_curr_time(char *buf, int len);


/************************
 *FUNC:
 * 比较时间.
 *  t1  -  license 记录的开始时间.
 *  t2  -  有效天数.
 * RETURN:
 * 1  - 表示 t1 + t2 < now  表示还在有效期. .
 * -1  - 表示 t1 + t2 == now 表示已经无效 .
 * -1 - 表示 t1 + t2 > now  表示已经无效..
 * *********************/
int compare_time(char *t1, int t2) ;


/*******************************
 *FUNC:
 *  判断 license 是否还在有效期.
 *  判断是否在有效期内,或者过期.
 *
 * RETURN:
 * 1 success有效.  other failed无效..
 * firsttime - 返回 license 记录的首次运行时间.
 * validdya  - 返回 license 授权的有效天数.
 * **********************/
int license_time_is_valid(char *file, char *firsttime, int *validday ) ;

/*************************
 *FUNC:
 * 查找license.cfg 中某个entry 值, 也可以用于判断entry 是否存在.

 *NOTICE:
 *  value 如果为NULL, 则不反馈entry值.
 *  无论value类型，均转换输出为字符串.
 * 
 *
 * RETURN:
 * 1 find .   other not find.
 * **********************/
int find_cfg_key_val(char *file, char *key, char *value, int vlen) ;

/******************************
 * FUNC:
 *  查找license.cfg 中的某个值.是否存在.
 *
 * PARAM:
 * pkey - "hardware.values"
 * ckey - "cpu0"
 *
 * NOTICE:
 *  value 如果为NULL, 则不反馈entry值.
 *  无论值类型，查询输出均转换为字符串.
 *
 * RETURN:
 * 1 find .   other not find.
 ******************************/
int find_entry_value(char *file, char *pkey, char *ckey, char *value, int vlen) ;

/********************
 *FUNC:
 * 判断 license 注册硬件信息是否发送改变.
 *
 * NOTICE:
 * val - 返回发现不同的entry. (如果val ==NULL，则不返回.)
 *
 *RETURN:
 *1 发生改变, 0 没有改变.
 * *****************/
int hardware_is_change(char *file, struct hardware_info *hinfo, char *val, int vlen) ;

/***************
 *FUNC:
 * 从环境变量获取/设置license 信息.
 *
 * PARAM:
 *  envkey  - env环境变量 key. 默认以 PRISM_XXX 开头.
 *  flag    - 1 设置val 值到env.  0 从env中获取val 值
 *  val     - 获取/设置的值.
 *  vlen    - 值长度.
 *
 * RETURN:
 * 0 success     other failed
 * ************/
int license_env_info(char *envkey, char *val, char vlen,  int flag) ;

/*
 * md5sum 长度固定为32bytes.
 */
int show_md5(char *cfg, char *md5 ) ;

/**********************
 *FUNC:
 *  判断是否是合法 UUID
 *
 * 判断依据： 
 * 字符串长度是否为 36
 * 字符串的格式是否符合 UUID 的模式：8-4-4-4-12。
 * 是否包含有效的十六进制字符(0-9 和 a-f 或 A-F)
 *
 * RETURN:
 * 1: 是UUID, 其他非UUID
 * ******************/
int is_valid_uuid(const char *uuid); 

/************************
 *FUNC:
 *  生成uuid 字符串.
 *
 * Return:
 *  返回 uuid 字符串, 和字符串长度.
 * **********************/
int make_uuid(char *uuid, int len);

/*************************
 *FUNC:
 *  设置license.cfg UUID
 *
 * NOTICE:
 *  如果已经有合法UUID, 则保留，不重新生成新UUID.
 *
 * RETURN:
 * 1: 成功， 其他失败.
 * **********************/
int get_license_uuid(char *file, char *uuid, int len);


#endif
