#include <stdint.h>
#include <sys/sysinfo.h>
#include <linux/hdreg.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/io.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/ioctl.h>
#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libconfig.h>
#include <stdarg.h>
#include "system_info.h"
#include <uuid/uuid.h>
#include <libudev.h>
#include <uuid/uuid.h>

int global_quiet;

/************************************
 * FUNC:
 *  debug 信息.
 *
 *NOTICE:
 * global_quiet == 1 则打印信息. other 不打印信息.
 * 该函数 fmt 必须是以 "%s xxx" , "%d xxx" 开头.
 * ********************************/
void debug(FILE *fd, const char *fmt, ...)
{
    int d;
    char *s=NULL;
   va_list ap;
   va_start(ap, fmt);
   do{
         if(global_quiet==1)
         {
             while(*fmt)
             {
                 switch(*fmt++){
                 case 's':
                     s = va_arg(ap, char*);
                     fprintf(fd, "%s\n", s);
                    break;
                 case 'd':
                 case 'c':
                     d = va_arg(ap, int); 
                     fprintf(fd, "%d\n", d);
                    break;
                 }
             }
         }
         va_end(ap);
   }while(0); 
}

/***************
 *FUNC:
 *  获取当前时间.
 *  格式： YYYYMMDD
 *
 * ************/
void local_curr_time(char *buf, int len)
{
    time_t now;
    struct tm *local=NULL;

    if(!buf && len <8)
    {
        return ;
    }

    time(&now);
    local = localtime(&now);
    snprintf(buf, len-1, "%04d%02d%02d", 
             local->tm_year + 1900,
             local->tm_mon +1,
             local->tm_mday );    

    return ;
}

/************************
 *FUNC:
 * 比较时间.
 *  t1  -  license 记录的开始时间.
 *  t2  -  有效天数.
 * RETURN:
 * 1  - 表示 (t1 + t2) = tt2 > now  表示在有效期. .
 * 1  - 表示 (t1 + t2) = tt2 == now 表示在有效 .
 * -1 - 表示 (t1 + t2) = tt2 < now  表示已经无效..
 * *********************/
int compare_time(char *t1, int t2)
{
    int ret=-1;
    time_t now;
    struct tm tm1={0} ; 
    char buf[64]={0};

    if(t2<0){ //如果有效期为负,则表示无效.
        return -1;
    }
    snprintf(buf, sizeof(buf)-1, "%.4s-%.2s-%.2s 0:0:0", t1, &t1[4], &t1[6]);
    strptime(buf, "%Y-%m-%d %H:%M:%S", &tm1);

    time_t tt1 = mktime(&tm1); 
    time_t tt2 = t2*24*3600 + tt1; // tt2 表示从 tt1 开始的有效秒数..
    time_t tnow = time(&now);

    //printf("%s %d  t1:[%s] tt1:[%ld], tt2:[%ld] now:[%ld]\n", __FUNCTION__, __LINE__,t1, tt1, tt2, tnow);
    if(tt2 < tnow)
    { //无效.
        ret = -1;
    }
    else if(tt2 >= tnow)
    { //有效.
        ret = 1;
    }

    return ret;
}


/**
 * @brief getCpuId     获取Linux下的CPU序列号
 *  dmidecode -t processor |grep "ID:"
 * @param id     存储获取到的CPU序列号的字符串变量
 * @return       0：获取成功  其他返回值：获取失败
*/
int getCpuId(char *id)
{
    unsigned int s1,s2;
    asm volatile
    ( "movl $0x01,%%eax ; \n\t"
      "xorl %%edx,%%edx ;\n\t"
      "cpuid ;\n\t"
      "movl %%edx , %0;\n\t"
      "movl %%eax , %1;\n\t"
      :"=m"(s1),"=m"(s2)
    );
    if(0 == s1 && 0 == s2) {
        return -1;
    }
    char cpu_id[32] = {0};
    sprintf(cpu_id, "%08X-%08X", htonl(s2), htonl(s1));
    strcpy(id, cpu_id);
    return 0;
}

/**********************
 *FUNC:
 * 获取CPU UUID.  * 与 dmidecode -t processor 命令获取ID 一致.
 *
 *Return 
 * 1：获取成功  其他返回值：获取失败
 * *******************/
int getCpuUUID(char *uuid)
{
    int ret=-1;
    char id[64]={0};
    char UUID_FILE_PATH[]={"/sys/devices/virtual/dmi/id/product_uuid"};

    if(!uuid){
        return ret;
    }
        

    FILE *fp = fopen(UUID_FILE_PATH, "r");
    if (fp == NULL) {
        perror("Failed to open UUID file");
        return ret;
    }

    if (fgets(id, sizeof(id)-1, fp) != NULL) {
        id[strcspn(id, "\n")] = 0;
        snprintf(uuid, sizeof(id)-1, "%s", id);
       ret=1;
    } else {
        printf("Failed to read CPU UUID\n");
    }

    fclose(fp);
    return ret;
}


/**
 * @brief removeBlank  删除字符串中的空格
 * @param str          需要处理的字符串
 * @return             无返回值
*/
void removeBlank(char *str)
{
    char *str_c = str;
    int i,j=0;
    for(i=0;str[i]!='\0';i++) {
        if(str[i]!=' ') {
            str_c[j++]=str[i];
		}
    }
    str_c[j]='\0';
    str = str_c;
}

/**
 * @brief getDiskId       获取Linux下的硬盘序列号
 * @param hd_name         硬盘所在位置 例：/dev/sda
 * @param id              存储获取到的硬盘序列号的字符串变量
 * @return                0：获取成功  其他返回值：获取失败
*/
int getDiskId1(char *hd_name, char *id)
{
    struct hd_driveid hid;
    int fd = open(hd_name,O_RDONLY | O_NONBLOCK);
    if(fd <0) {
     //   perror("open fd");
        return -1;
    }
    if(ioctl(fd,HDIO_GET_IDENTITY,&hid)<0) {
        perror("ioctl");
        return -1;
    }
    close(fd);
    char disk_id[32] = {0};
    sprintf(disk_id, "%s", hid.serial_no);
    removeBlank(disk_id); //删除字符串中的空格
    strcpy(id, disk_id);
    return 0;
}

int getDiskId2(char *hd_name, char *id)
{
    int ret=-1;
    char cmd[1024]={0};
    FILE *fp=NULL;
    char *ptr=NULL, *begptr=NULL, *endptr=NULL;

    snprintf(cmd, sizeof(cmd)-1, "blkid %s", hd_name);
    if(!(fp=popen(cmd, "r")) )
    {
        return ret;
    }

    while(fgets(cmd, sizeof(cmd)-1, fp))
    {
        if((ptr = strstr(cmd, "UUID=")) )
        {
            if((begptr=strchr(ptr+sizeof("UUID"), '"')))
            {
                if((endptr=strchr(begptr+1, '"')))
                {
                    snprintf(id, endptr-begptr, "%s", begptr+1);
                    ret=0;
                }   
            }
        }
    }
    pclose(fp);
    return ret;
}



/****************
 * 0 success.
 *  blkid /dev/sda1  获取UUID
 * */
int getDiskId(struct disk_info *df)
{
    int n=0, ret=0;
    char id[128]={0};
    char buf[][32]={
        "/dev/sda1",
        "/dev/sdb1",
        "/dev/sdc1"
    };
    df->mask=0;
    for( n=0; n < 3; n++ )
    {
        if((ret=getDiskId2(buf[n], id)) ){ //0 success. other fail.
            if((ret=getDiskId1(buf[n], id))){
                continue;
            }
        }
        df->mask |= 1<<n;
        switch (n)
        {
            case 0:
                snprintf(df->dinfoptr[n], sizeof(df->dinfoptr[0])-1, "%s", id );
                break;
            case 1:
                snprintf(df->dinfoptr[n], sizeof(df->dinfoptr[0])-1, "%s", id );
                break;
            case 2:
                snprintf(df->dinfoptr[n], sizeof(df->dinfoptr[0])-1, "%s", id );
                break;
            default:
                break;
        }
        memset(id, 0, sizeof(id));
    }
    if(df->mask>0)
        return 0;
}


/***********************
 *FUNC:
 * 获取硬盘UUID. 与 blkid 一致.
 *
 *RETURN:
 * 1：成功, 其他失败.
 * ********************/
int getDiskUUID(struct disk_info *df)
{
    int ret=-1, num=0;
    char (*ptr)[64]=NULL;
    struct udev *udev=NULL;
    struct udev_enumerate *enumerate=NULL;
    struct udev_list_entry *devices=NULL, *dev_list_entry=NULL;
    struct udev_device *dev=NULL;
    
    if(!df ){
        return ret;
    }
    memset(df, 0, sizeof(struct disk_info));
    ptr = df->dinfoptr = (char (*)[64])df->dinfobuf;
    
    udev = udev_new();
    if (!udev) {
        printf("%s %d %s\n",__FUNCTION__, __LINE__,  "Cannot create udev_new() failed\n");
        return ret;
    }

    enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "block");
    udev_enumerate_scan_devices(enumerate);
    devices = udev_enumerate_get_list_entry(enumerate);
 
    udev_list_entry_foreach(dev_list_entry, devices) {
        const char *path;
        const char *val;
 
        path = udev_list_entry_get_name(dev_list_entry);
        dev = udev_device_new_from_syspath(udev, path);
        val = udev_device_get_property_value(dev, "ID_FS_UUID");
        if(val && num < MAX_HDD_NUM) {
            snprintf(ptr[num], sizeof(*ptr)-1, "%s", val);
            num++;
            ret=1;
        }
        udev_device_unref(dev);
    }
 
    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    df->mask = num;

    return ret;
}

/******************************
 * @brief getNetUUID   
 * 获取Linux下的所有网卡UUID 序列号 与 nmcli -g UUID conn show|sort |cut -d: -f1 一致.
 *
 * @param iface   
 * 存储网卡信息的结构体
 *
 * @return             
 * 1：获取成功  其他返回值：获取失败
******************************/
int getNetUUID(net_iface *iface)
{
    int ret=-1, n=0, num=0;
    char command[128]={0};
    char uuid[64]={0};
    char (*ptr)[64]=NULL;

    if(!iface) {
        return ret;
    }
    ptr = iface->nicptr = (char (*)[64]) iface->nicbuf;

    snprintf(command, sizeof(command)-1, "%s", "nmcli -g UUID connection show|sort | cut -d: -f1");

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        return ret;
    }

    for(n=0; n< MAX_NIC_NUM; n++) {
        if (fgets(uuid, sizeof(uuid), fp) != NULL) {
            uuid[strcspn(uuid, "\n")] = 0;
            snprintf(ptr[n], sizeof(*ptr)-1, "%s", uuid);
            ret = 1;
            num++;
        } else {
            break;
        }
    }

    pclose(fp);

    iface->mask = num;

    return ret;
}

/**
 * @brief check_nic    检测网卡是否已经插上网线
 * @param eth_name     IN 网卡名字
 * @return             0：网卡已插上网线   -1：网卡未插上网线      其他返回值：错误
 */
int check_nic(const char *net_name)
{
    struct ifreq ifr;
    int errno, skfd = socket(AF_INET, SOCK_DGRAM, 0);
    char buf[1024]={0};

    if(skfd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        printf("socket error: %s [%s]\n", buf, __FUNCTION__);
        return -2;
    }
    strcpy(ifr.ifr_name, net_name);
    if(ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        close(skfd);
        return -3;
    }
    if(ifr.ifr_flags & IFF_RUNNING) {
        close(skfd);
        return 0; //网卡已插上网线
    }
    else {
        close(skfd);
        return -1;
    }
}

/**
 * @brief get_iface_info	   获取本地所有网卡名字和IP
 * @param netIface             网卡信息结构体指针，用户自行分配存储空间
 * @param outBuffLen           netIface分配的存储空间大小，若与实际获取到的数据总大小不一致，则将实际的总大小返回
 * @return                     0：成功
 *                             1：outBuffLen与实际获取到的数据总大小不一致，将实际的大小赋值给outBuffLen并返回
 *                             -1：错误
 * 使用步骤注意：
 * 1、malloc申请 netIface 堆内存空间，初始化 outBuffLen 变量的值
 * 2、调用一次该函数，目的是确定实际outBuffLen的大小
 * 3、判断返回值，如果返回1，则释放netIface堆内存空间，根据outBuffLen的大小重新分配堆内存空间；
 *    如果返回0，证明获取网卡信息成功，直接跳过第3、4步
 * 4、再一次调用该函数，若成功返回，则网卡信息获取完成
 * 5、遍历获取网卡信息，根据结构体的 next 指针即可遍历指向下一个网卡信息的地址，直到 next 为空
 */
int get_iface_info(struct net_iface_1 *netIface, unsigned int *outBuffLen)
{
    unsigned int i=0;
    int sock_get_iface;
    struct ifconf ifc_get_iface;
    struct ifreq *ifr_get_iface;
    //初始化 ifconf
    char buf[512];
    ifc_get_iface.ifc_len = 512;
    ifc_get_iface.ifc_buf = buf;

    sock_get_iface = socket(AF_INET,SOCK_DGRAM,0);
    if(sock_get_iface < 0) {
        perror("SOCKET:");
        return -1;
    }
    if(ioctl(sock_get_iface ,SIOCGIFCONF,&ifc_get_iface) < 0) {
        perror("ioctl");
        return -1;
    }
    unsigned int num = (ifc_get_iface.ifc_len/sizeof(struct ifreq)); //网卡个数
    if(*outBuffLen != num * sizeof(struct net_iface_1)) {
        *outBuffLen = num * sizeof(struct net_iface_1);
        return 1;
    }
    memset(netIface, 0, *outBuffLen);
    ifr_get_iface = (struct ifreq*)buf;
    for( i=0; i<num; i++) {
        strcpy(netIface[i].net_name, ifr_get_iface->ifr_name);
        strcpy(netIface[i].net_ip, inet_ntoa(((struct sockaddr_in*)&(ifr_get_iface->ifr_addr))->sin_addr));
        if(i == num - 1) {
            netIface[i].next = NULL;
        }
        else {
            netIface[i].next = netIface + (i + 1);
        }
        ifr_get_iface++;
    }
    close(sock_get_iface);
    return 0;
}


/*******************
 *FUNC:
 *  license init .
 *
 * PARAM:
 *  config_flag : config_read  - read 配置信息标识..
 *  config_flag : config_write  - write 配置信息标识.
 *
 * RETURN:
 * 0 success. other failed.
 *
 *NOTICE:
 * 默认获取当前目录下 license.cfg 文件.
 * ****************/
static int local_license_init(char *file, config_t *cfg, int flag)
{
    char cfgfile[1024]={"./license.cfg"};

    if(file && strlen(file)>1)
    {
        snprintf(cfgfile, sizeof(cfgfile)-1, "%s", file);
    }

    //config file info.
    config_init(cfg); 
    switch (flag)
    {
       case config_write_flag:
            config_set_options(cfg,
                       (CONFIG_OPTION_FSYNC
                        | CONFIG_OPTION_SEMICOLON_SEPARATORS
                        | CONFIG_OPTION_COLON_ASSIGNMENT_FOR_GROUPS
                        | CONFIG_OPTION_OPEN_BRACE_ON_SEPARATE_LINE));

       case config_read_flag:
            if(! config_read_file(cfg, cfgfile))
            {
                fprintf(stderr, "%s:%d - %s\n", config_error_file(cfg),
                    config_error_line(cfg), config_error_text(cfg));
                config_destroy(cfg);
                return -1;
            }
            break;
         default:
            break;
    }

    return 0;
}


/***************
 *FUNC:
 * config lookup.
 *
 *PARAM:
 *  keyinfo - 查找配置文件中的关键字. for example : "hardware.info" , "valid.info" , "hardware.values"
 *
 * RETURN:
 * 0 success , other failed.
 * ************/
static int local_config_lookup(config_t *cfg, char *keyinfo, struct hardware_info *hinfo)
{
    int ret=-1;
    config_setting_t *setting=NULL;
    const char *str=NULL;
    char buf[128]={0};

    if(!cfg || !keyinfo|| !hinfo)
    {
        printf("%s %d params error\n", __FUNCTION__, __LINE__);
        return ret;
    }

    if(strstr(keyinfo, "serial"))
    {
        if(config_lookup_string(cfg, "serial", &str))
        {
           snprintf(hinfo->serial, sizeof(hinfo->serial)-1, "%s" , str);
        }
        return 0;
    }

    setting = config_lookup(cfg, keyinfo);
    if(setting != NULL)
    {
        int count = config_setting_length(setting);
        int i , m;
        for(i = 0; i < count; ++i)
        {
          int nic, hdd, cpu, days;
          config_setting_t *info= config_setting_get_elem(setting, i);

             if(strstr(keyinfo, "hardware.info"))
             {
                   if(config_setting_lookup_int(info, "NIC", &nic)) //1 success.  , 0 failed.
                   {
                       hinfo->nicmask =  (nic < MAX_NIC_NUM ? nic : MAX_NIC_NUM) ; //限制最大NIC 个数 16 
                   }
                   if(config_setting_lookup_int(info, "HDD", &hdd))
                   {
                       hinfo->hddmask =  (hdd < MAX_HDD_NUM ? hdd : MAX_HDD_NUM ); //限制最大HDD 个数 16
                   }
                   if(config_setting_lookup_int(info, "CPU", &cpu))
                   {
                       hinfo->cpumask =  (cpu < MAX_CPU_NUM ? cpu : MAX_CPU_NUM ); //限制最大CPU 个数 1
                   }
                   ret=0;
             } 
             else if(strstr(keyinfo, "valid.info"))
             {
                   if(config_setting_lookup_string(info, "firsttime", &str)) //1 success.  , 0 failed.
                   {
                       snprintf(hinfo->firsttime, sizeof(hinfo->firsttime)-1, "%s", str); 
                   }
                   if(config_setting_lookup_int(info, "validday", &days)) //有效天数.
                   {
                       hinfo->validday = days;
                   }
                   ret=0;
             }
            else if(strstr(keyinfo, "hardware.values"))            
            {
                //cpu group info.
                for(m=0; m<hinfo->cpumask; m++)
                {
                    snprintf(buf, sizeof(buf)-1, "cpu%d", m);
                    if(config_setting_lookup_string(info, buf, &str))
                    {
                        snprintf(hinfo->cpu[m], sizeof(hinfo->cpu[m])-1, "%s", str);
                    }
                }
                //hdd group info.
                for(m=0; m<hinfo->hddmask; m++)
                {
                    snprintf(buf, sizeof(buf)-1, "hdd%d", m);
                    if(config_setting_lookup_string(info, buf, &str))
                    {
                        snprintf(hinfo->hdd[m], sizeof(hinfo->hdd[m])-1, "%s", str);
                    }
                }
                //nic group info.
                for(m=0; m<hinfo->nicmask; m++)
                {
                    snprintf(buf, sizeof(buf)-1, "nic%d", m);
                    if(config_setting_lookup_string(info, buf, &str))
                    {
                        snprintf(hinfo->nic[m], sizeof(hinfo->nic[m])-1, "%s", str);
                    }
                }
                //
            }
        }
    }
    
    return ret;
}


/***************
 *FUNC:
 * 获取license 中参数信息.
 * serial, hardware.info, valid.info
 * 
 *RETURN:
 * 获取到license中信息并填充struct hardware_info 结构体.
 * 0 success, other failed.
 *
 *NOTICE:
 * 默认获取当前目录下 license.cfg 文件.
 * *************/
int get_license_info(char *file, struct hardware_info *hinfo)
{
    int ret=-1;
    config_t cfg;

    memset(hinfo, 0, sizeof(struct hardware_info));
    if(!local_license_init(file, &cfg, config_read_flag))// 0 success.
    {
        local_config_lookup(&cfg, "serial", hinfo);
        local_config_lookup(&cfg, "hardware.info", hinfo);
        local_config_lookup(&cfg, "hardware.values", hinfo);
        local_config_lookup(&cfg, "valid.info", hinfo);
    
        config_destroy(&cfg);
    }

    return ret;
}


/***********************
 * FUNC:
 *  name - "hardware" 设置硬件信息.
 *       - "valid"    设置当前时间日期.
 *
 * NOTICE:
 * set license file, for hardware info and firsttime .
 * ********************/
static int local_set_config_values(char *file, struct hardware_info *hinfo, char *name, int config_flag )
{
    int n;
    char buf[1024]={0}, curtime[16]={0};
    config_t cfg; 
    config_setting_t *root=NULL, *setting=NULL, *key=NULL;

    //默认保存当前目录. ./license.cfg 
    char cfgfile[1024]={"./license.cfg"};
    if(file && strlen(file)>1)
    {
        snprintf(cfgfile, sizeof(cfgfile)-1, "%s", file);
    }

    if(!local_license_init(cfgfile, &cfg, config_write_flag))// 0 success.
    {
        root = config_root_setting(&cfg);
        if(strstr(name, "serial"))
        {
            if(!(setting = config_setting_get_member(root, "serial")))
            {
                setting = config_setting_add(root, "serial", CONFIG_TYPE_STRING);
                if(!setting)
                {
                    fprintf(stderr, "error add setting serial\n");
                    config_destroy(&cfg);
                    return -1;
                }
            }
        }
        else if(strstr(name, "hardware"))
        {
             if(!(setting = config_setting_get_member(root, "hardware")) )
             { //不存在则设置hardware entry.
                 setting = config_setting_add(root, "hardware", CONFIG_TYPE_GROUP);
             }
             if(!(setting = config_setting_get_member(setting, "values")) )
             { //不存在则设置values entry.
                 setting = config_setting_add(setting, "values", CONFIG_TYPE_LIST);
             }
            key= config_setting_add(setting, NULL, CONFIG_TYPE_GROUP);
        }
        else if(strstr(name, "valid"))
        {
            if(!(setting = config_setting_get_member(root, "valid")) )
             { //不存在则设置 valid entry.
                 setting = config_setting_add(root, "valid", CONFIG_TYPE_GROUP);
             }
             if(!(setting = config_setting_get_member(setting, "info")) )
             { //不存在则设置info entry.
                 setting = config_setting_add(setting, "info", CONFIG_TYPE_LIST);
             }
            key= config_setting_add(setting, NULL, CONFIG_TYPE_GROUP);
        }

        //
        if(!setting)
        {
            printf("%s %d hardware.values is null\n",__FUNCTION__, __LINE__);
            return  -1;
        }

        switch (config_flag)
        {
         case config_serial_flag:
             config_setting_set_string(setting, hinfo->serial); //仅仅设置一个字符串到 serial="xxx";
             n=1;
             break;

         case config_cpu_flag:
             for(n=0; n<hinfo->cpumask; n++)
             {
                 snprintf(buf, sizeof(buf)-1, "cpu%d", n);
                 {
                     setting = config_setting_add(key, buf, CONFIG_TYPE_STRING);
                     if(hinfo->cpu[n] && strlen(hinfo->cpu[n])>1) {
                        config_setting_set_string(setting, hinfo->cpu[n]);
                     }
                }
             }
             break;

         case config_hdd_flag:
             for(n=0; n<hinfo->hddmask; n++)
             {
                 snprintf(buf, sizeof(buf)-1, "hdd%d", n);
                 {
                     setting = config_setting_add(key, buf, CONFIG_TYPE_STRING);
                     if(hinfo->hdd[n] && strlen(hinfo->hdd[n])>1){
                        config_setting_set_string(setting, hinfo->hdd[n]);
                     }
                 } 
             }
             break;
         case config_nic_flag:
             for(n=0; n<hinfo->nicmask; n++)
             {
                 snprintf(buf, sizeof(buf)-1, "nic%d", n);
                 {
                     setting = config_setting_add(key, buf, CONFIG_TYPE_STRING);
                     if(hinfo->nic[n] && strlen(hinfo->nic[n])>1){
                        config_setting_set_string(setting, hinfo->nic[n]);
                     }
                 }
             }
             break;
         case config_firsttime_flag:
             setting = config_setting_add(key, "firsttime", CONFIG_TYPE_STRING);
             local_curr_time(curtime, sizeof(curtime));
             config_setting_set_string(setting, curtime);
             n=1; //灰常重要，否则 无法进入下面config_write_file 
             break;
         default:
             break;
        }

         if(n > 0)
         { 
            if(!config_write_file( &cfg, cfgfile))
            {
                fprintf(stderr, "Error while writing file.\n");
                config_destroy(&cfg);
                return -1;
            }
        }
    }

    return 0;
}

/***********************
 *FUNC:
 * 保存硬件信息到license.cfg.
 *
 *
 * NOTICE:
 * 默认保存到当前目录 ./license.cfg 文件.
 * ********************/
int  set_license_info(char *file, struct hardware_info *hinfo)
{
    int n, ret=0;
    config_t cfg;
    char uuid[256]={0};
    //设置uuid.如果已经设置UUID, 则忽略之.
    if((ret=is_valid_uuid(hinfo->serial))!=1)
    { //已经不存在有效的UUID.则设置新UUID.
        memset(hinfo->serial, 0, sizeof(hinfo->serial));
        make_uuid(uuid, sizeof(uuid));
        snprintf(hinfo->serial, sizeof(hinfo->serial)-1, "%s", uuid);
        local_set_config_values(file, hinfo, "serial", config_serial_flag);
    }

    //create the new entry for hardware info..
    local_set_config_values( file, hinfo, "hardware", config_cpu_flag );  //设置cpu值到配置文件.
    local_set_config_values( file, hinfo, "hardware", config_hdd_flag );  //设置hdd值到配置文件.
    local_set_config_values( file, hinfo, "hardware", config_nic_flag );  //设置NIC值到配置文件.
    local_set_config_values( file, hinfo, "valid",    config_firsttime_flag ); //设置首次运行日期.

    return ret;
}



/*******************************
 *FUNC:
 *  判断 license 是否还在有效期.
 *  判断是否在有效期内,或者过期.
 *
 * RETURN:
 * 1 success有效.  other failed无效..
 *
 * firsttime - 返回 license 记录的首次运行时间.
 * validdya  - 返回 license 授权的有效天数.
 * **********************/
int license_time_is_valid(char *file, char *firsttime, int *validday ) 
{
    int n, ret=0;
    time_t tm;
    char buf[1024]={0}, curtime[16]={0};
    config_t cfg; 
    config_setting_t *root=NULL, *setting=NULL, *key=NULL;
    struct hardware_info hinfo;

    memset(&hinfo, 0, sizeof(struct hardware_info));

    //默认保存当前目录. ./license.cfg 
    char cfgfile[1024]={"./license.cfg"};
    if(file && strlen(file)>1)
    {
        snprintf(cfgfile, sizeof(cfgfile)-1, "%s", file);
    }
    local_curr_time(curtime, sizeof(curtime));

    if(!local_license_init(file, &cfg, config_read_flag))// 0 success.
    {
        local_config_lookup(&cfg, "valid.info", &hinfo);
        config_destroy(&cfg);
    }
    //fprintf(stderr, "%s %d firsttime:[%s] valid :[%d] days.\n", __FUNCTION__, __LINE__, hinfo.firsttime, hinfo.validday );
    ret = compare_time(hinfo.firsttime, hinfo.validday);
    if(ret == -1) //license 过期了.
    {
        if(global_quiet != 1)
        fprintf(stderr, "license date expire,  begin:%s, validity:%d days, please contact persm...\n", hinfo.firsttime, hinfo.validday );
    }
    else if(ret >=0 ) //license 没有过期.
    {
        if(global_quiet != 1)
        fprintf(stderr, "license normal begin:%s, validity:%d days ...\n", hinfo.firsttime, hinfo.validday );
        ret = 1;
    }
    if(firsttime){
        snprintf(firsttime, sizeof(hinfo.firsttime)-1, "%s", hinfo.firsttime);
    }
    if(validday){
        *validday = hinfo.validday;
    }
    config_destroy(&cfg);
    return ret;
}

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
int find_cfg_key_val(char *file, char *key, char *value, int vlen)
{
    int ok, isfind=0;
    config_t cfg;
    config_setting_t *setting, *info;
    const char *str=NULL;
    int nval=0;
    int64_t nval64=0;
    double nvalfloat=0.0;

    if(!value || vlen <1){
        return -1;
    }

    config_init(&cfg);
    config_read_file(&cfg, file);
    {
        if(config_lookup_int(&cfg, key, &nval) || config_lookup_bool(&cfg, key, &nval))
        {
            snprintf(value, vlen-1, "%d", nval);
            isfind=1;
        } 
        else if(config_lookup_int64(&cfg, key, &nval64))
        {
            snprintf(value, vlen-1, "%ld", nval64);
            isfind=1;
        } 
        else if(config_lookup_float(&cfg, key, &nvalfloat))
        {
            snprintf(value, vlen-1, "%f", nvalfloat);
            isfind=1;
        } 
        else if(config_lookup_string(&cfg, key, &str))
        {
            if(str){
              snprintf(value, vlen-1, "%s", str);
              isfind=1;
            }
        }
    }

    config_destroy(&cfg);
    return isfind;
}

/******************************
 * FUNC:  硬件信息查询..
 *  查找license.cfg 中的 硬件 entry 值. 也可用于判断 硬件 entry是否存在.
 *
 * PARAM:
 * pkey  - "hardware.values"
 * ckey  - "cpu0"
 * value -  返回存放entry 的值.
 *
 * NOTICE:
 *  value 如果为NULL, 则不反馈entry值.
 *  无论value类型，均转换输出为字符串.
 * 
 *
 * RETURN:
 * 1 find .   other not find.
 ******************************/
int find_entry_value(char *file, char *pkey, char *ckey, char *value, int vlen)
{
    int n, ok, count, isfind=0;
    config_t cfg;
    config_setting_t *setting, *info;
    const char *str=NULL;

    if(!value || vlen <1){
        return -1;
    }

    config_init(&cfg);
    config_read_file(&cfg, file);
    setting = config_lookup(&cfg, pkey);
    if(setting)
    {
        count= config_setting_length(setting);
        for(n=0; n<count; n++)
        {
            str=NULL;
            info = config_setting_get_elem(setting, n);
            {
                ok = config_setting_lookup_string(info, ckey, &str);
                if(ok && str){
                 // printf("%s %d  %s %s [%s] find\n", __FUNCTION__, __LINE__, pkey, ckey , str);
                  snprintf(value, vlen-1, "%s", str);
                  isfind=1;
                  break;
                }
            }
        }
    }
    config_destroy(&cfg);
    return isfind;
}

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
int hardware_is_change(char *file, struct hardware_info *hinfo, char *val, int vlen)
{
    int n, ret=0, flag=0;
    char buf[128]={0}, ckey[64]={0};

    if(!hinfo)
    {//认为没有改变.
        return ret;
    }

    //license hdd compire.
    for(n=0; n<hinfo->hddmask; n++)
    {
        snprintf(ckey, sizeof(ckey)-1, "hdd%d", n);
        if((ret=find_entry_value(file, "hardware.values", ckey, buf, sizeof(buf)))==1)
        {
            if( hinfo->hdd[n] && strcmp(buf, hinfo->hdd[n])) //存在但是不相同.
            {
                flag=1;
                if(vlen >1 && val)
                {
                    snprintf(val, vlen-1, "hardware.values.%s", ckey);
                }
                return 1;
            }
        } 
    }

    //license nic compire.
    for(n=0; n<hinfo->nicmask; n++)
    {
        snprintf(ckey, sizeof(ckey)-1, "nic%d", n);
        if((ret=find_entry_value(file, "hardware.values", ckey, buf, sizeof(buf)))==1)
        {
            if( hinfo->nic[n] && strcmp(buf, hinfo->nic[n])) //存在但是不相同.
            {
                flag=1;
                if(vlen >1 && val)
                {
                    snprintf(val, vlen-1, "hardware.values.%s", ckey);
                }
                return 1;
            }
        } 
    }

    //license cpu compire.
    for(n=0; n<hinfo->cpumask; n++)
    {
        snprintf(ckey, sizeof(ckey)-1, "cpu%d", n);
        if((ret=find_entry_value(file, "hardware.values", ckey, buf, sizeof(buf)))==1)
        {
            if( hinfo->cpu[n] && strcmp(buf, hinfo->cpu[n])) //存在但是不相同.
            {
                flag=1;
                if(vlen >1 && val)
                {
                    snprintf(val, vlen-1, "hardware.values.%s", ckey);
                }
                return 1;
            }
        } 
    }
        
    return 0;
}

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
int license_env_info(char *envkey, char *val, char vlen,  int flag)
{
    int ret=-1;

    if(!envkey || !val || !vlen)
        return ret;

    if(flag==0)
    {
        strncpy(val, getenv(envkey), vlen);
    }
    else if(flag==1)
    {
        setenv(envkey, val, 1); //改写源环境变量.
    }

    return ret;
}

void show_license(char *file)
{
    int n=0;
    config_t cfg;
    struct hardware_info hin, *hinfo=&hin;

    get_license_info(file, &hin);
    printf("-------%s------ \n", __FUNCTION__);
    printf("serial:[%s]\n", hinfo->serial);

    printf("cpu num:[%d]\n", hinfo->cpumask);
    for(n=0; n<hinfo->cpumask; n++)
    {
        printf("cpu%d %s\n", n, hinfo->cpu[n]);
    }

    printf("hdd num:[%d]\n", hinfo->hddmask);
    for(n=0; n<hinfo->hddmask; n++)
    {
        printf("hdd%d %s\n", n, hinfo->hdd[n]);
    }

    printf("nic num:[%d]\n", hinfo->nicmask);
    for(n=0; n<hinfo->nicmask; n++)
    {
        printf("nic%d %s\n", n, hinfo->nic[n]);
    }

    if(hinfo->firsttime && strlen(hinfo->firsttime)>1)
    {
        printf("firsttime:[%s]\n", hinfo->firsttime);
    }
    printf("validday:[%d]\n", hinfo->validday);

    printf("-------------------------\n\n");
    return ;
}

/*
 * md5sum 长度固定为32bytes.
 */
int show_md5(char *cfgfile, char *md5 )
{
    FILE *fp=NULL;
    struct stat st;    
    char buf[1024]={0};
    char cmdbuf[1024]= {0}, cmd[]="md5sum";

    if(!cfgfile || access(cfgfile, F_OK) !=0 ){
        printf("license file %s not find\n", cfgfile);
        exit(0);
    }
    snprintf(cmdbuf, sizeof(cmdbuf)-1, "%s %s", cmd, cfgfile);
    fp = popen(cmdbuf, "r");
    if(fp==NULL){
        perror( "md5sum failed\n") ;
        exit(0);
    }

    while(fgets(buf, sizeof(buf), fp)!=NULL){
        if(md5){
            sscanf(buf, "%32s", md5);
            return 1;
        } 
    }

    pclose(fp);
    return 0;
}

/*******************
*FUNC:
* 规范uuid 以字母p开头，_ 分割.
* *****************/
int repaire_uuid(char *uuid)
{
    int i=0, j=0;
    if(!uuid ){
        return -1;
    }
    for (i=0, j=0; i<36; i++)
    {
        if(uuid[i] == '-')
        {
            uuid[i] = '_';
        }   
    }

    if(isdigit(uuid[0]))
    {    uuid[0] = 'p'; }

    return 1;
}

/************************
 *FUNC:
 *  生成uuid 字符串.
 *
 * Return:
 *  返回 uuid 字符串和长度.
 * **********************/
int make_uuid(char *out_uuid, int len)
{
    uuid_t out;
    char uuid[42]={0};
    if(!out_uuid || len<38)
    {
        return -1;
    }

    uuid_generate(out);
    uuid_unparse(out, uuid);
    
    repaire_uuid(uuid);
    snprintf(out_uuid, len-1, "%s", uuid);

    return strlen(out_uuid);
}

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
int is_valid_uuid(const char *uuid)
{
    if (strlen(uuid) != 36) {
        return 0;  // 长度必须为 36
    }

    // 检查破折号位置
    if (uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-') {
        return 0;
    }

    // 检查每个字符
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            continue; // 跳过破折号
        }
        if (!isxdigit(uuid[i])) {
            return 0;  // 必须是十六进制字符
        }
    }

    return 1;  // 字符串符合 UUID 格式
}

/*************************
 *FUNC:
 *  设置license.cfg UUID
 *
 * NOTICE:
 *  如果已经有合法UUID, 则保留，不重新生成新UUID.
 *
 * RETURN:
 *  1：成功, 其他设置失败..
 * **********************/
int get_license_uuid(char *file, char *uuid, int len)
{
    int ret=-1;
    config_t cfg;
    struct hardware_info tmp_hinfo;

    if(!uuid || !file)
    {
        return ret;
    }

    memset(&tmp_hinfo, 0, sizeof(struct hardware_info));
    if(!local_license_init(file, &cfg, config_read_flag)) // 0 success.
    {
        local_config_lookup(&cfg, "serial", &tmp_hinfo);
        config_destroy(&cfg);
    }
    //判断是否有效UUID.
    if( strlen(tmp_hinfo.serial) >1 )
    {
        if((ret = is_valid_uuid(tmp_hinfo.serial)) == 1)
        {
            snprintf(uuid, len-1, "%s", tmp_hinfo.serial);
        }
    }
    return ret;
}






