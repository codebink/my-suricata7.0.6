#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "system_info.h"

//默认取当前目录下 ./license.cfg 文件.
char global_cfgfile[1024]={"./license.cfg"};
char global_cfgfile_md5[1024]={"./.prism"};
int global_stegano_md5;   //是否将md5 加入license, 1 加, 0 不加.

void usage(char *arg)
{
    printf("license tools for prism. v1.0\n");
    printf("help        -h  help\n");
    printf("show        -s  show license info\n");
    printf("cfgfile     -f  set license file path. default current path ./license.cfg\n");
    printf("set md5     -e  set md5 to license file\n");
    printf("show md5    -m  show license file md5 example: -m ./license.cfg\n");
    printf("\n");
    exit(0);
}

void prism_info(int fd)
{
    char info[]= "Prism Co.,Ltd.\n\
www.prismtech.com.cn\n\
TEL:010-53652821\n\
EMail:Market@prismtech.com.cn\n";

    if(fd>3){
        write(fd, info, strlen(info));
    }
    return;
}

int stegano_md5(char *outfile)
{
    int ret=-1;
    struct stat st;    
    char md5[40]={0};
    FILE *infp = NULL, *outfp=NULL;
    char tmpfile[]="/tmp/.prism_md5_XXXXXX";
    
    if( access(global_cfgfile, F_OK) !=0 ){
        printf("license file %s not find\n", global_cfgfile);
        return ret;
    }
    if(show_md5(global_cfgfile, md5) != 1)
    {
        printf("license file md5 failed\n");
        return ret;
    }
    int fd = mkstemp(tmpfile);
    if(fd <0){
        printf("%s %d mkstemp failed\n", __FUNCTION__, __LINE__);
        return ret;
    }

    prism_info(fd);
    if((infp=fdopen(fd, "r"))==NULL)
    {
        printf("%s %d license fdopen %s failed \n", __FUNCTION__, __LINE__, tmpfile);
        return ret;
    }
    fseek(infp, 0L, SEEK_SET);
    if((outfp=fopen(outfile, "w"))==NULL)
    {
        printf("%s %d outfile %s fopen failed\n",__FUNCTION__, __LINE__, outfile);
        return ret;
    }

    if(message_string_encode(md5, infp, outfp)) //1 : suceess 
    {
        printf("md5 success into license !\n");    
        unlink(tmpfile);
    }

    fclose(infp);
    fclose(outfp);

    unlink(tmpfile);
    return ret;
}


//参数解析..
void parse(int argc, char **argv)
{
    char ch ,tmp[1024]={0};
    int option_index=0;
    
    if(argc<2 ){
        usage(argv[0]);
        exit (0);
    }
    struct option long_options[]={
            {"help", no_argument, NULL, 'h'},
            {"show", no_argument, NULL, 's'},
            {"cfgfile", required_argument, NULL, 'f'},
            {"stegano_md5", optional_argument, NULL, 'e'},
            {"md5", no_argument, NULL, 'm'},
            {0,0,0,0}
    };
    while((ch=getopt_long(argc, argv, "hse:m:f:", long_options, &option_index)) !=-1 )
    {
        //int option_index=0;
        switch(ch)
        {
        case 'h':
        case '?':
            usage(argv[0]);
            break;
        case 's':
            show_license(global_cfgfile);
            break;
        case 'f':
            if(optarg )
            {
                snprintf(global_cfgfile, sizeof(global_cfgfile)-1, "%s", optarg);
                char *dirpath = strdup(global_cfgfile);
                char * dname = dirname(dirpath);
                snprintf(tmp, sizeof(tmp)-1, "%s/%s", dname, basename(global_cfgfile_md5));
                snprintf(global_cfgfile_md5, sizeof(global_cfgfile_md5)-1, "%s", tmp);
                free(dirpath);
            }
            break;
        case 'e':
            global_stegano_md5 = 1;
            if(optarg )
            {
                snprintf(global_cfgfile, sizeof(global_cfgfile)-1, "%s", optarg);
                char *dirpath = strdup(global_cfgfile);
                char * dname = dirname(dirpath);
                snprintf(tmp, sizeof(tmp)-1, "%s/%s", dname, basename(global_cfgfile_md5));
                snprintf(global_cfgfile_md5, sizeof(global_cfgfile_md5)-1, "%s", tmp);
                free(dirpath);
            }
            stegano_md5(global_cfgfile_md5);
            printf("stegano_md5 to license file\n");
            break;
        case 'm':
            if(optarg )
            {
                snprintf(global_cfgfile, sizeof(global_cfgfile)-1, "%s", optarg);
            }
            char md5[40]={0};
            show_md5(global_cfgfile,  md5);
            printf("show license md5 %s\n", md5);
            exit(0);
            break;
        default:
            usage(argv[0]);
            exit(0);
        }
    }

    return ;
}



int main(int argc, char **argv)
{
    char buf[128]={0}, key[128]={0};
    int n=0 ,ret=0;
    net_iface iface;
    struct disk_info dinfo;
    struct hardware_info hinfo;
    
    parse(argc, argv);
    //
    memset(&hinfo, 0, sizeof(struct hardware_info));
    get_license_info(global_cfgfile, &hinfo); //当前获取需要查询的硬件列表.

    if( (ret=getCpuUUID(buf)) != 1){
        printf("getCpuUUID failed\n");
    }
    for(n=0; ret==1 && n<hinfo.cpumask; n++) //填充到 结构体中 cpu[][]中.
    {
        snprintf(hinfo.cpu[n], sizeof(hinfo.cpu[n])-1, "%s", buf);
    }

    memset(&dinfo, 0, sizeof(dinfo));
    ret=getDiskUUID(&dinfo ); //非0 表示失败.
    if(ret==1){
        for(n=0; n< dinfo.mask; n++){
            snprintf(hinfo.hdd[n], sizeof(hinfo.hdd[0])-1, "%s", dinfo.dinfoptr[n]);
        }
    }else{
        printf("getDiskUUID failed\n");
    }
    
    memset(&iface, 0, sizeof(net_iface));
    ret=getNetUUID(&iface);
    if(ret==1){
        for(n=0; n<iface.mask; n++){
            snprintf(hinfo.nic[n], sizeof(hinfo.nic[0])-1, "%s", iface.nicptr[n]);
        }
    }else{
        printf("getNetUUID failed\n");
    }
    
    memset(buf, 0, sizeof(buf));
    //依据注册时间(firsttime), 判断license 是否已经注册过.
    if((ret = find_entry_value(global_cfgfile, "valid.info", "firsttime", buf, sizeof(buf)-1))==1)
    {
        if(buf && strlen(buf)>1){
            printf("license already register from %s\n", buf);
        }else{
            set_license_info(global_cfgfile, &hinfo);
        }
    }
    else 
    { //没有找到entry value .则认为 license 还没有注册.
        set_license_info(global_cfgfile, &hinfo);
    }

    //判断license 是否过期.
    ret = license_time_is_valid(global_cfgfile, NULL, NULL);
    if(ret==1){
        printf("license is valid %d\n", ret);
    }else{
        printf("license is expired %d\n", ret);
    }

    //判断硬件是否发生改变.
    memset(buf, 0, sizeof(buf));
    ret = hardware_is_change(global_cfgfile, &hinfo, buf, sizeof(buf)-1);
    if(ret==1){
        printf("hardware is chanage :[%s]\n", buf);
    }else{
        printf("hardware is not change\n");
    }

    //stegano md5 to license file.
    stegano_md5(global_cfgfile_md5);
    printf("already set md5 to license file ok\n");

    return 0;
}

