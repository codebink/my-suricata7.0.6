/*****************************
 *FUNC:
 *
 *  该工具license_judge 用于判断硬件是否与 license.cfg 注册信息匹配.
 *
 *最终结果文件中保存如下信息：
 *  PRISM_LICENSE_VALID       值为 1 表示license 正常.  0 表示license无效, 不正常.
 *  PRISM_LICENSE_DATE_EXPIRE 值为 1 表示日期过期.,     0 表示日期正常..
 *  PRISM_LICENSE_HW_CHANGE   值为 1 表示硬件发生改动,  0表示注册硬件信息正常.
 * **************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <libconfig.h>
#include "system_info.h"


//默认取当前目录下 ./license.cfg 文件.
char global_cfgfile[1024]={"/opt/license4.0/license.cfg"};
char global_resultfile[1024]={"/opt/license4.0/license_valid_result"};
char global_cfgfile_md5[1024]={"/opt/license4.0/.prism"};
int  global_flag=0;
extern int global_flag;

void usage(char *arg)
{
    printf("license tools for prism. v1.0\n");
    printf("help        -h  help\n");
    printf("quiet       -q  quiet mode\n");
    printf("show        -s  show license info\n");
    printf("result      -r  get license_valid_result file path\n");
    printf("cfgfile     -f  set license file path. default current path ./license.cfg\n");
    printf("show_md5    -m  show license file md5\n");
    printf("\n");
    exit(0);
}

int stegano_md5_show(char *cfgfile, char *md5, int len)
{
    int ret=-1;
    FILE *infp=NULL, *outfp=NULL;
    char tmpfile[]= "/tmp/.prism_XXXXXX";

    if(!cfgfile || !md5)
    {
        printf("%s %d param error\n", __FUNCTION__, __LINE__);
        return ret;
    }
    if( access(cfgfile, F_OK) !=0 )
    {
      printf("license file %s not find\n", cfgfile);
      return ret;
    }
    int fd = mkstemp(tmpfile);
    if(fd<0){
        printf("%s %d mkstemp failed\n",__FUNCTION__, __LINE__);
        return ret;
    }
    if((outfp=fdopen(fd, "w"))==NULL){
        printf("%s %d %s failed\n", __FUNCTION__, __LINE__, tmpfile);
        return ret;
    } 
    if((infp=fopen(cfgfile, "r"))==NULL){
        printf("%s %d %s failed\n", __FUNCTION__, __LINE__, cfgfile);
        return ret;
    } 
    
    if(message_extract(infp, outfp)) // 1:success.
    {
        fflush(outfp);
        fclose(outfp);
        if((outfp = fopen(tmpfile, "r"))==NULL)
        {
            printf("%s %d reopen %s failed \n",__FUNCTION__, __LINE__, tmpfile);
            return ret;
        }
        if(fgets(md5, len, outfp)!=NULL)
        {
            ret=1;
        }
    }

    unlink(tmpfile);

    fclose(infp);
    fclose(outfp);
    return ret;
}

/***
 *FUNC:
 *  检查md5 是否一致.
 *  返回值：
 *  md5 正常，返回 1，不一致返回 -1.
 * */
int check_md5(char *val)
{
    int ret=-1;
    char md5[40]={0}, curmd5[40]={0};
    if(stegano_md5_show(global_cfgfile_md5, md5, sizeof(md5)) == 1) //获取 .prism 文件中的license md5值.
    {
       show_md5(global_cfgfile, curmd5);
       if(strncmp(md5, curmd5, strlen(md5))==0)
       {
           //printf("MD5 is valid\n");
           ret = 1;
       }
    }
    if(val){
        snprintf(val, 33, "%s", md5);
    }
    return ret;
}

//参数解析..
void parse(int argc, char **argv)
{
    char ch;
    int option_index=0;

    struct option long_options[]={
            {"help  ", no_argument, NULL, 'h'},
            {"quiet",  no_argument, NULL, 'q'},
            {"show", no_argument, NULL, 's'},
            {"result", no_argument, NULL, 'r'},
            {"cfgfile", required_argument, NULL, 'f'},
            {"md5", optional_argument, NULL, 'm'},
            {0,0,0,0}
    };
    while((ch=getopt_long(argc, argv, "hqsr:mf:", long_options, &option_index)) !=-1 )
    {
        int option_index=0;
        switch(ch)
        {
        case 'h':
        case '?':
            usage(argv[0]);
            global_flag=0;
            break;
        case 's':
            show_license(global_cfgfile);
            global_flag=0;
            break;
        case 'q':
            global_quiet = 1;
            global_flag=0;
            break;
        case 'f':
            if(optarg )
            {
                global_flag=1;
                snprintf(global_cfgfile, sizeof(global_cfgfile)-1, "%s", optarg);
            }
            break;
        case 'm':
            if(optarg)
            {
                snprintf(global_cfgfile_md5, sizeof(global_cfgfile_md5)-1, "%s", optarg);
            }
            char buf[128]={0};
            check_md5(buf);
            printf("%s\n",buf);
            exit(0);
        case 'r':
            if(optarg )
            {
                global_flag=1;
                snprintf(global_resultfile, sizeof(global_resultfile)-1, "%s", optarg);
            }
            break;
        default:
            usage(argv[0]);
            global_flag=0;
            break;
        }
    }

    return ;
}

/*******************
 *FUNC:
 *  mode == 1 默认模式，将在 /etc/prism/生成 验证结果文件 license_valid_result
 *  mode == 0 静默模式，将在 stdout 输出结果.
 *Return:
 *  验证通过返回 1
 *  验证失败返回 -1
 *NOTICE:
 *  可以仅仅通过返回值判断，详细验证结果可以在 /etc/prism/license_valid_result 中查看.
 * ****************/
int check_license_valid(int mode)
{
    char buf[128]={0},  firsttime[128]={0}; 
    int n=0 ,ret=0, validday, resultflag=-1;
    net_iface iface;
    struct disk_info dinfo;
    struct hardware_info hinfo;

    int isexpire=0, ishd_change=0, ismd5_change=0;

    if(mode ==0){
        global_quiet = 0; 
        global_flag=1;
    }else if(mode == 1){
        //静默模式. 
        global_quiet = 1; 
    }

    //parse(argc, argv);
    //if(argc==1){ //默认没有参数输入，则输出license_result 到当前目录下.
    //  global_flag=1;
    //}

    memset(&hinfo, 0, sizeof(struct hardware_info));
    get_license_info(global_cfgfile, &hinfo);

    if( (ret=getCpuUUID(buf)) != 1){
        printf("getCpuUUID failed\n");
    }
    for(n=0; ret==1 && n<hinfo.cpumask; n++) //填充到 结构体中 cpu[][]中.
    {
        snprintf(hinfo.cpu[n], sizeof(hinfo.cpu[n])-1, "%s", buf);
    }

    memset(&dinfo, 0, sizeof( dinfo));
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
    //判断license 是否过期.
    ret = license_time_is_valid(global_cfgfile, firsttime, &validday);
    if(ret==1){
        isexpire=0;
        if(global_quiet != 1)
        printf( "license time is valid %d\n", ret);
    }else{
        isexpire=1;
        if(global_quiet != 1)
        printf( "license time is expired %d\n", ret);
    }

    //判断硬件是否发生改变.
    memset(buf, 0, sizeof(buf));
    ret = hardware_is_change(global_cfgfile, &hinfo, buf, sizeof(buf)-1);
    if(ret==1){
        ishd_change=1;
        if(global_quiet != 1)
        printf("hardware is chanage :[%s]\n", buf);
    }else{
        ishd_change=0;
        if(global_quiet != 1)
        printf("hardware is not change\n");
    }

    //判断MD5 是否发生改变.
    ret = check_md5(buf);
    if(ret==-1) { 
        ismd5_change=1;  //md5 无效.
        if(global_quiet != 1)
            printf("md5 is chanage \nlicense is invalid\n");
    }else{
        ismd5_change=0; //md5 有效.
        if(global_quiet != 1)
        printf("md5 is valid\n");
    }

    FILE *fp=NULL;
    if(global_flag==1 || global_quiet==1)
    {

        if(global_quiet == 1)
        {
            fp=fopen(global_resultfile, "w");
            //fp = stderr; //如果用stderr ，则 prismscan_utils.c中必须设置dup2 ,popen 才能fgets收到输出.
        }
        else
            fp = stdout;     

        if(fp)
        {
            if(isexpire==0 && ishd_change==0 && ismd5_change==0) //0 有效期正常，0 硬件没改动. md5 没有改动.
            {
                fprintf(fp, "PRISM_LICENSE_VALID:%d\n",  1);
                resultflag=1; //验证通过。
            }else{
                fprintf(fp, "PRISM_LICENSE_VALID:%d\n",  0);
                resultflag=-1; //验证失败不通过.。
            }
            fprintf(fp, "PRISM_LICENSE_DATE_EXPIRE:%d\n", isexpire);
            fprintf(fp, "PRISM_LICENSE_HW_CHANGE:%d\n",  ishd_change);
            fprintf(fp, "FRISTTIME:%s\nVALIDDAYS:%d\n", firsttime, validday);
            fprintf(fp, "PRISM_MD5_VALID:%d\n", ismd5_change==0 ? 1:0);

            fflush(fp);
            if(global_quiet != 1)
                fclose(fp); 
        }
    }

    return resultflag;
}

