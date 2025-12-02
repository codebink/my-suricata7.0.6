/*****************************
 *FUNC:
 *
 *  ¸Ã¹¤¾ßlicense_judge ÓÃÓÚÅÐ¶ÏÓ²¼þÊÇ·ñÓë license.cfg ×¢²áÐÅÏ¢Æ¥Åä.
 *
 *×îÖÕ½á¹ûÎÄ¼þÖÐ±£´æÈçÏÂÐÅÏ¢£º
 *  PRISM_LICENSE_VALID       ÖµÎª 1 ±íÊ¾license Õý³£.  0 ±íÊ¾licenseÎÞÐ§, ²»Õý³£.
 *  PRISM_LICENSE_DATE_EXPIRE ÖµÎª 1 ±íÊ¾ÈÕÆÚ¹ýÆÚ.,     0 ±íÊ¾ÈÕÆÚÕý³£..
 *  PRISM_LICENSE_HW_CHANGE   ÖµÎª 1 ±íÊ¾Ó²¼þ·¢Éú¸Ä¶¯,  0±íÊ¾×¢²áÓ²¼þÐÅÏ¢Õý³£.
 * **************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <libconfig.h>
#include "system_info.h"


//Ä¬ÈÏÈ¡µ±Ç°Ä¿Â¼ÏÂ ./license.cfg ÎÄ¼þ.
char global_cfgfile[1024]={"./license.cfg"};
char global_resultfile[1024]={"./license_valid_result"};
char global_cfgfile_md5[1024]={"./.prism"};
int  global_flag=0;
extern int global_flag;

void usage(char *arg)
{
    printf("license tools for prism. v1.0\n");
    printf("help        -h  help\n");
    printf("quiet       -q  quiet mode\n");
    printf("show        -s  show license info\n");
    printf("result      -r  get license_valid_result file path. default ./license_valid_result\n");
    printf("cfgfile     -f  set license file path. default current path ./license.cfg\n");
    printf("show_md5    --md5  show license file md5. default --m=./license.cfg\n");
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
 *  ¼ì²émd5 ÊÇ·ñÒ»ÖÂ.
 *  ·µ»ØÖµ£º
 *  md5 Õý³££¬·µ»Ø 1£¬²»Ò»ÖÂ·µ»Ø -1.
 * */
int check_md5(char *val)
{
    int ret=-1;
    char md5[40]={0}, curmd5[40]={0};
    if(stegano_md5_show(global_cfgfile_md5, md5, sizeof(md5)) == 1) //»ñÈ¡ .prism ÎÄ¼þÖÐµÄlicense md5Öµ.
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

//²ÎÊý½âÎö..
void parse(int argc, char **argv)
{
    char ch, tmp[1024]={0};
    int option_index=0;

    if(argc <2){
        usage(argv[0]);
        exit(0);
    }

    struct option long_options[]={
            {"help  ", no_argument, NULL, 'h'},
            {"quiet",  no_argument, NULL, 'q'},
            {"show", no_argument, NULL, 's'},
            {"result", no_argument, NULL, 'r'},
            {"cfgfile", required_argument, NULL, 'f'},
            {"md5", optional_argument, NULL, 'm'},
            {0,0,0,0}
    };
    while((ch=getopt_long(argc, argv, "hqsrmf:", long_options, &option_index)) !=-1 )
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
                char *dirpath = strdup(global_cfgfile);
                char * dname = dirname(dirpath);
                snprintf(tmp, sizeof(tmp)-1, "%s/%s", dname, basename(global_cfgfile_md5));
                snprintf(global_cfgfile_md5, sizeof(global_cfgfile_md5)-1, "%s", tmp);
                free(dirpath);
            }
            break;
        case 'm':
            if(optarg)
            {
                snprintf(global_cfgfile, sizeof(global_cfgfile)-1, "%s", optarg);
                char *dirpath = strdup(global_cfgfile);
                char * dname = dirname(dirpath);
                snprintf(tmp, sizeof(tmp)-1, "%s/%s", dname, basename(global_cfgfile_md5));
                snprintf(global_cfgfile_md5, sizeof(global_cfgfile_md5)-1, "%s", tmp);
                free(dirpath);
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


int main(int argc, char **argv)
{
    char buf[128]={0},  firsttime[128]={0}; 
    int n=0 ,ret=0, validday;
    net_iface iface;
    struct disk_info dinfo;
    struct hardware_info hinfo;

    int isexpire=0, ishd_change=0, ismd5_change=0;

    parse(argc, argv);
    if(argc==1){ //Ä¬ÈÏÃ»ÓÐ²ÎÊýÊäÈë£¬ÔòÊä³ölicense_result µ½µ±Ç°Ä¿Â¼ÏÂ.
       global_flag=1;
    }

    memset(&hinfo, 0, sizeof(struct hardware_info));
    get_license_info(global_cfgfile, &hinfo);

    if( (ret=getCpuUUID(buf)) != 1){
        printf("getCpuUUID failed\n");
    }
    for(n=0; ret==1 && n<hinfo.cpumask; n++) //Ìî³äµ½ ½á¹¹ÌåÖÐ cpu[][]ÖÐ.
    {
        snprintf(hinfo.cpu[n], sizeof(hinfo.cpu[n])-1, "%s", buf);
    }

    memset(&dinfo, 0, sizeof(dinfo));
    ret=getDiskUUID(&dinfo ); //·Ç0 ±íÊ¾Ê§°Ü.
    if(ret==1){
        for(n=0; n<dinfo.mask; n++){
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
    //ÅÐ¶Ïlicense ÊÇ·ñ¹ýÆÚ.
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

    //ÅÐ¶ÏÓ²¼þÊÇ·ñ·¢Éú¸Ä±ä.
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

    //ÅÐ¶ÏMD5 ÊÇ·ñ·¢Éú¸Ä±ä.
    ret = check_md5(buf);
    if(ret==-1) { 
        ismd5_change=1;  //md5 ÎÞÐ§.
        if(global_quiet != 1)
            printf("md5 is chanage \nlicense is invalid\n");
    }else{
        ismd5_change=0; //md5 ÓÐÐ§.
        if(global_quiet != 1)
        printf("md5 is valid\n");
    }

    FILE *fp=NULL;
    if(global_flag==1 || global_quiet==1)
    {

        if(global_quiet == 1)
        {
            fp = stdout;     
            //fp = stderr; //Èç¹ûÓÃstderr £¬Ôò prismscan_utils.cÖÐ±ØÐëÉèÖÃdup2 ,popen ²ÅÄÜfgetsÊÕµ½Êä³ö.
        }
        else
            fp=fopen(global_resultfile, "w");

        if(fp)
        {
            if(isexpire==0 && ishd_change==0 && ismd5_change==0) //0 ÓÐÐ§ÆÚÕý³££¬0 Ó²¼þÃ»¸Ä¶¯. md5 Ã»ÓÐ¸Ä¶¯.
            {
                fprintf(fp, "PRISM_LICENSE_VALID:%d\n",  1);
            }else{
                fprintf(fp, "PRISM_LICENSE_VALID:%d\n",  0);
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

    return 0;
}

