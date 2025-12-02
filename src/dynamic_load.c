
/***********************
 *FUNC:
 * 动态加载解析插件函数.for libxxx.so
 *
 * ********************/

#include "suricata-common.h"
#include "util-file.h"
#include "util-config.h"
#include "debug_log.h"

#include "dynamic_load.h"
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

//解析库位置.
#define PLUGIN_PATH "/opt/license4.0/lib/"

//解析插件协议类型.配置文件.
#define PLUGIN_CONF "app-layer.protocols"
#define PLUGIN_STR_MAX_LEN  128



/*************
 *FUNC:
 * 动态调用解析so
 *
 * dkey 取值: 
 * RegisterDBParsers_key -- 表示加载 RegisterDBParsers for app-layer-parser.c  AppLayerParserRegisterProtocolParsers注册.
 * OutputDBLogRegister_key -- 表示加载 OutputDBLogRegister for Output.c OutputRegisterLoggers注册.
 *
 *Return:
 * 1：成功， other failed.
 * **********/
int Dynamic_Load(enum dynamic_key dkey)
{
    typedef void (*AppLayerParserRegisterFunc)(void);
    AppLayerParserRegisterFunc  reg_func = NULL;
    ConfNode *lnode = NULL;
    int num = 0;
    char plugin_libname[ PLUGIN_STR_MAX_LEN ]={0};
    char plugin_regfunc[ PLUGIN_STR_MAX_LEN ]={0};
    void *so_handler =NULL;


    ConfNode *node = ConfGetNode(PLUGIN_CONF);
    if(unlikely(node ==NULL) ){
        return -1;
    }

    TAILQ_FOREACH(lnode, &node->head, next){
        char *plugin_name =NULL;
        char *regfunc_name = NULL;

        ConfGetChildValue(lnode, "reg-so", (const char**)&plugin_name );
        ConfGetChildValue(lnode, "reg-func", (const char**)&regfunc_name);
        memset(plugin_libname, 0, sizeof(plugin_libname));
        if(plugin_name !=NULL){
            snprintf(plugin_libname, sizeof(plugin_libname), "%s/%s", PLUGIN_PATH, plugin_name);
        } else{
            plugin_name = lnode->name;
            snprintf(plugin_libname, sizeof(plugin_libname), "%s/lib%s.so", PLUGIN_PATH, plugin_name);
        }

        if(!(so_handler = dlopen(plugin_libname, RTLD_LAZY)))
        {
            SCLogNotice("%s %d dlopen - [%s]\n",__FUNCTION__, __LINE__, dlerror() );
            continue;
        }

        if(regfunc_name !=NULL) {
            snprintf(plugin_regfunc, sizeof(plugin_regfunc), "%s", regfunc_name);
        }else{
            switch (dkey) {
            case RegisterDBParsers_Key:
                snprintf(plugin_regfunc, sizeof(plugin_regfunc), "Register%sParsers", plugin_name); //for DB RegisterMysqlParsers.
                break;
            case OutputDBLogRegister_Key:
                snprintf(plugin_regfunc, sizeof(plugin_regfunc), "Json%sLogRegister", plugin_name); //for DB JsonmysqlLogRegister    
                break;
            default:
                SCLogDebug("%s %d %s dkey:%d not find\n", __FUNCTION__, __LINE__, plugin_name, dkey);
                break;
            }
        }
        reg_func = (AppLayerParserRegisterFunc) dlsym(so_handler, plugin_regfunc);
        if(unlikely(reg_func ==NULL)){
            //DEBUG_DLOG("%s %d dlsym - [%s]\n", __FUNCTION__, __LINE__, plugin_regfunc);
            continue;
        }
        
        //循环调用所有的DB 注册函数.
        (*reg_func)(); //调用注册函数.
        SCLogNotice("register protocol[%d]: %s success ...\n", num, plugin_name);
        num++;
    }    

    return 1;
}

int license_load_check(const char *so_path, const char *so_name, const char *prog_name)
{
    int ret=-1;
    void *so_handler =NULL;
    char plugin_libname[ PLUGIN_STR_MAX_LEN ]={0};
    char plugin_regfunc[ PLUGIN_STR_MAX_LEN ]={0};
    typedef int (*License_Valice_Func)(int);
    License_Valice_Func  reg_func = NULL;

    if(!so_path || !so_name || !prog_name){
        printf("%s %d license_load param error so_path not find\n",__FUNCTION__, __LINE__ );
        return ret;
    }

    snprintf(plugin_libname, sizeof(plugin_libname)-1, "%s/%s",  PLUGIN_PATH, so_name);

    if(!(so_handler = dlopen(plugin_libname, RTLD_LAZY)))
    {
        printf("%s %d dlopen - [%s]\n",__FUNCTION__, __LINE__, dlerror() );
        return ret;
    }
    snprintf(plugin_regfunc, sizeof(plugin_regfunc)-1, "%s", prog_name); //for DB RegisterMysqlParsers.
    reg_func = (License_Valice_Func) dlsym(so_handler, plugin_regfunc);
    if(unlikely(reg_func ==NULL)){
       printf("%s %d dlsym - [%s]\n", __FUNCTION__, __LINE__, plugin_regfunc);
       return ret;
    }

    ret = (*reg_func)(1); //调用check_license_valid()函数.
    
    printf("check license valid result:[%d]:  ...\n", ret);

    return ret;
}

