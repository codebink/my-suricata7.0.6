#ifndef __DYNAMIC_LOAD_H_
#define __DYNAMIC_LOAD_H_

enum dynamic_key {
    RegisterDBParsers_Key,
    OutputDBLogRegister_Key,

    Unknow_Key
};

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
int Dynamic_Load(enum dynamic_key dkey);

/**************
 *FUNC:
 *  动态调用liblicense_valid 验证。
 *
 * so_path : /opt/license4.0/lib/
 * so_name : liblicense_valid.so
 * prog_name: 程序名称.
 *
 * Result:
 * 验证通过返回1
 * 验证失败返回-1
 * ***********/
int license_load_check(const char *so_path, const char *so_name, const char *prog_name);

#endif

