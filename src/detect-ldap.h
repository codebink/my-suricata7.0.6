#ifndef __DETECT_LDAP_H__
#define __DETECT_LDAP_H__

#include "app-layer-ldap.h"

#include "cJSON.h"

/* 调试宏，发布时记得注释掉着两行 */
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* 规则结构 */
typedef struct DetectLdapData_ {
	uint8_t full_hit;      //兜底规则
	uint8_t full_hit_key;  //是否解析成功标志

	/* 下面定义与 tx 结构体相同的私有字段，用于规则匹配 */
	uint8_t user_name[LDAP_VALUE_LEN65];         //用户名
	uint8_t domain_name[LDAP_VALUE_LEN65];       //域名
	uint8_t passwd[LDAP_VALUE_LEN65];            //密码，只有在简 simple 单认证模式时，才能取出密码
	uint8_t req_name[LDAP_VALUE_LEN65];          //请求名称，只有基于 TLS 协议的 LDAP 才会使用该字段
	
	uint8_t user_name_key;    //1 解析成功，下面同
	uint8_t domain_name_key;
	uint8_t passwd_key;
	uint8_t req_name_key;

} DetectLdapData;


/* 注册规则匹配相关函数 */
void DetectLdapRegister(void);

#endif /* __DETECT_LDAP_H__ */
