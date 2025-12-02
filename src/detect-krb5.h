#ifndef __DETECT_KRB5_H__
#define __DETECT_KRB5_H__

#include "output-json-krb5.h"

#include "cJSON.h"

/* 调试宏，发布时记得注释掉着两行 */
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* 规则结构 */
typedef struct DetectKrb5Data_ {
	uint8_t full_hit;      //兜底规则
	uint8_t full_hit_key;  //是否解析成功标志

	/* 下面定义与 tx 结构体相同的私有字段，用于规则匹配 */
	uint8_t cname[KRB5_VALUE_LEN129];         //用户名
	uint8_t realm[KRB5_VALUE_LEN129];         //域名
	uint8_t host[KRB5_VALUE_LEN129];          //主机名
	
	uint8_t cname_key;    //1 解析成功，下面同
	uint8_t realm_key;
	uint8_t host_key;

} DetectKrb5Data;


/* 注册规则匹配相关函数 */
void DetectKrb5Register(void);

#endif /* __DETECT_KRB5_H__ */
