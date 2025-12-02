#ifndef __DETECT_TIDB_H__
#define __DETECT_TIDB_H__

#include "cJSON.h"

/* 调试宏，发布时记得注释掉着两行 */
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* 规则结构 */
typedef struct DetectTidbData_ {
	uint8_t full_hit;      //兜底规则
	uint8_t full_hit_key;  //是否解析成功标志

	/* 下面定义与 tx 结构体相同的私有字段，用于规则匹配 */
	//uint8_t tidb_ts;      //tidb协议的传输类型，兜底规则一律填 255 其他协议也一样
	//uint8_t tidb_ts_key;  //是否解析成功标志
} DetectTidbData;


/* 注册规则匹配相关函数 */
void DetectTidbRegister(void);

#endif /* __DETECT_TIDB_H__ */
