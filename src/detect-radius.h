#ifndef __DETECT_RADIUS_H__
#define __DETECT_RADIUS_H__

#include "output-json-radius.h"

#include "cJSON.h"

/* 调试宏，发布时记得注释掉着两行 */
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* 规则结构 */
typedef struct DetectRadiusData_ {
	uint8_t full_hit;      //兜底规则
	uint8_t full_hit_key;  //是否解析成功标志

	/* 下面定义与 tx 结构体相同的私有字段，用于规则匹配 */
	char user_name[RADIUS_USER_NAME_LEN];            // 用户名
	char nas_ip[RADIUS_NAS_IP_LEN];                  // NAS(网络接入服务器)IP, NAS 作为 RADIUS 客户端
	int nas_port;                                    // NAS(网络接入服务器)PORT, NAS 作为 RADIUS 客户端
	char called_station_mac[RADIUS_CALL_MAC_LEN];    // 被叫号码 MAC
	char calling_station_mac[RADIUS_CALL_MAC_LEN];   // 主叫号码 MAC
	char radius_passwd[RADIUS_PASSWD_STRING_LEN];    // passwd

	uint8_t user_name_key;             //1 解析成功，下面同
	uint8_t nas_ip_key;                
	uint8_t nas_port_key;               
	uint8_t called_station_mac_key;   
	uint8_t calling_station_mac_key;  
	uint8_t radius_passwd_key;        

} DetectRadiusData;


/* 注册规则匹配相关函数 */
void DetectRadiusRegister(void);

#endif /* __DETECT_RADIUS_H__ */
