#ifndef __APP_LAYER_RADIUS_H__
#define __APP_LAYER_RADIUS_H__

#include "rust.h"
#if __BYTE_ORDER == __BIG_ENDIAN
#include "util-byte.h"
#endif

#include <iconv.h>

#define RADIUS_ENABLED_NODE "app-layer.protocols.radius.enabled"
#define RADIUS_LOG_NODE "app-layer.protocols.radius.log"

/* 调试宏，发布时记得注释掉下面一行 */
//#define ENABLE_DECODER_DEBUG
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* radius 协议使用 UDP port 1812 (计费服务使用1813) */
#define RADIUS_DEFAULT_PORT "1812"

/* 消息的最小大小。对于某些协议，这可能是一个头的大小 */
#define RADIUS_MIN_FRAME_LEN 22
#define RADIUS_PROTO_NAME_LEN 16

#define RADIUS_USER_NAME_GBK_LEN 40
#define RADIUS_USER_NAME_LEN 80
#define RADIUS_NAS_IP_LEN 16
#define RADIUS_CALL_MAC_GBK_LEN 18
#define RADIUS_CALL_MAC_LEN 36
#define RADIUS_PASSWD_UCHAR_LEN 18
#define RADIUS_PASSWD_STRING_LEN 36

/* 特征 Access-Request 判断宏 */
#define IS_RADIUS_ACCESS_REQUEST(P)  ( (0x01 == (unsigned char)(*(P+0))) ? 1 : 0)

/* 长度提取宏 */
#define RADIUS_GET_LEN_HOST8(P) ((unsigned int)(*(P)))
#define RADIUS_GET_LEN_HOST16(P) (((unsigned int)(*(P+0)) << 8) + ((unsigned int)(*(P+1))))
#define RADIUS_GET_VALUE_NET32(P) (((unsigned int)(*(P+3)) << 24)+((unsigned int)(*(P+2)) << 16)\
                         + ((unsigned int)(*(P+1)) << 8) + *(P))

/* attribute type */
enum radius_type{ 
	RADIUS_NAME_TYPE = 0x01,
	RADIUS_USER_PASSWD_TYPE = 0x02,
	RADIUS_CHAP_PASSWD_TYPE = 0x03,
	RADIUS_NAS_IP_TYPE = 0x04,
	RADIUS_NAS_PORT_TYPE = 0x05,
	RADIUS_CALLED_TYPE = 0x1e,
	RADIUS_CALLING_TYPE = 0x1f,
};


/* 查询 list 结构 */
typedef struct _radius_info_list {
	int code;
	const char *value;
}radius_info_list;


/* 用于重组的缓冲 buff */
typedef struct RadiusBuffer_ {
    uint8_t *buffer;
    size_t   size;
    int      len;
    int      offset;
} RadiusBuffer;


/* radius transaction tx 私有结构, 用于存储每个请求或响应解析的字段，用于 规则匹配 与 json 日志发送 */
typedef struct RadiusTransaction_ {
#ifdef ENABLE_DECODER_DEBUG
		char src_ip[INET6_ADDRSTRLEN];	//源IP 最大长度 46
		char dst_ip[INET6_ADDRSTRLEN];	//目的IP 同上
		uint16_t src_port;				//源 port
		uint16_t dst_port;				//目的 port
		uint8_t src_mac[20];			//源 MAC
		uint8_t dst_mac[20];			//目的 MAC
	
		char time_buff[32]; 			//时间（2021/09/22 12:21:30）
#endif


/******************************************************* 私有数据 start *******************************************************/

    bool is_request;                      //方向
    struct RadiusState_ *radius;          //可不包含，包含也有好处，就是在 tx 中能够看到 state
	char proto[RADIUS_PROTO_NAME_LEN];    //传输层协议名称，如 tcp、udp

    uint8_t done;                     //完成标志，预留，未使用           
    uint8_t complete;                 //进度标志，预留，未使用 


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


	uint8_t radius_match_flag;           //防止重复发日志开关
/******************************************************* 私有数据 end *******************************************************/

    AppLayerTxData tx_data;   //必须包含，应用层事务数据核心结构
    uint64_t tx_num;          //必须包含，tx 数量，等于 transaction_max

    TAILQ_ENTRY(RadiusTransaction_) next;
} RadiusTransaction;

/* flow radius state 流状态，生命周期与流相同 */
typedef struct RadiusState_ {
    AppLayerStateData state_data;              //必须包含，相当于啊 session 的结构，伴随流的生命周期
    TAILQ_HEAD(, RadiusTransaction_) tx_list;    //必须包含，用于存储会话 tx 的 list, 架构中，请求和响应共用一个 tx, detect 结束后就彻底释放了, list 中只有一个 tx
    uint64_t transaction_max;                  //必须包含，list 中的 tx 个数，本架构中永远不超过 1

/******************************************************* 私有数据 start *******************************************************/
	 
    RadiusTransaction *curr;                     //当前操纵的 tx，注意不要释放这个否则段错误，自有释放的地方

    RadiusBuffer request_buffer;                 //请求缓冲区，根据需求使用，不需要缓存分片时，不要用
    RadiusBuffer response_buffer;                //响应缓冲区，根据需求使用，不需要缓存分片时，不要用
    
/******************************************************* 私有数据 end *******************************************************/


} RadiusState;


/* 原子开关 */
typedef struct RadiusConf_ {
	SC_ATOMIC_DECLARE(int, radius_enable);
	SC_ATOMIC_DECLARE(int, log_enable);
}RadiusConf;

/* Reload 函数 */
void RadiusReload(void);

/* 核心注册函数 */
void RegisterRadiusParsers(void);

#endif /* __APP_LAYER_RADIUS_H__ */
