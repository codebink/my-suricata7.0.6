#ifndef __APP_LAYER_KRB5_H__
#define __APP_LAYER_KRB5_H__

#include "rust.h"
#if __BYTE_ORDER == __BIG_ENDIAN
#include "util-byte.h"
#endif

#include <iconv.h>

#define KRB5_ENABLED_NODE "app-layer.protocols.krb5.enabled"
#define KRB5_LOG_NODE "app-layer.protocols.krb5.log"

/* 调试宏，发布时记得注释掉下面一行 */
//#define ENABLE_DECODER_DEBUG
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* krb5 协议使用 TCP/UDP 协议，默认端口 */
#define KRB5_DEFAULT_PORT_TCP "88"
#define KRB5_DEFAULT_PORT_UDP "88"

/* 消息的最小大小。对于某些协议，这可能是一个头的大小 */
#define KRB5_MIN_FRAME_LEN 24
#define KRB5_PROTO_NAME_LEN 16

#define KRB5_VALUE_LEN257 257
#define KRB5_VALUE_LEN65 65
#define KRB5_VALUE_LEN129 129

/* TCP 特征 krb-as-req(10) 6A 82 共 23 字节判断宏 */
#define TCP_IS_AS_REQ10_6A82(P)  ( ( (0x00 == (unsigned int)(*(P+0))) \
						&& (0x00 == (unsigned int)(*(P+1))) \
						&& (0x6a == (unsigned int)(*(P+4))) \
						&& (0x82 == (unsigned int)(*(P+5))) \
						&& (0x30 == (unsigned int)(*(P+8))) \
						&& (0x82 == (unsigned int)(*(P+9))) \
						&& (0xa1 == (unsigned int)(*(P+12))) \
						&& (0x03 == (unsigned int)(*(P+13))) \
						&& (0x02 == (unsigned int)(*(P+14))) \
						&& (0x01 == (unsigned int)(*(P+15))) \
						&& (0x05 == (unsigned int)(*(P+16))) \
						&& (0xa2 == (unsigned int)(*(P+17))) \
						&& (0x03 == (unsigned int)(*(P+18))) \
						&& (0x02 == (unsigned int)(*(P+19))) \
						&& (0x01 == (unsigned int)(*(P+20))) \
						&& (0x0a == (unsigned int)(*(P+21))) \
						&& (0xa3 == (unsigned int)(*(P+22))) \
						) ? 1 : 0)	

/* TCP 特征 krb-as-req(10) 6A 81 共 21 字节判断宏 */
#define TCP_IS_AS_REQ10_6A81(P)  ( ( (0x00 == (unsigned int)(*(P+0))) \
						&& (0x00 == (unsigned int)(*(P+1))) \
						&& (0x6a == (unsigned int)(*(P+4))) \
						&& (0x81 == (unsigned int)(*(P+5))) \
						&& (0x30 == (unsigned int)(*(P+7))) \
						&& (0x81 == (unsigned int)(*(P+8))) \
						&& (0xa1 == (unsigned int)(*(P+10))) \
						&& (0x03 == (unsigned int)(*(P+11))) \
						&& (0x02 == (unsigned int)(*(P+12))) \
						&& (0x01 == (unsigned int)(*(P+13))) \
						&& (0x05 == (unsigned int)(*(P+14))) \
						&& (0xa2 == (unsigned int)(*(P+15))) \
						&& (0x03 == (unsigned int)(*(P+16))) \
						&& (0x02 == (unsigned int)(*(P+17))) \
						&& (0x01 == (unsigned int)(*(P+18))) \
						&& (0x0a == (unsigned int)(*(P+19))) \
						&& (0xa3 == (unsigned int)(*(P+20))) \
						) ? 1 : 0)

/* UDP 特征 krb-as-req(10) 6A 82 共 19 字节判断宏 */
#define UDP_IS_AS_REQ10_6A82(P)  ( ( (0x6a == (unsigned int)(*(P+0))) \
						&& (0x82 == (unsigned int)(*(P+1))) \
						&& (0x30 == (unsigned int)(*(P+4))) \
						&& (0x82 == (unsigned int)(*(P+5))) \
						&& (0xa1 == (unsigned int)(*(P+8))) \
						&& (0x03 == (unsigned int)(*(P+9))) \
						&& (0x02 == (unsigned int)(*(P+10))) \
						&& (0x01 == (unsigned int)(*(P+11))) \
						&& (0x05 == (unsigned int)(*(P+12))) \
						&& (0xa2 == (unsigned int)(*(P+13))) \
						&& (0x03 == (unsigned int)(*(P+14))) \
						&& (0x02 == (unsigned int)(*(P+15))) \
						&& (0x01 == (unsigned int)(*(P+16))) \
						&& (0x0a == (unsigned int)(*(P+17))) \
						&& (0xa3 == (unsigned int)(*(P+18))) \
						) ? 1 : 0)	

/* UDP 特征 krb-as-req(10) 6A 81 共 17 字节判断宏 */
#define UDP_IS_AS_REQ10_6A81(P)  ( ( (0x6a == (unsigned int)(*(P+0))) \
						&& (0x81 == (unsigned int)(*(P+1))) \
						&& (0x30 == (unsigned int)(*(P+3))) \
						&& (0x81 == (unsigned int)(*(P+4))) \
						&& (0xa1 == (unsigned int)(*(P+6))) \
						&& (0x03 == (unsigned int)(*(P+7))) \
						&& (0x02 == (unsigned int)(*(P+8))) \
						&& (0x01 == (unsigned int)(*(P+9))) \
						&& (0x05 == (unsigned int)(*(P+10))) \
						&& (0xa2 == (unsigned int)(*(P+11))) \
						&& (0x03 == (unsigned int)(*(P+12))) \
						&& (0x02 == (unsigned int)(*(P+13))) \
						&& (0x01 == (unsigned int)(*(P+14))) \
						&& (0x0a == (unsigned int)(*(P+15))) \
						&& (0xa3 == (unsigned int)(*(P+16))) \
						) ? 1 : 0)
						
#define KRB5_GET_VALUE_HOST32(P) (((uint32_t)(*(P+0)) << 24)\
							+ ((uint32_t)(*(P+1)) << 16)\
							+ ((uint32_t)(*(P+2)) << 8)\
							+ *(P+3))

#define KRB5_GET_VALUE_HOST8(P) ((uint8_t)(*(P)))	


/* 查询 list 结构 */
typedef struct _krb5_info_list {
	int code;
	const char *value;
}krb5_info_list;


/* 用于重组的缓冲 buff */
typedef struct Krb5Buffer_ {
    uint8_t *buffer;
    size_t   size;
    int      len;
    int      offset;
} Krb5Buffer;


/* krb5 transaction tx 私有结构, 用于存储每个请求或响应解析的字段，用于 规则匹配 与 json 日志发送 */
typedef struct Krb5Transaction_ {
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

    bool is_request;                  //方向
    struct Krb5State_ *krb5;          //可不包含，包含也有好处，就是在 tx 中能够看到 state
	char proto[KRB5_PROTO_NAME_LEN];  //传输层协议名称，如 tcp、udp

    uint8_t done;                     //完成标志，预留，未使用           
    uint8_t complete;                 //进度标志，预留，未使用 

	uint8_t cname[KRB5_VALUE_LEN129];         //用户名
	uint8_t realm[KRB5_VALUE_LEN129];         //域名
	uint8_t host[KRB5_VALUE_LEN129];          //主机名
	
	uint8_t cname_key;    //1 解析成功，下面同
	uint8_t realm_key;
	uint8_t host_key;


	uint8_t krb5_match_flag;           //防止重复发日志开关
/******************************************************* 私有数据 end *******************************************************/

    AppLayerTxData tx_data;   //必须包含，应用层事务数据核心结构
    uint64_t tx_num;          //必须包含，tx 数量，等于 transaction_max

    TAILQ_ENTRY(Krb5Transaction_) next;
} Krb5Transaction;

/* flow krb5 state 流状态，生命周期与流相同 */
typedef struct Krb5State_ {
    AppLayerStateData state_data;              //必须包含，相当于啊 session 的结构，伴随流的生命周期
    TAILQ_HEAD(, Krb5Transaction_) tx_list;    //必须包含，用于存储会话 tx 的 list, 架构中，请求和响应共用一个 tx, detect 结束后就彻底释放了, list 中只有一个 tx
    uint64_t transaction_max;                  //必须包含，list 中的 tx 个数，本架构中永远不超过 1

/******************************************************* 私有数据 start *******************************************************/
	 
    Krb5Transaction *curr;                     //当前操纵的 tx，注意不要释放这个否则段错误，自有释放的地方

    Krb5Buffer request_buffer;                 //请求缓冲区，根据需求使用，不需要缓存分片时，不要用
    Krb5Buffer response_buffer;                //响应缓冲区，根据需求使用，不需要缓存分片时，不要用
    
/******************************************************* 私有数据 end *******************************************************/


} Krb5State;


/* 原子开关 */
typedef struct Krb5Conf_ {
	SC_ATOMIC_DECLARE(int, krb5_enable);
	SC_ATOMIC_DECLARE(int, log_enable);
}Krb5Conf;

/* Reload 函数 */
void Krb5Reload(void);

/* 核心注册函数 */
void RegisterKrb5ParsersTcp(void);
void RegisterKrb5ParsersUdp(void);

#endif /* __APP_LAYER_KRB5_H__ */
