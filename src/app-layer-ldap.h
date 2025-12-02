#ifndef __APP_LAYER_LDAP_H__
#define __APP_LAYER_LDAP_H__

#include "rust.h"
#if __BYTE_ORDER == __BIG_ENDIAN
#include "util-byte.h"
#endif

#define LDAP_ENABLED_NODE "app-layer.protocols.ldap.enabled"
#define LDAP_LOG_NODE "app-layer.protocols.ldap.log"

/* 调试宏，发布时记得注释掉下面一行 */
//#define ENABLE_DECODER_DEBUG
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* ldap 协议使用 TCP 协议，默认端口 */
#define LDAP_DEFAULT_PORT "389"

/* 消息的最小大小。对于某些协议，这可能是一个头的大小 */
#define LDAP_MIN_FRAME_LEN 10
#define LDAP_PROTO_NAME_LEN 16
#define LDAP_VALUE_LEN257 257
#define LDAP_VALUE_LEN65 65

/* 特征 bindRequest(0) 判断宏 */
#define IS_LDAP_BIND_REQUEST(P)  ( ( (0x30 == (unsigned int)(*(P+0))) \
						&& (0x02 == (unsigned int)(*(P+2))) \
						&& (0x01 == (unsigned int)(*(P+3))) \
						&& (0x60 == (unsigned int)(*(P+5))) \
						&& (0x02 == (unsigned int)(*(P+7))) \
						&& (0x01 == (unsigned int)(*(P+8))) \
						&& ((0x03 == (unsigned int)(*(P+9))) || (0x02 == (unsigned int)(*(P+9)))) \
						) ? 1 : 0)	

/* 特征 extendedReq(23) 判断宏 */
#define IS_LDAP_EXTENDED_REQ(P)  ( ( (0x30 == (unsigned int)(*(P+0))) \
						&& (0x02 == (unsigned int)(*(P+2))) \
						&& (0x01 == (unsigned int)(*(P+3))) \
						&& (0x77 == (unsigned int)(*(P+5))) \
						&& (0x80 == (unsigned int)(*(P+7))) \
						) ? 1 : 0)	
						
#define LDAP_GET_VALUE_HOST32(P) (((uint32_t)(*(P+0)) << 24)\
							+ ((uint32_t)(*(P+1)) << 16)\
							+ ((uint32_t)(*(P+2)) << 8)\
							+ *(P+3))

#define LDAP_GET_VALUE_HOST8(P) ((uint8_t)(*(P)))	


/* 查询 list 结构 */
typedef struct _ldap_info_list {
	int code;
	const char *value;
}ldap_info_list;


/* 用于重组的缓冲 buff */
typedef struct LdapBuffer_ {
    uint8_t *buffer;
    size_t   size;
    int      len;
    int      offset;
} LdapBuffer;


/* ldap transaction tx 私有结构, 用于存储每个请求或响应解析的字段，用于 规则匹配 与 json 日志发送 */
typedef struct LdapTransaction_ {
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
    struct LdapState_ *ldap;          //可不包含，包含也有好处，就是在 tx 中能够看到 state
	char proto[LDAP_PROTO_NAME_LEN];  //传输层协议名称，如 tcp、udp

    uint8_t done;                     //完成标志，预留，未使用           
    uint8_t complete;                 //进度标志，预留，未使用 

	uint8_t user_name[LDAP_VALUE_LEN65];         //用户名
	uint8_t domain_name[LDAP_VALUE_LEN65];       //域名
	uint8_t passwd[LDAP_VALUE_LEN65];            //密码，只有在简 simple 单认证模式时，才能取出密码
	uint8_t req_name[LDAP_VALUE_LEN65];          //请求名称，只有基于 TLS 协议的 LDAP 才会使用该字段
	
	uint8_t user_name_key;                       //1 解析成功，下面同
	uint8_t domain_name_key;
	uint8_t passwd_key;
	uint8_t req_name_key;
  
	uint8_t hit_key;                             //规则命中标志


	uint8_t ldap_match_flag;           //防止重复发日志开关
/******************************************************* 私有数据 end *******************************************************/

    AppLayerTxData tx_data;   //必须包含，应用层事务数据核心结构
    uint64_t tx_num;          //必须包含，tx 数量，等于 transaction_max

    TAILQ_ENTRY(LdapTransaction_) next;
} LdapTransaction;

/* 存储整个会话解析数据的核心结构 */
typedef struct curr_ldap_info_ {
	/*****************************************私有数据 Start *********************************************/

	uint8_t user_name[LDAP_VALUE_LEN65];         //用户名
	uint8_t domain_name[LDAP_VALUE_LEN65];       //域名
	uint8_t passwd[LDAP_VALUE_LEN65];            //密码，只有在简 simple 单认证模式时，才能取出密码
	uint8_t req_name[LDAP_VALUE_LEN65];          //请求名称，只有基于 TLS 协议的 LDAP 才会使用该字段
	
	uint8_t user_name_key;    //1 解析成功，下面同
	uint8_t domain_name_key;
	uint8_t passwd_key;
	uint8_t req_name_key;
  
	/*****************************************私有数据 END ***********************************************/
} curr_ldap_info;


/* flow ldap state 流状态，生命周期与流相同 */
typedef struct LdapState_ {
    AppLayerStateData state_data;              //必须包含，相当于啊 session 的结构，伴随流的生命周期
    TAILQ_HEAD(, LdapTransaction_) tx_list;    //必须包含，用于存储会话 tx 的 list, 架构中，请求和响应共用一个 tx, detect 结束后就彻底释放了, list 中只有一个 tx
    uint64_t transaction_max;                  //必须包含，list 中的 tx 个数，本架构中永远不超过 1

/******************************************************* 私有数据 start *******************************************************/
	 
    LdapTransaction *curr;                     //当前操纵的 tx，注意不要释放这个否则段错误，自有释放的地方

    LdapBuffer request_buffer;                 //请求缓冲区，根据需求使用，不需要缓存分片时，不要用
    LdapBuffer response_buffer;                //响应缓冲区，根据需求使用，不需要缓存分片时，不要用

    curr_ldap_info curr_tx; 				   //整个会话解析数据，预留

   
/******************************************************* 私有数据 end *******************************************************/


} LdapState;


/* 原子开关 */
typedef struct LdapConf_ {
	SC_ATOMIC_DECLARE(int, ldap_enable);
	SC_ATOMIC_DECLARE(int, log_enable);
}LdapConf;

/* Reload 函数 */
void LdapReload(void);

/* 核心注册函数 */
void RegisterLdapParsers(void);

#endif /* __APP_LAYER_LDAP_H__ */
