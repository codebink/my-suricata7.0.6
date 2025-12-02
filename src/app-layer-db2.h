#ifndef __APP_LAYER_DB2_H__
#define __APP_LAYER_DB2_H__

#include "rust.h"
#if __BYTE_ORDER == __BIG_ENDIAN
#include "util-byte.h"
#endif

#define DB2_ENABLED_NODE "app-layer.protocols.db2.enabled"
#define DB2_LOG_NODE "app-layer.protocols.db2.log"

/* 调试宏，发布时记得注释掉下面一行 */
//#define ENABLE_DECODER_DEBUG
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* db2 协议使用 TCP 协议，默认端口 */
#define DB2_DEFAULT_PORT "50000,60000"

/* 消息的最小大小。对于某些协议，这可能是一个头的大小 */
#define DB2_MIN_FRAME_LEN 3
#define DB2_PROTO_NAME_LEN 16



/* 查询 list 结构 */
typedef struct _db2_info_list {
	int code;
	const char *value;
}db2_info_list;


/* 用于重组的缓冲 buff */
typedef struct Db2Buffer_ {
    uint8_t *buffer;
    size_t   size;
    int      len;
    int      offset;
} Db2Buffer;


/* db2 transaction tx 私有结构, 用于存储每个请求或响应解析的字段，用于 规则匹配 与 json 日志发送 */
typedef struct Db2Transaction_ {
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
    struct Db2State_ *db2;          //可不包含，包含也有好处，就是在 tx 中能够看到 state
	char proto[DB2_PROTO_NAME_LEN];  //传输层协议名称，如 tcp、udp

    uint8_t done;                     //完成标志，预留，未使用           
    uint8_t complete;                 //进度标志，预留，未使用 


	uint8_t db2_match_flag;           //防止重复发日志开关
/******************************************************* 私有数据 end *******************************************************/

    AppLayerTxData tx_data;   //必须包含，应用层事务数据核心结构
    uint64_t tx_num;          //必须包含，tx 数量，等于 transaction_max

    TAILQ_ENTRY(Db2Transaction_) next;
} Db2Transaction;

/* flow db2 state 流状态，生命周期与流相同 */
typedef struct Db2State_ {
    AppLayerStateData state_data;              //必须包含，相当于啊 session 的结构，伴随流的生命周期
    TAILQ_HEAD(, Db2Transaction_) tx_list;    //必须包含，用于存储会话 tx 的 list, 架构中，请求和响应共用一个 tx, detect 结束后就彻底释放了, list 中只有一个 tx
    uint64_t transaction_max;                  //必须包含，list 中的 tx 个数，本架构中永远不超过 1

/******************************************************* 私有数据 start *******************************************************/
	 
    Db2Transaction *curr;                     //当前操纵的 tx，注意不要释放这个否则段错误，自有释放的地方

    Db2Buffer request_buffer;                 //请求缓冲区，根据需求使用，不需要缓存分片时，不要用
    Db2Buffer response_buffer;                //响应缓冲区，根据需求使用，不需要缓存分片时，不要用
    
/******************************************************* 私有数据 end *******************************************************/


} Db2State;


/* 原子开关 */
typedef struct Db2Conf_ {
	SC_ATOMIC_DECLARE(int, db2_enable);
	SC_ATOMIC_DECLARE(int, log_enable);
}Db2Conf;

/* Reload 函数 */
void Db2Reload(void);

/* 核心注册函数 */
void RegisterDb2Parsers(void);

#endif /* __APP_LAYER_DB2_H__ */
