#ifndef __APP_LAYER_REDIS_H__
#define __APP_LAYER_REDIS_H__

#include "rust.h"
#if __BYTE_ORDER == __BIG_ENDIAN
#include "util-byte.h"
#endif

#include <iconv.h>

#define REDIS_FREESTR(P) if(NULL != P){free(P); P = NULL;}

#define REDIS_ENABLED_NODE "app-layer.protocols.redis.enabled"
#define REDIS_LOG_NODE "app-layer.protocols.redis.log"
#define REDIS_DPORT "app-layer.protocols.redis.detection-ports.dp"
#define REDIS_RESULT "app-layer.protocols.redis.result"


/* 调试宏，发布时记得注释掉下面一行 */
//#define ENABLE_DECODER_DEBUG
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* redis 协议使用 TCP 协议，默认端口 */
#define REDIS_DEFAULT_PORT "6379"

/* 消息的最小大小。对于某些协议，这可能是一个头的大小 */
#define REDIS_MIN_FRAME_LEN 4
#define REDIS_PROTO_NAME_LEN 16
#define REDIS_VERSION_LEN 17
#define REDIS_USER_LEN 65
#define REDIS_PASSWD_LEN 65
#define REDIS_PROTOCOL_NUM 10
#define REDIS_PACKET_LEN 1460
#define REDIS_ERR_CODE 0xff
#define REDIS_DATABASE_LEN 65
#define REDIS_LENGTH_LEN 21



/* 定义换行符号 */
static const uint8_t REDIS_CRLF[3] = {0x23, 0x0d, 0x0a};
static const uint8_t REDIS_DOT[2] = {0x23, 0x23};
static const uint8_t REDIS_SPACE[1] = {0x20};


#define REDIS_GET_VALUE32(P) (((uint32_t)(*(P+3)) << 24)\
							+((uint32_t)(*(P+2)) << 16)\
							+((uint32_t)(*(P+1)) << 8)\
							+ *(P))

#define REDIS_GET_VALUE24(P) (((uint32_t)(*(P+2)) << 16)\
							+((uint32_t)(*(P+1)) << 8)\
							+ *(P))

#define REDIS_GET_VALUE16(P) (((uint32_t)(*(P+1)) << 8)\
							+ *(P))


#define REDIS_IS_AUTH_REQUEST(p) \
		(((p)[0] == 0x0d && (p)[1] == 0x0a && (p)[2] == 0x41 && (p)[3] == 0x55 \
		  && (p)[4] == 0x54 && (p)[5] == 0x48 && (p)[6] == 0x0d && (p)[7] == 0x0a) ? 1 : 0)

#define REDIS_IS_SERVER(p) \
		(((p)[0] == 0x23 && (p)[1] == 0x20 && (p)[2] == 0x53 && (p)[3] == 0x65 \
		&& (p)[4] == 0x72 && (p)[5] == 0x76 && (p)[6] == 0x65 && (p)[7] == 0x72 \
		&& (p)[8] == 0x0d && (p)[9] == 0x0a) ? 1 : 0)


/* 查询 list 结构 */
typedef struct _redis_info_list {
	int code;
	const char *value;
}redis_info_list;


/* 用于重组的缓冲 buff */
typedef struct RedisBuffer_ {
    uint8_t   *buffer;            // 应用层数据缓冲区
    size_t    size;               // 当前缓冲区大小
    uint32_t  len;                // 当前已重组的数据长度
    uint32_t  offset;             // 实际已经解析的字符个数，未使用
    
    uint32_t  total_len;          // 专为请求分片包准备，响应分片包直到结束才知道传了多少
    uint8_t   finish_key;         // 是否缓冲完成，请求和响应解析完成标志
    uint8_t   column_count;       // 列字段个数，就是表字段个数，行数据的个数依据
    uint8_t   fields_finish;      // 专为响应包准备，代表表结构字段是否解析完成
    uint8_t   curr_column_count;  // 当前已经解析的 Bulk String 个数

} RedisBuffer;


/* redis transaction tx 私有结构, 用于存储每个请求或响应解析的字段，用于 规则匹配 与 json 日志发送 */
typedef struct RedisTransaction_ {
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
    struct RedisState_ *redis;          //可不包含，包含也有好处，就是在 tx 中能够看到 state
	char proto[REDIS_PROTO_NAME_LEN];  //传输层协议名称，如 tcp、udp

    uint8_t done;                     //完成标志，预留，未使用           
    uint8_t complete;                 //进度标志，预留，未使用 

	uint32_t version_len;
	uint32_t user_len;
	uint32_t passwd_len;

	uint8_t version[REDIS_VERSION_LEN];   //版本
	uint8_t user[REDIS_USER_LEN];         //用户名
	uint8_t passwd[REDIS_PASSWD_LEN];     //密码
	uint8_t *query_cmd;                   //SQL 语句
	uint8_t *result_set;                  //结果集

	uint8_t version_key;                  //1 解析成功，下面同
	uint8_t user_key;
	uint8_t passwd_key;
	uint8_t query_cmd_key;
	uint8_t result_set_key;

	uint8_t redis_match_flag;           //防止重复发日志开关
/******************************************************* 私有数据 end *******************************************************/

    AppLayerTxData tx_data;   //必须包含，应用层事务数据核心结构
    uint64_t tx_num;          //必须包含，tx 数量，等于 transaction_max

    TAILQ_ENTRY(RedisTransaction_) next;
} RedisTransaction;

/* flow redis state 流状态，生命周期与流相同 */
typedef struct RedisState_ {
    AppLayerStateData state_data;              //必须包含，相当于啊 session 的结构，伴随流的生命周期
    TAILQ_HEAD(, RedisTransaction_) tx_list;    //必须包含，用于存储会话 tx 的 list, 架构中，请求和响应共用一个 tx, detect 结束后就彻底释放了, list 中只有一个 tx
    uint64_t transaction_max;                  //必须包含，list 中的 tx 个数，本架构中永远不超过 1

/******************************************************* 私有数据 start *******************************************************/
	 
    RedisTransaction *curr;                     //当前操纵的 tx，注意不要释放这个否则段错误，自有释放的地方


	uint8_t pkt_num;                      //包计数，version 在第一个响应包中，user 和 passwd 在第二个请求包中
	uint8_t send_key;                     //是否可以发送请求和响应合并后的日志
	uint16_t field_count;                 //字段计数


    RedisBuffer query_cmd_buffer;         //SQL 语句
    RedisBuffer result_set_buffer;        //结果集，暂时不解析
	RedisBuffer db_name;                  //数据库名称
	RedisBuffer table_name;               //表名称，预留未使用
	RedisBuffer fields;                   //列
	RedisBuffer client_version;           //客户端版本
	RedisBuffer user;                     //用户名，加密不解析
	RedisBuffer server_version;           //服务端版本
	RedisBuffer client_name;              //客户端程序名称
	RedisBuffer system_name;              //操作系统名称
	RedisBuffer host_name;                //主机名称
	RedisBuffer client_ip;                //客户端 IP
	RedisBuffer link_time;                //连接时间
	RedisBuffer auth;                     //认证信息，包括用户名和密码，一般只有密码
	RedisBuffer executable;               //可执行程序路径
	RedisBuffer config_file;              //配置文件路径

	uint8_t request_buffer_need;          //是否需要缓存 请求，1 需要
	//uint8_t request_buffer_key;           //缓存请求是否 完成，1 完成，预留未使用
	
	uint8_t response_buffer_need;         //是否需要缓存 响应，1 需要
	//uint8_t response_buffer_key;          //缓存响应是否 完成，1 完成，预留未使用


    RedisBuffer request_buffer;           //请求缓冲区，根据需求使用，不需要缓存分片时，不要用
    RedisBuffer response_buffer;          //响应缓冲区，根据需求使用，不需要缓存分片时，不要用
    
/******************************************************* 私有数据 end *******************************************************/


} RedisState;


/* 原子开关 */
typedef struct RedisConf_ {
	SC_ATOMIC_DECLARE(int, redis_enable);
	SC_ATOMIC_DECLARE(int, log_enable);
	SC_ATOMIC_DECLARE(int, redis_dport);
	SC_ATOMIC_DECLARE(int, result);
}RedisConf;

/* Reload 函数 */
void RedisReload(void);

/* 核心注册函数 */
void RegisterRedisParsers(void);

#endif /* __APP_LAYER_REDIS_H__ */
