#ifndef __APP_LAYER_CASSANDRA_H__
#define __APP_LAYER_CASSANDRA_H__

#include "rust.h"
#if __BYTE_ORDER == __BIG_ENDIAN
#include "util-byte.h"
#endif

#include <iconv.h>

#define CASSANDRA_FREESTR(P) if(NULL != P){free(P); P = NULL;}

#define CASSANDRA_ENABLED_NODE "app-layer.protocols.cassandra.enabled"
#define CASSANDRA_LOG_NODE "app-layer.protocols.cassandra.log"
#define CASSANDRA_DPORT "app-layer.protocols.cassandra.detection-ports.dp"
#define CASSANDRA_RESULT "app-layer.protocols.cassandra.result"


/* 调试宏，发布时记得注释掉下面一行 */
//#define ENABLE_DECODER_DEBUG
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* cassandra 协议使用 TCP 协议，默认端口 */
#define CASSANDRA_DEFAULT_PORT "9042"

/* 消息的最小大小。对于某些协议，这可能是一个头的大小 */
#define CASSANDRA_MIN_FRAME_LEN 9
#define CASSANDRA_PROTO_NAME_LEN 16
#define CASSANDRA_VERSION_LEN 17
#define CASSANDRA_USER_LEN 65
#define CASSANDRA_PASSWD_LEN 65
#define CASSANDRA_PROTOCOL_NUM 10
#define CASSANDRA_PACKET_LEN 1460
#define CASSANDRA_ERR_CODE 0xff
#define CASSANDRA_DATABASE_LEN 65

/* 定义换行符号 */
static const uint8_t CASSANDRA_CRLF[3] = {0x23, 0x0d, 0x0a};
static const uint8_t CASSANDRA_DOT[2] = {0x23, 0x23};
static const uint8_t CASSANDRA_SPACE[1] = {0x20};


#define CASSANDRA_GET_VALUE32(P) (((uint32_t)(*(P)) << 24)\
							+((uint32_t)(*(P+1)) << 16)\
							+((uint32_t)(*(P+2)) << 8)\
							+ *(P+3))

#define CASSANDRA_GET_VALUE24(P) (((uint32_t)(*(P)) << 16)\
							+((uint32_t)(*(P+1)) << 8)\
							+ *(P+2))

#define CASSANDRA_GET_VALUE16(P) (((uint32_t)(*(P)) << 8)\
							+ *(P+1))

#define CASSANDRA_IS_V4_REQUEST(p) ((0x00 == (0x80 & (p)[0])) ? 1 : 0)

#define CASSANDRA_IS_V4_RESPONSE(p) ((0x80 == (0x80 & (p)[0])) ? 1 : 0)

#define CASSANDRA_IS_V5_QUERY(p) \
	(((p)[0] == 0x05 && ((p)[4] == 0x07 || (p)[4] == 0x09)) ? 1 : 0)

#define CASSANDRA_IS_V5_CQL_VERSION(p) \
	(((p)[0] == 0x05 && (p)[1] == 0x00 && (p)[2] == 0x00 && (p)[3] == 0x00 && (p)[4] == 0x01) ? 1 : 0)


/* 查询 list 结构 */
typedef struct _cassandra_info_list {
	int code;
	const char *value;
}cassandra_info_list;


/* 用于重组的缓冲 buff */
typedef struct CassandraBuffer_ {
    uint8_t   *buffer;      // 应用层数据缓冲区
    size_t    size;         // 当前缓冲区大小
    uint32_t  len;          // 当前已重组的数据长度
    uint32_t  offset;       // 实际已经解析的字符个数，未使用
    
    uint32_t  total_len;    // 专为请求分片包准备，响应分片包直到结束才知道传了多少
    uint8_t   finish_key;   // 是否缓冲完成，请求和响应解析完成标志
    uint8_t   column_count; // 列字段个数，就是表字段个数，行数据的个数依据
    uint8_t   fields_finish;// 专为响应包准备，代表表结构字段是否解析完成

} CassandraBuffer;


/* cassandra transaction tx 私有结构, 用于存储每个请求或响应解析的字段，用于 规则匹配 与 json 日志发送 */
typedef struct CassandraTransaction_ {
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
    struct CassandraState_ *cassandra;          //可不包含，包含也有好处，就是在 tx 中能够看到 state
	char proto[CASSANDRA_PROTO_NAME_LEN];  //传输层协议名称，如 tcp、udp

    uint8_t done;                     //完成标志，预留，未使用           
    uint8_t complete;                 //进度标志，预留，未使用 

	uint32_t version_len;
	uint32_t user_len;
	uint32_t passwd_len;

	uint8_t version[CASSANDRA_VERSION_LEN];   //版本
	uint8_t user[CASSANDRA_USER_LEN];         //用户名
	uint8_t passwd[CASSANDRA_PASSWD_LEN];     //密码
	uint8_t *query_cmd;                   //SQL 语句
	uint8_t *result_set;                  //结果集

	uint8_t version_key;                  //1 解析成功，下面同
	uint8_t user_key;
	uint8_t passwd_key;
	uint8_t query_cmd_key;
	uint8_t result_set_key;

	uint8_t cassandra_match_flag;           //防止重复发日志开关
/******************************************************* 私有数据 end *******************************************************/

    AppLayerTxData tx_data;   //必须包含，应用层事务数据核心结构
    uint64_t tx_num;          //必须包含，tx 数量，等于 transaction_max

    TAILQ_ENTRY(CassandraTransaction_) next;
} CassandraTransaction;

/* flow cassandra state 流状态，生命周期与流相同 */
typedef struct CassandraState_ {
    AppLayerStateData state_data;              //必须包含，相当于啊 session 的结构，伴随流的生命周期
    TAILQ_HEAD(, CassandraTransaction_) tx_list;    //必须包含，用于存储会话 tx 的 list, 架构中，请求和响应共用一个 tx, detect 结束后就彻底释放了, list 中只有一个 tx
    uint64_t transaction_max;                  //必须包含，list 中的 tx 个数，本架构中永远不超过 1

/******************************************************* 私有数据 start *******************************************************/
	 
    CassandraTransaction *curr;                     //当前操纵的 tx，注意不要释放这个否则段错误，自有释放的地方


	uint8_t pkt_num;                      //包计数，version 在第一个响应包中，user 和 passwd 在第二个请求包中
	uint8_t send_key;                     //是否可以发送请求和响应合并后的日志
	uint16_t field_count;                 //字段计数


    CassandraBuffer query_cmd_buffer;         //SQL 语句
    CassandraBuffer result_set_buffer;        //结果集，暂时不解析
	CassandraBuffer db_name;                  //数据库名称
	CassandraBuffer table_name;               //表名称，预留未使用
	CassandraBuffer fields;                   //列
	CassandraBuffer cql_version;              //CQL 版本
	CassandraBuffer user;                     //用户名，加密不解析
	CassandraBuffer server_version;           //服务端版本
	CassandraBuffer driver_name;              //driver 名称
	CassandraBuffer system_name;              //操作系统名称
	CassandraBuffer host_name;                //主机名称
	CassandraBuffer client_id;                //客户端 ID
	CassandraBuffer driver_version;           //driver version
	uint8_t version;                          //整数版本号

	uint8_t request_buffer_need;          //是否需要缓存 请求，1 需要
	//uint8_t request_buffer_key;           //缓存请求是否 完成，1 完成，预留未使用
	
	uint8_t response_buffer_need;         //是否需要缓存 响应，1 需要
	//uint8_t response_buffer_key;          //缓存响应是否 完成，1 完成，预留未使用


    CassandraBuffer request_buffer;           //请求缓冲区，根据需求使用，不需要缓存分片时，不要用
    CassandraBuffer response_buffer;          //响应缓冲区，根据需求使用，不需要缓存分片时，不要用
    
/******************************************************* 私有数据 end *******************************************************/


} CassandraState;


/* 原子开关 */
typedef struct CassandraConf_ {
	SC_ATOMIC_DECLARE(int, cassandra_enable);
	SC_ATOMIC_DECLARE(int, log_enable);
	SC_ATOMIC_DECLARE(int, cassandra_dport);
	SC_ATOMIC_DECLARE(int, result);
}CassandraConf;

/* Reload 函数 */
void CassandraReload(void);

/* 核心注册函数 */
void RegisterCassandraParsers(void);

#endif /* __APP_LAYER_CASSANDRA_H__ */
