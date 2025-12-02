#ifndef __APP_LAYER_SQLSERVER_H__
#define __APP_LAYER_SQLSERVER_H__

#include "rust.h"
#if __BYTE_ORDER == __BIG_ENDIAN
#include "util-byte.h"
#endif

#include <iconv.h>

#define SQLSERVER_FREESTR(P) if(NULL != P){free(P); P = NULL;}

#define SQLSERVER_ENABLED_NODE "app-layer.protocols.sqlserver.enabled"
#define SQLSERVER_LOG_NODE "app-layer.protocols.sqlserver.log"
#define SQLSERVER_DPORT "app-layer.protocols.sqlserver.detection-ports.dp"
#define SQLSERVER_RESULT "app-layer.protocols.sqlserver.result"


/* 调试宏，发布时记得注释掉下面一行 */
//#define ENABLE_DECODER_DEBUG
#ifdef ENABLE_DECODER_DEBUG
#include "./debug_log.h"
#endif

/* sqlserver 协议使用 TCP 协议，默认端口 */
#define SQLSERVER_DEFAULT_PORT "1433"

/* 消息的最小大小。对于某些协议，这可能是一个头的大小 */
#define SQLSERVER_MIN_FRAME_LEN 8
#define SQLSERVER_PROTO_NAME_LEN 16
#define SQLSERVER_VERSION_LEN 64
#define SQLSERVER_USER_LEN 65
#define SQLSERVER_PASSWD_LEN 65
#define SQLSERVER_PROTOCOL_NUM 10
#define SQLSERVER_PACKET_LEN 1460
#define SQLSERVER_ERR_CODE 0xff

/* 定义换行符号 */
static const uint8_t SQLSERVER_CRLF[3] = {0x23, 0x0d, 0x0a};
static const uint8_t SQLSERVER_DOT[2] = {0x23, 0x23};


#define SQLSERVER_GET_VALUE32(P) (((uint32_t)(*(P+3)) << 24)\
				+ ((uint32_t)(*(P+2)) << 16)\
				+ ((uint32_t)(*(P+1)) << 8)\
				+ *(P))

#define SQLSERVER_GET_VALUE16(P) (((uint32_t)(*(P)) << 8)\
							+ *(P+1))



/* 查询 list 结构 */
typedef struct _sqlserver_info_list {
	int code;
	const char *value;
}sqlserver_info_list;


/* 用于重组的缓冲 buff */
typedef struct SqlserverBuffer_ {
    uint8_t   *buffer;      // 应用层数据缓冲区
    size_t    size;         // 当前缓冲区大小
    uint32_t  len;          // 当前已重组的数据长度
    uint32_t  offset;       // 实际已经解析的字符个数，未使用
    
    uint32_t  total_len;    // 专为请求分片包准备，响应分片包直到结束才知道传了多少
    uint8_t   finish_key;   // 是否缓冲完成，请求和响应解析完成标志
    uint8_t   column_count; // 列字段个数，就是表字段个数，行数据的个数依据
    uint8_t   fields_finish;// 专为响应包准备，代表表结构字段是否解析完成

} SqlserverBuffer;


/* sqlserver transaction tx 私有结构, 用于存储每个请求或响应解析的字段，用于 规则匹配 与 json 日志发送 */
typedef struct SqlserverTransaction_ {
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
    struct SqlserverState_ *sqlserver;          //可不包含，包含也有好处，就是在 tx 中能够看到 state
	char proto[SQLSERVER_PROTO_NAME_LEN];  //传输层协议名称，如 tcp、udp

    uint8_t done;                     //完成标志，预留，未使用           
    uint8_t complete;                 //进度标志，预留，未使用 

	uint32_t version_len;
	uint32_t user_len;
	uint32_t passwd_len;

	uint8_t version[SQLSERVER_VERSION_LEN];   //版本
	uint8_t user[SQLSERVER_USER_LEN];         //用户名
	uint8_t passwd[SQLSERVER_PASSWD_LEN];     //密码
	uint8_t *query_cmd;                   //SQL 语句
	uint8_t *result_set;                  //结果集

	uint8_t version_key;                  //1 解析成功，下面同
	uint8_t user_key;
	uint8_t passwd_key;
	uint8_t query_cmd_key;
	uint8_t result_set_key;

	uint8_t sqlserver_match_flag;           //防止重复发日志开关
/******************************************************* 私有数据 end *******************************************************/

    AppLayerTxData tx_data;   //必须包含，应用层事务数据核心结构
    uint64_t tx_num;          //必须包含，tx 数量，等于 transaction_max

    TAILQ_ENTRY(SqlserverTransaction_) next;
} SqlserverTransaction;

/* flow sqlserver state 流状态，生命周期与流相同 */
typedef struct SqlserverState_ {
    AppLayerStateData state_data;              //必须包含，相当于啊 session 的结构，伴随流的生命周期
    TAILQ_HEAD(, SqlserverTransaction_) tx_list;    //必须包含，用于存储会话 tx 的 list, 架构中，请求和响应共用一个 tx, detect 结束后就彻底释放了, list 中只有一个 tx
    uint64_t transaction_max;                  //必须包含，list 中的 tx 个数，本架构中永远不超过 1

/******************************************************* 私有数据 start *******************************************************/
	 
    SqlserverTransaction *curr;                     //当前操纵的 tx，注意不要释放这个否则段错误，自有释放的地方


	uint8_t pkt_num;                      //包计数，version 在第一个响应包中，user 和 passwd 在第二个请求包中
	uint8_t send_key;                     //是否可以发送请求和响应合并后的日志
	uint8_t encryption_key;               //是否使用加密方式传输，如果加密，则不解析

	uint32_t version_len;                 //版本长度
	uint32_t user_len;                    //用户名长度
	uint32_t passwd_len;                  //密码长度

	uint16_t major_version;               //主版本
	uint16_t sec_version;                 //次版本
	uint16_t minor_version;               //微小版本

	uint8_t version[SQLSERVER_VERSION_LEN];   //版本
	uint8_t user[SQLSERVER_USER_LEN];         //用户名
	uint8_t passwd[SQLSERVER_PASSWD_LEN];     //密码

	uint8_t version_key;                  //1 解析成功，下面同
	uint8_t user_key;
	uint8_t passwd_key;
	

    SqlserverBuffer query_cmd_buffer;         //SQL 语句
    SqlserverBuffer result_set_buffer;        //结果集
	SqlserverBuffer db_name;                  //数据库名称
	SqlserverBuffer table_name;               //表名称
	SqlserverBuffer fields;                   //列



	uint8_t request_buffer_need;          //是否需要缓存 请求，1 需要
	//uint8_t request_buffer_key;           //缓存请求是否 完成，1 完成，预留未使用
	
	uint8_t response_buffer_need;         //是否需要缓存 响应，1 需要
	//uint8_t response_buffer_key;          //缓存响应是否 完成，1 完成，预留未使用


    SqlserverBuffer request_buffer;           //请求缓冲区，根据需求使用，不需要缓存分片时，不要用
    SqlserverBuffer response_buffer;          //响应缓冲区，根据需求使用，不需要缓存分片时，不要用
    
/******************************************************* 私有数据 end *******************************************************/


} SqlserverState;


/* 原子开关 */
typedef struct SqlserverConf_ {
	SC_ATOMIC_DECLARE(int, sqlserver_enable);
	SC_ATOMIC_DECLARE(int, log_enable);
	SC_ATOMIC_DECLARE(int, sqlserver_dport);
	SC_ATOMIC_DECLARE(int, result);
}SqlserverConf;

/* Reload 函数 */
void SqlserverReload(void);

/* 核心注册函数 */
void RegisterSqlserverParsers(void);

/* 寻找 STRINGBINDINGs 数组元素的起始位置 */
int SqlserverSundayALG(const uint8_t *src, uint32_t src_len, uint8_t *patt_str, int patt_len, uint32_t *dst_len);

#endif /* __APP_LAYER_SQLSERVER_H__ */
