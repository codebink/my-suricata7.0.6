#include "suricata-common.h"
#include "suricata.h"
#include "stream.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-hashlist.h"

#include "util-print.h"
#include "util-spm-bs.h"
#include "util-enum.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "app-layer-sqlserver.h"

SqlserverConf sqlserver_conf;

/* 0x00 模式串，用于快速查找字符串结尾 */
//static uint8_t SQLSERVER_END_PATT[1] = {0x00};

/* sqlserver 模式串 */
//static uint8_t Sqlserver_STR_END_PATT[7] = {0x2d, 0x54, 0x69, 0x44, 0x42, 0x2d};


/* 热加载函数 */
void SqlserverReload(void)
{
	/* 获取是否打开日志开关 */
	ConfNode *node = NULL;

	/* 插件开关 */
	node = NULL;
	node = ConfGetNode(SQLSERVER_ENABLED_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(sqlserver_conf.sqlserver_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(sqlserver_conf.sqlserver_enable, 0);
	}

	/* 获取是否打开日志开关 */
	node = ConfGetNode(SQLSERVER_LOG_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(sqlserver_conf.log_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(sqlserver_conf.log_enable, 0);
	}	

	/* 获取 sqlserver 配置文件中的 dport 用于方向判断 */
	node = ConfGetNode(SQLSERVER_DPORT);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(sqlserver_conf.sqlserver_dport, atoi(node->val));
	}else {
		SC_ATOMIC_SET(sqlserver_conf.sqlserver_dport, atoi(SQLSERVER_DEFAULT_PORT));
	}	

	/* 获取是否打开结果集开关 */
	node = ConfGetNode(SQLSERVER_RESULT);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(sqlserver_conf.result, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(sqlserver_conf.result, 0);
	}

	return;
}


#ifdef ENABLE_DECODER_DEBUG
/*
	名字：void get_local_time(char *time_buff)
	功能：获取本地时间
	参数：
		1 char *time_buff(传入传出型参数):本地时间,格式 2016/09/22 12:21:30
	返回:
		char *类型,时间字符串地址, NULL 异常
	时间：2016/09/22
	研发：deer
	版本：1.0.0.1
*/
static char *get_local_time(char *time_buff)
{
	if (NULL == time_buff) {
		return NULL;
	}

	int			year;
	int			month;
	int			day;
	int			hourl;
	int			min;
	int			sec;

	/* 时间句柄,结构体 */
	time_t		nowtime;
	struct tm	*timeinfo;

	/* 获取本地时间 */
	time(&nowtime);
	timeinfo = localtime(&nowtime);

	/* 取出年 月 日 星期 时 分 秒 */
	year = timeinfo->tm_year + 1900;
	month = timeinfo->tm_mon + 1;
	day = timeinfo->tm_mday;

	hourl = timeinfo->tm_hour;
	min = timeinfo->tm_min;
	sec = timeinfo->tm_sec;

	sprintf(time_buff, "%4d/%02d/%02d %02d:%02d:%02d", year, month, day, hourl, min, sec);

	return time_buff;
}


/*
	功能：打印信息审计，用于调试
	参数：
		1 SqlserverTransaction *tx: Sqlserver 的私有结构

	返回：void
*/
static void print_sqlserver_event(Flow *f, SqlserverTransaction *tx, uint16_t direction)
{
	/* 参数检查 */
	if (NULL == tx) {
		return;
	}

	char msg_buf[1024] = {0};
	SqlserverTransaction *sqlserver_data = NULL;

	char src_ip[INET6_ADDRSTRLEN] = {0};   //源IP 最大长度 46
	char dst_ip[INET6_ADDRSTRLEN] = {0};   //目的IP 同上
	uint16_t src_port = 0;                 //源 port
	uint16_t dst_port = 0;                 //目的 port

	/* 根据 flow 中的 flags 判断方向 */
	if (STREAM_TOSERVER == direction) {
		if (FLOW_IS_IPV4(f)) {
			PrintInet(AF_INET, (const void *)&f->src.addr_data32[0], src_ip, sizeof(src_ip));
			PrintInet(AF_INET, (const void *)&f->dst.addr_data32[0], dst_ip, sizeof(dst_ip));
		} else if (FLOW_IS_IPV6(f)) {
			PrintInet(AF_INET6, (const void *)f->src.addr_data32, src_ip, sizeof(src_ip));
			PrintInet(AF_INET6, (const void *)f->dst.addr_data32, dst_ip, sizeof(dst_ip));
		}

		/* 获取端口 */
		src_port = f->sp;
		dst_port = f->dp;
	}else {
		if (FLOW_IS_IPV4(f)) {
			PrintInet(AF_INET, (const void *)&f->dst.addr_data32[0], src_ip, sizeof(src_ip));
			PrintInet(AF_INET, (const void *)&f->src.addr_data32[0], dst_ip, sizeof(dst_ip));
		} else if (FLOW_IS_IPV6(f)) {
			PrintInet(AF_INET6, (const void *)f->dst.addr_data32, src_ip, sizeof(src_ip));
			PrintInet(AF_INET6, (const void *)f->src.addr_data32, dst_ip, sizeof(dst_ip));
		}

		/* 获取端口 */
		src_port = f->dp;
		dst_port = f->sp;
	}

	/* 私有结构，负载，负载长度 */
	sqlserver_data = tx;

	/* 时间 2016/09/22 12:21:30 */
	get_local_time(sqlserver_data->time_buff);
	
	/* 打印 */
	snprintf(msg_buf, sizeof(msg_buf), "done=%u", \
			sqlserver_data->done \
			);

	/* 打印公共字段 */
	DEBUG_DLOG("-----8888888888----- date: %s, s_ip: %s, s_port: %u, d_ip: %s, d_port: %u, dir: %d, protocal: %s, msg_buf: %s", \
				sqlserver_data->time_buff,\
				src_ip, src_port,\
				dst_ip, dst_port,\
				sqlserver_data->is_request, sqlserver_data->proto,\
				msg_buf \
				);

	return;
}
#endif


/* Ts 和 Tc 是指 Request 和 Response 方向协议识别和异常判断，合并到一起了，以后需要时还要拆分成两个函数，因为请求包和响应包结构不同 */
static AppProto SqlserverProbingParserTsTc(Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
	if (NULL == input || 0 >= input_len) {
		return ALPROTO_UNKNOWN;
	}

	//const uint8_t *p_data = NULL;
	uint16_t p_len = 0;

	/* 如果没有打开则强制不再识别识别, 后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(sqlserver_conf.sqlserver_enable)) {
		return ALPROTO_UNKNOWN;
	}
	
	/* 负载和负载长度 */
	//p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if (p_len < SQLSERVER_MIN_FRAME_LEN) {
		return ALPROTO_UNKNOWN;
	}

	return ALPROTO_SQLSERVER;
}

/* 分配一个 sqlserver 状态对象，表示一个 sqlserver TCP 会话 */
static void *SqlserverStateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	SqlserverState *sqlserver;

	sqlserver = (SqlserverState *)SCCalloc(1, sizeof(SqlserverState));
	if (unlikely(sqlserver == NULL)) {
		return NULL;
	}
	TAILQ_INIT(&sqlserver->tx_list);

	SCReturnPtr(sqlserver, "void");
}

/* 分配一个 sqlserver transaction */
static SqlserverTransaction *SqlserverTxAlloc(SqlserverState *sqlserver, bool request)
{
	SqlserverTransaction *tx = SCCalloc(1, sizeof(SqlserverTransaction));
	if (unlikely(tx == NULL)) {
		return NULL;
	}
	sqlserver->transaction_max++;
	sqlserver->curr = tx;
	tx->sqlserver = sqlserver;
	tx->tx_num = sqlserver->transaction_max;
	tx->is_request = request;
	if (tx->is_request) {
		tx->tx_data.detect_flags_tc |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	} else {
		tx->tx_data.detect_flags_ts |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	}

	TAILQ_INSERT_TAIL(&sqlserver->tx_list, tx, next);

	return tx;
}

/* 高效 & 安全的 UTF-16LE ➜ UTF-8 转换函数  */
static char * SqlserverUnicodeToUtf8(char *filename, uint32_t filename_len, char *to_filename, uint32_t *to_file_len)
{
	if (NULL == filename || 0 >= filename_len || NULL == to_filename || NULL == to_file_len || (filename_len * 4) > *to_file_len) {
		return NULL;
	}

	// UTF-16LE 必须是偶数字节数（每 2 字节表示 1 个码点）
	if ((filename_len & 1) != 0) {
		return NULL;
	}

	// UTF-8 最多 3 字节/字符，保守预估空间（+1 是为了 '\0'）
	uint32_t estimated_max = (filename_len / 2) * 3 + 1;
	if (*to_file_len < estimated_max) {
		return NULL;
	}
    
	char *out_ptr = to_filename;
	const char *out_end = to_filename + *to_file_len - 1; // 留 '\0'，这里的 out_end 是哨兵，是数组最后一个字节
	const uint8_t *in_ptr = (const uint8_t *)filename;
	const uint8_t *in_end = in_ptr + filename_len; //这里的 in_end 是哨兵，是数组外部第一个字节地址，等于它就越界了

	while (in_ptr + 1 < in_end) {
		// 安全读取两个字节
		uint16_t codepoint = in_ptr[0] | (in_ptr[1] << 8);
		in_ptr += 2;

		// 快速路径：ASCII（常见）
		if (codepoint <= 0x7F) {
			if (out_ptr >= out_end) {
				return NULL;
			}
			*out_ptr++ = (char)codepoint;
		}
		// 两字节 UTF-8
		else if (codepoint <= 0x7FF) {
			if (out_ptr + 1 >= out_end) {
				return NULL;
			}
			*out_ptr++ = 0xC0 | (codepoint >> 6);
			*out_ptr++ = 0x80 | (codepoint & 0x3F);
		}
		// 三字节 UTF-8
		else {
			if (out_ptr + 2 >= out_end) {
				return NULL;
			}
			*out_ptr++ = 0xE0 | (codepoint >> 12);
			*out_ptr++ = 0x80 | ((codepoint >> 6) & 0x3F);
			*out_ptr++ = 0x80 | (codepoint & 0x3F);
		}
	}

	// 最后添加 '\0'，确保返回 C 字符串
	*out_ptr = '\0';

	// 返回实际长度
	*to_file_len = (uint32_t)(out_ptr - to_filename);
	return to_filename;
}


#if 0
static char sqlserver_hex_to_char(unsigned char ch)
{
	char tmp_char = '0';

	switch(ch) {
		case 0x00 :
			tmp_char = '0';
		break;

		case 0x01 :
			tmp_char = '1';
		break;

		case 0x02 :
			tmp_char = '2';
		break;

		case 0x03 :
			tmp_char = '3';
		break;

		case 0x04 :
			tmp_char = '4';
		break;

		case 0x05 :
			tmp_char = '5';
		break;

		case 0x06 :
			tmp_char = '6';
		break;

		case 0x07 :
			tmp_char = '7';
		break;

		case 0x08 :
			tmp_char = '8';
		break;

		case 0x09 :
			tmp_char = '9';
		break;

		case 0x0a :
			tmp_char = 'a';
		break;

		case 0x0b :
			tmp_char = 'b';
		break;

		case 0x0c :
			tmp_char = 'c';
		break;

		case 0x0d :
			tmp_char = 'd';
		break;

		case 0x0e :
			tmp_char = 'e';
		break;

		case 0x0f :
			tmp_char = 'f';
		break;

		default :
			/* 其他 */
		break;
	}

	return tmp_char;
}

static int sqlserver_hex_to_str(unsigned char *src, uint32_t src_len, char *dst, uint32_t *dst_len)
{
	if (NULL == src || 0 >= src_len || NULL == dst || NULL == dst_len) {
		return 1;
	}

	uint32_t i = 0;
	uint32_t j = 0;
	char t_chr = '0';

	unsigned char src_char = 0x00;
	unsigned char tmp_char = 0x00;

	for (i = 0; i < src_len; i++) {
		/* 高 4 bit 转换 */
		src_char = 0x00;
		src_char = src[i];
		tmp_char = 0x00;
		tmp_char = (src_char & 0xf0) >> 4;

		/* 获取高位转换的字符 */
		t_chr = '0';
		t_chr = sqlserver_hex_to_char(tmp_char);
		dst[j] = t_chr;

		/* 低 4 bit 转换 */
		src_char = 0x00;
		src_char = src[i];
		tmp_char = 0x00;
		tmp_char = (src_char & 0x0f);

		/* 获取低位转换的字符 */
		t_chr = '0';
		t_chr = sqlserver_hex_to_char(tmp_char);
		dst[j+1] = t_chr;

		j += 2;
	}

	*dst_len = j;

	return 0;
}

/* 配合 sunday 算法获取模式串第一次命中的位置 */
static int SqlserverFindIndex(uint8_t *patt_str, int patt_len, uint8_t uc_tmp, int *index)
{
    if ( (NULL == patt_str) || (0 >= patt_len) ) {
        return -1;
    }

    int i = 0;

    for ( i = (patt_len -1); i >= 0; i-- ) {
        if ( patt_str[i] == uc_tmp ) {
            *index = i;
            return 0;
        }
    }

    return -1;
}

/* 寻找 STRINGBINDINGs 数组元素的起始位置 */
int SqlserverSundayALG(const uint8_t *src, uint32_t src_len, uint8_t *patt_str, int patt_len, uint32_t *dst_len)
{
    if ( (NULL == src) || (0 >= src_len) || (NULL == patt_str) || (0 >= patt_len) ) {
        return -1;
    }

    int ret = 0;
    int index = 0;
    int j = 0;
    long i = 0;

    long tmp = 0;
    long location = 0;

    while (i < src_len) {
        /* 异常判断 */
        if (j >= patt_len) {
            return -1;
        }    

        /* 比对如果相等, 保存距离起始位置长度 */
        if ( src[i] == patt_str[j]) {
            if ( j == patt_len - 1) {
                location = i + 1 - patt_len;
                *dst_len = (uint32_t)location;

                return 0;
            }

            i++;
            j++;
        } else{
            /* 发现不相等的位置, tmp 为字符串后面的第一个字符位置 */
            tmp = patt_len - j + i;
            if (tmp >= src_len) {
                return -1;
            }

            index = 0;
            ret = SqlserverFindIndex(patt_str, patt_len, src[tmp], &index);
            if ( ret == 1) {
                /* 未找到位置后移 */
                i = tmp + 1;
                j = 0;
            } else{
                /* 找到位置 */
                i = tmp - index;
                j = 0;
            }
        }
    }

    return -1;
}
#endif

/* 释放分片重组缓冲区 */
static int SqlserverBufferFree(SqlserverBuffer *buffer)
{
	if (NULL == buffer) {
		return 1;
	}

	if (NULL != buffer->buffer) {
		free(buffer->buffer);
		buffer->buffer = NULL;
	}

	buffer->size = 0;
	buffer->len = 0;
	buffer->offset = 0;
	buffer->total_len = 0;
	buffer->finish_key = 0;
	buffer->column_count = 0;
	buffer->fields_finish = 0;

	return 0;
}

/* 应用层分片重组，注意：成功时返回 0，失败时返回 1 */
static int SqlserverBufferAdd(SqlserverBuffer *buffer, const uint8_t *data, uint32_t len)
{
	if (NULL == buffer || NULL == data || 1 > len) {
		return 1;
	}

	if (buffer->size == 0) {
		buffer->buffer = SCCalloc(1, len + 1);
		if (unlikely(buffer->buffer == NULL)) {
			return 1;
		}
		buffer->size = len;
	}
	else if (buffer->len + len > buffer->size) {
		uint8_t *tmp = SCRealloc(buffer->buffer, buffer->len + len + 1);
		if (unlikely(tmp == NULL)) {
			return 1;
		}
		buffer->buffer = tmp;
		buffer->size = buffer->len + len;
	}
	memcpy(buffer->buffer + buffer->len, data, len);
	buffer->len += len;

	return 0;
}


/* 解析 sqlserver Version 包 */
static int SqlserverParseRespVersion(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, SqlserverTransaction *sqlserver_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	SqlserverState *sqlserver_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;

	//uint32_t location = 0;
	uint16_t find_len = 0;

	uint16_t minor_ver = 0;
	uint16_t offset = 0;
	uint8_t token = 0;
	uint32_t head_len8 = 8;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	sqlserver_state = (SqlserverState *)statev;
	p_data = input;
	p_len = input_len;

	/* pos 游标滑动到 Pre-Login Massage */
	pos += 8;
	
	/* 异常判断 */
	if (pos + 5 >= p_len) {
		return 1;
	}
	
	/* 取出	offset */
	offset = SQLSERVER_GET_VALUE16(p_data + pos + 1);
	
	/* 异常判断 */
	if (pos + offset >= p_len) {
		return 1;
	}

	/* 取出 version 长度 */
	find_len = SQLSERVER_GET_VALUE16(p_data + pos + 3);

	/* 异常判断 */
	if (pos + offset + find_len >= p_len) {
		return 1;
	}

	/* 异常判断 */
	if (4 > find_len) {
		return 1;
	}

	/* 从 16 进制版本转换成字符串版本 */
	minor_ver = SQLSERVER_GET_VALUE16(p_data + pos + offset + 2);
	snprintf((char *)(sqlserver_state->version), SQLSERVER_VERSION_LEN, "%d.%d.%d", (p_data + pos + offset)[0], (p_data + pos + offset)[1], minor_ver);
	sqlserver_state->version_len = (uint32_t)(strlen((char *)(sqlserver_state->version)));
	sqlserver_state->version_key = 1;
	sqlserver_state->major_version = (p_data + pos + offset)[0];
	sqlserver_state->sec_version = (p_data + pos + offset)[1];
	sqlserver_state->minor_version = minor_ver;

	/* pos 跳过 Version */
	pos += 5;

	/* 异常判断 */
	if (pos + 5 >= p_len) {
		return 1;
	}

	/* 取出是否加密 Token */
	token = (p_data + pos)[0];

	/* 取出	offset */
	offset = SQLSERVER_GET_VALUE16(p_data + pos + 1);
	
	/* 异常判断 */
	if (head_len8 + offset >= p_len) {
		return 1;
	}

	/* 取出   Encryptor 长度 */
	find_len = SQLSERVER_GET_VALUE16(p_data + pos + 3);

	/* 异常判断 */
	if (head_len8 + offset + find_len >= p_len) {
		return 1;
	}

	/* 异常判断 */
	if (1 > find_len) {
		return 1;
	}

	/* 是否加密开关赋值 */
	if (1 <= find_len && 1 == token && 1 == (p_data + head_len8 + offset)[0]) {
		sqlserver_state->encryption_key = 1;
	}else {
		sqlserver_state->encryption_key = 0;
	}

	return 0;
}

/* 解析 Query 中的 SQL 语句 */
static int SqlserverParseReqQuery(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, SqlserverTransaction *sqlserver_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	SqlserverState *sqlserver_state = NULL;
	const uint8_t *c_p_data = NULL;
	uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint8_t *t_p_data = NULL;
	uint32_t t_p_len = 0;
	uint32_t pos = 0;
	uint32_t pkt_len = 0;

	uint32_t total_len = 0;
	uint8_t ret = 0;
	uint8_t *cmd = NULL;
	uint32_t cmd_len = 0;
	char *conv_ret = NULL;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	sqlserver_state = (SqlserverState *)statev;

	/* 判断是解析缓存还是解析数据包 */
	if ((1 == sqlserver_state->request_buffer_need)
		&& (0 != sqlserver_state->query_cmd_buffer.len)) {
		/* 赋值给局部变量，易于理解 */
		p_data = sqlserver_state->query_cmd_buffer.buffer;
		p_len = sqlserver_state->query_cmd_buffer.len;

		/* 异常判断 */
		if (pos + 8 >= p_len) {
			return 1;
		}

		/* pos 移动到 TDS Query Packet */
		pos += 8;		

		/* 异常判断 */
		if (pos + 4 >= p_len) {
			return 1;
		}

		/* 取出 请求 CMD 前面的头部长度 */
		total_len = SQLSERVER_GET_VALUE32(p_data + pos);		

		/* pos 跳过 total_len */
		pos += total_len;

		/* 异常判断 */
		if (pos + 2 > p_len) {
			return 1;
		}

		/* 缓存是 unicode 编码，需要转换成 UTF-8，分配缓存 */
		cmd = (uint8_t *)calloc((((p_len - pos) * 4) + 2), sizeof(uint8_t));
		cmd_len = (((p_len - pos) * 4) + 2);
		if (NULL == cmd) {
			SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
			return 1;
		}		

		/* Unicode 转 UTF-8 */
		conv_ret = SqlserverUnicodeToUtf8((char *)(p_data + pos), (p_len - pos), (char *)cmd, &cmd_len);
		if (NULL == conv_ret) {
			SQLSERVER_FREESTR(cmd);
			SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
			return 1;
		}

		/* 存储转换后的 UTF-8 编码 */
		SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
		ret = SqlserverBufferAdd(&(sqlserver_state->query_cmd_buffer), cmd, cmd_len);
		if (0 != ret) {
			SQLSERVER_FREESTR(cmd);
			return 1;
		}

		/* 最重要：释放中间编码 */
		SQLSERVER_FREESTR(cmd);

		/* 能调到这个函数，说明已经完成纯 SQL 语句的缓存，打开已完成开关 */
		sqlserver_state->query_cmd_buffer.finish_key = 1;

	}else {
		c_p_data = input;
		p_len = input_len;

		/* 清空上次缓存 */
		SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
	
		/* 异常判断 */
		if (pos + 8 >= p_len) {
			return 1;
		}
		
		/* 取出 packet len */
		pkt_len = SQLSERVER_GET_VALUE16(c_p_data + 2);		
		
		/* 异常判断 */
		if (pkt_len > p_len) {
			return 1;
		}
		
		/* pos 移动到 TDS Query Packet */
		pos += 8;		

		/* 异常判断 */
		if (pos + 4 >= p_len) {
			return 1;
		}

		/* 取出 请求 CMD 前面的头部长度 */
		total_len = SQLSERVER_GET_VALUE32(c_p_data + pos);

		/* 异常判断 */
		if (pos + total_len >= p_len) {
			return 1;
		}

		/* pos 跳过 CMD 前面的头部长度 */
		pos += total_len;
		
		/* 保存 Query   */
		ret = SqlserverBufferAdd(&(sqlserver_state->query_cmd_buffer), (c_p_data + pos), (p_len - pos));
		if (0 != ret) {
			SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
			return 1;
		}

		t_p_data = sqlserver_state->query_cmd_buffer.buffer;
		t_p_len = sqlserver_state->query_cmd_buffer.len;

		/* 缓存是 unicode 编码，需要转换成 UTF-8 */
		cmd = (uint8_t *)calloc(((t_p_len * 4) + 2), sizeof(uint8_t));
		cmd_len = ((t_p_len * 4) + 2);
		if (NULL == cmd) {
			SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
			return 1;
		}		

		/* Unicode 转 UTF-8 */
		conv_ret = SqlserverUnicodeToUtf8((char *)(t_p_data), t_p_len, (char *)cmd, &cmd_len);
		if (NULL == conv_ret) {
			SQLSERVER_FREESTR(cmd);
			SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
			return 1;
		}

		/* 存储转换后的 UTF-8 编码 */
		SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
		ret = SqlserverBufferAdd(&(sqlserver_state->query_cmd_buffer), cmd, cmd_len);
		if (0 != ret) {
			SQLSERVER_FREESTR(cmd);
			return 1;
		}

		/* 最重要：释放中间编码 */
		SQLSERVER_FREESTR(cmd);

		sqlserver_state->query_cmd_buffer.finish_key = 1;

	}

	return 0;
}

/* 解析 sqlserver 响应 包 */
static int SqlserverParseResp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, SqlserverTransaction *sqlserver_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	SqlserverState *sqlserver_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t pkt_len = 0;
	uint8_t pkt_num = 0;

	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	sqlserver_state = (SqlserverState *)statev;
	p_data = input;
	p_len = input_len;

	/* 结果集开关关闭时不解析结果集，直接返回 */
	if (2 <= sqlserver_state->pkt_num && 0 == SC_ATOMIC_GET(sqlserver_conf.result)) {
		return 1;
	}

	/* 就前两个数据包需要计数，其他都不用 */
	if (sqlserver_state->pkt_num < 2) {
		sqlserver_state->pkt_num += 1;
	}

	/* 响应包到来，说明前面的请求都已经结束了，需要关闭请求缓存开关，但是不能释放请求缓存，请求缓存还需和响应合并 */
	sqlserver_state->request_buffer_need = 0;
	//SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));

	/* 异常判断 */
	if ((1 != sqlserver_state->response_buffer_need) && (pos + 8 >= p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 异常判断 */
	if (pos + 8 >= p_len) {
		return 1;
	}

	/* 判断是否是真正响应包 */
	if (0x04 != p_data[0]) {
		return 1;
	}

	/* 判断是否是 End 0f message */
	if (0x01 != (0x01 & p_data[1])) {
		return 1;
	}	

	/* 取出 packet len */
	pkt_len = SQLSERVER_GET_VALUE16(p_data + 2);

	/* 取出 packet number，0 或 1，交互阶段与正常 请求 0 和 响应 1 恰好相反 */
	pkt_num = (p_data + 6)[0];

	/* 首先解析请求中的 version 解析完退出函数 */
	if ((1 != sqlserver_state->version_key) && (1 == pkt_num) && (2 == sqlserver_state->pkt_num) && (pkt_len == p_len)) {
		/* 解析 version */
		ret = SqlserverParseRespVersion(f, statev, pstate, input, input_len, local_data, sqlserver_data);
		if (0 != ret) {
			return 1;
		}else {
			return 0;
		}
	}

	return 0;
}

/* 解析 sqlserver 请求 包 */
static int SqlserverParseReq(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, SqlserverTransaction *sqlserver_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	SqlserverState *sqlserver_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t pkt_len = 0;
	uint8_t pkt_num = 0;

	uint8_t ret = 0;
	uint8_t type = 0;
	uint8_t status = 0;

	uint32_t total_len = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	sqlserver_state = (SqlserverState *)statev;
	p_data = input;
	p_len = input_len;

	/* 请求包到来就释放响应缓存，因为说明前面的响应都已经结束了 */
	SqlserverBufferFree(&(sqlserver_state->result_set_buffer));
	SqlserverBufferFree(&(sqlserver_state->db_name));
	SqlserverBufferFree(&(sqlserver_state->table_name));
	SqlserverBufferFree(&(sqlserver_state->fields));
	sqlserver_state->response_buffer_need = 0;
	SqlserverBufferFree(&(sqlserver_state->response_buffer));
	sqlserver_state->send_key = 0;

	/* 就前两个数据包需要计数，其他都不用 */
	if (sqlserver_state->pkt_num < 2) {
		sqlserver_state->pkt_num += 1;
	}

	/* 异常判断 */
	if ((1 != sqlserver_state->request_buffer_need) && (pos + 8 >= p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == sqlserver_state->request_buffer_need) {
		/* 异常判断 */
		if (8 >= p_len) {
			/* 缓存不带头部的数据 */
			SqlserverBufferAdd(&(sqlserver_state->query_cmd_buffer), p_data, p_len);
		}else {
			/* 取出 status */
			status = 0x01 & (p_data + 1)[0];

			/* 取出 packet number，0 或 n */
			pkt_num = (p_data + 6)[0];

			/* 区分中间包和 End of message 包 */
			if (0x01 == p_data[0] && 0x01 == status && 2 <= pkt_num) {		
				/* pos 移动到 total len */
				pos += 8;

				/* 异常判断 */
				if (pos + 4 >= p_len) {
					return 1;
				}

				/* 取出 请求 CMD 前面的头部长度 */
				total_len = SQLSERVER_GET_VALUE32(p_data + pos);		
				
				/* pos 跳过 total_len */
				pos += total_len;

				/* 异常判断 */
				if (pos + 2 >= p_len) {
					return 1;
				}

				/* 缓存数据 */
				SqlserverBufferAdd(&(sqlserver_state->query_cmd_buffer), p_data + pos, p_len - pos);			
			}else {
				/* 缓存数据 */
				SqlserverBufferAdd(&(sqlserver_state->query_cmd_buffer), p_data, p_len);
			}
		}

		/* 判断缓存是否结束 */
		if (0 != sqlserver_state->query_cmd_buffer.len && sqlserver_state->query_cmd_buffer.len >= sqlserver_state->query_cmd_buffer.total_len) {
			/* 异常判断 */
			if (8 >= p_len) {
				return 1;
			}

			/* 取出 status */
			status = 0x01 & (p_data + 1)[0];

			/* 取出 packet number，0 或 n */
			pkt_num = (p_data + 6)[0];


			/* 判断是否是最后一个包 */
			if (0x01 == p_data[0] && 0x01 == status && 2 <= pkt_num) {
				/* 解析请求 SQL 语句或脚本 */
				ret = SqlserverParseReqQuery(f, statev, pstate, input, input_len, local_data, sqlserver_data);

				/* 已经解析完缓存了，关闭需要缓存开关 */
				sqlserver_state->request_buffer_need = 0;

				/* 判断是否解析成功 */
				if (0 != ret) {
					return 1;
				}else {
					return 0;
				}
			}

		}

		/* 这里是除了第一次缓存完请求包的返回处，因为是缓存，并没有解析，所以返回 1 */
		return 1;
	}

	/* 异常判断 */
	if (pos + 8 >= p_len) {
		return 1;
	}

	/* 取出 type 只解析 SQL batch 命令 */
	type = p_data[0];

	/* 只解析 SQLbatch 命令 */
	if (1 != type) {
		return 1;
	}

	/* 取出 status */
	status = 0x01 & (p_data + 1)[0];
	
	/* 取出 packet len */
	pkt_len = SQLSERVER_GET_VALUE16(p_data + 2);

	/* 取出 packet number，0 或 n */
	pkt_num = (p_data + 6)[0];

	/* 判断：如果请求是应用层分片的，需要重组后再解析 */
	if ((1 == pkt_num) && (pkt_len > p_len) && (0x00 == status)) {
		/* 应用层重组开关置位 */
		sqlserver_state->request_buffer_need = 1;

		/* 初次缓存，清理旧的缓存信息 */
		SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));

		/* 保存总长度，用于判断是否缓存完成，只有请求包才有这个总长度，响应包所有响应结束才知道传输了多少字节 */
		sqlserver_state->query_cmd_buffer.total_len = pkt_len;

		/* 缓存数据，从头部开始，保持完整 */
		SqlserverBufferAdd(&(sqlserver_state->query_cmd_buffer), p_data, p_len);

		/* 判断缓存是否结束 */
		if (0 != sqlserver_state->query_cmd_buffer.len && sqlserver_state->query_cmd_buffer.len >= sqlserver_state->query_cmd_buffer.total_len) {
			/* 异常判断，缓存超过了真实长度 */
			if (sqlserver_state->query_cmd_buffer.len > sqlserver_state->query_cmd_buffer.total_len) {
				SqlserverBufferFree(&(sqlserver_state->query_cmd_buffer));
				return 1;
			}

			/* 解析请求 SQL 语句或脚本 */
			//ret = SqlserverParseReqQuery(f, statev, pstate, input, input_len, local_data, sqlserver_data);

			/* 已经解析完缓存了，关闭需要缓存开关 */
			//sqlserver_state->request_buffer_need = 0;

			/* 判断是否解析成功 */
			//if (0 != ret) {
				//return 1;
			//}else {
				//return 0;
			//}
		}

		/* 这里是第一次缓存完请求包的返回处，因为是缓存，并没有解析，所以返回 1 */
		return 1;
	}

	/* 请求包没有分片，直接解析 */
	ret = SqlserverParseReqQuery(f, statev, pstate, input, input_len, local_data, sqlserver_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}


/* 请求包 解析函数 */
static AppLayerResult SqlserverParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	SqlserverTransaction *tx = NULL;
	//SqlserverTransaction *ttx = NULL;

	SqlserverState *sqlserver_state = NULL;
	SqlserverTransaction *sqlserver_data = NULL;

	const uint8_t *input = NULL;
	uint32_t input_len = 0;

	int ret = 1;

	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(sqlserver_conf.sqlserver_enable)) {
		goto error;
	}

	/* 获取 state 和 input 和 input_len */
	sqlserver_state = (SqlserverState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);

	/* 如果是加密流量不再解析 */
	if (1 == sqlserver_state->encryption_key) {
		goto error;
	}

	/* 如果已经解析了版本，那么需要判断是否需要继续解析 */
	if (1 == sqlserver_state->version_key) 
	{
		/* 只解析版本 16.0.1000      及以上的包     */
		if (16 > sqlserver_state->major_version) {
			goto error;
		}else if (16 == sqlserver_state->major_version 
			&& 0 == sqlserver_state->sec_version
			&& 1000 > sqlserver_state->minor_version) {
			goto error;
		}
	}

	/* 异常判断 */
	if (NULL == input) {
		if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) {
			/* 这是一个流结束的信号，如果需要，做任何清理工作，这里通常不需要什么 */
			SCReturnStruct(APP_LAYER_OK);
		}

		goto error;
	}

	/* 异常判断 */
	if (1 > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 异常判断 */
	if (SQLSERVER_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = SqlserverTxAlloc(sqlserver_state, true);
	sqlserver_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(sqlserver_data->proto, "tcp", 3);
	sqlserver_data->is_request = true;

#if 0
	/* 注意: 可能响应先来，因此请求也需要查一下有没有分配 tx, 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &sqlserver_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	sqlserver_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//sqlserver_state->transaction_max = 0;
		
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = SqlserverTxAlloc(sqlserver_state, true);
		sqlserver_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(sqlserver_data->proto, "tcp", 3);
	}
	sqlserver_data->is_request = true;
#endif
/************************* 解析私有数据 start ************************/	
	/* 判断真实的方向，防止三次握手第一个包丢失造成方向识别错误，记住值永远都放在左侧，防止判断恒等时使用复制符号 '=' */
	if (SC_ATOMIC_GET(sqlserver_conf.sqlserver_dport) == f->dp) {
		ret = SqlserverParseReq(f, state, pstate, input, input_len, local_data, sqlserver_data);
	}else if (SC_ATOMIC_GET(sqlserver_conf.sqlserver_dport) == f->sp) {
		ret = SqlserverParseResp(f, state, pstate, input, input_len, local_data, sqlserver_data);
	}else {
		ret = 1;
	}


	/* 如果解析失败，不发送日志 */
	if (0 != ret) {
		goto end;
	}


	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	sqlserver_data->done = 1;
	sqlserver_data->complete = 0;
	
/************************* 解析私有数据 end ************************/	


#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_sqlserver_event(f, sqlserver_data, STREAM_TOSERVER);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 响应包 解析函数 */
static AppLayerResult SqlserverParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	SqlserverTransaction *tx = NULL;
	//SqlserverTransaction *ttx = NULL;
	
	SqlserverState *sqlserver_state = NULL;
	SqlserverTransaction *sqlserver_data = NULL;
	
	const uint8_t *input = NULL;
	uint32_t input_len = 0;

	int ret = 1;
	
	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(sqlserver_conf.sqlserver_enable)) {
		goto error;
	}
	
	/* 获取 state 和 input 和 input_len */
	sqlserver_state = (SqlserverState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);

	/* 如果是加密流量不再解析 */
	if (1 == sqlserver_state->encryption_key) {
		goto error;
	}

	/* 如果已经解析了版本，那么需要判断是否需要继续解析 */
	if (1 == sqlserver_state->version_key) {
		/* 只解析版本 16.0.1000      及以上的包     */
		if (16 > sqlserver_state->major_version) {
			goto error;
		}else if (16 == sqlserver_state->major_version 
			&& 0 == sqlserver_state->sec_version
			&& 1000 > sqlserver_state->minor_version) {
			goto error;
		}
	}

	/* 可能连接关闭了 */
	if ((NULL == input || 1 > input_len) && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 异常判断 */
	if (NULL == input || 1 > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}
	
	/* 异常判断 */
	if (SQLSERVER_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = SqlserverTxAlloc(sqlserver_state, false);
	sqlserver_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(sqlserver_data->proto, "tcp", 3);
	sqlserver_data->is_request = false;

#if 0
    /* 注意: 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &sqlserver_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	sqlserver_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//sqlserver_state->transaction_max = 0;
	
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = SqlserverTxAlloc(sqlserver_state, false);
		sqlserver_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(sqlserver_data->proto, "tcp", 3);
	}
	sqlserver_data->is_request = false;
#endif	
	/************************* 解析私有数据 start ************************/	
	/* 请求和响应公用一个 tx, 因此响应要清理请求的 tx */
	/* 判断真实的方向，防止三次握手第一个包丢失造成方向识别错误，记住值永远都放在左侧，防止判断恒等时使用复制符号 '=' */
	if (SC_ATOMIC_GET(sqlserver_conf.sqlserver_dport) == f->sp) {
		ret = SqlserverParseReq(f, state, pstate, input, input_len, local_data, sqlserver_data);
	}else if (SC_ATOMIC_GET(sqlserver_conf.sqlserver_dport) == f->dp) {
		ret = SqlserverParseResp(f, state, pstate, input, input_len, local_data, sqlserver_data);
	}else {
		ret = 1;
	}

	/* 如果解析失败，不发送日志 */
	if (0 != ret) {
		goto end;
	}

	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	sqlserver_data->done = 1;
	sqlserver_data->complete = 1;
		
	/************************* 解析私有数据 end ************************/ 	
	
	
#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_sqlserver_event(f, sqlserver_data, STREAM_TOCLIENT);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 获取 tx */
static void *SqlserverGetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	SqlserverState *sqlserver = (SqlserverState *)alstate;
	SqlserverTransaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH(tx, &sqlserver->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

/* 获取 tx 计数 */
static uint64_t SqlserverGetTxCnt(void *state)
{
	SCEnter();
	uint64_t count = ((uint64_t)((SqlserverState *)state)->transaction_max);
	SCReturnUInt(count);
}

/* 释放一个 sqlserver tx */
static void SqlserverTxFree(SqlserverTransaction *tx)
{
	SCEnter();

	AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

	if (tx->tx_data.de_state != NULL) {
		DetectEngineStateFree(tx->tx_data.de_state);
	}

	/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
	if (NULL != tx->query_cmd) {
		SQLSERVER_FREESTR(tx->query_cmd);
	}
	
	/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
	if (NULL != tx->result_set) {
		SQLSERVER_FREESTR(tx->result_set);
	}

	SCFree(tx);
	SCReturn;
}

/* 通过 ID 释放特定 sqlserver 状态上的一个事务 */
static void SqlserverStateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	SqlserverState *sqlserver = state;
	SqlserverTransaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &sqlserver->tx_list, next, ttx) {

		if (tx->tx_num != tx_num) {
			continue;
		}

		//最好不要使用这个 curr，这个就是容易段错误的根源
		if (tx == sqlserver->curr) {
			sqlserver->curr = NULL;
		}

		TAILQ_REMOVE(&sqlserver->tx_list, tx, next);
		SqlserverTxFree(tx);
		break;
	}

	SCReturn;
}

/* 释放 sqlserver state */
static void SqlserverStateFree(void *state)
{
	SCEnter();
	SqlserverState *sqlserver = state;
	SqlserverTransaction *tx;
	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&sqlserver->tx_list)) != NULL) {
			TAILQ_REMOVE(&sqlserver->tx_list, tx, next);
			SqlserverTxFree(tx);
		}

		/* state 中的 请求体 和 响应体 缓存释放语句 */
		if (sqlserver->request_buffer.buffer != NULL) {
			SQLSERVER_FREESTR(sqlserver->request_buffer.buffer);
		}
		if (sqlserver->response_buffer.buffer != NULL) {
			SQLSERVER_FREESTR(sqlserver->response_buffer.buffer);
		}

		/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
		if (sqlserver->query_cmd_buffer.buffer != NULL) {
			SQLSERVER_FREESTR(sqlserver->query_cmd_buffer.buffer);
		}
		if (sqlserver->result_set_buffer.buffer != NULL) {
			SQLSERVER_FREESTR(sqlserver->result_set_buffer.buffer);
		}
		if (sqlserver->db_name.buffer != NULL) {
			SQLSERVER_FREESTR(sqlserver->db_name.buffer);
		}
		if (sqlserver->table_name.buffer != NULL) {
			SQLSERVER_FREESTR(sqlserver->table_name.buffer);
		}
		if (sqlserver->fields.buffer != NULL) {
			SQLSERVER_FREESTR(sqlserver->fields.buffer);
		}


		SCFree(sqlserver);
	}
	SCReturn;
}

/* 由应用层调用来获取状态进度 */
static int SqlserverGetAlstateProgress(void *tx, uint8_t direction)
{
	/* 直接返回，用完 tx 就释放提高性能 */
	return 1;

	SqlserverTransaction *sqlservertx = (SqlserverTransaction *)tx;
	int retval = 0;

	/* 原生逻辑是进度完成再释放，性能低 */
	if (sqlservertx->complete) {
		retval = 1;
	}	

	SCReturnInt(retval);
}

/* 获取 tx_data */
static AppLayerTxData *SqlserverGetTxData(void *vtx)
{
	SqlserverTransaction *tx = (SqlserverTransaction *)vtx;
	return &tx->tx_data;
}

/* 获取 state_data */
static AppLayerStateData *SqlserverGetStateData(void *vstate)
{
	SqlserverState *state = (SqlserverState *)vstate;
	return &state->state_data;
}

/* 迭代器 */
static AppLayerGetTxIterTuple SqlserverGetTxIterator(const uint8_t ipproto, const AppProto alproto,
	void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
	SqlserverState *dnp_state = (SqlserverState *)alstate;
	AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
	if (dnp_state) {
		SqlserverTransaction *tx_ptr;
		if (state->un.ptr == NULL) {
			tx_ptr = TAILQ_FIRST(&dnp_state->tx_list);
		} else {
			tx_ptr = (SqlserverTransaction *)state->un.ptr;
		}
		if (tx_ptr) {
			while (tx_ptr->tx_num < min_tx_id + 1) {
				tx_ptr = TAILQ_NEXT(tx_ptr, next);
				if (!tx_ptr) {
					return no_tuple;
				}
			}
			if (tx_ptr->tx_num >= max_tx_id + 1) {
				return no_tuple;
			}
			state->un.ptr = TAILQ_NEXT(tx_ptr, next);
			AppLayerGetTxIterTuple tuple = {
				.tx_ptr = tx_ptr,
				.tx_id = tx_ptr->tx_num - 1,
				.has_next = (state->un.ptr != NULL),
			};
			return tuple;
		}
	}
	return no_tuple;
}

/* 核心注册函数 */
void RegisterSqlserverParsers(void)
{
	const char *proto_name = "sqlserver";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_SQLSERVER, proto_name);

	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_SQLSERVER, 0, SQLSERVER_MIN_FRAME_LEN, SqlserverProbingParserTsTc, SqlserverProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_TCP, SQLSERVER_DEFAULT_PORT, ALPROTO_SQLSERVER, 0, SQLSERVER_MIN_FRAME_LEN, STREAM_TOSERVER, SqlserverProbingParserTsTc, SqlserverProbingParserTsTc);	
	}

	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
		SCLogConfig("Registering sqlserver/tcp parsers.");
		
		SqlserverReload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(sqlserver_conf.sqlserver_enable , 0);
		SC_ATOMIC_SET(sqlserver_conf.log_enable, 0);
		SC_ATOMIC_SET(sqlserver_conf.sqlserver_dport, atoi(SQLSERVER_DEFAULT_PORT));
		SC_ATOMIC_SET(sqlserver_conf.result, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Sqlserver流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_SQLSERVER, SqlserverStateAlloc, SqlserverStateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SQLSERVER, STREAM_TOSERVER, SqlserverParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SQLSERVER, STREAM_TOCLIENT, SqlserverParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_SQLSERVER, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_SQLSERVER, SqlserverGetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_SQLSERVER, SqlserverGetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_SQLSERVER, SqlserverStateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_SQLSERVER, SqlserverGetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_SQLSERVER, SqlserverGetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_SQLSERVER, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_SQLSERVER, SqlserverGetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_SQLSERVER, SqlserverGetStateData);
	
	SCReturn;
}

