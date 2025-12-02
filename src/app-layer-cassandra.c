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

#include "app-layer-cassandra.h"

CassandraConf cassandra_conf;

/* 0x00 模式串，用于快速查找字符串结尾 */
//static uint8_t CASSANDRA_STR_END_PATT[1] = {0x00};

/* CQL_VERSION(0x43,0x51,0x4C,0x5F,0x56,0x45,0x52,0x53,0x49,0x4F,0x4E) 模式串 */
static uint8_t CASSANDRA_CQL_VERSION_PATT[11] = {0x43, 0x51, 0x4C, 0x5F, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4F, 0x4E};

/* DRIVER_NAME(0x44,0x52,0x49,0x56,0x45,0x52,0x5F,0x4E,0x41,0x4D,0x45) 模式串 */
static uint8_t CASSANDRA_DRIVER_NAME_PATT[11] = {0x44, 0x52, 0x49, 0x56, 0x45, 0x52, 0x5F, 0x4E, 0x41, 0x4D, 0x45};

/* DRIVER_VERSION(0x44,0x52,0x49,0x56,0x45,0x52,0x5F,0x56,0x45,0x52,0x53,0x49,0x4F,0x4E) 模式串 */
static uint8_t CASSANDRA_DRIVER_VERSION_PATT[14] = {0x44, 0x52, 0x49, 0x56, 0x45, 0x52, 0x5F, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4F, 0x4E};

/* CLIENT_ID(0x43,0x4C,0x49,0x45,0x4E,0x54,0x5F,0x49,0x44) 模式串 */
static uint8_t CASSANDRA_CLIENT_ID_PATT[9] = {0x43, 0x4C, 0x49, 0x45, 0x4E, 0x54, 0x5F, 0x49, 0x44};

/* 热加载函数 */
void CassandraReload(void)
{
	/* 获取是否打开日志开关 */
	ConfNode *node = NULL;

	/* 插件开关 */
	node = NULL;
	node = ConfGetNode(CASSANDRA_ENABLED_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(cassandra_conf.cassandra_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(cassandra_conf.cassandra_enable, 0);
	}

	/* 获取是否打开日志开关 */
	node = ConfGetNode(CASSANDRA_LOG_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(cassandra_conf.log_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(cassandra_conf.log_enable, 0);
	}	

	/* 获取 Cassandra 配置文件中的 dport 用于方向判断 */
	node = ConfGetNode(CASSANDRA_DPORT);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(cassandra_conf.cassandra_dport, atoi(node->val));
	}else {
		SC_ATOMIC_SET(cassandra_conf.cassandra_dport, atoi(CASSANDRA_DEFAULT_PORT));
	}	

	/* 获取是否打开结果集开关 */
	node = ConfGetNode(CASSANDRA_RESULT);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(cassandra_conf.result, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(cassandra_conf.result, 0);
	}	

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
		1 CassandraTransaction *tx: Cassandra 的私有结构

	返回：void
*/
static void print_cassandra_event(Flow *f, CassandraTransaction *tx, uint16_t direction)
{
	/* 参数检查 */
	if (NULL == tx) {
		return;
	}

	char msg_buf[1024] = {0};
	CassandraTransaction *cassandra_data = NULL;

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
	cassandra_data = tx;

	/* 时间 2016/09/22 12:21:30 */
	get_local_time(cassandra_data->time_buff);
	
	/* 打印 */
	snprintf(msg_buf, sizeof(msg_buf), "done=%u", \
			cassandra_data->done \
			);

	/* 打印公共字段 */
	DEBUG_DLOG("-----8888888888----- date: %s, s_ip: %s, s_port: %u, d_ip: %s, d_port: %u, dir: %d, protocal: %s, msg_buf: %s", \
				cassandra_data->time_buff,\
				src_ip, src_port,\
				dst_ip, dst_port,\
				cassandra_data->is_request, cassandra_data->proto,\
				msg_buf \
				);

	return;
}
#endif






/* Ts 和 Tc 是指 Request 和 Response 方向协议识别和异常判断，合并到一起了，以后需要时还要拆分成两个函数，因为请求包和响应包结构不同 */
static AppProto CassandraProbingParserTsTc(Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
	if (NULL == input || 0 >= input_len) {
		return ALPROTO_UNKNOWN;
	}

	//const uint8_t *p_data = NULL;
	uint16_t p_len = 0;

	/* 如果没有打开则强制不再识别识别, 后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(cassandra_conf.cassandra_enable)) {
		return ALPROTO_UNKNOWN;
	}
	
	/* 负载和负载长度 */
	//p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if (p_len < CASSANDRA_MIN_FRAME_LEN) {
		return ALPROTO_UNKNOWN;
	}

	return ALPROTO_CASSANDRA;
}

/* 分配一个 cassandra 状态对象，表示一个 cassandra TCP 会话 */
static void *CassandraStateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	CassandraState *cassandra;

	cassandra = (CassandraState *)SCCalloc(1, sizeof(CassandraState));
	if (unlikely(cassandra == NULL)) {
		return NULL;
	}
	TAILQ_INIT(&cassandra->tx_list);

	SCReturnPtr(cassandra, "void");
}

/* 分配一个 cassandra transaction */
static CassandraTransaction *CassandraTxAlloc(CassandraState *cassandra, bool request)
{
	CassandraTransaction *tx = SCCalloc(1, sizeof(CassandraTransaction));
	if (unlikely(tx == NULL)) {
		return NULL;
	}
	cassandra->transaction_max++;
	cassandra->curr = tx;
	tx->cassandra = cassandra;
	tx->tx_num = cassandra->transaction_max;
	tx->is_request = request;
	if (tx->is_request) {
		tx->tx_data.detect_flags_tc |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	} else {
		tx->tx_data.detect_flags_ts |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	}

	TAILQ_INSERT_TAIL(&cassandra->tx_list, tx, next);

	return tx;
}

#if 0
static char cassandra_hex_to_char(unsigned char ch)
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

static int cassandra_hex_to_str(unsigned char *src, uint32_t src_len, char *dst, uint32_t *dst_len)
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
		t_chr = cassandra_hex_to_char(tmp_char);
		dst[j] = t_chr;

		/* 低 4 bit 转换 */
		src_char = 0x00;
		src_char = src[i];
		tmp_char = 0x00;
		tmp_char = (src_char & 0x0f);

		/* 获取低位转换的字符 */
		t_chr = '0';
		t_chr = cassandra_hex_to_char(tmp_char);
		dst[j+1] = t_chr;

		j += 2;
	}

	*dst_len = j;

	return 0;
}

#endif


/* 配合 sunday 算法获取模式串第一次命中的位置 */
static int CassandraFindIndex(uint8_t *patt_str, int patt_len, uint8_t uc_tmp, int *index)
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
static int CassandraSundayALG(const uint8_t *src, uint32_t src_len, uint8_t *patt_str, int patt_len, uint32_t *dst_len)
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
            ret = CassandraFindIndex(patt_str, patt_len, src[tmp], &index);
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


/* 释放分片重组缓冲区 */
static int CassandraBufferFree(CassandraBuffer *buffer)
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
static int CassandraBufferAdd(CassandraBuffer *buffer, const uint8_t *data, uint32_t len)
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

#if 0
/* 解析 解析 major.minor 版本 user 和 database 包 */
static int CassandraParseReqUserDatabaseVersion(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t location = 0;
	uint32_t find_len = 0;
	uint8_t version[CASSANDRA_VERSION_LEN] = {0};

	uint16_t major = 0;
	uint16_t minor = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* pos 游标滑动到 major 版本 */
	pos += 4;
	
	/* 异常判断 */
	if (pos + 4 >= p_len) {
		return 1;
	}

	/* 取出主次版本 */
	major = CASSANDRA_GET_VALUE16(p_data + pos);
	minor = CASSANDRA_GET_VALUE16(p_data + pos + 2);

	/* 保存版本 */
	snprintf((char *)version, sizeof(version), "%u.%u", major, minor);
	CassandraBufferFree(&(cassandra_state->client_version));
	CassandraBufferAdd(&(cassandra_state->client_version), version, strlen((char *)version));

	/* pos 移动到 user */
	pos += 4;

	/* 异常判断 */
	if (pos + 6 >= p_len) {
		return 1;
	}

	/* 异常判断 */
	if (0 != strncasecmp((char *)(p_data + pos), "user", 4)) {
		return 1;
	}

	/* pos 移动到 username */
	pos += 5;
	
	/* 异常判断 */
	if (pos + 2 >= p_len) {
		return 1;
	}
	
	/* 如果 pos 游标后的剩余长度大于用户名缓存，也只查询用户名缓存这么长，提高效率 */
	if (p_len - pos >= CASSANDRA_USER_LEN) {
		find_len = CASSANDRA_USER_LEN;
	}else {
		find_len = (p_len - pos);
	}
	
	/* 查找用户名结尾 0x00 */
	location = 0;
	CassandraSundayALG((p_data + pos), find_len, CASSANDRA_STR_END_PATT, 1, &location);
	if (0 == location) {
		return 1;
	}
	
	/* 取出 Username */
	CassandraBufferFree(&(cassandra_state->user));
	CassandraBufferAdd(&(cassandra_state->user), (p_data + pos), location);
	
	/* pos 移动到 database */
	pos += location + 1;
	
	/* 异常判断 */
	if (pos + 10 >= p_len) {
		return 1;
	}

	/* 异常判断 */
	if (0 != strncasecmp((char *)(p_data + pos), "database", 8)) {
		return 1;
	}

	/* pos 移动到 database */
	pos += 9;
	
	/* 异常判断 */
	if (pos + 2 >= p_len) {
		return 1;
	}

	/* 如果 pos 游标后的剩余长度大于database名缓存，也只查询缓存这么长，提高效率 */
	if (p_len - pos >= CASSANDRA_DATABASE_LEN) {
		find_len = CASSANDRA_DATABASE_LEN;
	}else {
		find_len = (p_len - pos);
	}
	
	/* 查找用户名结尾 0x00 */
	location = 0;
	CassandraSundayALG((p_data + pos), find_len, CASSANDRA_STR_END_PATT, 1, &location);
	if (0 == location) {
		return 1;
	}

	/* 取出 database */
	CassandraBufferFree(&(cassandra_state->db_name));
	CassandraBufferAdd(&(cassandra_state->db_name), (p_data + pos), location);

	return 0;
}

/* 解析 Response 中的 Result Set，循环解析  */
static int CassandraParseRespResultSetLoop(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data, uint8_t *fram_key)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len || NULL == fram_key) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_pos = 0;
	uint32_t start_pos = 0;
	uint32_t type = 0;
	uint32_t length = 0;
	uint8_t number_of_field = 0;
	uint16_t field_count = 0;
	uint32_t location = 0;
	uint8_t skip_row_key = 0;
	uint32_t column_length = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* 判断需要解析拼接后的缓存，还是直接解析完整的数据包 */
	if (1 == cassandra_state->response_buffer_need) {
		/* 如果上一个包有分片，缓存本次数据包，与上一个数据包尾部的分片组成一个完整的 buff ，像解析 DNS 一样循环解析，然后还要判断尾部是否有下一个数据包的分片 */
		CassandraBufferAdd(&(cassandra_state->response_buffer), p_data, p_len);

		/* 局部变量重新赋值 */
		p_data = cassandra_state->response_buffer.buffer;
		p_len = cassandra_state->response_buffer.len;
	}

	/* 异常判断 */
	if (pos + 7 > p_len) {
		return 1;
	}

	/* 取出 Type */
	type = p_data[0];

	/* 取出 Length */
	if (0 == type) {
		length = CASSANDRA_GET_VALUE32(p_data);
		
		/* 向后移动 pos */
		pos += 4;
	}else {
		length = CASSANDRA_GET_VALUE32(p_data + 1);

		/* 向后移动 pos */
		pos += 4 + 1;
	}

	/* 判断 C/Z 结尾 */
	if (0x43 == type 
		&& 1 == cassandra_state->fields.fields_finish
		&& (1 + length + 1) < p_len
		&& 0x5a == (p_data + 1 + length)[0]) {

		/* 如果遇见 C/Z 结尾，说明响应包已经结束 */
		cassandra_state->result_set_buffer.finish_key = 1;
		cassandra_state->send_key = 1;
	}

	/* 如果是响应的第一个包*/
	if (0x54 == type) {
		/* 如果是解析新的第一个响应包，清空缓存 */
		CassandraBufferFree(&(cassandra_state->result_set_buffer));
		//CassandraBufferFree(&(cassandra_state->db_name));
		//CassandraBufferFree(&(cassandra_state->table_name));
		CassandraBufferFree(&(cassandra_state->fields));
		//CassandraBufferFree(&(cassandra_state->version));
		//CassandraBufferFree(&(cassandra_state->user));

		/* 如果是第一个新的响应包取出 列个数 */
		cassandra_state->fields.column_count = CASSANDRA_GET_VALUE16(p_data + 1 + 4);

		/* 字段计数器清零 */
		cassandra_state->field_count = 0;

		/* pos 跳过 Field count */
		pos += 2;
	}

	/* 循环解析 */
	while (pos + 7 <= p_len) {
		/* 判断是解析 列 还是 行 */
		if (0 != cassandra_state->fields.column_count 
			&& 0 == cassandra_state->fields.fields_finish) {
			/* 卡关用于解析 data row 数据时判断是否解析过 Row description */
			skip_row_key = 1;

			/* 累加临时字段计数 */
			cassandra_state->field_count += 1;

			/* 异常判断 */
			if (pos + 2 > p_len) {
				continue;
			}

			/* 查找用户名结尾 0x00 */
			location = 0;
			CassandraSundayALG((p_data + pos), (p_len - pos), CASSANDRA_STR_END_PATT, 1, &location);
			if (0 == location) {
				return 1;
			}

			/* 取出  字段 name */
			if (0 == cassandra_state->fields.fields_finish && 1 != cassandra_state->fields.finish_key) {
				/* 保存字段名称 */
				CassandraBufferAdd(&(cassandra_state->fields), (p_data + pos), location);

				/* 如果是最后一个字段后面加换行符 */
				if (cassandra_state->field_count == cassandra_state->fields.column_count) {
					cassandra_state->fields.finish_key = 1;
					CassandraBufferAdd(&(cassandra_state->fields), CASSANDRA_CRLF, 3);
				}else {
					CassandraBufferAdd(&(cassandra_state->fields), CASSANDRA_DOT, 2);
				}

			}			

			/* pos 跳到字段结构的尾部 */
			pos += location + 1 + 4 + 2 + 4 + 2 + 4 + 2;

			/* 判断是否解析完列字段 */
			if (cassandra_state->field_count == cassandra_state->fields.column_count) {
				cassandra_state->fields.fields_finish = 1;
			}
			
			/* 使用单层循环解析列字段 */
			continue;

		}else if (0 != cassandra_state->fields.column_count 
			&& 1 == cassandra_state->fields.fields_finish) {
			/* 判断是否数据包到来直接进入 data row 解析 */
			if (1 == skip_row_key) {
				type = (p_data + pos)[0];
				length = CASSANDRA_GET_VALUE32(p_data + pos + 1);
				field_count = CASSANDRA_GET_VALUE16(p_data + pos + 1 + 4);

				/* 异常判断 */
				if (0x44 != type && 0x43 != type && 0x5a != type) {
					return 1;
				}
				
				/* 移动 pos 到数据部分 */
				pos += 1 + 4 + 2;
			}else {
				/* 开关打开，下次就开始从头部解析了 */
				skip_row_key = 1;

				/* 异常判断 */
				if (0x44 != type && 0x43 != type && 0x5a != type) {
					return 1;
				}

				/* 如果直接进入这个逻辑 pos 已经累加了 1 + 4 个字节 */
				field_count = CASSANDRA_GET_VALUE16(p_data + pos);
				
				/* 移动 pos 到数据部分 */
				pos += 2;
			}

			/* 先回退 pos，然后判断是否数据包的尾部有下一个包的分片 */
			start_pos = pos - 2 - 4 - 1;
			if (start_pos + 1 + length > p_len) {
				if (p_len > start_pos) {
					/* 打开分片开关 */
					*fram_key = 1;
					cassandra_state->response_buffer_need = 1;
			
					/* 缓存分片，先清理后缓存 */
					CassandraBufferFree(&(cassandra_state->response_buffer));
					CassandraBufferAdd(&(cassandra_state->response_buffer), (p_data + start_pos), (p_len - start_pos));
					return 1;
				}else {
					return 1;
				}
			}

			/* 先回退 pos，然后判断 C/Z 结尾 */
			start_pos = pos - 2 - 4 - 1;
			if (0x43 == type 
				&& 1 == cassandra_state->fields.fields_finish
				&& (start_pos + 1 + length + 1) < p_len
				&& 0x5a == (p_data + start_pos + 1 + length)[0]) {
			
				/* 如果遇见 C/Z 结尾，说明响应包已经结束 */
				cassandra_state->result_set_buffer.finish_key = 1;
				cassandra_state->send_key = 1;

				return 0;
			}

			/* 循环解析 Data row 的数据部分，pos 已经移动到该部分 */
			tmp_pos = pos;
			number_of_field = 0;
			while (tmp_pos + 4 < p_len
				&& number_of_field < field_count) {
				
				/* 累加列字段计数 */
				number_of_field += 1;

				/* 取出 Column length */
				column_length = CASSANDRA_GET_VALUE32(p_data + tmp_pos);

				/* 异常判断 */
				if (0xffffffff != column_length && tmp_pos + 4 + column_length > p_len) {
					return 1;
				}

				/* tmp_pos 移动到 text */
				tmp_pos += 4;

				/* 存储 row 信息 */
				if (0xffffffff == column_length) {
					CassandraBufferAdd(&(cassandra_state->result_set_buffer), (const uint8_t *)"null", 4);
					
					/* 如果是最后一个字段后面加换行符 */
					if (number_of_field == field_count) {
						CassandraBufferAdd(&(cassandra_state->result_set_buffer), CASSANDRA_CRLF, 3);
					}else {
						CassandraBufferAdd(&(cassandra_state->result_set_buffer), CASSANDRA_DOT, 2);
					}

					continue;
				}else {
					CassandraBufferAdd(&(cassandra_state->result_set_buffer), (p_data + tmp_pos), column_length);
				}

				/* 如果是最后一个字段后面加换行符 */
				if (number_of_field == field_count) {
					CassandraBufferAdd(&(cassandra_state->result_set_buffer), CASSANDRA_CRLF, 3);
				}else {
					CassandraBufferAdd(&(cassandra_state->result_set_buffer), CASSANDRA_DOT, 2);
				}

				/* tmp_pos 跳过 text */
				tmp_pos += column_length;
			}

			/* pos 跳过 row */
			pos -= (2 + 4 + 1);
			pos += 1 + length;

		}else {
			return 1;
		}
	}

	/* 尾巴剩余的可能不够满足一个响应头部，因此缓存起来，与下一个包拼接成完整的头部 */
	if (pos + 7 > p_len && p_len - pos > 0) {
		/* 打开分片开关 */
		*fram_key = 1;
		cassandra_state->response_buffer_need = 1;
		
		/* 缓存分片，先清理后缓存 */
		CassandraBufferFree(&(cassandra_state->response_buffer));
		CassandraBufferAdd(&(cassandra_state->response_buffer), (p_data + pos), (p_len - pos));
		return 1;
	}


	return 0;
}
#endif

/* 解析 Response 中的 Result Set  */
static int CassandraParseRespResultSet(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

#if 0
	CassandraState *cassandra_state = NULL;
	uint8_t fram_key = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;

	/* 判断是否有上一个数据包的分片 */
	if (1 == cassandra_state->response_buffer_need) {
		/* 循环解析响应中的结果集 */
		CassandraParseRespResultSetLoop(f, statev, pstate, input, input_len, local_data, cassandra_data, &fram_key);

		/* 判断这个包的尾巴是否有分片，如果有分片，存储起来下次响应包到来的时候与写一个包拼接成一个完整的包 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		CassandraBufferFree(&(cassandra_state->response_buffer));
		cassandra_state->response_buffer_need = 0;
	}else {
		/* 循环解析响应中的结果集 */
		CassandraParseRespResultSetLoop(f, statev, pstate, input, input_len, local_data, cassandra_data, &fram_key);

		/* 如果响应包的尾部有下一个包的分片，那么打开开关，缓存分片 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		CassandraBufferFree(&(cassandra_state->response_buffer));
		cassandra_state->response_buffer_need = 0;
	}
#endif

	return 0;
}

#if 0
/* 解析 Query 中的 SQL 语句 */
static int CassandraParseReqQuery(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t length = 0;
	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* 判断是解析缓存还是解析数据包 */
	if ((1 == cassandra_state->request_buffer_need)
		&& (0 != cassandra_state->query_cmd_buffer.len)
		&& (cassandra_state->query_cmd_buffer.len == cassandra_state->query_cmd_buffer.total_len)) {

		/* 能调到这个函数，说明已经完成纯 SQL 语句的缓存，打开已完成开关 */
		cassandra_state->query_cmd_buffer.finish_key = 1;

	}else {
		/* 清空上次缓存 */
		CassandraBufferFree(&(cassandra_state->query_cmd_buffer));
	
		/* 异常判断 */
		if (pos + 9 + 4 >= p_len) {
			return 1;
		}
		
		/* 取出 Message   length */
		length = CASSANDRA_GET_VALUE32(p_data + 5);		
		
		/* 异常判断 */
		if (length + 9 != p_len) {
			return 1;
		}
		
		/* pos 移动到 String Length */
		pos += 9;		

		/* 取出 String   length */
		length = CASSANDRA_GET_VALUE32(p_data + pos);	

		/* pos 移动到数据头部 */
		pos += 4;

		/* 异常判断 */
		if (pos + length > p_len) {
			return 1;
		}
		
		/* 保存 Query   */
		ret = CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), (p_data + pos), length);
		if (0 != ret) {
			CassandraBufferFree(&(cassandra_state->query_cmd_buffer));
			return 1;
		}
		cassandra_state->query_cmd_buffer.finish_key = 1;

	}

	return 0;
}
#endif

/* 解析 cassandra 响应 包 */
static int CassandraParseResp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	//const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	//uint32_t length = 0;

	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	//p_data = input;
	p_len = input_len;

	/* 就前两个数据包需要计数，其他都不用 */
	if (cassandra_state->pkt_num < 4) {
		cassandra_state->pkt_num += 1;
	}

	/* 响应包到来，说明前面的请求都已经结束了，需要关闭请求缓存开关，但是不能释放请求缓存，请求缓存还需和响应合并 */
	cassandra_state->request_buffer_need = 0;
	CassandraBufferFree(&(cassandra_state->request_buffer));
	//CassandraBufferFree(&(cassandra_state->query_cmd_buffer));

	/* 结果集开关关闭时不解析结果集，直接返回 */
	if (4 <= cassandra_state->pkt_num && 0 == SC_ATOMIC_GET(cassandra_conf.result)) {
		return 1;
	}

	/* 异常判断 */
	if ((1 != cassandra_state->response_buffer_need) && (pos + 9 > p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == cassandra_state->response_buffer_need) {
		/* 解析响应缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
		ret = CassandraParseRespResultSet(f, statev, pstate, input, input_len, local_data, cassandra_data);
		if (0 != ret) {
			return 1;
		}else {
			return 0;
		}
	}

	/* 解析响应缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
	ret = CassandraParseRespResultSet(f, statev, pstate, input, input_len, local_data, cassandra_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}

/* 解析 Reruest 的 SQL 语句，循环解析  */
static int CassandraParseReqCmdV4Loop(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data, uint8_t *fram_key)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len || NULL == fram_key) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t start_pos = 0;
	uint8_t opcode = 0;
	uint32_t string_length = 0;
	uint32_t message_length = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* 判断需要解析拼接后的缓存，还是直接解析完整的数据包 */
	if (1 == cassandra_state->request_buffer_need) {
		/* 如果上一个包有分片，缓存本次数据包，与上一个数据包尾部的分片组成一个完整的 buff ，像解析 DNS 一样循环解析，然后还要判断尾部是否有下一个数据包的分片 */
		CassandraBufferAdd(&(cassandra_state->request_buffer), p_data, p_len);

		/* 局部变量重新赋值 */
		p_data = cassandra_state->request_buffer.buffer;
		p_len = cassandra_state->request_buffer.len;

		/* 异常判断 */
		if (5 + 4 >= p_len) {
			return 1;
		}

		/* 取出总长度 */
		if (0 == cassandra_state->request_buffer.total_len) {
			/* 总长度赋值 */
			cassandra_state->request_buffer.total_len = CASSANDRA_GET_VALUE32(p_data + 5);
		}

		/* 判断本分片的 SQL String 是否已经缓冲完成，没有完成接着缓冲 */
		if (cassandra_state->request_buffer.total_len > p_len - 5 - 4) {
			return 1;
		}
	}

	/* 异常判断 */
	if (pos + 14 > p_len) {
		return 1;
	}

	/* 循环解析 SQL String 数据 */
	while (pos + 14 < p_len) {
		/* pos 移动到 opcode */
		pos += 4;

		/* 取出 opcode */
		opcode = (p_data + pos)[0];	

		/* pos 跳过 opcode 特征 */
		pos += 1;

		/* 取出 Message Length */
		message_length = CASSANDRA_GET_VALUE32(p_data + pos);

		/* 只解析 query */
		if (0x07 != opcode) {
			/* 不是 query 命令，跳过后面长度 */
			pos += 4 + message_length;
			continue;
		}

		/* 取出 string_length */
		string_length = CASSANDRA_GET_VALUE32(p_data + pos + 4);

		/* 异常判断 */
		if (string_length >= message_length) {
			return 1;
		}

		/* 先回退 pos，缓存分片 */
		start_pos = pos - 5;
		if (pos + 4 + message_length > p_len) {
			/* 打开分片开关 */
			*fram_key = 1;
			cassandra_state->request_buffer_need = 1;
		
			/* 缓存分片，先清理后缓存 */
			CassandraBufferFree(&(cassandra_state->request_buffer));
			if (p_len > start_pos) {
				CassandraBufferAdd(&(cassandra_state->request_buffer), (p_data + start_pos), (p_len - start_pos));
			}

			/* 总长度赋值 */
			cassandra_state->request_buffer.total_len = message_length;

			return 1;
		}

		/* pos 移动到数据头部 */
		pos += 8;

		/* 异常判断 */
		if (pos + string_length > p_len) {
			return 1;
		}

		/* 保存 SQL cmd 信息 */
		CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), (p_data + pos), string_length);
	
		/* 如果是最后一个字段后面加换行符 */
		if ((pos - 4 + message_length == p_len) || ((pos - 4 + message_length + 1 < p_len) && (0x04 != (p_data + pos - 4 + message_length)[0]))) {
			CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), CASSANDRA_CRLF, 3);
			cassandra_state->query_cmd_buffer.finish_key = 1;
		}else {
			CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), CASSANDRA_SPACE, 1);
		}
	
		/* pos 跳到 text */
		pos += message_length - 4;

		/* 解析请求结束 */
		if (1 == cassandra_state->query_cmd_buffer.finish_key) {
			break;
		}
	}

	/* 尾巴剩余的可能不够满足一个响应头部，因此缓存起来，与下一个包拼接成完整的头部 */
	if ((pos + 14 >= p_len) && (p_len - pos > 5) && (0x07 == (p_data + pos + 4)[0]) && (0x04 == (p_data + pos)[0])) {
		/* 打开分片开关 */
		*fram_key = 1;
		cassandra_state->request_buffer_need = 1;
		
		/* 缓存分片，先清理后缓存 */
		CassandraBufferFree(&(cassandra_state->request_buffer));
		CassandraBufferAdd(&(cassandra_state->request_buffer), (p_data + pos), (p_len - pos)); 

		return 1;
	}

	return 0;
}

/* 解析 Reruest 的 SQL 语句，循环解析  */
static int CassandraParseReqCmdV5Loop(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data, uint8_t *fram_key)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len || NULL == fram_key) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t start_pos = 0;

	uint32_t sql_len = 0;
	uint32_t total_len = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* 判断需要解析拼接后的缓存，还是直接解析完整的数据包 */
	if (1 == cassandra_state->request_buffer_need) {
		/* 如果上一个包有分片，缓存本次数据包，与上一个数据包尾部的分片组成一个完整的 buff ，像解析 DNS 一样循环解析，然后还要判断尾部是否有下一个数据包的分片 */
		CassandraBufferAdd(&(cassandra_state->request_buffer), p_data, p_len);

		/* 局部变量重新赋值 */
		p_data = cassandra_state->request_buffer.buffer;
		p_len = cassandra_state->request_buffer.len;

		/* 异常判断 */
		if (5 + 4 >= p_len) {
			return 1;
		}

		/* 取出总长度 */
		if (0 == cassandra_state->request_buffer.total_len) {
			/* 总长度赋值 */
			cassandra_state->request_buffer.total_len = CASSANDRA_GET_VALUE32(p_data + 5);
		}

		/* 判断本分片的 SQL String 是否已经缓冲完成，没有完成接着缓冲 */
		if (cassandra_state->request_buffer.total_len > p_len - 5 - 4) {
			return 1;
		}
	}

	/* 如果是非分片数据包，pos 要跳过头部 6 个字节 */
	if (1 != cassandra_state->request_buffer_need) {
		pos += 6;
	}

	/* 异常判断 */
	if (pos + 5 >= p_len) {
		return 1;
	}

	/* 判断是否是 query，只解析这种类型数据包 */
	if (1 != CASSANDRA_IS_V5_QUERY(p_data + pos)) {
		return 1;
	}

	/* 循环解析 SQL String 数据 */
	while (pos + 5 + 8 < p_len) {

		/* 判断是否是 query，只解析这种类型数据包 */
		if (1 != CASSANDRA_IS_V5_QUERY(p_data + pos)) {
			return 1;
		}		

		/* pos 跳过 query 特征 */
		pos += 5;

		/* 取出 total_len */
		total_len = CASSANDRA_GET_VALUE32(p_data + pos);

		/* 取出 sql_len */
		sql_len = CASSANDRA_GET_VALUE32(p_data + pos + 4);

		/* 异常判断 */
		if (sql_len >= total_len) {
			return 1;
		}

		/* 先回退 pos，缓存分片 */
		start_pos = pos - 5;
		if (pos + 4 + total_len > p_len) {
			/* 打开分片开关 */
			*fram_key = 1;
			cassandra_state->request_buffer_need = 1;
		
			/* 缓存分片，先清理后缓存 */
			CassandraBufferFree(&(cassandra_state->request_buffer));
			if (p_len > start_pos) {
				CassandraBufferAdd(&(cassandra_state->request_buffer), (p_data + start_pos), (p_len - start_pos));
			}

			/* 总长度赋值 */
			cassandra_state->request_buffer.total_len = total_len;
			
			return 1;
		}

		/* pos 移动到数据头部 */
		pos += 8;

		/* 异常判断 */
		if (pos + sql_len > p_len) {
			return 1;
		}

		/* 保存 SQL cmd 信息 */
		CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), (p_data + pos), sql_len);
	
		/* 如果是最后一个字段后面加换行符 */
		if (((pos - 4 + total_len + 1 < p_len) && (0x05 != (p_data + pos - 4 + total_len)[0])) || (pos - 4 + total_len + 4 == p_len)) {
			CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), CASSANDRA_CRLF, 3);
			cassandra_state->query_cmd_buffer.finish_key = 1;
		}else {
			CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), CASSANDRA_SPACE, 1);
		}
	
		/* pos 跳到 text */
		pos += total_len - 4;

		/* 解析请求结束 */
		if (1 == cassandra_state->query_cmd_buffer.finish_key) {
			break;
		}
	}

	/* 尾巴剩余的可能不够满足一个响应头部，因此缓存起来，与下一个包拼接成完整的头部 */
	if ((pos + 5 + 8 >= p_len) && (p_len - pos > 5) && (1 == CASSANDRA_IS_V5_QUERY(p_data + pos))) {
		/* 打开分片开关 */
		*fram_key = 1;
		cassandra_state->request_buffer_need = 1;
		
		/* 缓存分片，先清理后缓存 */
		CassandraBufferFree(&(cassandra_state->request_buffer));
		CassandraBufferAdd(&(cassandra_state->request_buffer), (p_data + pos), (p_len - pos)); 
		return 1;
	}

	return 0;
}

/* 解析 Request 中的 命令  */
static int CassandraParseReqCmdV4(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	uint8_t fram_key = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;

	/* 判断是否有上一个数据包的分片 */
	if (1 == cassandra_state->request_buffer_need) {
		/* 循环解析响应中的结果集 */
		CassandraParseReqCmdV4Loop(f, statev, pstate, input, input_len, local_data, cassandra_data, &fram_key);

		/* 判断这个包的尾巴是否有分片，如果有分片，存储起来下次响应包到来的时候与写一个包拼接成一个完整的包 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		CassandraBufferFree(&(cassandra_state->request_buffer));
		cassandra_state->request_buffer_need = 0;
	}else {
		/* 循环解析响应中的结果集 */
		CassandraParseReqCmdV4Loop(f, statev, pstate, input, input_len, local_data, cassandra_data, &fram_key);

		/* 如果响应包的尾部有下一个包的分片，那么打开开关，缓存分片 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		CassandraBufferFree(&(cassandra_state->request_buffer));
		cassandra_state->request_buffer_need = 0;
	}

	return 0;
}


/* 解析 Request 中的 命令  */
static int CassandraParseReqCmdV5(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	uint8_t fram_key = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;

	/* 判断是否有上一个数据包的分片 */
	if (1 == cassandra_state->request_buffer_need) {
		/* 循环解析响应中的结果集 */
		CassandraParseReqCmdV5Loop(f, statev, pstate, input, input_len, local_data, cassandra_data, &fram_key);

		/* 判断这个包的尾巴是否有分片，如果有分片，存储起来下次响应包到来的时候与写一个包拼接成一个完整的包 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		CassandraBufferFree(&(cassandra_state->request_buffer));
		cassandra_state->request_buffer_need = 0;
	}else {
		/* 循环解析响应中的结果集 */
		CassandraParseReqCmdV5Loop(f, statev, pstate, input, input_len, local_data, cassandra_data, &fram_key);

		/* 如果响应包的尾部有下一个包的分片，那么打开开关，缓存分片 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		CassandraBufferFree(&(cassandra_state->request_buffer));
		cassandra_state->request_buffer_need = 0;
	}

	return 0;
}


/* 解析 cassandra V5 请求 包 */
static int CassandraParseReqV5(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_pos = 0;
	uint64_t length = 0;
	uint32_t location = 0;
	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if ((1 != cassandra_state->request_buffer_need) && (pos + 20 >= p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == cassandra_state->request_buffer_need) {
		/* 解析请求缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
		ret = CassandraParseReqCmdV5(f, statev, pstate, input, input_len, local_data, cassandra_data);
		if (0 != ret) {
			return 1;
		}else {
			return 0;
		}
	}

	/* 异常判断 */
	if (pos + 20 >= p_len) {
		return 1;
	}

	/* pos 移动到 query 特征头部 */
	pos += 6;

	/* 判断是否是 query，只解析这种类型数据包 */
	if (1 != CASSANDRA_IS_V5_QUERY(p_data + pos) && 1 != CASSANDRA_IS_V5_CQL_VERSION(p_data)) {
		return 1;
	}

	/* 请求的第一个包清理各种缓存 */
	CassandraBufferFree(&(cassandra_state->query_cmd_buffer));
	cassandra_state->request_buffer_need = 0;
	CassandraBufferFree(&(cassandra_state->request_buffer));

	/* 判断是否是 CQL_WERSION */
	length = CASSANDRA_GET_VALUE32(p_data + 5);
	if (0 == cassandra_state->cql_version.len
		&& 4 >= cassandra_state->pkt_num 
		&& 1 == CASSANDRA_IS_V5_CQL_VERSION(p_data)
		&& length + 9 == p_len) {

		/************** (1) CQL_VERSION **************/
		
		/* 异常判断 */
		if (tmp_pos + 14 > p_len) {
			return 1;
		}

		/* 查找用户名结尾 0x00 */
		location = 0;
		CassandraSundayALG((p_data + tmp_pos), (p_len - tmp_pos), CASSANDRA_CQL_VERSION_PATT, 11, &location);
		if (0 == location) {
			return 1;
		}		

		/* tmp_pos 移动到    CQL_VERSION 后面长度 */
		tmp_pos += location + 11;

		/* 取出 CQL_VERSION len */
		length = CASSANDRA_GET_VALUE16(p_data + tmp_pos);

		/* tmp_pos 移动到    CQL_VERSION data */
		tmp_pos += 2;

		/* 异常判断 */
		if (tmp_pos + length > p_len) {
			return 1;
		}

		/* 取出 CQL_VERSION */
		CassandraBufferFree(&(cassandra_state->cql_version));
		CassandraBufferAdd(&(cassandra_state->cql_version), (p_data + tmp_pos), length);

		/* tmp_pos 跳过   CQL_VERSION */
		tmp_pos += length;

		/************** (2) DRIVER_NAME **************/
		
		/* 异常判断 */
		if (tmp_pos + 14 > p_len) {
			return 1;
		}

		/* 查找用户名结尾 0x00 */
		location = 0;
		CassandraSundayALG((p_data + tmp_pos), (p_len - tmp_pos), CASSANDRA_DRIVER_NAME_PATT, 11, &location);
		if (0 == location) {
			return 1;
		}		

		/* tmp_pos 移动到    DRIVER_NAME 后面长度 */
		tmp_pos += location + 11;

		/* 取出 DRIVER_NAME len */
		length = CASSANDRA_GET_VALUE16(p_data + tmp_pos);

		/* tmp_pos 移动到    DRIVER_NAME data */
		tmp_pos += 2;

		/* 异常判断 */
		if (tmp_pos + length > p_len) {
			return 1;
		}

		/* 取出 DRIVER_NAME */
		CassandraBufferFree(&(cassandra_state->driver_name));
		CassandraBufferAdd(&(cassandra_state->driver_name), (p_data + tmp_pos), length);

		/* tmp_pos 跳过   DRIVER_NAME */
		tmp_pos += length;

		/************** (3) DRIVER_VERSION **************/
		
		/* 异常判断 */
		if (tmp_pos + 17 > p_len) {
			return 1;
		}

		/* 查找用户名结尾 0x00 */
		location = 0;
		CassandraSundayALG((p_data + tmp_pos), (p_len - tmp_pos), CASSANDRA_DRIVER_VERSION_PATT, 14, &location);
		if (0 == location) {
			return 1;
		}		

		/* tmp_pos 移动到    DRIVER_NAME 后面长度 */
		tmp_pos += location + 14;

		/* 取出 DRIVER_VERSION len */
		length = CASSANDRA_GET_VALUE16(p_data + tmp_pos);

		/* tmp_pos 移动到    DRIVER_VERSION data */
		tmp_pos += 2;

		/* 异常判断 */
		if (tmp_pos + length > p_len) {
			return 1;
		}

		/* 取出 DRIVER_VERSION */
		CassandraBufferFree(&(cassandra_state->driver_version));
		CassandraBufferAdd(&(cassandra_state->driver_version), (p_data + tmp_pos), length);

		/* tmp_pos 跳过   DRIVER_VERSION */
		tmp_pos += length;
		
		/************** (4) CLIENT_ID **************/
		
		/* 异常判断 */
		if (tmp_pos + 12 > p_len) {
			return 1;
		}

		/* 查找用户名结尾 0x00 */
		location = 0;
		CassandraSundayALG((p_data + tmp_pos), (p_len - tmp_pos), CASSANDRA_CLIENT_ID_PATT, 9, &location);
		if (0 == location) {
			return 1;
		}		

		/* tmp_pos 移动到    CLIENT_ID 后面长度 */
		tmp_pos += location + 9;

		/* 取出 CLIENT_ID len */
		length = CASSANDRA_GET_VALUE16(p_data + tmp_pos);

		/* tmp_pos 移动到    CLIENT_ID data */
		tmp_pos += 2;

		/* 异常判断 */
		if (tmp_pos + length > p_len) {
			return 1;
		}

		/* 取出 CLIENT_ID */
		CassandraBufferFree(&(cassandra_state->client_id));
		CassandraBufferAdd(&(cassandra_state->client_id), (p_data + tmp_pos), length);

		return 0;
	}

	/* 解析请求缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
	ret = CassandraParseReqCmdV5(f, statev, pstate, input, input_len, local_data, cassandra_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}

/* 解析 cassandra V4 请求 包 */
static int CassandraParseReqV4(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_pos = 0;
	uint8_t opcode = 0;
	uint32_t length = 0;
	uint32_t location = 0;
	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if ((1 != cassandra_state->request_buffer_need) && (pos + 9 > p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == cassandra_state->request_buffer_need) {
		/* 解析请求缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
		ret = CassandraParseReqCmdV4(f, statev, pstate, input, input_len, local_data, cassandra_data);
		if (0 != ret) {
			return 1;
		}else {
			return 0;
		}
	}

	/* 异常判断 */
	if (pos + 9 > p_len) {
		return 1;
	}

	/* 异常判断，只解析正常的请求包 */
	if (1 != CASSANDRA_IS_V4_REQUEST(p_data)) {
		/* 清空上次缓存 */
		CassandraBufferFree(&(cassandra_state->query_cmd_buffer));

		return 1;
	}

	/* pos 移动到 Opcode */
	pos += 4;

	/* 只解析 QUERY */
	opcode = (p_data + pos)[0]; 
	if (0x07 != opcode && 0x01 != opcode) {
		return 1;
	}

	/* 请求的第一个包清理各种缓存 */
	CassandraBufferFree(&(cassandra_state->query_cmd_buffer));
	cassandra_state->request_buffer_need = 0;
	CassandraBufferFree(&(cassandra_state->request_buffer));

	/* pos 移动到 Message Length */
	pos += 1;

	/* 取出 Message Length */
	length = CASSANDRA_GET_VALUE32(p_data + pos);

	/* 异常判断 */
	if (pos + 4 + length > p_len) {
		return 1;
	}

	/* 判断是否是 CQL_WERSION */
	if (0 == cassandra_state->cql_version.len
		&& 0x01 == opcode) {

		/************** (1) CQL_VERSION **************/
		
		/* 异常判断 */
		if (tmp_pos + 14 > p_len) {
			return 1;
		}
		
		/* 查找用户名结尾 0x00 */
		location = 0;
		CassandraSundayALG((p_data + tmp_pos), (p_len - tmp_pos), CASSANDRA_CQL_VERSION_PATT, 11, &location);
		if (0 == location) {
			return 1;
		}		
		
		/* tmp_pos 移动到	CQL_VERSION 后面长度 */
		tmp_pos += location + 11;
		
		/* 取出 CQL_VERSION len */
		length = CASSANDRA_GET_VALUE16(p_data + tmp_pos);
		
		/* tmp_pos 移动到	CQL_VERSION data */
		tmp_pos += 2;
		
		/* 异常判断 */
		if (tmp_pos + length > p_len) {
			return 1;
		}
		
		/* 取出 CQL_VERSION */
		CassandraBufferFree(&(cassandra_state->cql_version));
		CassandraBufferAdd(&(cassandra_state->cql_version), (p_data + tmp_pos), length);
		
		return 0;
	}	

	/* 解析请求缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
	ret = CassandraParseReqCmdV4(f, statev, pstate, input, input_len, local_data, cassandra_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}

#if 0
/* 解析 cassandra V4 请求 包 */
static int CassandraParseReqV4(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint8_t opcode = 0;
	uint32_t length = 0;

	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if ((1 != cassandra_state->request_buffer_need) && (pos + 9 > p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == cassandra_state->request_buffer_need) {
		/* 缓存数据 */
		CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), p_data, p_len);

		/* 判断缓存是否结束 */
		if (0 != cassandra_state->query_cmd_buffer.len && cassandra_state->query_cmd_buffer.len >= cassandra_state->query_cmd_buffer.total_len) {
			/* 缓存超过了数据长度，说明缓存完成，截取真实长度 */
			if (cassandra_state->query_cmd_buffer.len > cassandra_state->query_cmd_buffer.total_len) {
				cassandra_state->query_cmd_buffer.len = cassandra_state->query_cmd_buffer.total_len;
			}

			/* 解析请求 SQL 语句或脚本 */
			ret = CassandraParseReqQuery(f, statev, pstate, input, input_len, local_data, cassandra_data);

			/* 已经解析完缓存了，关闭需要缓存开关 */
			cassandra_state->request_buffer_need = 0;

			/* 判断是否解析成功 */
			if (0 != ret) {
				return 1;
			}else {
				return 0;
			}
		}

		/* 这里是除了第一次缓存完请求包的返回处，因为是缓存，并没有解析，所以返回 1 */
		return 1;
	}

	/* 异常判断 */
	if (pos + 9 > p_len) {
		return 1;
	}

	/* 异常判断，只解析正常的请求包 */
	if (1 != CASSANDRA_IS_V4_REQUEST(p_data)) {
		/* 清空上次缓存 */
		CassandraBufferFree(&(cassandra_state->query_cmd_buffer));

		return 1;
	}

	/* pos 移动到 Opcode */
	pos += 4;

	/* 只解析 QUERY */
	opcode = (p_data + pos)[0]; 
	if (0x07 != opcode) {
		return 1;
	}

	/* pos 移动到 Message Length */
	pos += 1;

	/* 取出 SQL 语句长度 */
	length = CASSANDRA_GET_VALUE32(p_data + pos);

	/* pos 移动到 String Length */
	pos += 4;

	/* 异常判断 */
	if (pos + 4 >= p_len) {
		return 1;
	}

	/* 取出 String Length */
	length = CASSANDRA_GET_VALUE32(p_data + pos);

	/* 判断：如果请求是应用层分片的，需要重组后再解析 */
	if (pos + 4 + length > p_len) {
		/* 应用层重组开关置位 */
		cassandra_state->request_buffer_need = 1;

		/* 初次缓存，清理旧的缓存信息 */
		CassandraBufferFree(&(cassandra_state->query_cmd_buffer));

		/* 保存总长度，用于判断是否缓存完成，只有请求包才有这个总长度，响应包所有响应结束才知道传输了多少字节 */
		cassandra_state->query_cmd_buffer.total_len = length;

		/* pos 移动到数据头部 */
		pos += 4;

		/* 异常判断 */
		if (0 >= p_len - pos) {
			return 1;
		}

		/* 缓存数据，从真实数据开始 */
		CassandraBufferAdd(&(cassandra_state->query_cmd_buffer), p_data + pos, p_len - pos);

		/* 判断缓存是否结束 */
		if (0 != cassandra_state->query_cmd_buffer.len && cassandra_state->query_cmd_buffer.len >= cassandra_state->query_cmd_buffer.total_len) {
			/* 缓存超过了数据长度，说明缓存完成，截取真实长度 */
			if (cassandra_state->query_cmd_buffer.len > cassandra_state->query_cmd_buffer.total_len) {
				cassandra_state->query_cmd_buffer.len = cassandra_state->query_cmd_buffer.total_len;
			}

			/* 解析请求 SQL 语句或脚本 */
			ret = CassandraParseReqQuery(f, statev, pstate, input, input_len, local_data, cassandra_data);

			/* 已经解析完缓存了，关闭需要缓存开关 */
			cassandra_state->request_buffer_need = 0;

			/* 判断是否解析成功 */
			if (0 != ret) {
				return 1;
			}else {
				return 0;
			}
		}

		/* 这里是第一次缓存完请求包的返回处，因为是缓存，并没有解析，所以返回 1 */
		return 1;
	}

	/* 请求包没有分片，直接解析 */
	ret = CassandraParseReqQuery(f, statev, pstate, input, input_len, local_data, cassandra_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}
#endif

/* 解析 cassandra 请求 包 */
static int CassandraParseReq(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, CassandraTransaction *cassandra_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	CassandraState *cassandra_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint8_t ret = 1;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	cassandra_state = (CassandraState *)statev;
	p_data = input;
	p_len = input_len;

	/* 请求包到来就释放响应缓存，因为说明前面的响应都已经结束了 */
	CassandraBufferFree(&(cassandra_state->result_set_buffer));
	CassandraBufferFree(&(cassandra_state->fields));
	cassandra_state->response_buffer_need = 0;
	CassandraBufferFree(&(cassandra_state->response_buffer));
	cassandra_state->send_key = 0;

	/* 就前两个数据包需要计数，其他都不用 */
	if (cassandra_state->pkt_num < 4) {
		cassandra_state->pkt_num += 1;
	}

	/* 异常判断 */
	if ((1 != cassandra_state->request_buffer_need) && (pos + 9 > p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 异常判断 */
	if (pos + 1 > p_len) {
		return 1;
	}

	/* 取出 version */
	if (0 == cassandra_state->server_version.len && 4 >= cassandra_state->pkt_num) {
		if (0x04 == p_data[0] || 0x84 == p_data[0]) {
			CassandraBufferFree(&(cassandra_state->server_version));
			CassandraBufferAdd(&(cassandra_state->server_version), (const uint8_t *)"4", 1);
			cassandra_state->version = 4;
		}else if (0x05 == p_data[0] || 0x85 == p_data[0]) {
			CassandraBufferFree(&(cassandra_state->server_version));
			CassandraBufferAdd(&(cassandra_state->server_version), (const uint8_t *)"5", 1);
			cassandra_state->version = 5;
		}
	}

	/* 异常判断 */
	if (0 == cassandra_state->server_version.len) {
		return 1;
	}

	/* V4 V5 版本独立解析 */
	if (4 == cassandra_state->version) {
		ret = CassandraParseReqV4(f, statev, pstate, input, input_len, local_data, cassandra_data);
	}else if (5 == cassandra_state->version) {
		ret = CassandraParseReqV5(f, statev, pstate, input, input_len, local_data, cassandra_data);
	}

	if (0 != ret) {
		return 1;
	}

	return 0;
}


/* 请求包 解析函数 */
static AppLayerResult CassandraParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	CassandraTransaction *tx = NULL;
	//CassandraTransaction *ttx = NULL;

	CassandraState *cassandra_state = NULL;
	CassandraTransaction *cassandra_data = NULL;

	const uint8_t *input = NULL;
	uint32_t input_len = 0;


	int ret = 1;

	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(cassandra_conf.cassandra_enable)) {
		goto error;
	}

	/* 获取 state 和 input 和 input_len */
	cassandra_state = (CassandraState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);

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
	if (CASSANDRA_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = CassandraTxAlloc(cassandra_state, true);
	cassandra_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(cassandra_data->proto, "tcp", 3);
	cassandra_data->is_request = true;

#if 0
	/* 注意: 可能响应先来，因此请求也需要查一下有没有分配 tx, 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &cassandra_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	cassandra_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//cassandra_state->transaction_max = 0;
		
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = CassandraTxAlloc(cassandra_state, true);
		cassandra_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(cassandra_data->proto, "tcp", 3);
	}
	cassandra_data->is_request = true;
#endif
/************************* 解析私有数据 start ************************/	
	/* 判断真实的方向，防止三次握手第一个包丢失造成方向识别错误，记住值永远都放在左侧，防止判断恒等时使用复制符号 '=' */
	if (SC_ATOMIC_GET(cassandra_conf.cassandra_dport) == f->dp) {
		ret = CassandraParseReq(f, state, pstate, input, input_len, local_data, cassandra_data);
	}else if (SC_ATOMIC_GET(cassandra_conf.cassandra_dport) == f->sp) {
		ret = CassandraParseResp(f, state, pstate, input, input_len, local_data, cassandra_data);
	}else {
		ret = 1;
	}


	/* 如果解析失败，不发送日志 */
	if (0 != ret) {
		goto end;
	}


	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	cassandra_data->done = 1;
	cassandra_data->complete = 0;
	
/************************* 解析私有数据 end ************************/	


#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_cassandra_event(f, cassandra_data, STREAM_TOSERVER);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 响应包 解析函数 */
static AppLayerResult CassandraParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	CassandraTransaction *tx = NULL;
	//CassandraTransaction *ttx = NULL;
	
	CassandraState *cassandra_state = NULL;
	CassandraTransaction *cassandra_data = NULL;
	
	const uint8_t *input = NULL;
	uint32_t input_len = 0;
	
	int ret = 1;
	
	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(cassandra_conf.cassandra_enable)) {
		goto error;
	}
	
	/* 获取 state 和 input 和 input_len */
	cassandra_state = (CassandraState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);
	
	/* 可能连接关闭了 */
	if ((NULL == input || 1 > input_len) && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 异常判断 */
	if (NULL == input || 1 > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}
	
	/* 异常判断 */
	if (CASSANDRA_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = CassandraTxAlloc(cassandra_state, false);
	cassandra_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(cassandra_data->proto, "tcp", 3);
	cassandra_data->is_request = false;

#if 0
    /* 注意: 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &cassandra_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	cassandra_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//cassandra_state->transaction_max = 0;
	
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = CassandraTxAlloc(cassandra_state, false);
		cassandra_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(cassandra_data->proto, "tcp", 3);
	}
	cassandra_data->is_request = false;
#endif	
	/************************* 解析私有数据 start ************************/	
	/* 请求和响应公用一个 tx, 因此响应要清理请求的 tx */
	/* 判断真实的方向，防止三次握手第一个包丢失造成方向识别错误，记住值永远都放在左侧，防止判断恒等时使用复制符号 '=' */
	if (SC_ATOMIC_GET(cassandra_conf.cassandra_dport) == f->sp) {
		ret = CassandraParseReq(f, state, pstate, input, input_len, local_data, cassandra_data);
	}else if (SC_ATOMIC_GET(cassandra_conf.cassandra_dport) == f->dp) {
		ret = CassandraParseResp(f, state, pstate, input, input_len, local_data, cassandra_data);
	}else {
		ret = 1;
	}

	/* 如果解析失败，不发送日志 */
	if (0 != ret) {
		goto end;
	}

	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	cassandra_data->done = 1;
	cassandra_data->complete = 1;
		
	/************************* 解析私有数据 end ************************/ 	
	
	
#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_cassandra_event(f, cassandra_data, STREAM_TOCLIENT);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 获取 tx */
static void *CassandraGetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	CassandraState *cassandra = (CassandraState *)alstate;
	CassandraTransaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH(tx, &cassandra->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

/* 获取 tx 计数 */
static uint64_t CassandraGetTxCnt(void *state)
{
	SCEnter();
	uint64_t count = ((uint64_t)((CassandraState *)state)->transaction_max);
	SCReturnUInt(count);
}

/* 释放一个 cassandra tx */
static void CassandraTxFree(CassandraTransaction *tx)
{
	SCEnter();

	AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

	if (tx->tx_data.de_state != NULL) {
		DetectEngineStateFree(tx->tx_data.de_state);
	}

	/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
	if (NULL != tx->query_cmd) {
		CASSANDRA_FREESTR(tx->query_cmd);
	}
	
	/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
	if (NULL != tx->result_set) {
		CASSANDRA_FREESTR(tx->result_set);
	}

	SCFree(tx);
	SCReturn;
}

/* 通过 ID 释放特定 cassandra 状态上的一个事务 */
static void CassandraStateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	CassandraState *cassandra = state;
	CassandraTransaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &cassandra->tx_list, next, ttx) {

		if (tx->tx_num != tx_num) {
			continue;
		}

		//最好不要使用这个 curr，这个就是容易段错误的根源
		if (tx == cassandra->curr) {
			cassandra->curr = NULL;
		}

		TAILQ_REMOVE(&cassandra->tx_list, tx, next);
		CassandraTxFree(tx);
		break;
	}

	SCReturn;
}

/* 释放 cassandra state */
static void CassandraStateFree(void *state)
{
	SCEnter();
	CassandraState *cassandra = state;
	CassandraTransaction *tx;
	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&cassandra->tx_list)) != NULL) {
			TAILQ_REMOVE(&cassandra->tx_list, tx, next);
			CassandraTxFree(tx);
		}

		/* state 中的 请求体 和 响应体 缓存释放语句 */
		if (cassandra->request_buffer.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->request_buffer.buffer);
		}
		if (cassandra->response_buffer.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->response_buffer.buffer);
		}

		/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
		if (cassandra->query_cmd_buffer.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->query_cmd_buffer.buffer);
		}
		if (cassandra->result_set_buffer.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->result_set_buffer.buffer);
		}
		if (cassandra->db_name.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->db_name.buffer);
		}
		if (cassandra->table_name.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->table_name.buffer);
		}
		if (cassandra->fields.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->fields.buffer);
		}
		if (cassandra->cql_version.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->cql_version.buffer);
		}
		if (cassandra->user.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->user.buffer);
		}
		if (cassandra->server_version.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->server_version.buffer);
		}
		if (cassandra->driver_name.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->driver_name.buffer);
		}
		if (cassandra->system_name.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->system_name.buffer);
		}
		if (cassandra->host_name.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->host_name.buffer);
		}
		if (cassandra->client_id.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->client_id.buffer);
		}
		if (cassandra->driver_version.buffer != NULL) {
			CASSANDRA_FREESTR(cassandra->driver_version.buffer);
		}


		SCFree(cassandra);
	}
	SCReturn;
}

/* 由应用层调用来获取状态进度 */
static int CassandraGetAlstateProgress(void *tx, uint8_t direction)
{
	/* 直接返回，用完 tx 就释放提高性能 */
	return 1;

	CassandraTransaction *cassandratx = (CassandraTransaction *)tx;
	int retval = 0;

	/* 原生逻辑是进度完成再释放，性能低 */
	if (cassandratx->complete) {
		retval = 1;
	}	

	SCReturnInt(retval);
}

/* 获取 tx_data */
static AppLayerTxData *CassandraGetTxData(void *vtx)
{
	CassandraTransaction *tx = (CassandraTransaction *)vtx;
	return &tx->tx_data;
}

/* 获取 state_data */
static AppLayerStateData *CassandraGetStateData(void *vstate)
{
	CassandraState *state = (CassandraState *)vstate;
	return &state->state_data;
}

/* 迭代器 */
static AppLayerGetTxIterTuple CassandraGetTxIterator(const uint8_t ipproto, const AppProto alproto,
	void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
	CassandraState *dnp_state = (CassandraState *)alstate;
	AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
	if (dnp_state) {
		CassandraTransaction *tx_ptr;
		if (state->un.ptr == NULL) {
			tx_ptr = TAILQ_FIRST(&dnp_state->tx_list);
		} else {
			tx_ptr = (CassandraTransaction *)state->un.ptr;
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
void RegisterCassandraParsers(void)
{
	const char *proto_name = "cassandra";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_CASSANDRA, proto_name);

	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_CASSANDRA, 0, CASSANDRA_MIN_FRAME_LEN, CassandraProbingParserTsTc, CassandraProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_TCP, CASSANDRA_DEFAULT_PORT, ALPROTO_CASSANDRA, 0, CASSANDRA_MIN_FRAME_LEN, STREAM_TOSERVER, CassandraProbingParserTsTc, CassandraProbingParserTsTc);	
	}

	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
		SCLogConfig("Registering cassandra/tcp parsers.");
		
		CassandraReload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(cassandra_conf.cassandra_enable , 0);
		SC_ATOMIC_SET(cassandra_conf.log_enable, 0);
		SC_ATOMIC_SET(cassandra_conf.cassandra_dport, atoi(CASSANDRA_DEFAULT_PORT));
		SC_ATOMIC_SET(cassandra_conf.result, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Cassandra流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_CASSANDRA, CassandraStateAlloc, CassandraStateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_CASSANDRA, STREAM_TOSERVER, CassandraParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_CASSANDRA, STREAM_TOCLIENT, CassandraParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_CASSANDRA, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_CASSANDRA, CassandraGetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_CASSANDRA, CassandraGetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_CASSANDRA, CassandraStateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_CASSANDRA, CassandraGetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_CASSANDRA, CassandraGetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_CASSANDRA, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_CASSANDRA, CassandraGetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_CASSANDRA, CassandraGetStateData);
	
	SCReturn;
}

