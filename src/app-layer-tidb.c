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

#include "app-layer-tidb.h"

TidbConf tidb_conf;

/* 0x00 模式串，用于快速查找字符串结尾 */
static uint8_t TIDB_END_PATT[1] = {0x00};

/* tidb 模式串 */
static uint8_t Tidb_STR_END_PATT[7] = {0x2d, 0x54, 0x69, 0x44, 0x42, 0x2d};


/* 热加载函数 */
void TidbReload(void)
{
	/* 获取是否打开日志开关 */
	ConfNode *node = NULL;

	/* 插件开关 */
	node = NULL;
	node = ConfGetNode(TIDB_ENABLED_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(tidb_conf.tidb_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(tidb_conf.tidb_enable, 0);
	}

	/* 获取是否打开日志开关 */
	node = ConfGetNode(TIDB_LOG_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(tidb_conf.log_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(tidb_conf.log_enable, 0);
	}	

	/* 获取 tidb 配置文件中的 dport 用于方向判断 */
	node = ConfGetNode(TIDB_DPORT);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(tidb_conf.tidb_dport, atoi(node->val));
	}else {
		SC_ATOMIC_SET(tidb_conf.tidb_dport, atoi(TIDB_DEFAULT_PORT));
	}	

	/* 获取是否打开结果集开关 */
	node = ConfGetNode(TIDB_RESULT);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(tidb_conf.result, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(tidb_conf.result, 0);
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
		1 TidbTransaction *tx: Tidb 的私有结构

	返回：void
*/
static void print_tidb_event(Flow *f, TidbTransaction *tx, uint16_t direction)
{
	/* 参数检查 */
	if (NULL == tx) {
		return;
	}

	char msg_buf[1024] = {0};
	TidbTransaction *tidb_data = NULL;

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
	tidb_data = tx;

	/* 时间 2016/09/22 12:21:30 */
	get_local_time(tidb_data->time_buff);
	
	/* 打印 */
	snprintf(msg_buf, sizeof(msg_buf), "done=%u", \
			tidb_data->done \
			);

	/* 打印公共字段 */
	DEBUG_DLOG("-----8888888888----- date: %s, s_ip: %s, s_port: %u, d_ip: %s, d_port: %u, dir: %d, protocal: %s, msg_buf: %s", \
				tidb_data->time_buff,\
				src_ip, src_port,\
				dst_ip, dst_port,\
				tidb_data->is_request, tidb_data->proto,\
				msg_buf \
				);

	return;
}
#endif


/* Ts 和 Tc 是指 Request 和 Response 方向协议识别和异常判断，合并到一起了，以后需要时还要拆分成两个函数，因为请求包和响应包结构不同 */
static AppProto TidbProbingParserTsTc(Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
	if (NULL == input || 0 >= input_len) {
		return ALPROTO_UNKNOWN;
	}

	const uint8_t *p_data = NULL;
	uint16_t p_len = 0;
	uint32_t location = 0;
	int ret_low = -1;

	/* 如果没有打开则强制不再识别识别, 后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(tidb_conf.tidb_enable)) {
		return ALPROTO_UNKNOWN;
	}
	
	/* 负载和负载长度 */
	p_data = input;
	p_len = input_len;


	/* 查找用户名结尾 0x00 */
	if (6 < p_len) {
		location = 0;
		ret_low = TidbSundayALG(p_data, p_len, Tidb_STR_END_PATT, 6, &location);
		if (0 != ret_low) {
			return ALPROTO_UNKNOWN;
		}
	}

	/* 异常判断 */
	if (p_len < TIDB_MIN_FRAME_LEN) {
		return ALPROTO_UNKNOWN;
	}

	return ALPROTO_TIDB;
}

/* 分配一个 tidb 状态对象，表示一个 tidb TCP 会话 */
static void *TidbStateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	TidbState *tidb;

	tidb = (TidbState *)SCCalloc(1, sizeof(TidbState));
	if (unlikely(tidb == NULL)) {
		return NULL;
	}
	TAILQ_INIT(&tidb->tx_list);

	SCReturnPtr(tidb, "void");
}

/* 分配一个 tidb transaction */
static TidbTransaction *TidbTxAlloc(TidbState *tidb, bool request)
{
	TidbTransaction *tx = SCCalloc(1, sizeof(TidbTransaction));
	if (unlikely(tx == NULL)) {
		return NULL;
	}
	tidb->transaction_max++;
	tidb->curr = tx;
	tx->tidb = tidb;
	tx->tx_num = tidb->transaction_max;
	tx->is_request = request;
	if (tx->is_request) {
		tx->tx_data.detect_flags_tc |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	} else {
		tx->tx_data.detect_flags_ts |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	}

	TAILQ_INSERT_TAIL(&tidb->tx_list, tx, next);

	return tx;
}

static char tidb_hex_to_char(unsigned char ch)
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

static int tidb_hex_to_str(unsigned char *src, uint32_t src_len, char *dst, uint32_t *dst_len)
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
		t_chr = tidb_hex_to_char(tmp_char);
		dst[j] = t_chr;

		/* 低 4 bit 转换 */
		src_char = 0x00;
		src_char = src[i];
		tmp_char = 0x00;
		tmp_char = (src_char & 0x0f);

		/* 获取低位转换的字符 */
		t_chr = '0';
		t_chr = tidb_hex_to_char(tmp_char);
		dst[j+1] = t_chr;

		j += 2;
	}

	*dst_len = j;

	return 0;
}


/* 配合 sunday 算法获取模式串第一次命中的位置 */
static int TidbFindIndex(uint8_t *patt_str, int patt_len, uint8_t uc_tmp, int *index)
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
int TidbSundayALG(const uint8_t *src, uint32_t src_len, uint8_t *patt_str, int patt_len, uint32_t *dst_len)
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
            ret = TidbFindIndex(patt_str, patt_len, src[tmp], &index);
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
static int TidbBufferFree(TidbBuffer *buffer)
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
static int TidbBufferAdd(TidbBuffer *buffer, const uint8_t *data, uint32_t len)
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


/* 解析 tidb Version 包 */
static int TidbParseRespVersion(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, TidbTransaction *tidb_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	TidbState *tidb_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_len = 0;
	uint8_t protocol = 0;
	uint32_t location = 0;
	uint32_t find_len = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	tidb_state = (TidbState *)statev;
	p_data = input;
	p_len = input_len;

	/* pos 游标滑动到 Protocol */
	pos += 3 + 1;
	
	/* 异常判断 */
	if (pos + 1 >= p_len) {
		return 1;
	}
	
	/* 取出	Protocol */
	protocol = (p_data + pos)[0];
	
	/* 异常判断 */
	if (protocol != TIDB_PROTOCOL_NUM) {
		return 1;
	}
	
	/* pos 游标跳过 Protocol */
	pos += 1;
	
	/* 异常判断 */
	if (pos + 2 >= p_len) {
		return 1;
	}
	
	/* 如果 pos 游标后的剩余长度大于用户名缓存，也只查询用户名缓存这么长，提高效率 */
	if (p_len - pos >= TIDB_VERSION_LEN) {
		find_len = TIDB_VERSION_LEN;
	}else {
		find_len = (p_len - pos);
	}

	/* 查找用户名结尾 0x00 */
	TidbSundayALG((p_data + pos), find_len, TIDB_END_PATT, 1, &location);
	if (0 == location) {
		return 1;
	}
	
	/* 取出 version */
	tmp_len = 0;
	if (location >= TIDB_VERSION_LEN) {
		tmp_len = (TIDB_VERSION_LEN - 1);
	}else {
		tmp_len = location;
	}
	memcpy(tidb_state->version, (p_data + pos), tmp_len);
	tidb_state->version_len = tmp_len;
	tidb_state->version_key = 1;

	return 0;
}

/* 解析 tidb user 和 passwd 包 */
static int TidbParseReqUserPasswd(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, TidbTransaction *tidb_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	TidbState *tidb_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_len = 0;
	uint32_t location = 0;
	uint32_t find_len = 0;
	uint32_t passwd_len = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	tidb_state = (TidbState *)statev;
	p_data = input;
	p_len = input_len;

	/* pos 游标滑动到 username */
	pos += 3 + 1 + 2 + 2 + 4 + 1 + 23;
	
	/* 异常判断 */
	if (pos + 2 >= p_len) {
		return 1;
	}
	
	/* 如果 pos 游标后的剩余长度大于用户名缓存，也只查询用户名缓存这么长，提高效率 */
	if (p_len - pos >= TIDB_USER_LEN) {
		find_len = TIDB_USER_LEN;
	}else {
		find_len = (p_len - pos);
	}
	
	/* 查找用户名结尾 0x00 */
	TidbSundayALG((p_data + pos), find_len, TIDB_END_PATT, 1, &location);
	if (0 == location) {
		return 1;
	}
	
	/* 取出 Username */
	tmp_len = 0;
	if (location >= TIDB_USER_LEN) {
		tmp_len = (TIDB_USER_LEN - 1);
	}else {
		tmp_len = location;
	}
	memcpy(tidb_state->user, (p_data + pos), tmp_len);
	tidb_state->user_len = tmp_len;
	tidb_state->user_key = 1;
	
	/* pos 移动到 passwd */
	pos += location + 1;
	
	/* 异常判断 */
	if (pos + 2 >= p_len) {
		return 1;
	}
	
	/* 获取密码长度 */
	passwd_len = (p_data + pos)[0];
	
	/* pos 移动到密码起始位置 */
	pos += 1;
	
	/* 异常判断 */
	if (pos + passwd_len >= p_len) {
		return 1;
	}
	
	/* 16 进制转换成人类可读字符串 */
	tmp_len = 0;
	if (passwd_len * 2 >= TIDB_PASSWD_LEN) {
		tmp_len = passwd_len - 1;
	}else {
		tmp_len = passwd_len;
	}
	tidb_hex_to_str((unsigned char *)(p_data + pos), tmp_len, (char *)tidb_state->passwd, &(tidb_state->passwd_len));
	tidb_state->passwd_key = 1;

	return 0;
}

/* 解析 Response 中的 Result Set，循环解析  */
static int TidbParseRespResultSetLoop(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, TidbTransaction *tidb_data, uint8_t *fram_key)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len || NULL == fram_key) {
		return 1;
	}

	TidbState *tidb_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_pos = 0;
	uint32_t pkt_len = 0;
	uint8_t pkt_num = 0;

	uint8_t number_of_field = 0;
	uint8_t more_resulte = 0;
	uint8_t prefix_len = 0;
	uint8_t command = 0;
	uint16_t warning_len = 0;
	uint32_t tmp_len = 0;


	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	tidb_state = (TidbState *)statev;
	p_data = input;
	p_len = input_len;

	/* 判断需要解析拼接后的缓存，还是直接解析完整的数据包 */
	if (1 == tidb_state->response_buffer_need) {
		/* 如果上一个包有分片，缓存本次数据包，与上一个数据包尾部的分片组成一个完整的 buff ，像解析 DNS 一样循环解析，然后还要判断尾部是否有下一个数据包的分片 */
		TidbBufferAdd(&(tidb_state->response_buffer), p_data, p_len);

		/* 局部变量重新赋值 */
		p_data = tidb_state->response_buffer.buffer;
		p_len = tidb_state->response_buffer.len;
	}

	/* 异常判断 */
	if (pos + 6 > p_len) {
		return 1;
	}

	/* 取出 packet len */
	pkt_len = TIDB_GET_VALUE24(p_data);

	/* 取出 packet number */
	pkt_num = (p_data + 3)[0];

	/* 判断 response EOF 包 */
	if (0xfe == (p_data + 4)[0]
		&& 1 == tidb_state->fields.fields_finish
		&& pkt_num - 2 > tidb_state->fields.column_count) {

		/* pos 移动到	warning len */
		pos += 3 + 1 + 1;					
		
		/* 异常判断 */
		if (pos + 2 >= p_len) {
			return 1;
		}
		
		/* 取出 warning len 2 个字节 */
		warning_len = TIDB_GET_VALUE16(p_data + pos);
		
		/* pos 跳过 warning len 和 上述长度的数据 */
		pos += 2 + warning_len;
		
		/* 异常判断 */
		if (pos + 2 > p_len) {
			return 1;
		}

		/* 如果 More results 为 0，说明响应包已经结束 */
		more_resulte = 0x08 & (p_data + pos)[0];
		if (0 == more_resulte) {
			tidb_state->result_set_buffer.finish_key = 1;
			tidb_state->send_key = 1;

			goto end;
		}

	}

	/* 如果是响应的第一个包，取出 number of fields */
	if (1 == pkt_len && 1 == pkt_num) {
		/* 如果是解析新的第一个响应包，清空缓存 */
		TidbBufferFree(&(tidb_state->result_set_buffer));
		TidbBufferFree(&(tidb_state->db_name));
		TidbBufferFree(&(tidb_state->table_name));
		TidbBufferFree(&(tidb_state->fields));

		/* 如果是第一个新的响应包取出 列个数 */
		tidb_state->fields.column_count = (p_data + 4)[0];

		/* 如果是第一个新的响应包跳过列头部 */
		pos += 5;
	}else if (1 == pkt_len && 1 < pkt_num) {
		/* 如果是第一个新的响应包取出 列个数 */
		tidb_state->fields.column_count = (p_data + 4)[0];

		/* 开关复位 */
		tidb_state->fields.fields_finish = 0;
		
		/* 如果是第一个新的响应包跳过列头部 */
		pos += 5;
	}

	/* 循环解析 */
	while (pos + 6 <= p_len) {
		/* 判断是解析 列 还是 行 */
		if (0 != tidb_state->fields.column_count 
			&& 0 == tidb_state->fields.fields_finish) {
			/* 取出 packet len */
			pkt_len = TIDB_GET_VALUE24(p_data + pos);
			
			/* 取出 packet number */
			pkt_num = (p_data + pos + 3)[0];

			/* 取出 Command 这个字段有时表示长度，有多种含义 */
			command = (p_data + pos + 4)[0];

			/* 判断是否是 intermediate EOF */
			if ((pkt_num - 2 == tidb_state->fields.column_count && 0xfe == command)
				|| (1 == tidb_state->fields.finish_key && 0xfe == command)) {
				tidb_state->fields.fields_finish = 1;

				/* pos 移动到	warning len */
				pos += 3 + 1 + 1;					

				/* 异常判断 */
				if (pos + 2 >= p_len) {
					return 1;
				}
				
				/* 取出 warning len 2 个字节 */
				warning_len = TIDB_GET_VALUE16(p_data + pos);

				/* pos 跳过 warning len 和 上述长度的数据 */
				pos += 2 + warning_len;

				/* 异常判断 */
				if (pos + 2 > p_len) {
					return 1;
				}

				/* pos 跳过 Server Status 2 字节，来到 row */
				pos += 2;

				/* 转去解析 row */
				continue;
			}

			/* pos 移动到 Database */
			pos += 3 + 1 + 1 + command;

			/* 异常判断 */
			if (pos + 1 >= p_len) {
				return 1;
			}

			/* 取出 database len */
			tmp_len = (p_data + pos)[0];

			/* 如果 database len 为 0 */
			//if (0 == tmp_len) {
				//tidb_state->result_set_buffer.finish_key = 1;
				//tidb_state->send_key = 1;
				//goto end;
			//}

			/* 异常判断 */
			if (pos + 1 + tmp_len >= p_len) {
				return 1;
			}				

			/* pos 移动到 database */
			pos += 1;

			/* 取出 database */
			if (0 == tidb_state->db_name.len && 0 != tmp_len) {
				TidbBufferAdd(&(tidb_state->db_name), (p_data + pos), tmp_len);
			}

			/* pos 跳过 database */
			pos += tmp_len;

			/* 异常判断 */
			if (pos + 1 >= p_len) {
				return 1;
			}
			
			/* 取出 table len */
			tmp_len = (p_data + pos)[0];
			
			/* 如果 table len 为 0 */
			if (0 == tmp_len) {
				tidb_state->result_set_buffer.finish_key = 1;
				tidb_state->send_key = 1;
				goto end;
			}				
			
			/* 异常判断 */
			if (pos + 1 + tmp_len >= p_len) {
				return 1;
			}				
			
			/* pos 移动到 table */
			pos += 1;
			
			/* 取出 table */
			if (0 == tidb_state->table_name.len && 0 != tmp_len) {
				TidbBufferAdd(&(tidb_state->table_name), (p_data + pos), tmp_len);
			}

			/* pos 跳过 table */
			pos += tmp_len;
			
			/* 异常判断 */
			if (pos + 1 >= p_len) {
				return 1;
			}
			
			/* 取出 Original table len */
			tmp_len = (p_data + pos)[0];
			
			/* 异常判断 */
			if (pos + 1 + tmp_len >= p_len) {
				return 1;
			}	

			/* pos 跳过 Original table   */
			pos += 1 + tmp_len;

			/* 异常判断 */
			if (pos + 1 >= p_len) {
				return 1;
			}
			
			/* 取出 name len */
			tmp_len = (p_data + pos)[0];
			
			/* 如果 name len 为 0 */
			if (0 == tmp_len) {
				tidb_state->result_set_buffer.finish_key = 1;
				tidb_state->send_key = 1;
				goto end;
			}				
			
			/* 异常判断 */
			if (pos + 1 + tmp_len >= p_len) {
				return 1;
			}	

			/* pos 移动到 name */
			pos += 1;
			
			/* 取出  字段 name */
			if (0 == tidb_state->fields.fields_finish && 1 != tidb_state->fields.finish_key) {
				number_of_field += 1;
				TidbBufferAdd(&(tidb_state->fields), (p_data + pos), tmp_len);

				/* 如果是最后一个字段后面加换行符 */
				if (number_of_field == tidb_state->fields.column_count) {
					tidb_state->fields.finish_key = 1;
					TidbBufferAdd(&(tidb_state->fields), TIDB_CRLF, 3);
				}else {
					TidbBufferAdd(&(tidb_state->fields), TIDB_DOT, 2);
				}

			}

			/* pos 跳过 name */
			pos += tmp_len;

			/* 异常判断 */
			if (pos + 1 >= p_len) {
				return 1;
			}
			
			/* 取出 Original name len */
			tmp_len = (p_data + pos)[0];
			
			/* 异常判断 */
			if (pos + 1 + tmp_len >= p_len) {
				return 1;
			}	
			
			/* pos 跳过 Original name   */
			pos += 1 + tmp_len;

			/* 异常判断 */
			if (pos + 1 >= p_len) {
				return 1;
			}

			/* 取出 field 的剩余字段 len */
			tmp_len = (p_data + pos)[0];
			
			/* 异常判断 */
			if (pos + 1 + tmp_len >= p_len) {
				return 1;
			}	

			/* pos 跳过 field 的剩余字段   */
			pos += 1 + tmp_len; 			
		}else if (0 != tidb_state->fields.column_count 
			&& 1 == tidb_state->fields.fields_finish) {
			
			/* 取出 packet len */
			pkt_len = TIDB_GET_VALUE24(p_data + pos);
			
			/* 取出 packet number */
			pkt_num = (p_data + pos + 3)[0];
			
			/* 取出 Command 这个字段有时表示长度，有多种含义 */
			command = (p_data + pos + 4)[0];

			/* 判断是否数据包的尾部有下一个包的分片 */
			if (pos + 3 + 1 + pkt_len > p_len) {
				if (p_len > pos) {
					/* 打开分片开关 */
					*fram_key = 1;
					tidb_state->response_buffer_need = 1;

					/* 缓存分片，先清理后缓存 */
					TidbBufferFree(&(tidb_state->response_buffer));
					TidbBufferAdd(&(tidb_state->response_buffer), (p_data + pos), (p_len - pos));
					return 1;
				}else {
					return 1;
				}
			}

			/* 判断是否是 response EOF 包 */
			if (0xfe == command
				&& pkt_num - 2 > tidb_state->fields.column_count) {
			
				/* pos 移动到	warning len */
				pos += 3 + 1 + 1;					
				
				/* 异常判断 */
				if (pos + 2 >= p_len) {
					return 1;
				}
				
				/* 取出 warning len 2 个字节 */
				warning_len = TIDB_GET_VALUE16(p_data + pos);
				
				/* pos 跳过 warning len 和 上述长度的数据 */
				pos += 2 + warning_len;
				
				/* 异常判断 */
				if (pos + 2 > p_len) {
					return 1;
				}
			
				/* 如果 More results 为 0，说明响应包已经结束 */
				more_resulte = (0x08 & (p_data + pos)[0]);
				if (0 == more_resulte) {
					tidb_state->result_set_buffer.finish_key = 1;
					tidb_state->send_key = 1;
			
					goto end;
				}

				/* pos 跳过 Server Status 2 个字节 */
				pos += 2;

				/* 异常判断 */
				if (pos + 4 > p_len) {
					return 1;
				}

				/* 重新解析 column count */
				tidb_state->fields.column_count = (p_data + pos + 4)[0];
				tidb_state->fields.fields_finish = 0;

				/* 新的响应包跳过列头部 */
				pos += 5;

				/* Response EOF 结束，跳转到 column count 重新解析列 */
				continue;
			}

			/* 循环解析 row */
			tmp_pos = pos;
			tmp_pos += 3 + 1;
			number_of_field = 0;
			while (tmp_pos + 2 <= p_len 
				&& number_of_field < tidb_state->fields.column_count) {
				
				/* 累加列字段计数 */
				number_of_field += 1;

				/* 取出 Prefix/Length */
				prefix_len = (p_data + tmp_pos)[0];

				/* 异常判断 */
				if (1 > prefix_len) {
					tidb_state->result_set_buffer.finish_key = 1;
					tidb_state->send_key = 1;
					
					goto end;
				}

				/* 异常判断 */
				if (tmp_pos + 1 + prefix_len > p_len) {
					return 1;
				}

				/* tmp_pos 移动到 text */
				tmp_pos += 1;

				/* 存储 row 信息 */
				TidbBufferAdd(&(tidb_state->result_set_buffer), (p_data + tmp_pos), prefix_len);

				/* 如果是最后一个字段后面加换行符 */
				if (number_of_field == tidb_state->fields.column_count) {
					TidbBufferAdd(&(tidb_state->result_set_buffer), TIDB_CRLF, 3);
				}else {
					TidbBufferAdd(&(tidb_state->result_set_buffer), TIDB_DOT, 2);
				}

				/* tmp_pos 跳过 text */
				tmp_pos += prefix_len;
			}

			/* pos 跳过 row */
			pos += 3 + 1 + pkt_len;

		}else {
			return 1;
		}
	}

	/* 尾巴剩余的可能不够满足一个响应头部，因此缓存起来，与下一个包拼接成完整的头部 */
	if (pos + 6 > p_len && p_len - pos > 0) {
		/* 打开分片开关 */
		*fram_key = 1;
		tidb_state->response_buffer_need = 1;
		
		/* 缓存分片，先清理后缓存 */
		TidbBufferFree(&(tidb_state->response_buffer));
		TidbBufferAdd(&(tidb_state->response_buffer), (p_data + pos), (p_len - pos));
		return 1;
	}

end:
	return 0;
}

/* 解析 Response 中的 Result Set  */
static int TidbParseRespResultSet(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, TidbTransaction *tidb_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	TidbState *tidb_state = NULL;
	uint8_t fram_key = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	tidb_state = (TidbState *)statev;

	/* 判断是否有上一个数据包的分片 */
	if (1 == tidb_state->response_buffer_need) {
		/* 循环解析响应中的结果集 */
		TidbParseRespResultSetLoop(f, statev, pstate, input, input_len, local_data, tidb_data, &fram_key);

		/* 判断这个包的尾巴是否有分片，如果有分片，存储起来下次响应包到来的时候与写一个包拼接成一个完整的包 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		TidbBufferFree(&(tidb_state->response_buffer));
		tidb_state->response_buffer_need = 0;
	}else {
		/* 循环解析响应中的结果集 */
		TidbParseRespResultSetLoop(f, statev, pstate, input, input_len, local_data, tidb_data, &fram_key);

		/* 如果响应包的尾部有下一个包的分片，那么打开开关，缓存分片 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		TidbBufferFree(&(tidb_state->response_buffer));
		tidb_state->response_buffer_need = 0;
	}

	return 0;
}


/* 解析 Query 中的 SQL 语句 */
static int TidbParseReqQuery(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, TidbTransaction *tidb_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	TidbState *tidb_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t pkt_len = 0;
	//uint8_t pkt_num = 0;
	//uint8_t command = 0;
	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	tidb_state = (TidbState *)statev;
	p_data = input;
	p_len = input_len;

	/* 判断是解析缓存还是解析数据包 */
	if ((1 == tidb_state->request_buffer_need)
		&& (0 != tidb_state->query_cmd_buffer.len)
		&& (tidb_state->query_cmd_buffer.len == tidb_state->query_cmd_buffer.total_len)) {

		/* 异常判断 */
		if (pos + 4 >= tidb_state->query_cmd_buffer.len) {
			return 1;
		}

		/* 能调到这个函数，说明已经完成纯 SQL 语句的缓存，打开已完成开关 */
		tidb_state->query_cmd_buffer.finish_key = 1;

	}else {
		/* 清空上次缓存 */
		TidbBufferFree(&(tidb_state->query_cmd_buffer));
	
		/* 异常判断 */
		if (pos + 4 >= p_len) {
			return 1;
		}
		
		/* 取出 packet len */
		pkt_len = TIDB_GET_VALUE24(p_data);		
		
		/* 异常判断 */
		if (pkt_len != p_len - 4) {
			return 1;
		}
		
		/* pos 移动过 Command */
		pos += 3 + 1 + 1;		
		
		/* 保存 Query   */
		ret = TidbBufferAdd(&(tidb_state->query_cmd_buffer), (p_data + pos), (pkt_len - 1));
		if (0 != ret) {
			TidbBufferFree(&(tidb_state->query_cmd_buffer));
			return 1;
		}
		tidb_state->query_cmd_buffer.finish_key = 1;

	}

	return 0;
}

/* 解析 tidb 响应 包 */
static int TidbParseResp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, TidbTransaction *tidb_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	TidbState *tidb_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t pkt_len = 0;
	uint8_t pkt_num = 0;
	uint8_t resp_code = 0;

	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	tidb_state = (TidbState *)statev;
	p_data = input;
	p_len = input_len;

	/* 结果集开关关闭时不解析结果集，直接返回 */
	if (2 <= tidb_state->pkt_num && 0 == SC_ATOMIC_GET(tidb_conf.result)) {
		return 1;
	}

	/* 就前两个数据包需要计数，其他都不用 */
	if (tidb_state->pkt_num < 2) {
		tidb_state->pkt_num += 1;
	}

	/* 响应包到来，说明前面的请求都已经结束了，需要关闭请求缓存开关，但是不能释放请求缓存，请求缓存还需和响应合并 */
	tidb_state->request_buffer_need = 0;
	//TidbBufferFree(&(tidb_state->query_cmd_buffer));

	/* 异常判断 */
	if ((1 != tidb_state->response_buffer_need) && (pos + 4 >= p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == tidb_state->response_buffer_need) {
		/* 解析响应缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
		ret = TidbParseRespResultSet(f, statev, pstate, input, input_len, local_data, tidb_data);
		if (0 != ret) {
			return 1;
		}else {
			return 0;
		}
	}

	/* 异常判断 */
	if (pos + 4 >= p_len) {
		return 1;
	}

	/* 取出 packet len */
	pkt_len = TIDB_GET_VALUE24(p_data);

	/* 取出 packet number，0 或 1，交互阶段与正常 请求 0 和 响应 1 恰好相反 */
	pkt_num = (p_data + 3)[0];

	/* 首先解析请求中的 version 解析完退出函数 */
	if ((0 == pkt_num) && (1 == tidb_state->pkt_num) && (pkt_len + 4 == p_len)) {
		/* 解析 version */
		ret = TidbParseRespVersion(f, statev, pstate, input, input_len, local_data, tidb_data);
		if (0 != ret) {
			return 1;
		}else {
			return 0;
		}
	}

	/* pos 移动到 Response Code */
	pos += 3 + 1;

	/* 异常判断 */
	if (pos + 1 >= p_len) {
		return 1;
	}

	/* 取出 Response Code */
	resp_code = (p_data + pos)[0];

	/* 响应包，只有 Packet Number == 1 , Response Code != 0x00 的包才解析，因为前面用户登录的反常会话已经解析了 */
	if (0xfe == resp_code || 0x00 == resp_code) {
		/* 如果收到响应 */
		if (0 < tidb_state->query_cmd_buffer.len && NULL != tidb_state->query_cmd_buffer.buffer && 0x00 == resp_code) {
			tidb_state->send_key = 1;
			return 0;
		}

		return 1;
	}

	/* 解析响应缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
	ret = TidbParseRespResultSet(f, statev, pstate, input, input_len, local_data, tidb_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}

/* 解析 tidb 请求 包 */
static int TidbParseReq(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, TidbTransaction *tidb_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	TidbState *tidb_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t pkt_len = 0;
	uint8_t pkt_num = 0;

	uint8_t ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	tidb_state = (TidbState *)statev;
	p_data = input;
	p_len = input_len;

	/* 请求包到来就释放响应缓存，因为说明前面的响应都已经结束了 */
	TidbBufferFree(&(tidb_state->result_set_buffer));
	TidbBufferFree(&(tidb_state->db_name));
	TidbBufferFree(&(tidb_state->table_name));
	TidbBufferFree(&(tidb_state->fields));
	tidb_state->response_buffer_need = 0;
	TidbBufferFree(&(tidb_state->response_buffer));
	tidb_state->send_key = 0;

	/* 就前两个数据包需要计数，其他都不用 */
	if (tidb_state->pkt_num < 2) {
		tidb_state->pkt_num += 1;
	}

	/* 异常判断 */
	if ((1 != tidb_state->request_buffer_need) && (pos + 4 >= p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == tidb_state->request_buffer_need) {
		/* 缓存数据 */
		TidbBufferAdd(&(tidb_state->query_cmd_buffer), p_data, p_len);

		/* 判断缓存是否结束 */
		if (0 != tidb_state->query_cmd_buffer.len && tidb_state->query_cmd_buffer.len >= tidb_state->query_cmd_buffer.total_len) {
			/* 异常判断，缓存超过了真实长度 */
			if (tidb_state->query_cmd_buffer.len > tidb_state->query_cmd_buffer.total_len) {
				TidbBufferFree(&(tidb_state->query_cmd_buffer));
				return 1;
			}

			/* 解析请求 SQL 语句或脚本 */
			ret = TidbParseReqQuery(f, statev, pstate, input, input_len, local_data, tidb_data);

			/* 已经解析完缓存了，关闭需要缓存开关 */
			tidb_state->request_buffer_need = 0;

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
	if (pos + 4 >= p_len) {
		return 1;
	}

	/* 取出 packet len */
	pkt_len = TIDB_GET_VALUE24(p_data);

	/* 取出 packet number，0 或 1，交互阶段与正常 请求 0 和 响应 1 恰好相反 */
	pkt_num = (p_data + 3)[0];
	
	/* 首先解析请求中的 user 和 passwd */
	if ((1 == pkt_num) && (2 == tidb_state->pkt_num) && (pkt_len + 4 == p_len)) {
		/* 解析 user 和 passwd */
		ret = TidbParseReqUserPasswd(f, statev, pstate, input, input_len, local_data, tidb_data);
		if (0 != ret) {
			return 1;
		}else {
			return 0;
		}
	}

	/* pos 移动到 Command */
	pos += 3 + 1;

	/* 异常判断 */
	if (pos + 1 >= p_len) {
		return 1;
	}

	/* 取出 Command */
	//command = (p_data + pos)[0];
	
	/* 请求包，只有 Packet Number == 0，因为前面用户登录的反常会话已经解析了 */
	if (0 != pkt_num) {
		return 1;
	}

	/* 判断：如果请求是应用层分片的，需要重组后再解析 */
	if (pkt_len + 4 > p_len) {
		/* 应用层重组开关置位 */
		tidb_state->request_buffer_need = 1;

		/* 初次缓存，清理旧的缓存信息 */
		TidbBufferFree(&(tidb_state->query_cmd_buffer));

		/* 保存总长度，用于判断是否缓存完成，只有请求包才有这个总长度，响应包所有响应结束才知道传输了多少字节 */
		tidb_state->query_cmd_buffer.total_len = pkt_len - 1;

		/* 缓存数据，从真实数据开始 */
		TidbBufferAdd(&(tidb_state->query_cmd_buffer), p_data + 3 + 1 + 1, p_len - 5);

		/* 判断缓存是否结束 */
		if (0 != tidb_state->query_cmd_buffer.len && tidb_state->query_cmd_buffer.len >= tidb_state->query_cmd_buffer.total_len) {
			/* 异常判断，缓存超过了真实长度 */
			if (tidb_state->query_cmd_buffer.len > tidb_state->query_cmd_buffer.total_len) {
				TidbBufferFree(&(tidb_state->query_cmd_buffer));
				return 1;
			}

			/* 解析请求 SQL 语句或脚本 */
			ret = TidbParseReqQuery(f, statev, pstate, input, input_len, local_data, tidb_data);

			/* 已经解析完缓存了，关闭需要缓存开关 */
			tidb_state->request_buffer_need = 0;

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
	ret = TidbParseReqQuery(f, statev, pstate, input, input_len, local_data, tidb_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}


/* 请求包 解析函数 */
static AppLayerResult TidbParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	TidbTransaction *tx = NULL;
	//TidbTransaction *ttx = NULL;

	TidbState *tidb_state = NULL;
	TidbTransaction *tidb_data = NULL;

	const uint8_t *input = NULL;
	uint32_t input_len = 0;

	uint8_t prim_v = 0;
	uint8_t sec_v = 0;

	int ret = 1;

	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(tidb_conf.tidb_enable)) {
		goto error;
	}

	/* 获取 state 和 input 和 input_len */
	tidb_state = (TidbState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);

	/* 只解析版本 5.7      及以上的包     */
	if (1 == tidb_state->version_key && 3 <= tidb_state->version_len) {
		prim_v = (tidb_state->version)[0] - 0x30;
		sec_v = (tidb_state->version)[2] - 0x30;

		/* 判断 */
		if (5 > prim_v) {
			goto error;
		}else if (5 == prim_v && 5 > sec_v) {
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
	if (TIDB_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = TidbTxAlloc(tidb_state, true);
	tidb_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(tidb_data->proto, "tcp", 3);
	tidb_data->is_request = true;

#if 0
	/* 注意: 可能响应先来，因此请求也需要查一下有没有分配 tx, 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &tidb_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	tidb_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//tidb_state->transaction_max = 0;
		
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = TidbTxAlloc(tidb_state, true);
		tidb_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(tidb_data->proto, "tcp", 3);
	}
	tidb_data->is_request = true;
#endif
/************************* 解析私有数据 start ************************/	
	/* 判断真实的方向，防止三次握手第一个包丢失造成方向识别错误，记住值永远都放在左侧，防止判断恒等时使用复制符号 '=' */
	if (SC_ATOMIC_GET(tidb_conf.tidb_dport) == f->dp) {
		ret = TidbParseReq(f, state, pstate, input, input_len, local_data, tidb_data);
	}else if (SC_ATOMIC_GET(tidb_conf.tidb_dport) == f->sp) {
		ret = TidbParseResp(f, state, pstate, input, input_len, local_data, tidb_data);
	}else {
		ret = 1;
	}


	/* 如果解析失败，不发送日志 */
	if (0 != ret) {
		goto end;
	}


	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	tidb_data->done = 1;
	tidb_data->complete = 0;
	
/************************* 解析私有数据 end ************************/	


#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_tidb_event(f, tidb_data, STREAM_TOSERVER);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 响应包 解析函数 */
static AppLayerResult TidbParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	TidbTransaction *tx = NULL;
	//TidbTransaction *ttx = NULL;
	
	TidbState *tidb_state = NULL;
	TidbTransaction *tidb_data = NULL;
	
	const uint8_t *input = NULL;
	uint32_t input_len = 0;

	uint8_t prim_v = 0;
	uint8_t sec_v = 0;

	int ret = 1;
	
	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(tidb_conf.tidb_enable)) {
		goto error;
	}
	
	/* 获取 state 和 input 和 input_len */
	tidb_state = (TidbState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);

	/* 只解析版本 5.7      及以上的包     */
	if (1 == tidb_state->version_key && 3 <= tidb_state->version_len) {
		prim_v = (tidb_state->version)[0] - 0x30;
		sec_v = (tidb_state->version)[2] - 0x30;

		/* 判断 */
		if (5 > prim_v) {
			goto error;
		}else if (5 == prim_v && 5 > sec_v) {
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
	if (TIDB_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = TidbTxAlloc(tidb_state, false);
	tidb_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(tidb_data->proto, "tcp", 3);
	tidb_data->is_request = false;

#if 0
    /* 注意: 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &tidb_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	tidb_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//tidb_state->transaction_max = 0;
	
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = TidbTxAlloc(tidb_state, false);
		tidb_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(tidb_data->proto, "tcp", 3);
	}
	tidb_data->is_request = false;
#endif	
	/************************* 解析私有数据 start ************************/	
	/* 请求和响应公用一个 tx, 因此响应要清理请求的 tx */
	/* 判断真实的方向，防止三次握手第一个包丢失造成方向识别错误，记住值永远都放在左侧，防止判断恒等时使用复制符号 '=' */
	if (SC_ATOMIC_GET(tidb_conf.tidb_dport) == f->sp) {
		ret = TidbParseReq(f, state, pstate, input, input_len, local_data, tidb_data);
	}else if (SC_ATOMIC_GET(tidb_conf.tidb_dport) == f->dp) {
		ret = TidbParseResp(f, state, pstate, input, input_len, local_data, tidb_data);
	}else {
		ret = 1;
	}

	/* 如果解析失败，不发送日志 */
	if (0 != ret) {
		goto end;
	}

	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	tidb_data->done = 1;
	tidb_data->complete = 1;
		
	/************************* 解析私有数据 end ************************/ 	
	
	
#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_tidb_event(f, tidb_data, STREAM_TOCLIENT);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 获取 tx */
static void *TidbGetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	TidbState *tidb = (TidbState *)alstate;
	TidbTransaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH(tx, &tidb->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

/* 获取 tx 计数 */
static uint64_t TidbGetTxCnt(void *state)
{
	SCEnter();
	uint64_t count = ((uint64_t)((TidbState *)state)->transaction_max);
	SCReturnUInt(count);
}

/* 释放一个 tidb tx */
static void TidbTxFree(TidbTransaction *tx)
{
	SCEnter();

	AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

	if (tx->tx_data.de_state != NULL) {
		DetectEngineStateFree(tx->tx_data.de_state);
	}

	/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
	if (NULL != tx->query_cmd) {
		TIDB_FREESTR(tx->query_cmd);
	}
	
	/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
	if (NULL != tx->result_set) {
		TIDB_FREESTR(tx->result_set);
	}

	SCFree(tx);
	SCReturn;
}

/* 通过 ID 释放特定 tidb 状态上的一个事务 */
static void TidbStateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	TidbState *tidb = state;
	TidbTransaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &tidb->tx_list, next, ttx) {

		if (tx->tx_num != tx_num) {
			continue;
		}

		//最好不要使用这个 curr，这个就是容易段错误的根源
		if (tx == tidb->curr) {
			tidb->curr = NULL;
		}

		TAILQ_REMOVE(&tidb->tx_list, tx, next);
		TidbTxFree(tx);
		break;
	}

	SCReturn;
}

/* 释放 tidb state */
static void TidbStateFree(void *state)
{
	SCEnter();
	TidbState *tidb = state;
	TidbTransaction *tx;
	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&tidb->tx_list)) != NULL) {
			TAILQ_REMOVE(&tidb->tx_list, tx, next);
			TidbTxFree(tx);
		}

		/* state 中的 请求体 和 响应体 缓存释放语句 */
		if (tidb->request_buffer.buffer != NULL) {
			TIDB_FREESTR(tidb->request_buffer.buffer);
		}
		if (tidb->response_buffer.buffer != NULL) {
			TIDB_FREESTR(tidb->response_buffer.buffer);
		}

		/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
		if (tidb->query_cmd_buffer.buffer != NULL) {
			TIDB_FREESTR(tidb->query_cmd_buffer.buffer);
		}
		if (tidb->result_set_buffer.buffer != NULL) {
			TIDB_FREESTR(tidb->result_set_buffer.buffer);
		}
		if (tidb->db_name.buffer != NULL) {
			TIDB_FREESTR(tidb->db_name.buffer);
		}
		if (tidb->table_name.buffer != NULL) {
			TIDB_FREESTR(tidb->table_name.buffer);
		}
		if (tidb->fields.buffer != NULL) {
			TIDB_FREESTR(tidb->fields.buffer);
		}


		SCFree(tidb);
	}
	SCReturn;
}

/* 由应用层调用来获取状态进度 */
static int TidbGetAlstateProgress(void *tx, uint8_t direction)
{
	/* 直接返回，用完 tx 就释放提高性能 */
	return 1;

	TidbTransaction *tidbtx = (TidbTransaction *)tx;
	int retval = 0;

	/* 原生逻辑是进度完成再释放，性能低 */
	if (tidbtx->complete) {
		retval = 1;
	}	

	SCReturnInt(retval);
}

/* 获取 tx_data */
static AppLayerTxData *TidbGetTxData(void *vtx)
{
	TidbTransaction *tx = (TidbTransaction *)vtx;
	return &tx->tx_data;
}

/* 获取 state_data */
static AppLayerStateData *TidbGetStateData(void *vstate)
{
	TidbState *state = (TidbState *)vstate;
	return &state->state_data;
}

/* 迭代器 */
static AppLayerGetTxIterTuple TidbGetTxIterator(const uint8_t ipproto, const AppProto alproto,
	void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
	TidbState *dnp_state = (TidbState *)alstate;
	AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
	if (dnp_state) {
		TidbTransaction *tx_ptr;
		if (state->un.ptr == NULL) {
			tx_ptr = TAILQ_FIRST(&dnp_state->tx_list);
		} else {
			tx_ptr = (TidbTransaction *)state->un.ptr;
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


/* 安装响应和请求方向多种特征的协议识别函数 */
static int TidbRegisterPatternsForProtocolDetection(void)
{
	/* "-TiDB-" 特征匹配 */
	if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_TIDB, "-TiDB-", 32, 5,
		STREAM_TOCLIENT, TidbProbingParserTsTc, 5, 32) < 0) {
		return -1;
	}

#if 0
	/* "libmariadb" 特征匹配 */
	if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_TIDB, "libmariadb", 128, 36,
		STREAM_TOSERVER, TidbProbingParserTsTc, 36, 128) < 0) {
		return -1;
	}
#endif

	return 0;
}


/* 核心注册函数 */
void RegisterTidbParsers(void)
{
	const char *proto_name = "tidb";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_TIDB, proto_name);

	/* 注册 tidb 特征 */
	if (TidbRegisterPatternsForProtocolDetection() < 0 ) {
		SCLogConfig("Registering tidb/tcp TidbRegisterPatternsForProtocolDetection error!");
		SCReturn;
	}

#if 0
	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_TIDB, 0, TIDB_MIN_FRAME_LEN, TidbProbingParserTsTc, TidbProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_TCP, TIDB_DEFAULT_PORT, ALPROTO_TIDB, 0, TIDB_MIN_FRAME_LEN, STREAM_TOSERVER, TidbProbingParserTsTc, TidbProbingParserTsTc);	
	}
#endif

	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
		SCLogConfig("Registering tidb/tcp parsers.");
		
		TidbReload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(tidb_conf.tidb_enable , 0);
		SC_ATOMIC_SET(tidb_conf.log_enable, 0);
		SC_ATOMIC_SET(tidb_conf.tidb_dport, atoi(TIDB_DEFAULT_PORT));
		SC_ATOMIC_SET(tidb_conf.result, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Tidb流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TIDB, TidbStateAlloc, TidbStateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TIDB, STREAM_TOSERVER, TidbParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TIDB, STREAM_TOCLIENT, TidbParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_TIDB, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_TIDB, TidbGetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_TIDB, TidbGetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_TIDB, TidbStateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_TIDB, TidbGetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_TIDB, TidbGetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_TIDB, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_TIDB, TidbGetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_TIDB, TidbGetStateData);
	
	SCReturn;
}

