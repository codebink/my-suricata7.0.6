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

#include "app-layer-redis.h"

RedisConf redis_conf;


/* 0x0d 0x0a 模式串，用于快速查找字符串结尾 */
static uint8_t REDIS_STR2_END_PATT[2] = {0x0d, 0x0a};

/* redis_version:(0x72,0x65,0x64,0x69,0x73,0x5F,0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,0x3A) 模式串 */
static uint8_t REDIS_VERSION_PATT[14] = {0x72,0x65,0x64,0x69,0x73,0x5F,0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,0x3A};

/* os:(0x6F,0x73,0x3A) 模式串 */
static uint8_t REDIS_OS_PATT[3] = {0x6F,0x73,0x3A};

/* executable:(0x65,0x78,0x65,0x63,0x75,0x74,0x61,0x62,0x6C,0x65,0x3A) 模式串 */
static uint8_t REDIS_EXECUTABLE_PATT[11] = {0x65,0x78,0x65,0x63,0x75,0x74,0x61,0x62,0x6C,0x65,0x3A};

/* config_file:(0x63,0x6F,0x6E,0x66,0x69,0x67,0x5F,0x66,0x69,0x6C,0x65,0x3A) 模式串 */
static uint8_t REDIS_CONFIG_FILE_PATT[12] = {0x63,0x6F,0x6E,0x66,0x69,0x67,0x5F,0x66,0x69,0x6C,0x65,0x3A};


/* 热加载函数 */
void RedisReload(void)
{
	/* 获取是否打开日志开关 */
	ConfNode *node = NULL;

	/* 插件开关 */
	node = NULL;
	node = ConfGetNode(REDIS_ENABLED_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(redis_conf.redis_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(redis_conf.redis_enable, 0);
	}

	/* 获取是否打开日志开关 */
	node = ConfGetNode(REDIS_LOG_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(redis_conf.log_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(redis_conf.log_enable, 0);
	}	

	/* 获取 Redis 配置文件中的 dport 用于方向判断 */
	node = ConfGetNode(REDIS_DPORT);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(redis_conf.redis_dport, atoi(node->val));
	}else {
		SC_ATOMIC_SET(redis_conf.redis_dport, atoi(REDIS_DEFAULT_PORT));
	}	

	/* 获取是否打开结果集开关 */
	node = ConfGetNode(REDIS_RESULT);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(redis_conf.result, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(redis_conf.result, 0);
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
		1 RedisTransaction *tx: Redis 的私有结构

	返回：void
*/
static void print_redis_event(Flow *f, RedisTransaction *tx, uint16_t direction)
{
	/* 参数检查 */
	if (NULL == tx) {
		return;
	}

	char msg_buf[1024] = {0};
	RedisTransaction *redis_data = NULL;

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
	redis_data = tx;

	/* 时间 2016/09/22 12:21:30 */
	get_local_time(redis_data->time_buff);
	
	/* 打印 */
	snprintf(msg_buf, sizeof(msg_buf), "done=%u", \
			redis_data->done \
			);

	/* 打印公共字段 */
	DEBUG_DLOG("-----8888888888----- date: %s, s_ip: %s, s_port: %u, d_ip: %s, d_port: %u, dir: %d, protocal: %s, msg_buf: %s", \
				redis_data->time_buff,\
				src_ip, src_port,\
				dst_ip, dst_port,\
				redis_data->is_request, redis_data->proto,\
				msg_buf \
				);

	return;
}
#endif






/* Ts 和 Tc 是指 Request 和 Response 方向协议识别和异常判断，合并到一起了，以后需要时还要拆分成两个函数，因为请求包和响应包结构不同 */
static AppProto RedisProbingParserTsTc(Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
	if (NULL == input || 0 >= input_len) {
		return ALPROTO_UNKNOWN;
	}

	//const uint8_t *p_data = NULL;
	uint16_t p_len = 0;

	/* 如果没有打开则强制不再识别识别, 后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(redis_conf.redis_enable)) {
		return ALPROTO_UNKNOWN;
	}
	
	/* 负载和负载长度 */
	//p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if (p_len < REDIS_MIN_FRAME_LEN) {
		return ALPROTO_UNKNOWN;
	}

	return ALPROTO_REDIS;
}

/* 分配一个 redis 状态对象，表示一个 redis TCP 会话 */
static void *RedisStateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	RedisState *redis;

	redis = (RedisState *)SCCalloc(1, sizeof(RedisState));
	if (unlikely(redis == NULL)) {
		return NULL;
	}
	TAILQ_INIT(&redis->tx_list);

	SCReturnPtr(redis, "void");
}

/* 分配一个 redis transaction */
static RedisTransaction *RedisTxAlloc(RedisState *redis, bool request)
{
	RedisTransaction *tx = SCCalloc(1, sizeof(RedisTransaction));
	if (unlikely(tx == NULL)) {
		return NULL;
	}
	redis->transaction_max++;
	redis->curr = tx;
	tx->redis = redis;
	tx->tx_num = redis->transaction_max;
	tx->is_request = request;
	if (tx->is_request) {
		tx->tx_data.detect_flags_tc |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	} else {
		tx->tx_data.detect_flags_ts |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	}

	TAILQ_INSERT_TAIL(&redis->tx_list, tx, next);

	return tx;
}

#if 0
static char redis_hex_to_char(unsigned char ch)
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

static int redis_hex_to_str(unsigned char *src, uint32_t src_len, char *dst, uint32_t *dst_len)
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
		t_chr = redis_hex_to_char(tmp_char);
		dst[j] = t_chr;

		/* 低 4 bit 转换 */
		src_char = 0x00;
		src_char = src[i];
		tmp_char = 0x00;
		tmp_char = (src_char & 0x0f);

		/* 获取低位转换的字符 */
		t_chr = '0';
		t_chr = redis_hex_to_char(tmp_char);
		dst[j+1] = t_chr;

		j += 2;
	}

	*dst_len = j;

	return 0;
}
#endif

/* 配合 sunday 算法获取模式串第一次命中的位置 */
static int RedisFindIndex(uint8_t *patt_str, int patt_len, uint8_t uc_tmp, int *index)
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
static int RedisSundayALG(const uint8_t *src, uint32_t src_len, uint8_t *patt_str, int patt_len, uint32_t *dst_len)
{
    if ( (NULL == src) || (0 >= src_len) || (NULL == patt_str) || (0 >= patt_len) ) {
        return 1;
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
            return 1;
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
            ret = RedisFindIndex(patt_str, patt_len, src[tmp], &index);
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

    return 1;
}


/* 释放分片重组缓冲区 */
static int RedisBufferFree(RedisBuffer *buffer)
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
	buffer->curr_column_count = 0;

	return 0;
}

/* 应用层分片重组，注意：成功时返回 0，失败时返回 1 */
static int RedisBufferAdd(RedisBuffer *buffer, const uint8_t *data, uint32_t len)
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

/* 解析 Reruest 的 SQL 语句，循环解析  */
static int RedisParseReqCmdLoop(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RedisTransaction *redis_data, uint8_t *fram_key)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len || NULL == fram_key) {
		return 1;
	}

	RedisState *redis_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t start_pos = 0;
	uint32_t type = 0;
	uint32_t find_len = 0;
	uint32_t length = 0;
	uint32_t location = 0;
	uint8_t len_str[REDIS_LENGTH_LEN] = {0};
	uint64_t column_length = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	redis_state = (RedisState *)statev;
	p_data = input;
	p_len = input_len;

	/* 判断需要解析拼接后的缓存，还是直接解析完整的数据包 */
	if (1 == redis_state->request_buffer_need) {
		/* 如果上一个包有分片，缓存本次数据包，与上一个数据包尾部的分片组成一个完整的 buff ，像解析 DNS 一样循环解析，然后还要判断尾部是否有下一个数据包的分片 */
		RedisBufferAdd(&(redis_state->request_buffer), p_data, p_len);

		/* 局部变量重新赋值 */
		p_data = redis_state->request_buffer.buffer;
		p_len = redis_state->request_buffer.len;
	}

	/* 异常判断 */
	if (pos + 4 >= p_len) {
		return 1;
	}

	/* 取出 Type */
	type = p_data[0];

	/* 异常判断，不是 Bulk String 0x24 或第一个包 */
	if (0x24 != type && 0x2a != type) {
		return 1;
	}

	/* pos 跳过 Bulk String 标志 0x2a */
	pos += 1;

	/* 如果 pos 游标后的剩余长度大于 64bit 数字字符串字面长度，也只查询这么长，提高效率 */
	if (p_len - pos >= REDIS_LENGTH_LEN) {
		find_len = REDIS_LENGTH_LEN;
	}else {
		find_len = (p_len - pos);
	}

	/* 异常判断 */
	if (1 > find_len) {
		return 1;
	}
	
	/* 查找结尾 0x00 */
	location = 0;
	RedisSundayALG((p_data + pos), find_len, REDIS_STR2_END_PATT, 2, &location);
	if (0 == location) {
		return 1;
	}	

	/* 异常判断 */
	if (location > REDIS_LENGTH_LEN) {
		return 1;
	}

	/* 取出 length 元组个数 */
	memset(len_str, 0, REDIS_LENGTH_LEN);
	memcpy(len_str, (p_data + pos), location);
	char *end;
	length = (uint64_t)strtoull((char *)len_str, &end, 10);
	if (end == (char *)len_str || *end != '\0' || length == 0) {
		return 1; 
	}

	/* 异常判断 */
	if (pos + location + 2 > p_len) {
		return 1;
	}

	/* pos 跳过剩下的 length 结构，偏移到数据的起始位置 */
	pos += location + 2;

	/* 判断本分片的 Bulk String 是否已经缓冲完成，没有完成接着缓冲 */
	if (1 == redis_state->request_buffer_need 
		&& 1 <= p_len - pos
		&& length + 2 > p_len - pos) {
		return 1;
	}

	/* 如果不是第一个包，pos 回退到负载头部，准备解析 */
	if (0x24 == type) {
		pos = 0;
	}else if (0x2a == type) {
		/* 如果是第一个包保存字段总数 */
		redis_state->query_cmd_buffer.column_count = length;
		redis_state->query_cmd_buffer.curr_column_count = 0;
	}

	/* 循环解析 Bulk String 数据 */
	while (pos + 4 < p_len
		&& redis_state->query_cmd_buffer.curr_column_count < redis_state->query_cmd_buffer.column_count) {
		
		/* 累加列字段计数 */
		redis_state->query_cmd_buffer.curr_column_count += 1;
	
		/* 异常判断 */
		if (0x24 != (p_data + pos)[0]) {
			return 1;
		}
	
		/* tmp_pos 跳过标志 0x24 */
		pos += 1;
		
		/* 如果 pos 游标后的剩余长度大于 64bit 数字字符串字面长度，也只查询这么长，提高效率 */
		if (p_len - pos >= REDIS_LENGTH_LEN) {
			find_len = REDIS_LENGTH_LEN;
		}else {
			find_len = (p_len - pos);
		}
		
		/* 异常判断 */
		if (1 > find_len) {
			return 1;
		}
		
		/* 查找结尾 0x00 */
		location = 0;
		RedisSundayALG((p_data + pos), find_len, REDIS_STR2_END_PATT, 2, &location);
		if (0 == location) {
			return 1;
		}
		
		/* 异常判断 */
		if (location > REDIS_LENGTH_LEN) {
			return 1;
		}
		
		/* 取出 length   */
		memset(len_str, 0, REDIS_LENGTH_LEN);
		memcpy(len_str, (p_data + pos), location);
		char *end;
		column_length = 0;
		column_length = (uint64_t)strtoull((char *)len_str, &end, 10);
		if (end == (char *)len_str 
			|| *end != '\0' 
			|| column_length == 0) {
			return 1; 
		}
			
		/* tmp_pos 移动到数据头部 */
		pos += location + 2;

		/* 先回退 pos，缓存分片 */
		start_pos = pos - 1 - location - 2;
		if (pos + column_length + 2> p_len) {
			/* 打开分片开关 */
			*fram_key = 1;
			redis_state->request_buffer_need = 1;
		
			/* 缓存分片，先清理后缓存 */
			RedisBufferFree(&(redis_state->request_buffer));
			if (1 <= (p_len - start_pos)) {
				RedisBufferAdd(&(redis_state->request_buffer), (p_data + start_pos), (p_len - start_pos));
			}

			/* 由于这次是缓存去了，没有解析数据块，因此计数器减一 */
			redis_state->query_cmd_buffer.curr_column_count -= 1;

			return 1;
		}

		/* 保存 SQL cmd 信息 */
		RedisBufferAdd(&(redis_state->query_cmd_buffer), (p_data + pos), column_length);
	
		/* 如果是最后一个字段后面加换行符 */
		if (redis_state->query_cmd_buffer.curr_column_count == redis_state->query_cmd_buffer.column_count) {
			RedisBufferAdd(&(redis_state->query_cmd_buffer), REDIS_CRLF, 3);
			redis_state->query_cmd_buffer.finish_key = 1;
		}else {
			RedisBufferAdd(&(redis_state->query_cmd_buffer), REDIS_SPACE, 1);
		}
	
		/* tmp_pos 跳过 text */
		pos += column_length + 2;
	}

	/* 尾巴剩余的可能不够满足一个响应头部，因此缓存起来，与下一个包拼接成完整的头部 */
	if (pos + 4 >= p_len && p_len - pos > 0) {
		/* 打开分片开关 */
		*fram_key = 1;
		redis_state->request_buffer_need = 1;
		
		/* 缓存分片，先清理后缓存 */
		RedisBufferFree(&(redis_state->request_buffer));
		RedisBufferAdd(&(redis_state->request_buffer), (p_data + pos), (p_len - pos)); 
		return 1;
	}

	return 0;
}

/* 解析 Request 中的 命令  */
static int RedisParseReqCmd(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RedisTransaction *redis_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	RedisState *redis_state = NULL;
	uint8_t fram_key = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	redis_state = (RedisState *)statev;

	/* 判断是否有上一个数据包的分片 */
	if (1 == redis_state->request_buffer_need) {
		/* 循环解析响应中的结果集 */
		RedisParseReqCmdLoop(f, statev, pstate, input, input_len, local_data, redis_data, &fram_key);

		/* 判断这个包的尾巴是否有分片，如果有分片，存储起来下次响应包到来的时候与写一个包拼接成一个完整的包 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		RedisBufferFree(&(redis_state->request_buffer));
		redis_state->request_buffer_need = 0;
	}else {
		/* 循环解析响应中的结果集 */
		RedisParseReqCmdLoop(f, statev, pstate, input, input_len, local_data, redis_data, &fram_key);

		/* 如果响应包的尾部有下一个包的分片，那么打开开关，缓存分片 */
		if (1 == fram_key) {
			/* 有分片返回 1, 没有分片返回 0 */
			return 1;
		}

		/* 清理上次分片缓存，关闭缓存开关 */
		RedisBufferFree(&(redis_state->request_buffer));
		redis_state->request_buffer_need = 0;
	}

	return 0;
}


/* 解析 Response 中的 Result Set  */
static int RedisParseRespResultSet(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RedisTransaction *redis_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	/* 不解析响应，预留 */

	return 0;
}

/* 解析 redis 响应 包 */
static int RedisParseResp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RedisTransaction *redis_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	RedisState *redis_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint8_t type = 0;
	uint32_t length = 0;
	uint32_t find_len = 0;
	uint32_t location = 0;
	uint8_t len_str[REDIS_LENGTH_LEN] = {0};
	
	uint8_t ret = 0;
	int pm_ret = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	redis_state = (RedisState *)statev;
	p_data = input;
	p_len = input_len;

	/* 就前 15 个数据包需要计数，其他都不用 */
	if (redis_state->pkt_num < 10) {
		redis_state->pkt_num += 1;
	}

	/* 响应包到来，说明前面的请求都已经结束了，需要关闭请求缓存开关，但是不能释放请求缓存，请求缓存还需和响应合并 */
	redis_state->request_buffer_need = 0;
	RedisBufferFree(&(redis_state->request_buffer));
	//RedisBufferFree(&(redis_state->query_cmd_buffer));

	/* 结果集开关关闭时不解析结果集，直接返回 */
	if (15 <= redis_state->pkt_num && 0 == SC_ATOMIC_GET(redis_conf.result)) {
		return 1;
	}

	/* 异常判断 */
	if ((1 != redis_state->response_buffer_need) && (pos + 4 >= p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == redis_state->response_buffer_need) {
		/* 解析响应缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
		ret = RedisParseRespResultSet(f, statev, pstate, input, input_len, local_data, redis_data);
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

	/* 取出 type */
	type = p_data[0];

	/* 只解析有用的包 */
	if (0x2a != type && 0x24 != type) {
		return 1;
	}

	/* pos 跳过请求标志 0x2a */
	pos += 1;

	/* 如果 pos 游标后的剩余长度大于 64 bit 数字字符串最大长度，也只查询这么长，提高效率 */
	if (p_len - pos >= REDIS_LENGTH_LEN) {
		find_len = REDIS_LENGTH_LEN;
	}else {
		find_len = (p_len - pos);
	}

	/* 异常判断 */
	if (1 > find_len) {
		return 1;
	}
	
	/* 查找结尾 0x00 */
	location = 0;
	pm_ret = RedisSundayALG((p_data + pos), find_len, REDIS_STR2_END_PATT, 2, &location);
	if (0 != pm_ret && 0 == location) {
		return 1;
	}	

	/* 异常判断 */
	if (location > REDIS_LENGTH_LEN) {
		return 1;
	}

	/* 取出 length 元组个数 */
	memset(len_str, 0, REDIS_LENGTH_LEN);
	memcpy(len_str, (p_data + pos), location);
	char *end;
	length = (uint64_t)strtoull((char *)len_str, &end, 10);
	if (end == (char *)len_str || *end != '\0' || length == 0) {
		return 1; 
	}

	/* 异常判断 */
	if (pos + location + 2 > p_len) {
		return 1;
	}

	/* pos 跳过剩下的 length 结构 */
	pos += location + 2;	

	/* 判断是否是 server_version */
	if ((0x24 == type) 
		&& (0 == redis_state->server_version.len) 
		&& (length + 8 == p_len)
		&& pos + 10 < p_len 
		&& 1 == REDIS_IS_SERVER(p_data + pos)) {
		
		/* 异常判断 */
		if (pos + 14 >= p_len) {
			return 1;
		}

		/* 查找 redis_version: */
		location = 0;
		pm_ret = RedisSundayALG((p_data + pos), (p_len - pos), REDIS_VERSION_PATT, 14, &location);
		if (0 != pm_ret && 0 == location) {
			return 1;
		}			

		/* pos 跳过前面的距离和模式串 */
		pos += location + 14;

		/* 异常判断 */
		if (pos + 2 >= p_len) {
			return 1;
		}

		/* 查找结尾 0x00 */
		location = 0;
		pm_ret = RedisSundayALG((p_data + pos), (p_len - pos), REDIS_STR2_END_PATT, 2, &location);
		if (0 != pm_ret && 0 == location) {
			return 1;
		}

		/* 取出   redis_version: 数据 */
		RedisBufferFree(&(redis_state->server_version));
		RedisBufferAdd(&(redis_state->server_version), (p_data + pos), location);

		/* pos 移动过 redis_version: */
		pos += location + 2;

		/* 异常判断 */
		if (pos + 3 >= p_len) {
			return 1;
		}

		/* 查找 os: */
		location = 0;
		pm_ret = RedisSundayALG((p_data + pos), (p_len - pos), REDIS_OS_PATT, 3, &location);
		if (0 != pm_ret && 0 == location) {
			return 1;
		}			

		/* pos 跳过前面的距离和模式串 */
		pos += location + 3;

		/* 异常判断 */
		if (pos + 2 >= p_len) {
			return 1;
		}

		/* 查找结尾 0x00 */
		location = 0;
		pm_ret = RedisSundayALG((p_data + pos), (p_len - pos), REDIS_STR2_END_PATT, 2, &location);
		if (0 != pm_ret && 0 == location) {
			return 1;
		}

		/* 取出 os: 长度 */
		RedisBufferFree(&(redis_state->system_name));
		RedisBufferAdd(&(redis_state->system_name), (p_data + pos), location);

		/* pos 移动过 os: */
		pos += location + 2;

		/* 异常判断 */
		if (pos + 11 >= p_len) {
			return 1;
		}

		/* 查找 executable: */
		location = 0;
		pm_ret = RedisSundayALG((p_data + pos), (p_len - pos), REDIS_EXECUTABLE_PATT, 11, &location);
		if (0 != pm_ret && 0 == location) {
			return 1;
		}			

		/* pos 跳过前面的距离和模式串 */
		pos += location + 11;

		/* 异常判断 */
		if (pos + 2 >= p_len) {
			return 1;
		}

		/* 查找结尾 0x00 */
		location = 0;
		pm_ret = RedisSundayALG((p_data + pos), (p_len - pos), REDIS_STR2_END_PATT, 2, &location);
		if (0 != pm_ret && 0 == location) {
			return 1;
		}

		/* 取出 executable: 长度 */
		RedisBufferFree(&(redis_state->executable));
		RedisBufferAdd(&(redis_state->executable), (p_data + pos), location);

		/* pos 移动过    executable: */
		pos += location + 2;		

		/* 异常判断 */
		if (pos + 12 >= p_len) {
			return 1;
		}

		/* 查找 config_file: */
		location = 0;
		pm_ret = RedisSundayALG((p_data + pos), (p_len - pos), REDIS_CONFIG_FILE_PATT, 12, &location);
		if (0 != pm_ret && 0 == location) {
			return 1;
		}			

		/* pos 跳过前面的距离和模式串 */
		pos += location + 12;

		/* 异常判断 */
		if (pos + 2 >= p_len) {
			return 1;
		}

		/* 查找结尾 0x00 */
		location = 0;
		pm_ret = RedisSundayALG((p_data + pos), (p_len - pos), REDIS_STR2_END_PATT, 2, &location);
		if (0 != pm_ret && 0 == location) {
			return 1;
		}

		/* 取出 config_file: 长度 */
		RedisBufferFree(&(redis_state->config_file));
		RedisBufferAdd(&(redis_state->config_file), (p_data + pos), location);

		return 0;
	}


	/* 解析响应缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
	ret = RedisParseRespResultSet(f, statev, pstate, input, input_len, local_data, redis_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}

/* 解析 redis 请求 包 */
static int RedisParseReq(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RedisTransaction *redis_data)
{
	if (NULL == f || NULL == statev || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	RedisState *redis_state = NULL;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_pos = 0;
	uint32_t location = 0;
	uint32_t find_len = 0;
	uint8_t type = 0;
	uint64_t length = 0;
	uint64_t number_of_field = 0;
	uint32_t tmp_len = 0;
	uint8_t ret = 0;
	uint8_t len_str[REDIS_LENGTH_LEN] = {0};
	uint64_t column_length = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	redis_state = (RedisState *)statev;
	p_data = input;
	p_len = input_len;

	/* 请求包到来就释放响应缓存，因为说明前面的响应都已经结束了 */
	RedisBufferFree(&(redis_state->result_set_buffer));
	RedisBufferFree(&(redis_state->fields));
	redis_state->response_buffer_need = 0;
	RedisBufferFree(&(redis_state->response_buffer));
	redis_state->send_key = 0;

	/* 就前两个数据包需要计数，其他都不用 */
	if (redis_state->pkt_num < 10) {
		redis_state->pkt_num += 1;
	}

	/* 异常判断 */
	if ((1 != redis_state->request_buffer_need) && (pos + 4 >= p_len)) {
		/* 如果请求没分片，到来的数据包又小于 packet len + packet number 说明时异常包丢掉 */
		return 1;
	}

	/* 判断是否需要拼接请求分片，一定再所有解析的前面判断 */
	if (1 == redis_state->request_buffer_need) {
		/* 解析请求缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
		ret = RedisParseReqCmd(f, statev, pstate, input, input_len, local_data, redis_data);
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

	/* 取出 Type */
	type = p_data[0];

	/* 异常判断不是请求包 0x2a，且不是分片请求，因为分片请求在前面就拼接了到不了这 */
	if (0x2a != type) {
		/* 清空上次缓存 */
		RedisBufferFree(&(redis_state->query_cmd_buffer));

		return 1;
	}

	/* 请求的第一个包清理各种缓存 */
	RedisBufferFree(&(redis_state->query_cmd_buffer));
	redis_state->request_buffer_need = 0;
	RedisBufferFree(&(redis_state->request_buffer));

	/* pos 跳过请求标志 0x2a */
	pos += 1;

	/* 如果 pos 游标后的剩余长度大于 64 bit 数字字符串最大长度，也只查询这么长，提高效率 */
	if (p_len - pos >= REDIS_LENGTH_LEN) {
		find_len = REDIS_LENGTH_LEN;
	}else {
		find_len = (p_len - pos);
	}

	/* 异常判断 */
	if (1 > find_len) {
		return 1;
	}
	
	/* 查找结尾 0x00 */
	location = 0;
	RedisSundayALG((p_data + pos), find_len, REDIS_STR2_END_PATT, 2, &location);
	if (0 == location) {
		return 1;
	}	

	/* 异常判断 */
	if (location > REDIS_LENGTH_LEN) {
		return 1;
	}

	/* 取出 length 元组个数 */
	memset(len_str, 0, REDIS_LENGTH_LEN);
	memcpy(len_str, (p_data + pos), location);
	char *end;
	length = (uint64_t)strtoull((char *)len_str, &end, 10);
	if (end == (char *)len_str || *end != '\0' || length == 0) {
		return 1; 
	}

	/* 异常判断 */
	if (pos + location + 2 > p_len) {
		return 1;
	}

	/* pos 跳过剩下的 length 结构 */
	pos += location + 2;

	/* 判断是否是 AUTH */
	tmp_len = 4 + 2;
	if (1 == redis_state->pkt_num 
		&& 0 == redis_state->auth.len
		&& tmp_len + 8 < p_len 
		&& 1 == REDIS_IS_AUTH_REQUEST(p_data + tmp_len)) {

		/* 清空认证信息 */
		RedisBufferFree(&(redis_state->auth));

		/* 循环解析 Bulk String 数据，pos 已经移动到该部分 */
		tmp_pos = pos + 2 + 8;
		number_of_field += 1;
		while (tmp_pos + 4 < p_len
			&& number_of_field < length) {
			
			/* 累加列字段计数 */
			number_of_field += 1;

			/* 异常判断 */
			if (0x24 != (p_data + tmp_pos)[0]) {
				return 1;
			}

			/* tmp_pos 跳过标志 0x24 */
			tmp_pos += 1;
			
			/* 如果 pos 游标后的剩余长度大于用户名缓存，也只查询用户名缓存这么长，提高效率 */
			if (p_len - tmp_pos >= REDIS_LENGTH_LEN) {
				find_len = REDIS_LENGTH_LEN;
			}else {
				find_len = (p_len - tmp_pos);
			}
			
			/* 异常判断 */
			if (1 > find_len) {
				return 1;
			}
			
			/* 查找结尾 0x00 */
			location = 0;
			RedisSundayALG((p_data + tmp_pos), find_len, REDIS_STR2_END_PATT, 2, &location);
			if (0 == location) {
				return 1;
			}
			
			/* 异常判断 */
			if (location > REDIS_LENGTH_LEN) {
				return 1;
			}
			
			/* 取出 length   */
			memset(len_str, 0, REDIS_LENGTH_LEN);
			memcpy(len_str, (p_data + tmp_pos), location);
			char *end;
			column_length = (uint64_t)strtoull((char *)len_str, &end, 10);
			if (end == (char *)len_str 
				|| *end != '\0' 
				|| column_length == 0) {
				return 1; 
			}

			/* 异常判断 */
			if (tmp_pos + location + 2 + column_length + 2 > p_len) {
				return 1;
			}

			/* tmp_pos 移动到数据头部 */
			tmp_pos += location + 2;

			/* 保存 AUTH 信息 */
			RedisBufferAdd(&(redis_state->auth), (p_data + tmp_pos), column_length);
		
			/* 如果是最后一个字段后面加换行符 */
			if (number_of_field == length) {
				RedisBufferAdd(&(redis_state->auth), REDIS_CRLF, 3);
			}else {
				RedisBufferAdd(&(redis_state->auth), REDIS_SPACE, 1);
			}
		
			/* tmp_pos 跳过 text */
			tmp_pos += column_length + 2;
		}

		return 0;
	}

	/* 解析请求缓存，边扫描边解析，如果有分片就缓存上一个包的尾巴，用于与下一个包头部拼接成完整的数据包 */
	ret = RedisParseReqCmd(f, statev, pstate, input, input_len, local_data, redis_data);
	if (0 != ret) {
		return 1;
	}

	return 0;
}


/* 请求包 解析函数 */
static AppLayerResult RedisParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	RedisTransaction *tx = NULL;
	//RedisTransaction *ttx = NULL;

	RedisState *redis_state = NULL;
	RedisTransaction *redis_data = NULL;

	const uint8_t *input = NULL;
	uint32_t input_len = 0;


	int ret = 1;

	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(redis_conf.redis_enable)) {
		goto error;
	}

	/* 获取 state 和 input 和 input_len */
	redis_state = (RedisState *)state;
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
	if (REDIS_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = RedisTxAlloc(redis_state, true);
	redis_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(redis_data->proto, "tcp", 3);
	redis_data->is_request = true;

#if 0
	/* 注意: 可能响应先来，因此请求也需要查一下有没有分配 tx, 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &redis_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	redis_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//redis_state->transaction_max = 0;
		
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = RedisTxAlloc(redis_state, true);
		redis_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(redis_data->proto, "tcp", 3);
	}
	redis_data->is_request = true;
#endif
/************************* 解析私有数据 start ************************/	
	/* 判断真实的方向，防止三次握手第一个包丢失造成方向识别错误，记住值永远都放在左侧，防止判断恒等时使用复制符号 '=' */
	if (SC_ATOMIC_GET(redis_conf.redis_dport) == f->dp) {
		ret = RedisParseReq(f, state, pstate, input, input_len, local_data, redis_data);
	}else if (SC_ATOMIC_GET(redis_conf.redis_dport) == f->sp) {
		ret = RedisParseResp(f, state, pstate, input, input_len, local_data, redis_data);
	}else {
		ret = 1;
	}


	/* 如果解析失败，不发送日志 */
	if (0 != ret) {
		goto end;
	}


	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	redis_data->done = 1;
	redis_data->complete = 0;
	
/************************* 解析私有数据 end ************************/	


#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_redis_event(f, redis_data, STREAM_TOSERVER);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 响应包 解析函数 */
static AppLayerResult RedisParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	RedisTransaction *tx = NULL;
	//RedisTransaction *ttx = NULL;
	
	RedisState *redis_state = NULL;
	RedisTransaction *redis_data = NULL;
	
	const uint8_t *input = NULL;
	uint32_t input_len = 0;
	
	int ret = 1;
	
	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(redis_conf.redis_enable)) {
		goto error;
	}
	
	/* 获取 state 和 input 和 input_len */
	redis_state = (RedisState *)state;
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
	if (REDIS_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = RedisTxAlloc(redis_state, false);
	redis_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(redis_data->proto, "tcp", 3);
	redis_data->is_request = false;

#if 0
    /* 注意: 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &redis_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	redis_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//redis_state->transaction_max = 0;
	
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = RedisTxAlloc(redis_state, false);
		redis_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(redis_data->proto, "tcp", 3);
	}
	redis_data->is_request = false;
#endif	
	/************************* 解析私有数据 start ************************/	
	/* 请求和响应公用一个 tx, 因此响应要清理请求的 tx */
	/* 判断真实的方向，防止三次握手第一个包丢失造成方向识别错误，记住值永远都放在左侧，防止判断恒等时使用复制符号 '=' */
	if (SC_ATOMIC_GET(redis_conf.redis_dport) == f->sp) {
		ret = RedisParseReq(f, state, pstate, input, input_len, local_data, redis_data);
	}else if (SC_ATOMIC_GET(redis_conf.redis_dport) == f->dp) {
		ret = RedisParseResp(f, state, pstate, input, input_len, local_data, redis_data);
	}else {
		ret = 1;
	}

	/* 如果解析失败，不发送日志 */
	if (0 != ret) {
		goto end;
	}

	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	redis_data->done = 1;
	redis_data->complete = 1;
		
	/************************* 解析私有数据 end ************************/ 	
	
	
#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_redis_event(f, redis_data, STREAM_TOCLIENT);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 获取 tx */
static void *RedisGetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	RedisState *redis = (RedisState *)alstate;
	RedisTransaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH(tx, &redis->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

/* 获取 tx 计数 */
static uint64_t RedisGetTxCnt(void *state)
{
	SCEnter();
	uint64_t count = ((uint64_t)((RedisState *)state)->transaction_max);
	SCReturnUInt(count);
}

/* 释放一个 redis tx */
static void RedisTxFree(RedisTransaction *tx)
{
	SCEnter();

	AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

	if (tx->tx_data.de_state != NULL) {
		DetectEngineStateFree(tx->tx_data.de_state);
	}

	/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
	if (NULL != tx->query_cmd) {
		REDIS_FREESTR(tx->query_cmd);
	}
	
	/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
	if (NULL != tx->result_set) {
		REDIS_FREESTR(tx->result_set);
	}

	SCFree(tx);
	SCReturn;
}

/* 通过 ID 释放特定 redis 状态上的一个事务 */
static void RedisStateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	RedisState *redis = state;
	RedisTransaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &redis->tx_list, next, ttx) {

		if (tx->tx_num != tx_num) {
			continue;
		}

		//最好不要使用这个 curr，这个就是容易段错误的根源
		if (tx == redis->curr) {
			redis->curr = NULL;
		}

		TAILQ_REMOVE(&redis->tx_list, tx, next);
		RedisTxFree(tx);
		break;
	}

	SCReturn;
}

/* 释放 redis state */
static void RedisStateFree(void *state)
{
	SCEnter();
	RedisState *redis = state;
	RedisTransaction *tx;
	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&redis->tx_list)) != NULL) {
			TAILQ_REMOVE(&redis->tx_list, tx, next);
			RedisTxFree(tx);
		}

		/* state 中的 请求体 和 响应体 缓存释放语句 */
		if (redis->request_buffer.buffer != NULL) {
			REDIS_FREESTR(redis->request_buffer.buffer);
		}
		if (redis->response_buffer.buffer != NULL) {
			REDIS_FREESTR(redis->response_buffer.buffer);
		}

		/* 释放 state 前，释放会话中的 查询命令 和 结果集缓存 */
		if (redis->query_cmd_buffer.buffer != NULL) {
			REDIS_FREESTR(redis->query_cmd_buffer.buffer);
		}
		if (redis->result_set_buffer.buffer != NULL) {
			REDIS_FREESTR(redis->result_set_buffer.buffer);
		}
		if (redis->db_name.buffer != NULL) {
			REDIS_FREESTR(redis->db_name.buffer);
		}
		if (redis->table_name.buffer != NULL) {
			REDIS_FREESTR(redis->table_name.buffer);
		}
		if (redis->fields.buffer != NULL) {
			REDIS_FREESTR(redis->fields.buffer);
		}
		if (redis->client_version.buffer != NULL) {
			REDIS_FREESTR(redis->client_version.buffer);
		}
		if (redis->user.buffer != NULL) {
			REDIS_FREESTR(redis->user.buffer);
		}
		if (redis->server_version.buffer != NULL) {
			REDIS_FREESTR(redis->server_version.buffer);
		}
		if (redis->client_name.buffer != NULL) {
			REDIS_FREESTR(redis->client_name.buffer);
		}
		if (redis->system_name.buffer != NULL) {
			REDIS_FREESTR(redis->system_name.buffer);
		}
		if (redis->host_name.buffer != NULL) {
			REDIS_FREESTR(redis->host_name.buffer);
		}
		if (redis->client_ip.buffer != NULL) {
			REDIS_FREESTR(redis->client_ip.buffer);
		}
		if (redis->link_time.buffer != NULL) {
			REDIS_FREESTR(redis->link_time.buffer);
		}
		if (redis->auth.buffer != NULL) {
			REDIS_FREESTR(redis->auth.buffer);
		}
		if (redis->executable.buffer != NULL) {
			REDIS_FREESTR(redis->executable.buffer);
		}
		if (redis->config_file.buffer != NULL) {
			REDIS_FREESTR(redis->config_file.buffer);
		}

		SCFree(redis);
	}
	SCReturn;
}

/* 由应用层调用来获取状态进度 */
static int RedisGetAlstateProgress(void *tx, uint8_t direction)
{
	/* 直接返回，用完 tx 就释放提高性能 */
	return 1;

	RedisTransaction *redistx = (RedisTransaction *)tx;
	int retval = 0;

	/* 原生逻辑是进度完成再释放，性能低 */
	if (redistx->complete) {
		retval = 1;
	}	

	SCReturnInt(retval);
}

/* 获取 tx_data */
static AppLayerTxData *RedisGetTxData(void *vtx)
{
	RedisTransaction *tx = (RedisTransaction *)vtx;
	return &tx->tx_data;
}

/* 获取 state_data */
static AppLayerStateData *RedisGetStateData(void *vstate)
{
	RedisState *state = (RedisState *)vstate;
	return &state->state_data;
}

/* 迭代器 */
static AppLayerGetTxIterTuple RedisGetTxIterator(const uint8_t ipproto, const AppProto alproto,
	void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
	RedisState *dnp_state = (RedisState *)alstate;
	AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
	if (dnp_state) {
		RedisTransaction *tx_ptr;
		if (state->un.ptr == NULL) {
			tx_ptr = TAILQ_FIRST(&dnp_state->tx_list);
		} else {
			tx_ptr = (RedisTransaction *)state->un.ptr;
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
void RegisterRedisParsers(void)
{
	const char *proto_name = "redis";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_REDIS, proto_name);

	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_REDIS, 0, REDIS_MIN_FRAME_LEN, RedisProbingParserTsTc, RedisProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_TCP, REDIS_DEFAULT_PORT, ALPROTO_REDIS, 0, REDIS_MIN_FRAME_LEN, STREAM_TOSERVER, RedisProbingParserTsTc, RedisProbingParserTsTc);	
	}

	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
		SCLogConfig("Registering redis/tcp parsers.");
		
		RedisReload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(redis_conf.redis_enable , 0);
		SC_ATOMIC_SET(redis_conf.log_enable, 0);
		SC_ATOMIC_SET(redis_conf.redis_dport, atoi(REDIS_DEFAULT_PORT));
		SC_ATOMIC_SET(redis_conf.result, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Redis流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_REDIS, RedisStateAlloc, RedisStateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_REDIS, STREAM_TOSERVER, RedisParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_REDIS, STREAM_TOCLIENT, RedisParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_REDIS, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_REDIS, RedisGetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_REDIS, RedisGetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_REDIS, RedisStateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_REDIS, RedisGetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_REDIS, RedisGetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_REDIS, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_REDIS, RedisGetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_REDIS, RedisGetStateData);
	
	SCReturn;
}

