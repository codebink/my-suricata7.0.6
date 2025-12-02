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

#include "app-layer-radius.h"

RadiusConf radius_conf;


/* 热加载函数 */
void RadiusReload(void)
{
	/* 获取是否打开日志开关 */
	ConfNode *node = NULL;

	/* 插件开关 */
	node = NULL;
	node = ConfGetNode(RADIUS_ENABLED_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(radius_conf.radius_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(radius_conf.radius_enable, 0);
	}

	/* 获取是否打开日志开关 */
	node = ConfGetNode(RADIUS_LOG_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(radius_conf.log_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(radius_conf.log_enable, 0);
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
		1 RadiusTransaction *tx: Radius 的私有结构

	返回：void
*/
static void print_radius_event(Flow *f, RadiusTransaction *tx, uint16_t direction)
{
	/* 参数检查 */
	if (NULL == tx) {
		return;
	}

	char msg_buf[1024] = {0};
	RadiusTransaction *radius_data = NULL;

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
	radius_data = tx;

	/* 时间 2016/09/22 12:21:30 */
	get_local_time(radius_data->time_buff);
	
	/* 打印 */
	snprintf(msg_buf, sizeof(msg_buf), "done=%u", \
			radius_data->done \
			);

	/* 打印公共字段 */
	DEBUG_DLOG("-----8888888888----- date: %s, s_ip: %s, s_port: %u, d_ip: %s, d_port: %u, dir: %d, protocal: %s, msg_buf: %s", \
				radius_data->time_buff,\
				src_ip, src_port,\
				dst_ip, dst_port,\
				radius_data->is_request, radius_data->proto,\
				msg_buf \
				);

	return;
}
#endif






/* Ts 和 Tc 是指 Request 和 Response 方向协议识别和异常判断，合并到一起了，以后需要时还要拆分成两个函数，因为请求包和响应包结构不同 */
static AppProto RadiusProbingParserTsTc(Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
	if (NULL == input || 0 >= input_len) {
		return ALPROTO_UNKNOWN;
	}

	//const uint8_t *p_data = NULL;
	uint16_t p_len = 0;

	/* 如果没有打开则强制不再识别识别, 后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(radius_conf.radius_enable)) {
		return ALPROTO_UNKNOWN;
	}
	
	/* 负载和负载长度 */
	//p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if (p_len < RADIUS_MIN_FRAME_LEN) {
		return ALPROTO_UNKNOWN;
	}

	return ALPROTO_RADIUS;
}

/* 分配一个 radius 状态对象，表示一个 radius UDP 会话 */
static void *RadiusStateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	RadiusState *radius;

	radius = (RadiusState *)SCCalloc(1, sizeof(RadiusState));
	if (unlikely(radius == NULL)) {
		return NULL;
	}
	TAILQ_INIT(&radius->tx_list);

	SCReturnPtr(radius, "void");
}

/* 分配一个 radius transaction */
static RadiusTransaction *RadiusTxAlloc(RadiusState *radius, bool request)
{
	RadiusTransaction *tx = SCCalloc(1, sizeof(RadiusTransaction));
	if (unlikely(tx == NULL)) {
		return NULL;
	}
	radius->transaction_max++;
	radius->curr = tx;
	tx->radius = radius;
	tx->tx_num = radius->transaction_max;
	tx->is_request = request;
	if (tx->is_request) {
		tx->tx_data.detect_flags_tc |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	} else {
		tx->tx_data.detect_flags_ts |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	}

	TAILQ_INSERT_TAIL(&radius->tx_list, tx, next);

	return tx;
}

static int radius_gbk_to_utf8(char *gbk, u_int32_t gbken, char *utf8, int *len) {
	if (gbk == NULL || gbken <= 0 || utf8 == NULL) {
		return 1;
	}

	char *inbuf = (char*)gbk;
	size_t inlen = gbken;
	char *outbuf = utf8;
	size_t outlen = gbken * 3;
	
	iconv_t cd = iconv_open("UTF-8", "GBK");
	if (cd == (iconv_t)-1) {
		return 1;
	}

	int rc = iconv(cd, &inbuf, &inlen, &outbuf, &outlen);
	if (rc == -1 || inlen > 0) {
		iconv_close(cd);
		return 1;
	}
	
	iconv_close(cd);
	*len = strlen(utf8);
	
	return 0;
}

static char radius_hex_to_char(unsigned char ch)
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


static int radius_hex_to_str(unsigned char *src, int src_len, char *dst, int *dst_len)
{
	if (NULL == src || 0 >= src_len || NULL == dst || NULL == dst_len) {
		return 1;
	}

	int i = 0;
	int j = 0;
	char t_chr = '0';
	
	unsigned char src_char = 0x00;
	unsigned char tmp_char = 0x00;
	
	for (i = 0; i < src_len; i++) {
		/* 高 4 bit 转换 */	
		//src_char = 0x00;
		src_char = src[i];
		//tmp_char = 0x00;
		tmp_char = (src_char & 0xf0) >> 4;
		
		/* 获取高位转换的字符 */
		//t_chr = '0';
		t_chr = radius_hex_to_char(tmp_char);
		dst[j] = t_chr;

		/* 低 4 bit 转换 */
		//src_char = 0x00;
		src_char = src[i];
		//tmp_char = 0x00;
		tmp_char = (src_char & 0x0f);
		
		/* 获取低位转换的字符 */
		//t_chr = '0';
		t_chr = radius_hex_to_char(tmp_char);
		dst[j+1] = t_chr;

		j += 2;
	}

	*dst_len = j;
	
	return 0;
}

static int radius_get_calling_mac(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RadiusTransaction *radius_data, u_int32_t pos)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len || NULL == radius_data) {
		return 1;
	}
	
	u_int32_t tmp_pos = 0;
	u_int32_t value_len = 0;
	u_int32_t tmp_len = 0;
	int calling_mac_len = 0;
	const unsigned char *p_data = NULL;
	uint32_t p_len = 0;

	unsigned char calling_station_mac_gbk[RADIUS_CALL_MAC_GBK_LEN] = {0};
	char calling_station_mac[RADIUS_CALL_MAC_LEN] = {0};	

	/* 取出 value len */
	p_data = input;
	p_len = input_len;

	tmp_pos = pos + 1;
	value_len = RADIUS_GET_LEN_HOST8(p_data + tmp_pos) - 2;
	tmp_pos += 1;
	
	/* 长度检查 */
	if (tmp_pos + value_len > p_len) {
		return 1;
	}
	
	/* 提取 GBK 格式 user name */
	if (value_len >= RADIUS_CALL_MAC_GBK_LEN) {
		memcpy(calling_station_mac_gbk, (p_data + tmp_pos), (RADIUS_CALL_MAC_GBK_LEN - 1));
		tmp_len = (RADIUS_CALL_MAC_GBK_LEN - 1);
	}else {
		memcpy(calling_station_mac_gbk, (p_data + tmp_pos), value_len);
		tmp_len = value_len;
	}

	/* gbk 转 utf-8 */
	radius_gbk_to_utf8((char *)calling_station_mac_gbk, tmp_len, calling_station_mac, &calling_mac_len);
	if (0 >= strlen(calling_station_mac) || 0 >= calling_mac_len) {
		return 1;
	}
	
	/* 保存 called mac */
	memcpy(radius_data->calling_station_mac, calling_station_mac, calling_mac_len);
	radius_data->calling_station_mac_key = 1;
	
	return 0;
}


static int radius_get_called_mac(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RadiusTransaction *radius_data, u_int32_t pos)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len || NULL == radius_data) {
		return 1;
	}
	
	u_int32_t tmp_pos = 0;
	u_int32_t value_len = 0;
	u_int32_t tmp_len = 0;
	int called_mac_len = 0;
	const unsigned char *p_data = NULL;
	uint32_t p_len = 0;

	unsigned char called_station_mac_gbk[RADIUS_CALL_MAC_GBK_LEN] = {0};
	char called_station_mac[RADIUS_CALL_MAC_LEN] = {0};	

	/* 取出 value len */
	p_data = input;
	p_len = input_len;

	tmp_pos = pos + 1;
	value_len = RADIUS_GET_LEN_HOST8(p_data + tmp_pos) - 2;
	tmp_pos += 1;
	
	/* 长度检查 */
	if (tmp_pos + value_len > p_len) {
		return 1;
	}
	
	/* 提取 GBK 格式 user name */
	if (value_len >= RADIUS_CALL_MAC_GBK_LEN) {
		memcpy(called_station_mac_gbk, (p_data + tmp_pos), (RADIUS_CALL_MAC_GBK_LEN - 1));
		tmp_len = (RADIUS_CALL_MAC_GBK_LEN - 1);
	}else {
		memcpy(called_station_mac_gbk, (p_data + tmp_pos), value_len);
		tmp_len = value_len;
	}

	/* gbk 转 utf-8 */
	radius_gbk_to_utf8((char *)called_station_mac_gbk, tmp_len, called_station_mac, &called_mac_len);
	if (0 >= strlen(called_station_mac) || 0 >= called_mac_len) {
		return 1;
	}
	
	/* 保存 called mac */
	memcpy(radius_data->called_station_mac, called_station_mac, called_mac_len);
	radius_data->called_station_mac_key = 1;
	
	return 0;
}


static int radius_get_nas_port(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RadiusTransaction *radius_data, u_int32_t pos)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len || NULL == radius_data) {
		return 1;
	}

	u_int32_t tmp_pos = 0;
	u_int32_t value_len = 0;
	u_int32_t u_nas_port = 0;

	const unsigned char *p_data = NULL;
	uint32_t p_len = 0;

	/* 取出 value len */
	p_data = input;
	p_len = input_len;

	tmp_pos = pos + 1;
	value_len = RADIUS_GET_LEN_HOST8(p_data + tmp_pos) - 2;
	tmp_pos += 1;
	
	/* 长度检查 */
	if (tmp_pos + value_len > p_len) {
		return 1;
	}
	
	/* 提取 NAS port uint 类型数据 */
	u_nas_port = RADIUS_GET_VALUE_NET32(p_data + tmp_pos);

	/* 保存 NAS port */
	radius_data->nas_port = (int)(ntohl(u_nas_port));
	radius_data->nas_port_key = 1;
	
	return 0;
}


static int radius_get_nas_ip(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RadiusTransaction *radius_data, u_int32_t pos)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len || NULL == radius_data) {
		return 1;
	}
	
	u_int32_t tmp_pos = 0;
	u_int32_t value_len = 0;
	
	struct in_addr addr;
	const unsigned char *p_data = NULL;
	uint32_t p_len = 0;

	/* 取出 value len */
	p_data = input;
	p_len = input_len;

	tmp_pos = pos + 1;
	value_len = RADIUS_GET_LEN_HOST8(p_data + tmp_pos) - 2;
	tmp_pos += 1;
	
	/* 长度检查 */
	if (tmp_pos + value_len > p_len) {
		return 1;
	}
	
	/* 提取 NAS ip uint 类型数据 */
	addr.s_addr = RADIUS_GET_VALUE_NET32(p_data + tmp_pos);

	/* 保存 NAS ip */
	memcpy(radius_data->nas_ip, inet_ntoa(addr), (size_t)(strlen(inet_ntoa(addr))));
	radius_data->nas_ip_key = 1;
	
	return 0;
}


static int radius_get_passwd(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RadiusTransaction *radius_data, u_int32_t pos)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len || NULL == radius_data) {
		return 1;
	}
	
	u_int32_t tmp_pos = 0;
	u_int32_t value_len = 0;
	u_int32_t cpy_len = 0;
	int dst_len = 0;
	const unsigned char *p_data = NULL;
	uint32_t p_len = 0;

	unsigned char radius_passwd_tmp[RADIUS_PASSWD_UCHAR_LEN] = {0};
	char radius_passwd[RADIUS_PASSWD_STRING_LEN] = {0};

	/* 取出 value len */
	p_data = input;
	p_len = input_len;

	tmp_pos = pos + 1;
	value_len = RADIUS_GET_LEN_HOST8(p_data + tmp_pos) - 2;
	tmp_pos += 1;
	
	/* 长度检查 */
	if (tmp_pos + value_len > p_len) {
		return 1;
	}
	
	/* 提取 passwd */
	if (value_len >= RADIUS_PASSWD_UCHAR_LEN) {
		memcpy(radius_passwd_tmp, (p_data + tmp_pos), (RADIUS_PASSWD_UCHAR_LEN - 1));
		cpy_len = (RADIUS_PASSWD_UCHAR_LEN - 1);
	}else {
		memcpy(radius_passwd_tmp, (p_data + tmp_pos), value_len);
		cpy_len = value_len;
	}

	/* hex to string */
	radius_hex_to_str(radius_passwd_tmp, (int)cpy_len, radius_passwd, &dst_len);
	
	
	/* 保存 user passwd */
	memcpy(radius_data->radius_passwd, radius_passwd, dst_len);
	radius_data->radius_passwd_key = 1;
	
	return 0;
}


static int radius_get_name(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RadiusTransaction *radius_data, u_int32_t pos)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len || NULL == radius_data) {
		return 1;
	}
	
	u_int32_t tmp_pos = 0;
	u_int32_t value_len = 0;
	u_int32_t tmp_len = 0;
	int user_name_len = 0;
	const unsigned char *p_data = NULL;
	uint32_t p_len = 0;

	unsigned char user_name_gbk[RADIUS_USER_NAME_GBK_LEN] = {0};
	char user_name[RADIUS_USER_NAME_LEN] = {0};	

	/* 取出 value len */
	p_data = input;
	p_len = input_len;
	
	tmp_pos = pos + 1;
	value_len = RADIUS_GET_LEN_HOST8(p_data + tmp_pos) - 2;
	tmp_pos += 1;
	
	/* 长度检查 */
	if (tmp_pos + value_len > p_len) {
		return 1;
	}
	
	/* 提取 GBK 格式 user name */
	if (value_len >= RADIUS_USER_NAME_GBK_LEN) {
		memcpy(user_name_gbk, (p_data + tmp_pos), (RADIUS_USER_NAME_GBK_LEN - 1));
		tmp_len = (RADIUS_USER_NAME_GBK_LEN - 1);
	}else {
		memcpy(user_name_gbk, (p_data + tmp_pos), value_len);
		tmp_len = value_len;
	}

	/* gbk 转 utf-8 */
	radius_gbk_to_utf8((char *)user_name_gbk, tmp_len, user_name, &user_name_len);
	if (0 >= strlen(user_name) || 0 >= user_name_len) {
		return 1;
	}

	/* 保存 user name */
	memcpy(radius_data->user_name, user_name, strlen(user_name));
	radius_data->user_name_key = 1;
	
	return 0;
}


static int radius_access_request(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, RadiusTransaction *radius_data)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len || NULL == radius_data) {
		return 1;
	}

	u_int32_t pos = 0;
	u_int32_t tmp_pos = 0;
	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;

	int ret = 1;
	int send_key = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	p_data = input;
	p_len = input_len;

	/* 跳过 code + Packet identifier + Length + Authenticator */
	pos += 1 + 1 + 2 + 16;

	/* 解析属性链 */
	while (pos + 1 < p_len) {
		unsigned char type = (p_data + pos)[0];
 
		switch(type) {
			case RADIUS_NAME_TYPE :
				/* 获取 user name */
				ret = radius_get_name(f, statev, pstate, input, input_len, local_data, radius_data, pos);
				if (0 == ret) {
					send_key = 1;
				}
			break;
			
			case RADIUS_USER_PASSWD_TYPE :
				/* 获取 user passwd*/
				ret = radius_get_passwd(f, statev, pstate, input, input_len, local_data, radius_data, pos);
				if (0 == ret) {
					send_key = 1;
				}

			break;

			case RADIUS_CHAP_PASSWD_TYPE :
				/* 获取 chap passwd*/
				ret = radius_get_passwd(f, statev, pstate, input, input_len, local_data, radius_data, pos);
				if (0 == ret) {
					send_key = 1;
				}

			break;
			
			case RADIUS_NAS_IP_TYPE :
				/* 获取 NAS IP */
				ret = radius_get_nas_ip(f, statev, pstate, input, input_len, local_data, radius_data, pos);
				if (0 == ret) {
					send_key = 1;
				}

			break;

			case RADIUS_NAS_PORT_TYPE :
				/* 获取 NAS PORT */
				ret = radius_get_nas_port(f, statev, pstate, input, input_len, local_data, radius_data, pos);
				if (0 == ret) {
					send_key = 1;
				}

			break;

			case RADIUS_CALLED_TYPE :
				/* 获取 CALLED MAC */
				ret = radius_get_called_mac(f, statev, pstate, input, input_len, local_data, radius_data, pos);
				if (0 == ret) {
					send_key = 1;
				}

			break;
			
			case RADIUS_CALLING_TYPE :
				/* 获取 CALLING MAC */
				ret = radius_get_calling_mac(f, statev, pstate, input, input_len, local_data, radius_data, pos);
				if (0 == ret) {
					send_key = 1;
				}

			break;

			default :
				/* 其他不关注类型 */
			break;
		}
	
		/* 累加 pos 跳过 type + length + value*/
		tmp_pos = pos;
		pos += 1 + 1 + RADIUS_GET_LEN_HOST8(p_data + tmp_pos + 1) - 2;
	}

	if (1 == send_key) {
		ret = 0;
	}else {
		ret = 1;
	}
	
	return ret;	
}


/* 请求包 解析函数 */
static AppLayerResult RadiusParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	RadiusTransaction *tx = NULL;
	//RadiusTransaction *ttx = NULL;

	RadiusState *radius_state = NULL;
	RadiusTransaction *radius_data = NULL;

	const uint8_t *input = NULL;
	uint32_t input_len = 0;

	int ret = 0;

	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(radius_conf.radius_enable)) {
		goto error;
	}

	/* 获取 state 和 input 和 input_len */
	radius_state = (RadiusState *)state;
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
	if (RADIUS_MIN_FRAME_LEN > input_len || 1 != IS_RADIUS_ACCESS_REQUEST(input)) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = RadiusTxAlloc(radius_state, true);
	radius_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(radius_data->proto, "udp", 3);
	radius_data->is_request = true;

#if 0
	/* 注意: 可能响应先来，因此请求也需要查一下有没有分配 tx, 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &radius_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	radius_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//radius_state->transaction_max = 0;
		
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = RadiusTxAlloc(radius_state, true);
		radius_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(radius_data->proto, "udp", 3);
	}
	radius_data->is_request = true;
#endif
/************************* 解析私有数据 start ************************/	
	ret = radius_access_request(f, state, pstate, input, input_len, local_data, radius_data);
	if (0 != ret) {
		goto end;
	}

	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	radius_data->done = 1;
	radius_data->complete = 0;
	
/************************* 解析私有数据 end ************************/	


#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_radius_event(f, radius_data, STREAM_TOSERVER);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 响应包 解析函数 */
static AppLayerResult RadiusParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	/* 有用信息都在请求包中，响应包不解析 */
	goto end;

	RadiusTransaction *tx = NULL;
	//RadiusTransaction *ttx = NULL;
	
	RadiusState *radius_state = NULL;
	RadiusTransaction *radius_data = NULL;
	
	const uint8_t *input = NULL;
	uint32_t input_len = 0;
	
	
	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(radius_conf.radius_enable)) {
		goto error;
	}
	
	/* 获取 state 和 input 和 input_len */
	radius_state = (RadiusState *)state;
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
	if (RADIUS_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = RadiusTxAlloc(radius_state, false);
	radius_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(radius_data->proto, "udp", 3);
	radius_data->is_request = false;

#if 0
    /* 注意: 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &radius_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	radius_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//radius_state->transaction_max = 0;
	
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = RadiusTxAlloc(radius_state, false);
		radius_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(radius_data->proto, "udp", 3);
	}
	radius_data->is_request = false;
#endif	
	/************************* 解析私有数据 start ************************/	
	/* 请求和响应公用一个 tx, 因此响应要清理请求的 tx */


	
	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	radius_data->done = 1;
	radius_data->complete = 1;
		
	/************************* 解析私有数据 end ************************/ 	
	
	
#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_radius_event(f, radius_data, STREAM_TOCLIENT);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 获取 tx */
static void *RadiusGetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	RadiusState *radius = (RadiusState *)alstate;
	RadiusTransaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH(tx, &radius->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

/* 获取 tx 计数 */
static uint64_t RadiusGetTxCnt(void *state)
{
	SCEnter();
	uint64_t count = ((uint64_t)((RadiusState *)state)->transaction_max);
	SCReturnUInt(count);
}

/* 释放一个 radius tx */
static void RadiusTxFree(RadiusTransaction *tx)
{
	SCEnter();

	AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

	if (tx->tx_data.de_state != NULL) {
		DetectEngineStateFree(tx->tx_data.de_state);
	}

	SCFree(tx);
	SCReturn;
}

/* 通过 ID 释放特定 radius 状态上的一个事务 */
static void RadiusStateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	RadiusState *radius = state;
	RadiusTransaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &radius->tx_list, next, ttx) {

		if (tx->tx_num != tx_num) {
			continue;
		}

		//最好不要使用这个 curr，这个就是容易段错误的根源
		if (tx == radius->curr) {
			radius->curr = NULL;
		}

		TAILQ_REMOVE(&radius->tx_list, tx, next);
		RadiusTxFree(tx);
		break;
	}

	SCReturn;
}

/* 释放 radius state */
static void RadiusStateFree(void *state)
{
	SCEnter();
	RadiusState *radius = state;
	RadiusTransaction *tx;
	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&radius->tx_list)) != NULL) {
			TAILQ_REMOVE(&radius->tx_list, tx, next);
			RadiusTxFree(tx);
		}
		if (radius->request_buffer.buffer != NULL) {
			SCFree(radius->request_buffer.buffer);
		}
		if (radius->response_buffer.buffer != NULL) {
			SCFree(radius->response_buffer.buffer);
		}
		SCFree(radius);
	}
	SCReturn;
}

/* 由应用层调用来获取状态进度 */
static int RadiusGetAlstateProgress(void *tx, uint8_t direction)
{
	/* 直接返回，用完 tx 就释放提高性能 */
	return 1;

	RadiusTransaction *radiustx = (RadiusTransaction *)tx;
	int retval = 0;

	/* 原生逻辑是进度完成再释放，性能低 */
	if (radiustx->complete) {
		retval = 1;
	}	

	SCReturnInt(retval);
}

/* 获取 tx_data */
static AppLayerTxData *RadiusGetTxData(void *vtx)
{
	RadiusTransaction *tx = (RadiusTransaction *)vtx;
	return &tx->tx_data;
}

/* 获取 state_data */
static AppLayerStateData *RadiusGetStateData(void *vstate)
{
	RadiusState *state = (RadiusState *)vstate;
	return &state->state_data;
}

/* 迭代器 */
static AppLayerGetTxIterTuple RadiusGetTxIterator(const uint8_t ipproto, const AppProto alproto,
	void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
	RadiusState *dnp_state = (RadiusState *)alstate;
	AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
	if (dnp_state) {
		RadiusTransaction *tx_ptr;
		if (state->un.ptr == NULL) {
			tx_ptr = TAILQ_FIRST(&dnp_state->tx_list);
		} else {
			tx_ptr = (RadiusTransaction *)state->un.ptr;
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
void RegisterRadiusParsers(void)
{
	const char *proto_name = "radius";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_RADIUS, proto_name);

	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP, proto_name, ALPROTO_RADIUS, 0, RADIUS_MIN_FRAME_LEN, RadiusProbingParserTsTc, RadiusProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_UDP, RADIUS_DEFAULT_PORT, ALPROTO_RADIUS, 0, RADIUS_MIN_FRAME_LEN, STREAM_TOSERVER, RadiusProbingParserTsTc, RadiusProbingParserTsTc);	
	}

	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("udp", proto_name)) {
		SCLogConfig("Registering radius/udp parsers.");
		
		RadiusReload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(radius_conf.radius_enable , 0);
		SC_ATOMIC_SET(radius_conf.log_enable, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Radius流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_RADIUS, RadiusStateAlloc, RadiusStateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_RADIUS, STREAM_TOSERVER, RadiusParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_RADIUS, STREAM_TOCLIENT, RadiusParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_UDP, ALPROTO_RADIUS, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_RADIUS, RadiusGetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_RADIUS, RadiusGetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_RADIUS, RadiusStateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_UDP, ALPROTO_RADIUS, RadiusGetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_UDP, ALPROTO_RADIUS, RadiusGetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_RADIUS, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_RADIUS, RadiusGetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_UDP, ALPROTO_RADIUS, RadiusGetStateData);
	
	SCReturn;
}

