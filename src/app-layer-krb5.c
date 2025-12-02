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

#include "app-layer-krb5.h"

Krb5Conf krb5_conf;


/* 热加载函数 */
void Krb5Reload(void)
{
	/* 获取是否打开日志开关 */
	ConfNode *node = NULL;

	/* 插件开关 */
	node = NULL;
	node = ConfGetNode(KRB5_ENABLED_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(krb5_conf.krb5_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(krb5_conf.krb5_enable, 0);
	}

	/* 获取是否打开日志开关 */
	node = ConfGetNode(KRB5_LOG_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(krb5_conf.log_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(krb5_conf.log_enable, 0);
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
		1 Krb5Transaction *tx: Krb5 的私有结构

	返回：void
*/
static void print_krb5_event(Flow *f, Krb5Transaction *tx, uint16_t direction)
{
	/* 参数检查 */
	if (NULL == tx) {
		return;
	}

	char msg_buf[1024] = {0};
	Krb5Transaction *krb5_data = NULL;

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
	krb5_data = tx;

	/* 时间 2016/09/22 12:21:30 */
	get_local_time(krb5_data->time_buff);
	
	/* 打印 */
	snprintf(msg_buf, sizeof(msg_buf), "done=%u", \
			krb5_data->done \
			);

	/* 打印公共字段 */
	DEBUG_DLOG("-----8888888888----- date: %s, s_ip: %s, s_port: %u, d_ip: %s, d_port: %u, dir: %d, protocal: %s, msg_buf: %s", \
				krb5_data->time_buff,\
				src_ip, src_port,\
				dst_ip, dst_port,\
				krb5_data->is_request, krb5_data->proto,\
				msg_buf \
				);

	return;
}
#endif






/* Ts 和 Tc 是指 Request 和 Response 方向协议识别和异常判断，合并到一起了，以后需要时还要拆分成两个函数，因为请求包和响应包结构不同 */
static AppProto Krb5ProbingParserTsTc(Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
	if (NULL == input || 0 >= input_len) {
		return ALPROTO_UNKNOWN;
	}

	//const uint8_t *p_data = NULL;
	uint16_t p_len = 0;

	/* 如果没有打开则强制不再识别识别, 后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(krb5_conf.krb5_enable)) {
		return ALPROTO_UNKNOWN;
	}
	
	/* 负载和负载长度 */
	//p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if (p_len < KRB5_MIN_FRAME_LEN) {
		return ALPROTO_UNKNOWN;
	}

	return ALPROTO_KRB5;
}

/* 分配一个 krb5 状态对象，表示一个 krb5 TCP 会话 */
static void *Krb5StateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	Krb5State *krb5;

	krb5 = (Krb5State *)SCCalloc(1, sizeof(Krb5State));
	if (unlikely(krb5 == NULL)) {
		return NULL;
	}
	TAILQ_INIT(&krb5->tx_list);

	SCReturnPtr(krb5, "void");
}

/* 分配一个 krb5 transaction */
static Krb5Transaction *Krb5TxAlloc(Krb5State *krb5, bool request)
{
	Krb5Transaction *tx = SCCalloc(1, sizeof(Krb5Transaction));
	if (unlikely(tx == NULL)) {
		return NULL;
	}
	krb5->transaction_max++;
	krb5->curr = tx;
	tx->krb5 = krb5;
	tx->tx_num = krb5->transaction_max;
	tx->is_request = request;
	if (tx->is_request) {
		tx->tx_data.detect_flags_tc |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	} else {
		tx->tx_data.detect_flags_ts |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	}

	TAILQ_INSERT_TAIL(&krb5->tx_list, tx, next);

	return tx;
}

/* 解析 Udp 响应 包 */
static int Krb5ParseRespUdp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, Krb5Transaction *krb5_data)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	/* 只解析请求，不解析响应，响应中没有需要的信息 */

	return 1;
}

/* 解析 Udp 请求 包 */
static int Krb5ParseReqUdp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, Krb5Transaction *krb5_data)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_len = 0;
	
	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	p_data = input;
	p_len = input_len;

	/* 判断是 0x6A 0x82 还是 0x6A 0x82 特征数据包，POS 偏移不同 */
	if (1 == UDP_IS_AS_REQ10_6A82(p_data)) {
		pos += 19;
	}else if (1 == UDP_IS_AS_REQ10_6A81(p_data)) {
		pos += 17;
	}else {
		return 1;
	}

	/* 异常判断 */
	if ((pos + 3 >= p_len) 
		|| (2 != (p_data + pos)[0] - (p_data + pos)[2])
		|| (0x30 != (p_data + pos)[1])
		|| ((pos + 3 + (p_data + pos)[2]) >= p_len)) {
		return 1;
	}
	
	/* pos 跳过 padata */
	tmp_len = (p_data + pos)[2];
	pos += 3 + tmp_len;
	
	/* 异常判断 */
	if ((pos + 3 >= p_len)
		|| (0xa4 != (p_data + pos)[0])
		|| (0x81 != (p_data + pos)[1])
		|| ((pos + 3 + (p_data + pos)[2]) > p_len)) {
		return 1;
	}
	
	/* pos 跳过定常 Padding 和 kdc-options */
	pos += 3 + 8 + 4;

	/* 异常判断 */
	if ((pos + 15 >= p_len)
		|| (0xa1 != (p_data + pos)[0])
		|| ((pos + 2 + (p_data + pos)[1]) >= p_len)
		|| (0xa0 != (p_data + pos)[4] || 0x03 != (p_data + pos)[5] || 0x02 != (p_data + pos)[6] || 0x01 != (p_data + pos)[7])
		|| (0xa1 != (p_data + pos)[9])
		|| (2 != (p_data + pos)[10] - (p_data + pos)[12])
		|| (0x30 != (p_data + pos)[11])
		|| (0x1b != (p_data + pos)[13])
		|| (pos + 15 + (p_data + pos)[14] >= p_len)) {
		return 1;
	}
	
	/* 取出 cname-string 长度 */
	tmp_len = (p_data + pos)[14];
	
	/* pos 移动到 cname-string */
	pos += 15;
	
	/* 取出 cname-string */
	if (tmp_len >= KRB5_VALUE_LEN129) {
		memcpy((char *)(krb5_data->cname), (char *)(p_data + pos), KRB5_VALUE_LEN129 - 1);
	}else {
		memcpy((char *)(krb5_data->cname), (char *)(p_data + pos), tmp_len);
	}
	krb5_data->cname_key = 1;
	
	/* pos 跳过 cname-string */
	pos += tmp_len;
	
	/* 异常判断 */
	if ((pos + 4 >= p_len)
		|| (0xa2 != (p_data + pos)[0])
		|| (0x1b != (p_data + pos)[2])
		|| (2 != (p_data + pos)[1] - (p_data + pos)[3])
		|| (pos + 4 + (p_data + pos)[3] >= p_len)) {
		return 0;
	}
	
	/* 取出 realm 长度 */
	tmp_len = (p_data + pos)[3];
	
	/* pos 移动到 realm */
	pos += 4;
	
	/* 取出 realm */
	if (tmp_len >= KRB5_VALUE_LEN129) {
		memcpy((char *)(krb5_data->realm), (char *)(p_data + pos), KRB5_VALUE_LEN129 - 1);
	}else {
		memcpy((char *)(krb5_data->realm), (char *)(p_data + pos), tmp_len);
	}
	krb5_data->realm_key = 1;
	
	/* pos 跳过 realm */
	pos += tmp_len;	
	
	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa3 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 sname */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;
	
	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa5 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 till */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;	
	
	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa6 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 rtime */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;	

	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa7 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 nonce */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;	

	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa8 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 etype */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;

	/* 异常判断 */
	if ((pos + 15 >= p_len)
		|| (0xa9 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] > p_len)
		|| (0xa0 != (p_data + pos)[6] || 0x03 != (p_data + pos)[7] || 0x02 != (p_data + pos)[8] || 0x01 != (p_data + pos)[9])
		|| (0xa1 != (p_data + pos)[11])
		|| (2 != (p_data + pos)[12] - (p_data + pos)[14])
		|| (0x04 != (p_data + pos)[13])
		|| (pos + 15 + (p_data + pos)[14] > p_len)) {
		return 0;
	}
	
	/* 取出 addresses Name 长度 */
	tmp_len = (p_data + pos)[14];
	
	/* pos 移动到 Name */
	pos += 15;
	
	/* 取出 host */
	if (tmp_len >= KRB5_VALUE_LEN129) {
		memcpy((char *)(krb5_data->host), (char *)(p_data + pos), KRB5_VALUE_LEN129 - 1);
	}else {
		memcpy((char *)(krb5_data->host), (char *)(p_data + pos), tmp_len);
	}
	krb5_data->host_key = 1;	

	return 0;
}

/* 解析 Tcp 响应 包 */
static int Krb5ParseRespTcp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, Krb5Transaction *krb5_data)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	/* 只解析请求，不解析响应，响应中没有需要的信息 */

	return 1;
}

/* 解析 Tcp 请求 包 */
static int Krb5ParseReqTcp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, Krb5Transaction *krb5_data)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_len = 0;

	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	p_data = input;
	p_len = input_len;

	/* 判断是 0x6A 0x82 还是 0x6A 0x82 特征数据包，POS 偏移不同 */
	if (1 == TCP_IS_AS_REQ10_6A82(p_data)) {
		pos += 23;
	}else if (1 == TCP_IS_AS_REQ10_6A81(p_data)) {
		pos += 21;
	}else {
		return 1;
	}

	/* 异常判断 */
	if ((pos + 3 >= p_len) 
		|| (2 != (p_data + pos)[0] - (p_data + pos)[2])
		|| (0x30 != (p_data + pos)[1])
		|| ((pos + 3 + (p_data + pos)[2]) >= p_len)) {
		return 1;
	}
	
	/* pos 跳过 padata */
	tmp_len = (p_data + pos)[2];
	pos += 3 + tmp_len;
	
	/* 异常判断 */
	if ((pos + 3 >= p_len)
		|| (0xa4 != (p_data + pos)[0])
		|| (0x81 != (p_data + pos)[1])
		|| ((pos + 3 + (p_data + pos)[2]) > p_len)) {
		return 1;
	}
	
	/* pos 跳过定常 Padding 和 kdc-options */
	pos += 3 + 8 + 4;

	/* 异常判断 */
	if ((pos + 15 >= p_len)
		|| (0xa1 != (p_data + pos)[0])
		|| ((pos + 2 + (p_data + pos)[1]) >= p_len)
		|| (0xa0 != (p_data + pos)[4] || 0x03 != (p_data + pos)[5] || 0x02 != (p_data + pos)[6] || 0x01 != (p_data + pos)[7])
		|| (0xa1 != (p_data + pos)[9])
		|| (2 != (p_data + pos)[10] - (p_data + pos)[12])
		|| (0x30 != (p_data + pos)[11])
		|| (0x1b != (p_data + pos)[13])
		|| (pos + 15 + (p_data + pos)[14] >= p_len)) {
		return 1;
	}
	
	/* 取出 cname-string 长度 */
	tmp_len = (p_data + pos)[14];
	
	/* pos 移动到 cname-string */
	pos += 15;
	
	/* 取出 cname-string */
	if (tmp_len >= KRB5_VALUE_LEN129) {
		memcpy((char *)(krb5_data->cname), (char *)(p_data + pos), KRB5_VALUE_LEN129 - 1);
	}else {
		memcpy((char *)(krb5_data->cname), (char *)(p_data + pos), tmp_len);
	}
	krb5_data->cname_key = 1;
	
	/* pos 跳过 cname-string */
	pos += tmp_len;
	
	/* 异常判断 */
	if ((pos + 4 >= p_len)
		|| (0xa2 != (p_data + pos)[0])
		|| (0x1b != (p_data + pos)[2])
		|| (2 != (p_data + pos)[1] - (p_data + pos)[3])
		|| (pos + 4 + (p_data + pos)[3] >= p_len)) {
		return 0;
	}
	
	/* 取出 realm 长度 */
	tmp_len = (p_data + pos)[3];
	
	/* pos 移动到 realm */
	pos += 4;
	
	/* 取出 realm */
	if (tmp_len >= KRB5_VALUE_LEN129) {
		memcpy((char *)(krb5_data->realm), (char *)(p_data + pos), KRB5_VALUE_LEN129 - 1);
	}else {
		memcpy((char *)(krb5_data->realm), (char *)(p_data + pos), tmp_len);
	}
	krb5_data->realm_key = 1;
	
	/* pos 跳过 realm */
	pos += tmp_len;	
	
	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa3 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 sname */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;
	
	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa5 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 till */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;	
	
	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa6 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 rtime */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;	

	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa7 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 nonce */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;	

	/* 异常判断 */
	if ((pos + 2 >= p_len)
		|| (0xa8 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] >= p_len)) {
		return 0;
	}
	
	/* pos 跳过 etype */
	tmp_len = (p_data + pos)[1];
	pos += 2 + tmp_len;

	/* 异常判断 */
	if ((pos + 15 >= p_len)
		|| (0xa9 != (p_data + pos)[0])
		|| (pos + 2 + (p_data + pos)[1] > p_len)
		|| (0xa0 != (p_data + pos)[6] || 0x03 != (p_data + pos)[7] || 0x02 != (p_data + pos)[8] || 0x01 != (p_data + pos)[9])
		|| (0xa1 != (p_data + pos)[11])
		|| (2 != (p_data + pos)[12] - (p_data + pos)[14])
		|| (0x04 != (p_data + pos)[13])
		|| (pos + 15 + (p_data + pos)[14] > p_len)) {
		return 0;
	}
	
	/* 取出 addresses Name 长度 */
	tmp_len = (p_data + pos)[14];
	
	/* pos 移动到 Name */
	pos += 15;
	
	/* 取出 host */
	if (tmp_len >= KRB5_VALUE_LEN129) {
		memcpy((char *)(krb5_data->host), (char *)(p_data + pos), KRB5_VALUE_LEN129 - 1);
	}else {
		memcpy((char *)(krb5_data->host), (char *)(p_data + pos), tmp_len);
	}
	krb5_data->host_key = 1;	
	
	return 0;
}


/* 请求包 解析函数 */
static AppLayerResult Krb5ParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	Krb5Transaction *tx = NULL;
	//Krb5Transaction *ttx = NULL;

	Krb5State *krb5_state = NULL;
	Krb5Transaction *krb5_data = NULL;

	const uint8_t *input = NULL;
	uint32_t input_len = 0;

	int ret = 1;

	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(krb5_conf.krb5_enable)) {
		goto error;
	}

	/* 获取 state 和 input 和 input_len */
	krb5_state = (Krb5State *)state;
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
	if (KRB5_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = Krb5TxAlloc(krb5_state, true);
	krb5_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(krb5_data->proto, "tcp", 3);
	krb5_data->is_request = true;

#if 0
	/* 注意: 可能响应先来，因此请求也需要查一下有没有分配 tx, 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &krb5_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	krb5_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//krb5_state->transaction_max = 0;
		
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = Krb5TxAlloc(krb5_state, true);
		krb5_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(krb5_data->proto, "tcp", 3);
	}
	krb5_data->is_request = true;
#endif
/************************* 解析私有数据 start ************************/	
	if (IPPROTO_TCP == f->proto) {
		/* 解析请求或响应，带有再次纠错功能，即使丢包后方向被识别反，这里也能纠错 */
		if (f->sp > f->dp) {
			ret = Krb5ParseReqTcp(f, state, pstate, input, input_len, local_data, krb5_data);
		}else if (f->sp < f->dp) {
			ret = Krb5ParseRespTcp(f, state, pstate, input, input_len, local_data, krb5_data);
		}else {
			ret = 1;
		}	
	}else if (IPPROTO_UDP == f->proto) {
		/* 解析请求或响应，带有再次纠错功能，即使丢包后方向被识别反，这里也能纠错 */
		if (f->sp > f->dp) {
			ret = Krb5ParseReqUdp(f, state, pstate, input, input_len, local_data, krb5_data);
		}else if (f->sp < f->dp) {
			ret = Krb5ParseRespUdp(f, state, pstate, input, input_len, local_data, krb5_data);
		}else {
			ret = 1;
		}
	}

	if (0 != ret) {
		goto end;
	}

	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	krb5_data->done = 1;
	krb5_data->complete = 0;
	
/************************* 解析私有数据 end ************************/	


#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_krb5_event(f, krb5_data, STREAM_TOSERVER);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 响应包 解析函数 */
static AppLayerResult Krb5ParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	/* 有用信息都在请求包中，响应包不解析 */
	goto end;


	Krb5Transaction *tx = NULL;
	//Krb5Transaction *ttx = NULL;
	
	Krb5State *krb5_state = NULL;
	Krb5Transaction *krb5_data = NULL;
	
	const uint8_t *input = NULL;
	uint32_t input_len = 0;

	int ret = 1;	
	
	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(krb5_conf.krb5_enable)) {
		goto error;
	}
	
	/* 获取 state 和 input 和 input_len */
	krb5_state = (Krb5State *)state;
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
	if (KRB5_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = Krb5TxAlloc(krb5_state, false);
	krb5_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(krb5_data->proto, "tcp", 3);
	krb5_data->is_request = false;

#if 0
    /* 注意: 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &krb5_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	krb5_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//krb5_state->transaction_max = 0;
	
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = Krb5TxAlloc(krb5_state, false);
		krb5_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(krb5_data->proto, "tcp", 3);
	}
	krb5_data->is_request = false;
#endif	
	/************************* 解析私有数据 start ************************/	
	if (IPPROTO_TCP == f->proto) {
		/* 解析请求或响应，带有再次纠错功能，即使丢包后方向被识别反，这里也能纠错 */
		if (f->sp < f->dp) {
			ret = Krb5ParseReqTcp(f, state, pstate, input, input_len, local_data, krb5_data);
		}else if (f->sp > f->dp) {
			ret = Krb5ParseRespTcp(f, state, pstate, input, input_len, local_data, krb5_data);
		}else {
			ret = 1;
		}
	}else if (IPPROTO_UDP == f->proto) {
		/* 解析请求或响应，带有再次纠错功能，即使丢包后方向被识别反，这里也能纠错 */
		if (f->sp < f->dp) {
			ret = Krb5ParseReqUdp(f, state, pstate, input, input_len, local_data, krb5_data);
		}else if (f->sp > f->dp) {
			ret = Krb5ParseRespUdp(f, state, pstate, input, input_len, local_data, krb5_data);
		}else {
			ret = 1;
		}
	}

	if (0 != ret) {
		goto end;
	}

	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	krb5_data->done = 1;
	krb5_data->complete = 1;
		
	/************************* 解析私有数据 end ************************/ 	
	
	
#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_krb5_event(f, krb5_data, STREAM_TOCLIENT);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 获取 tx */
static void *Krb5GetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	Krb5State *krb5 = (Krb5State *)alstate;
	Krb5Transaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH(tx, &krb5->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

/* 获取 tx 计数 */
static uint64_t Krb5GetTxCnt(void *state)
{
	SCEnter();
	uint64_t count = ((uint64_t)((Krb5State *)state)->transaction_max);
	SCReturnUInt(count);
}

/* 释放一个 krb5 tx */
static void Krb5TxFree(Krb5Transaction *tx)
{
	SCEnter();

	AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

	if (tx->tx_data.de_state != NULL) {
		DetectEngineStateFree(tx->tx_data.de_state);
	}

	SCFree(tx);
	SCReturn;
}

/* 通过 ID 释放特定 krb5 状态上的一个事务 */
static void Krb5StateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	Krb5State *krb5 = state;
	Krb5Transaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &krb5->tx_list, next, ttx) {

		if (tx->tx_num != tx_num) {
			continue;
		}

		//最好不要使用这个 curr，这个就是容易段错误的根源
		if (tx == krb5->curr) {
			krb5->curr = NULL;
		}

		TAILQ_REMOVE(&krb5->tx_list, tx, next);
		Krb5TxFree(tx);
		break;
	}

	SCReturn;
}

/* 释放 krb5 state */
static void Krb5StateFree(void *state)
{
	SCEnter();
	Krb5State *krb5 = state;
	Krb5Transaction *tx;
	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&krb5->tx_list)) != NULL) {
			TAILQ_REMOVE(&krb5->tx_list, tx, next);
			Krb5TxFree(tx);
		}
		if (krb5->request_buffer.buffer != NULL) {
			SCFree(krb5->request_buffer.buffer);
		}
		if (krb5->response_buffer.buffer != NULL) {
			SCFree(krb5->response_buffer.buffer);
		}
		SCFree(krb5);
	}
	SCReturn;
}

/* 由应用层调用来获取状态进度 */
static int Krb5GetAlstateProgress(void *tx, uint8_t direction)
{
	/* 直接返回，用完 tx 就释放提高性能 */
	return 1;

	Krb5Transaction *krb5tx = (Krb5Transaction *)tx;
	int retval = 0;

	/* 原生逻辑是进度完成再释放，性能低 */
	if (krb5tx->complete) {
		retval = 1;
	}	

	SCReturnInt(retval);
}

/* 获取 tx_data */
static AppLayerTxData *Krb5GetTxData(void *vtx)
{
	Krb5Transaction *tx = (Krb5Transaction *)vtx;
	return &tx->tx_data;
}

/* 获取 state_data */
static AppLayerStateData *Krb5GetStateData(void *vstate)
{
	Krb5State *state = (Krb5State *)vstate;
	return &state->state_data;
}

/* 迭代器 */
static AppLayerGetTxIterTuple Krb5GetTxIterator(const uint8_t ipproto, const AppProto alproto,
	void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
	Krb5State *dnp_state = (Krb5State *)alstate;
	AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
	if (dnp_state) {
		Krb5Transaction *tx_ptr;
		if (state->un.ptr == NULL) {
			tx_ptr = TAILQ_FIRST(&dnp_state->tx_list);
		} else {
			tx_ptr = (Krb5Transaction *)state->un.ptr;
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

/* 核心注册函数 TCP */
void RegisterKrb5ParsersTcp(void)
{
	const char *proto_name = "krb5";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_KRB5, proto_name);

	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_KRB5, 0, KRB5_MIN_FRAME_LEN, Krb5ProbingParserTsTc, Krb5ProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_TCP, KRB5_DEFAULT_PORT_TCP, ALPROTO_KRB5, 0, KRB5_MIN_FRAME_LEN, STREAM_TOSERVER, Krb5ProbingParserTsTc, Krb5ProbingParserTsTc);	
	}

	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
		SCLogConfig("Registering krb5/tcp parsers.");
		
		Krb5Reload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(krb5_conf.krb5_enable , 0);
		SC_ATOMIC_SET(krb5_conf.log_enable, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Krb5流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_KRB5, Krb5StateAlloc, Krb5StateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_KRB5, STREAM_TOSERVER, Krb5ParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_KRB5, STREAM_TOCLIENT, Krb5ParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_KRB5, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_KRB5, Krb5GetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_KRB5, Krb5GetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_KRB5, Krb5StateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_KRB5, Krb5GetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_KRB5, Krb5GetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_KRB5, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_KRB5, Krb5GetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_KRB5, Krb5GetStateData);
	
	SCReturn;
}

/* 核心注册函数 UDP */
void RegisterKrb5ParsersUdp(void)
{
	const char *proto_name = "krb5";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_KRB5, proto_name);

	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP, proto_name, ALPROTO_KRB5, 0, KRB5_MIN_FRAME_LEN, Krb5ProbingParserTsTc, Krb5ProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_UDP, KRB5_DEFAULT_PORT_UDP, ALPROTO_KRB5, 0, KRB5_MIN_FRAME_LEN, STREAM_TOSERVER, Krb5ProbingParserTsTc, Krb5ProbingParserTsTc);	
	}

	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("udp", proto_name)) {
		SCLogConfig("Registering krb5/udp parsers.");
		
		Krb5Reload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(krb5_conf.krb5_enable , 0);
		SC_ATOMIC_SET(krb5_conf.log_enable, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Krb5流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_KRB5, Krb5StateAlloc, Krb5StateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_KRB5, STREAM_TOSERVER, Krb5ParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_KRB5, STREAM_TOCLIENT, Krb5ParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_UDP, ALPROTO_KRB5, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_KRB5, Krb5GetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_KRB5, Krb5GetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_KRB5, Krb5StateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_UDP, ALPROTO_KRB5, Krb5GetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_UDP, ALPROTO_KRB5, Krb5GetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_KRB5, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_KRB5, Krb5GetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_UDP, ALPROTO_KRB5, Krb5GetStateData);
	
	SCReturn;
}
