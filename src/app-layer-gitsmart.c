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

#include "app-layer-gitsmart.h"

GitsmartConf gitsmart_conf;


/* 热加载函数 */
void GitsmartReload(void)
{
	/* 获取是否打开日志开关 */
	ConfNode *node = NULL;

	/* 插件开关 */
	node = NULL;
	node = ConfGetNode(GITSMART_ENABLED_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(gitsmart_conf.gitsmart_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(gitsmart_conf.gitsmart_enable, 0);
	}

	/* 获取是否打开日志开关 */
	node = ConfGetNode(GITSMART_LOG_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(gitsmart_conf.log_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(gitsmart_conf.log_enable, 0);
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
		1 GitsmartTransaction *tx: Gitsmart 的私有结构

	返回：void
*/
static void print_gitsmart_event(Flow *f, GitsmartTransaction *tx, uint16_t direction)
{
	/* 参数检查 */
	if (NULL == tx) {
		return;
	}

	char msg_buf[1024] = {0};
	GitsmartTransaction *gitsmart_data = NULL;

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
	gitsmart_data = tx;

	/* 时间 2016/09/22 12:21:30 */
	get_local_time(gitsmart_data->time_buff);
	
	/* 打印 */
	snprintf(msg_buf, sizeof(msg_buf), "done=%u", \
			gitsmart_data->done \
			);

	/* 打印公共字段 */
	DEBUG_DLOG("-----8888888888----- date: %s, s_ip: %s, s_port: %u, d_ip: %s, d_port: %u, dir: %d, protocal: %s, msg_buf: %s", \
				gitsmart_data->time_buff,\
				src_ip, src_port,\
				dst_ip, dst_port,\
				gitsmart_data->is_request, gitsmart_data->proto,\
				msg_buf \
				);

	return;
}
#endif






/* Ts 和 Tc 是指 Request 和 Response 方向协议识别和异常判断，合并到一起了，以后需要时还要拆分成两个函数，因为请求包和响应包结构不同 */
static AppProto GitsmartProbingParserTsTc(Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
	if (NULL == input || 0 >= input_len) {
		return ALPROTO_UNKNOWN;
	}

	//const uint8_t *p_data = NULL;
	uint16_t p_len = 0;

	/* 如果没有打开则强制不再识别识别, 后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(gitsmart_conf.gitsmart_enable)) {
		return ALPROTO_UNKNOWN;
	}
	
	/* 负载和负载长度 */
	//p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if (p_len < GITSMART_MIN_FRAME_LEN) {
		return ALPROTO_UNKNOWN;
	}

	return ALPROTO_GITSMART;
}

/* 分配一个 gitsmart 状态对象，表示一个 gitsmart TCP 会话 */
static void *GitsmartStateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	GitsmartState *gitsmart;

	gitsmart = (GitsmartState *)SCCalloc(1, sizeof(GitsmartState));
	if (unlikely(gitsmart == NULL)) {
		return NULL;
	}
	TAILQ_INIT(&gitsmart->tx_list);

	SCReturnPtr(gitsmart, "void");
}

/* 分配一个 gitsmart transaction */
static GitsmartTransaction *GitsmartTxAlloc(GitsmartState *gitsmart, bool request)
{
	GitsmartTransaction *tx = SCCalloc(1, sizeof(GitsmartTransaction));
	if (unlikely(tx == NULL)) {
		return NULL;
	}
	gitsmart->transaction_max++;
	gitsmart->curr = tx;
	tx->gitsmart = gitsmart;
	tx->tx_num = gitsmart->transaction_max;
	tx->is_request = request;
	if (tx->is_request) {
		tx->tx_data.detect_flags_tc |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	} else {
		tx->tx_data.detect_flags_ts |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	}

	TAILQ_INSERT_TAIL(&gitsmart->tx_list, tx, next);

	return tx;
}

/* 请求包 解析函数 */
static AppLayerResult GitsmartParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		SCReturnStruct(APP_LAYER_ERROR);
	}

	GitsmartTransaction *tx = NULL;
	//GitsmartTransaction *ttx = NULL;

	GitsmartState *gitsmart_state = NULL;
	GitsmartTransaction *gitsmart_data = NULL;

	const uint8_t *input = NULL;
	uint32_t input_len = 0;


	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(gitsmart_conf.gitsmart_enable)) {
		SCReturnStruct(APP_LAYER_ERROR);
	}

	/* 获取 state 和 input 和 input_len */
	gitsmart_state = (GitsmartState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);

	/* 异常判断 */
	if (NULL == input) {
		if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) {
			/* 这是一个流结束的信号，如果需要，做任何清理工作，这里通常不需要什么 */
			SCReturnStruct(APP_LAYER_OK);
		}

		SCReturnStruct(APP_LAYER_ERROR);
	}

	/* 异常判断 */
	if (1 > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 异常判断 */
	if (GITSMART_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = GitsmartTxAlloc(gitsmart_state, true);
	gitsmart_data = tx;
	if (unlikely(tx == NULL)) {
		SCReturnStruct(APP_LAYER_ERROR);
	}
	memcpy(gitsmart_data->proto, "tcp", 3);
	gitsmart_data->is_request = true;

#if 0
	/* 注意: 可能响应先来，因此请求也需要查一下有没有分配 tx, 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &gitsmart_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	gitsmart_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//gitsmart_state->transaction_max = 0;
		
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = GitsmartTxAlloc(gitsmart_state, true);
		gitsmart_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(gitsmart_data->proto, "tcp", 3);
	}
	gitsmart_data->is_request = true;
#endif
/************************* 解析私有数据 start ************************/	


	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	gitsmart_data->done = 1;
	gitsmart_data->complete = 0;
	
/************************* 解析私有数据 end ************************/	


#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_gitsmart_event(f, gitsmart_data, STREAM_TOSERVER);
#endif


	SCReturnStruct(APP_LAYER_OK);

//error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 响应包 解析函数 */
static AppLayerResult GitsmartParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		SCReturnStruct(APP_LAYER_ERROR);
	}

	GitsmartTransaction *tx = NULL;
	//GitsmartTransaction *ttx = NULL;
	
	GitsmartState *gitsmart_state = NULL;
	GitsmartTransaction *gitsmart_data = NULL;
	
	const uint8_t *input = NULL;
	uint32_t input_len = 0;
	
	
	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(gitsmart_conf.gitsmart_enable)) {
		SCReturnStruct(APP_LAYER_ERROR);
	}
	
	/* 获取 state 和 input 和 input_len */
	gitsmart_state = (GitsmartState *)state;
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
	if (GITSMART_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = GitsmartTxAlloc(gitsmart_state, false);
	gitsmart_data = tx;
	if (unlikely(tx == NULL)) {
		SCReturnStruct(APP_LAYER_ERROR);
	}
	memcpy(gitsmart_data->proto, "tcp", 3);
	gitsmart_data->is_request = false;

#if 0
    /* 注意: 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &gitsmart_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	gitsmart_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//gitsmart_state->transaction_max = 0;
	
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = GitsmartTxAlloc(gitsmart_state, false);
		gitsmart_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(gitsmart_data->proto, "tcp", 3);
	}
	gitsmart_data->is_request = false;
#endif	
	/************************* 解析私有数据 start ************************/	
	/* 请求和响应公用一个 tx, 因此响应要清理请求的 tx */


	
	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	gitsmart_data->done = 1;
	gitsmart_data->complete = 1;
		
	/************************* 解析私有数据 end ************************/ 	
	
	
#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_gitsmart_event(f, gitsmart_data, STREAM_TOCLIENT);
#endif

	SCReturnStruct(APP_LAYER_OK);

//error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 获取 tx */
static void *GitsmartGetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	GitsmartState *gitsmart = (GitsmartState *)alstate;
	GitsmartTransaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH(tx, &gitsmart->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

/* 获取 tx 计数 */
static uint64_t GitsmartGetTxCnt(void *state)
{
	SCEnter();
	uint64_t count = ((uint64_t)((GitsmartState *)state)->transaction_max);
	SCReturnUInt(count);
}

/* 释放一个 gitsmart tx */
static void GitsmartTxFree(GitsmartTransaction *tx)
{
	SCEnter();

	AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

	if (tx->tx_data.de_state != NULL) {
		DetectEngineStateFree(tx->tx_data.de_state);
	}

	SCFree(tx);
	SCReturn;
}

/* 通过 ID 释放特定 gitsmart 状态上的一个事务 */
static void GitsmartStateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	GitsmartState *gitsmart = state;
	GitsmartTransaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &gitsmart->tx_list, next, ttx) {

		if (tx->tx_num != tx_num) {
			continue;
		}

		//最好不要使用这个 curr，这个就是容易段错误的根源
		if (tx == gitsmart->curr) {
			gitsmart->curr = NULL;
		}

		TAILQ_REMOVE(&gitsmart->tx_list, tx, next);
		GitsmartTxFree(tx);
		break;
	}

	SCReturn;
}

/* 释放 gitsmart state */
static void GitsmartStateFree(void *state)
{
	SCEnter();
	GitsmartState *gitsmart = state;
	GitsmartTransaction *tx;
	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&gitsmart->tx_list)) != NULL) {
			TAILQ_REMOVE(&gitsmart->tx_list, tx, next);
			GitsmartTxFree(tx);
		}
		if (gitsmart->request_buffer.buffer != NULL) {
			SCFree(gitsmart->request_buffer.buffer);
		}
		if (gitsmart->response_buffer.buffer != NULL) {
			SCFree(gitsmart->response_buffer.buffer);
		}
		SCFree(gitsmart);
	}
	SCReturn;
}

/* 由应用层调用来获取状态进度 */
static int GitsmartGetAlstateProgress(void *tx, uint8_t direction)
{
	/* 直接返回，用完 tx 就释放提高性能 */
	return 1;

	GitsmartTransaction *gitsmarttx = (GitsmartTransaction *)tx;
	int retval = 0;

	/* 原生逻辑是进度完成再释放，性能低 */
	if (gitsmarttx->complete) {
		retval = 1;
	}	

	SCReturnInt(retval);
}

/* 获取 tx_data */
static AppLayerTxData *GitsmartGetTxData(void *vtx)
{
	GitsmartTransaction *tx = (GitsmartTransaction *)vtx;
	return &tx->tx_data;
}

/* 获取 state_data */
static AppLayerStateData *GitsmartGetStateData(void *vstate)
{
	GitsmartState *state = (GitsmartState *)vstate;
	return &state->state_data;
}

/* 迭代器 */
static AppLayerGetTxIterTuple GitsmartGetTxIterator(const uint8_t ipproto, const AppProto alproto,
	void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
	GitsmartState *dnp_state = (GitsmartState *)alstate;
	AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
	if (dnp_state) {
		GitsmartTransaction *tx_ptr;
		if (state->un.ptr == NULL) {
			tx_ptr = TAILQ_FIRST(&dnp_state->tx_list);
		} else {
			tx_ptr = (GitsmartTransaction *)state->un.ptr;
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

/* 安装请求方向多种特征的协议识别函数 */
static int GitsmartRegisterPatternsForProtocolDetection(void)
{
	/* "git-upload-pack" 特征匹配 */
	if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_GITSMART, "git-upload-pack", 32, 4,
		STREAM_TOSERVER, GitsmartProbingParserTsTc, 4, 32) < 0) {
		return -1;
	}

	/* "git-upload-pack" 特征匹配 */
	if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_GITSMART, "git-upload-pack", 32, 4,
		STREAM_TOCLIENT, GitsmartProbingParserTsTc, 4, 32) < 0) {
		return -1;
	}

	/* "git-receive-pack" 特征匹配 */
	if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_GITSMART, "git-receive-pack", 32, 4,
		STREAM_TOSERVER, GitsmartProbingParserTsTc, 4, 32) < 0) {
		return -1;
	}

	/* "git-receive-pack" 特征匹配 */
	if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_GITSMART, "git-receive-pack", 32, 4,
		STREAM_TOCLIENT, GitsmartProbingParserTsTc, 4, 32) < 0) {
		return -1;
	}

	/* "git-upload-archive" 特征匹配 */
	if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_GITSMART, "git-upload-archive", 32, 4,
		STREAM_TOSERVER, GitsmartProbingParserTsTc, 4, 32) < 0) {
		return -1;
	}

	/* "git-upload-archive" 特征匹配 */
	if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_GITSMART, "git-upload-archive", 32, 4,
		STREAM_TOCLIENT, GitsmartProbingParserTsTc, 4, 32) < 0) {
		return -1;
	}
	
	return 0;
}

/* 核心注册函数 */
void RegisterGitsmartParsers(void)
{
	const char *proto_name = "gitsmart";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_GITSMART, proto_name);

	/* 注册 gitsmart 特征 */
	if (GitsmartRegisterPatternsForProtocolDetection() < 0 ) {
		SCLogConfig("Registering gitsmart/tcp GitsmartRegisterPatternsForProtocolDetection error!");
		SCReturn;
	}

#if 0
	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_GITSMART, 0, GITSMART_MIN_FRAME_LEN, GitsmartProbingParserTsTc, GitsmartProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_TCP, GITSMART_DEFAULT_PORT, ALPROTO_GITSMART, 0, GITSMART_MIN_FRAME_LEN, STREAM_TOSERVER, GitsmartProbingParserTsTc, GitsmartProbingParserTsTc);	
	}
#endif
	
	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
		SCLogConfig("Registering gitsmart/tcp parsers.");
		
		GitsmartReload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(gitsmart_conf.gitsmart_enable , 0);
		SC_ATOMIC_SET(gitsmart_conf.log_enable, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Gitsmart流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_GITSMART, GitsmartStateAlloc, GitsmartStateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_GITSMART, STREAM_TOSERVER, GitsmartParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_GITSMART, STREAM_TOCLIENT, GitsmartParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_GITSMART, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_GITSMART, GitsmartGetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_GITSMART, GitsmartGetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_GITSMART, GitsmartStateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_GITSMART, GitsmartGetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_GITSMART, GitsmartGetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_GITSMART, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_GITSMART, GitsmartGetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_GITSMART, GitsmartGetStateData);
	
	SCReturn;
}

