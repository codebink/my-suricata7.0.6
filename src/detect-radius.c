#include "suricata-common.h"

#include "stream.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-radius.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "app-layer-radius.h"
#include "util-byte.h"

extern RadiusConf radius_conf;

static int gg_radius_match_buffer_id = 0;

/*
	名字：char * ParseRuleOption(const char *rules, char *key, char *value, int *value_len)
	功能：解析 json 格式的规则字符串 rules，根据选项名称 key，取出选项值 value
	参数：
		1 char *rules(传入型参数): suricata 框架中，该协议的 json 格式规则字符串
		2 char *key(传入型参数): json 格式规则字符串中的具体规则名称
		3 char *value(传入传出型参数): json 格式规则字符串中的具体规则名称对应的规则字符串
		4 int *value_len(传入传出型参数): 规则字符串 value 传入传出参数缓冲区的长度，需要在函数调用前分配好缓冲区，函数返回时该参数保存规则实际长度
	返回:
		char *类型, 传入传出参数 value 字符串地址, 异常时返回 NULL
	时间：2022/02/28
	研发：D.D
	版本：1.0.0.1
*/
static char * ParseRuleOption(const char *rules, char *key, char *value, int *value_len)
{
	memset(value, 0, *value_len);
	
	/* 字符串 json 数据转为 JSON 对象格式 */
	cJSON * root = cJSON_Parse(rules);
	if(NULL == root) {
		return NULL;
	}

	/* 根据键 key 获取其对应的值 */
	cJSON *val = cJSON_GetObjectItem(root, key);
	if(NULL == val) {
		cJSON_Delete(root);
		return NULL;
	}

	/* 将获取值转化为字符串格式 */
	char *data = cJSON_Print(val);
	if(NULL == data) {
		cJSON_Delete(root);
		return NULL;
	}

	if ((int)strlen(data) >= *value_len || 0 >= (int)strlen(data) - 2) {
		free(data);
		cJSON_Delete(root);
		return NULL;
	}

	memcpy(value, (data + 1), (int)strlen(data) - 2);
	//*value_len = strlen(data) - 2;
	free(data);

	/* json 对象释放根节点，会自动释放子节点 */
	cJSON_Delete(root);

	return value;
}


/* 解析规则选项内容字符串，字符串以','分隔，因为规则格式和 snort 不同，因此 suricata 中的字段均为必填字段 */
static DetectRadiusData *DetectRadiusParse (const char *radiusstr)
{
	char value[20] = {0};
	int value_len = 20;
	char *ret = NULL;
	
    /* 分配规则结构 */
    DetectRadiusData *radiusd = SCMalloc(sizeof (DetectRadiusData));
    if (unlikely(radiusd == NULL)) {
		return NULL;
	}

	/* 解析 兜底规则 */
	ret = ParseRuleOption(radiusstr, (char *)"full_hit", value, &value_len);
	if (NULL != ret) {
		radiusd->full_hit = (uint8_t)atoi(value);
		radiusd->full_hit_key = 1;
	}else {
		radiusd->full_hit = 0x0f;
		radiusd->full_hit_key = 0;
	}
	
#if 0	
	/* 解析 传输状态 */
	ret = ParseRuleOption(radiusstr, (char *)"radius_ts", value, &value_len);
	if (NULL != ret) {
		radiusd->radius_ts = (uint8_t)atoi(value);
		radiusd->radius_ts_key = 1;
	}else {
		radiusd->radius_ts = 0x0f;
		radiusd->radius_ts_key = 0;
	}
#endif

    /* 返回规则结构体 */
    return radiusd;
}


/* 规则结构释放函数 */
static void DetectRadiusFree(DetectEngineCtx *de_ctx, void *ptr)
{
	DetectRadiusData *ed = (DetectRadiusData *)ptr;
	if (NULL != ed) {
		SCFree(ed);
	}
}

/* 注册规则解析函数 */
static int DetectRadiusSetup (DetectEngineCtx *de_ctx, Signature *s, const char *radiusstr)
{
	if (0 != DetectSignatureSetAppProto(s, ALPROTO_RADIUS)) {
		return -1;
	}

	/* 解析策略文件中的规则串，放在规则结构中返回 */
	DetectRadiusData *radiusd = DetectRadiusParse(radiusstr);
	if (NULL == radiusd) {
		return -1;
	}

	SigMatch *sm = SigMatchAlloc();
	if (sm == NULL) {
		DetectRadiusFree(de_ctx, radiusd);
		return -1;
	}

	sm->type = DETECT_RADIUS;
	sm->ctx = (void *)radiusd;

	SigMatchAppendSMToList(s, sm, gg_radius_match_buffer_id);
	return 0;
}

/* 规则匹配函数 */
static int DetectRadiusTxMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
	int ret = 0;
	
	/* 私有结构和规则结构赋值 */
	RadiusTransaction *et = (RadiusTransaction *) txv;
	const DetectRadiusData *ed = (const DetectRadiusData *) ctx;
	
	/* Radius 功能没有开启不处理 */
	if (0 == SC_ATOMIC_GET(radius_conf.radius_enable)){
		goto end;
	}

	/* 规则匹配，如果多规则时使用 "||" 逻辑，只要一个匹配上就说明命中，这里是兜底规则 */
	if (1 == ed->full_hit_key && 1 == ed->full_hit) {
		et->radius_match_flag = 1;
		ret = 1;
		goto end;
	}

	et->radius_match_flag = 1;
	ret = 1;
		
end:
	return ret;
}


/* 核心注册函数 */
void DetectRadiusRegister(void)
{
    sigmatch_table[DETECT_RADIUS].name          = "radius"; //模块关键字
    sigmatch_table[DETECT_RADIUS].alias         = NULL;   //别名
    sigmatch_table[DETECT_RADIUS].desc          = NULL;   //模块说明
    sigmatch_table[DETECT_RADIUS].url           = NULL;   //填写 radius 上关于 RADIUS 模块的说明 URL，这里不使用

	sigmatch_table[DETECT_RADIUS].Match         = NULL;                  //传入 pkt 的规则匹配函数，适用于 二层 协议的规则匹配
    sigmatch_table[DETECT_RADIUS].AppLayerTxMatch = DetectRadiusTxMatch;   //传入   tx 的规则匹配函数，适用于 应用层 协议的规则匹配
    sigmatch_table[DETECT_RADIUS].Setup         = DetectRadiusSetup;       //注册规则解析函数
    sigmatch_table[DETECT_RADIUS].Free          = DetectRadiusFree;        //注册释放函数


    /* 注册 请求 和 响应 两个方向的函数、索引和对象的列表 */
    DetectAppLayerInspectEngineRegister2("radius", ALPROTO_RADIUS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2("radius", ALPROTO_RADIUS, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    gg_radius_match_buffer_id = DetectBufferTypeRegister("radius");

}

