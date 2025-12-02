
#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-redis.h"

#include "detect-redis.h"

#include "output.h"
#include "output-json.h"
#include "output-json-redis.h"


extern RedisConf redis_conf;

typedef struct LogRedisFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogRedisFileCtx;

typedef struct LogRedisLogThread_ {
    LogRedisFileCtx *redislog_ctx;
    OutputJsonThreadCtx *ctx;
} LogRedisLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonRedisLogRequest(JsonBuilder *js, RedisTransaction *redistx, RedisState *state)
{
	if (NULL == js || NULL == redistx || NULL == state || 0 >= state->query_cmd_buffer.len) {
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", redistx->complete);

	/* 设置 server_version */
	if (0 < state->server_version.len) {
		jb_set_string_from_bytes(js, "server_version", (const uint8_t *)(state->server_version.buffer), state->server_version.len);
	}else {
		jb_set_string_from_bytes(js, "server_version", (const uint8_t *)"null", 4);
	}

	/* 设置 system_name */
	if (0 < state->system_name.len) {
		jb_set_string_from_bytes(js, "system_name", (const uint8_t *)(state->system_name.buffer), state->system_name.len);
	}else {
		jb_set_string_from_bytes(js, "system_name", (const uint8_t *)"null", 4);
	}

	/* 设置 executable */
	if (0 < state->executable.len) {
		jb_set_string_from_bytes(js, "executable", (const uint8_t *)(state->executable.buffer), state->executable.len);
	}else {
		jb_set_string_from_bytes(js, "executable", (const uint8_t *)"null", 4);
	}

	/* 设置 config_file */
	if (0 < state->config_file.len) {
		jb_set_string_from_bytes(js, "config_file", (const uint8_t *)(state->config_file.buffer), state->config_file.len);
	}else {
		jb_set_string_from_bytes(js, "config_file", (const uint8_t *)"null", 4);
	}

	/* 设置 auth */
	if (0 < state->auth.len) {
		jb_set_string_from_bytes(js, "auth", (const uint8_t *)(state->auth.buffer), state->auth.len);
	}else {
		jb_set_string_from_bytes(js, "auth", (const uint8_t *)"null", 4);
	}

	/* 设置 sql_cmd */
	if (0 < state->query_cmd_buffer.len) {
		jb_set_string_from_bytes(js, "sql_cmd", (const uint8_t *)(state->query_cmd_buffer.buffer), state->query_cmd_buffer.len);
	}else {
		jb_set_string_from_bytes(js, "sql_cmd", (const uint8_t *)"null", 4);
	}

	/* 设置 fields */
	if (0 < state->fields.len) {
		jb_set_string_from_bytes(js, "fields", (const uint8_t *)(state->fields.buffer), state->fields.len);
	}else {
		jb_set_string_from_bytes(js, "fields", (const uint8_t *)"null", 4);
	}

	/* 设置 result_set */
	if (0 < state->result_set_buffer.len) {
		jb_set_string_from_bytes(js, "result_set", (const uint8_t *)(state->result_set_buffer.buffer), state->result_set_buffer.len);
	}else {
		jb_set_string_from_bytes(js, "result_set", (const uint8_t *)"null", 4);
	}

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonRedisLogResponse(JsonBuilder *js, RedisTransaction *redistx, RedisState *state)
{
	if (NULL == js || NULL == redistx || NULL == state || 1 != state->send_key) {
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", redistx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonRedisLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((RedisState *)state)->query_cmd_buffer.len) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogRedisLogThread *thread = (LogRedisLogThread *)thread_data;
    RedisTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "redis", NULL, thread->redislog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "redis");
    JsonRedisLogRequest(js, tx, (RedisState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#if 0
/* 响应方向日志函数 */
static int JsonRedisLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((RedisState *)state)->send_key) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogRedisLogThread *thread = (LogRedisLogThread *)thread_data;
    RedisTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "redis", NULL, thread->redislog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "redis");
    JsonRedisLogResponse(js, tx, (RedisState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#endif

/* 核心日志发送函数 */
static int JsonRedisLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    RedisTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonRedisLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
		/* 暂时只解析了请求，因此注释掉响应事件的发送 */
        //JsonRedisLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputRedisLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogRedisFileCtx *redislog_ctx = (LogRedisFileCtx *)output_ctx->data;
    SCFree(redislog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputRedisLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogRedisFileCtx *redislog_ctx = SCCalloc(1, sizeof(*redislog_ctx));
    if (unlikely(redislog_ctx == NULL)) {
        return result;
    }
    redislog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(redislog_ctx);
        return result;
    }
    output_ctx->data = redislog_ctx;
    output_ctx->DeInit = OutputRedisLogDeInitCtxSub;

    SCLogInfo("redis log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_REDIS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonRedisLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogRedisLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for redis.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->redislog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->redislog_ctx->eve_ctx);
    if (thread->ctx == NULL) {
        goto error_exit;
    }

    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

/* 线程反初始化函数 */
static TmEcode JsonRedisLogThreadDeinit(ThreadVars *t, void *data)
{
    LogRedisLogThread *thread = (LogRedisLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonRedisLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonRedisLog", "eve-log.redis",
            OutputRedisLogInitSub, ALPROTO_REDIS, JsonRedisLogger, JsonRedisLogThreadInit,
            JsonRedisLogThreadDeinit, NULL);
}
