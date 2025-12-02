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
#include "app-layer-pgsql.h"

#include "detect-pgsql.h"

#include "output.h"
#include "output-json.h"
#include "output-json-pgsql.h"


extern PgsqlConf pgsql_conf;

typedef struct LogPgsqlFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogPgsqlFileCtx;

typedef struct LogPgsqlLogThread_ {
    LogPgsqlFileCtx *pgsqllog_ctx;
    OutputJsonThreadCtx *ctx;
} LogPgsqlLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonPgsqlLogRequest(JsonBuilder *js, PgsqlTransaction *pgsqltx, PgsqlState *state)
{
	if (NULL == js || NULL == pgsqltx || NULL == state) {
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", pgsqltx->complete);

	/* 设置 version */
	if (0 < state->version.len) {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)(state->version.buffer), state->version.len);
	}else {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)"null", 4);
	}

	/* 设置 user */
	if (0 < state->user.len) {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)(state->user.buffer), state->user.len);
	}else {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)"null", 4);
	}

	/* 设置 db_name */
	if (0 < state->db_name.len) {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)(state->db_name.buffer), state->db_name.len);
	}else {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)"null", 4);
	}

	/* 设置 sql_cmd */
	if (0 < state->query_cmd_buffer.len) {
		jb_set_string_from_bytes(js, "sql_cmd", (const uint8_t *)(state->query_cmd_buffer.buffer), state->query_cmd_buffer.len - 1);
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

	/* 设置 app_name */
	if (0 < state->app_name.len) {
		jb_set_string_from_bytes(js, "app_name", (const uint8_t *)(state->app_name.buffer), state->app_name.len);
	}else {
		jb_set_string_from_bytes(js, "app_name", (const uint8_t *)"null", 4);
	}

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonPgsqlLogResponse(JsonBuilder *js, PgsqlTransaction *pgsqltx, PgsqlState *state)
{
	if (NULL == js || NULL == pgsqltx || NULL == state || 1 != state->send_key) {
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", pgsqltx->complete);

	/* 设置 version */
	if (0 < state->version.len) {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)(state->version.buffer), state->version.len);
	}else {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)"null", 4);
	}

	/* 设置 user */
	if (0 < state->user.len) {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)(state->user.buffer), state->user.len);
	}else {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)"null", 4);
	}

	/* 设置 db_name */
	if (0 < state->db_name.len) {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)(state->db_name.buffer), state->db_name.len);
	}else {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)"null", 4);
	}

	/* 设置 sql_cmd */
	if (0 < state->query_cmd_buffer.len) {
		jb_set_string_from_bytes(js, "sql_cmd", (const uint8_t *)(state->query_cmd_buffer.buffer), state->query_cmd_buffer.len - 1);
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

	/* 设置 app_name */
	if (0 < state->app_name.len) {
		jb_set_string_from_bytes(js, "app_name", (const uint8_t *)(state->app_name.buffer), state->app_name.len);
	}else {
		jb_set_string_from_bytes(js, "app_name", (const uint8_t *)"null", 4);
	}

	/* 关闭对象 */
	jb_close(js);
}


/* 请求方向日志函数 */
static int JsonPgsqlLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((PgsqlState *)state)->query_cmd_buffer.len || 1 == SC_ATOMIC_GET(pgsql_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogPgsqlLogThread *thread = (LogPgsqlLogThread *)thread_data;
    PgsqlTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "pgsql", NULL, thread->pgsqllog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "pgsql");
    JsonPgsqlLogRequest(js, tx, (PgsqlState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}


/* 响应方向日志函数 */
static int JsonPgsqlLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((PgsqlState *)state)->send_key || 0 == SC_ATOMIC_GET(pgsql_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogPgsqlLogThread *thread = (LogPgsqlLogThread *)thread_data;
    PgsqlTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "pgsql", NULL, thread->pgsqllog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "pgsql");
    JsonPgsqlLogResponse(js, tx, (PgsqlState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonPgsqlLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    PgsqlTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonPgsqlLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonPgsqlLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputPgsqlLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogPgsqlFileCtx *pgsqllog_ctx = (LogPgsqlFileCtx *)output_ctx->data;
    SCFree(pgsqllog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputPgsqlLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogPgsqlFileCtx *pgsqllog_ctx = SCCalloc(1, sizeof(*pgsqllog_ctx));
    if (unlikely(pgsqllog_ctx == NULL)) {
        return result;
    }
    pgsqllog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(pgsqllog_ctx);
        return result;
    }
    output_ctx->data = pgsqllog_ctx;
    output_ctx->DeInit = OutputPgsqlLogDeInitCtxSub;

    SCLogInfo("pgsql log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_PGSQL);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonPgsqlLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogPgsqlLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for pgsql.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->pgsqllog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->pgsqllog_ctx->eve_ctx);
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
static TmEcode JsonPgsqlLogThreadDeinit(ThreadVars *t, void *data)
{
    LogPgsqlLogThread *thread = (LogPgsqlLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonPgsqlLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonPgsqlLog", "eve-log.pgsql",
            OutputPgsqlLogInitSub, ALPROTO_PGSQL, JsonPgsqlLogger, JsonPgsqlLogThreadInit,
            JsonPgsqlLogThreadDeinit, NULL);
}
