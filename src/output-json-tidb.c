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
#include "app-layer-tidb.h"

#include "detect-tidb.h"

#include "output.h"
#include "output-json.h"
#include "output-json-tidb.h"


extern TidbConf tidb_conf;

typedef struct LogTidbFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogTidbFileCtx;

typedef struct LogTidbLogThread_ {
    LogTidbFileCtx *tidblog_ctx;
    OutputJsonThreadCtx *ctx;
} LogTidbLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonTidbLogRequest(JsonBuilder *js, TidbTransaction *tidbtx, TidbState *state)
{
	if (NULL == js || NULL == tidbtx || NULL == state) {
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", tidbtx->complete);

	/* 设置 version */
	if (1 == state->version_key) {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)(state->version), state->version_len);
	}else {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)"null", 4);
	}

	/* 设置 user */
	if (1 == state->user_key) {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)(state->user), state->user_len);
	}else {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)"null", 4);
	}

	/* 设置 passwd */
	if (1 == state->passwd_key) {
		jb_set_string_from_bytes(js, "passwd", (const uint8_t *)(state->passwd), state->passwd_len);
	}else {
		jb_set_string_from_bytes(js, "passwd", (const uint8_t *)"null", 4);
	}

	/* 设置 db_name */
	if (0 < state->db_name.len) {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)(state->db_name.buffer), state->db_name.len);
	}else {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)"null", 4);
	}

	/* 设置 table_name */
	if (0 < state->table_name.len) {
		jb_set_string_from_bytes(js, "table_name", (const uint8_t *)(state->table_name.buffer), state->table_name.len);
	}else {
		jb_set_string_from_bytes(js, "table_name", (const uint8_t *)"null", 4);
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
void JsonTidbLogResponse(JsonBuilder *js, TidbTransaction *tidbtx, TidbState *state)
{
	if (NULL == js || NULL == tidbtx || NULL == state || 1 != state->send_key) {
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", tidbtx->complete);

	/* 设置 version */
	if (1 == state->version_key) {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)(state->version), state->version_len);
	}else {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)"null", 4);
	}

	/* 设置 user */
	if (1 == state->user_key) {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)(state->user), state->user_len);
	}else {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)"null", 4);
	}

	/* 设置 passwd */
	if (1 == state->passwd_key) {
		jb_set_string_from_bytes(js, "passwd", (const uint8_t *)(state->passwd), state->passwd_len);
	}else {
		jb_set_string_from_bytes(js, "passwd", (const uint8_t *)"null", 4);
	}

	/* 设置 db_name */
	if (0 < state->db_name.len) {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)(state->db_name.buffer), state->db_name.len);
	}else {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)"null", 4);
	}

	/* 设置 table_name */
	if (0 < state->table_name.len) {
		jb_set_string_from_bytes(js, "table_name", (const uint8_t *)(state->table_name.buffer), state->table_name.len);
	}else {
		jb_set_string_from_bytes(js, "table_name", (const uint8_t *)"null", 4);
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


/* 请求方向日志函数 */
static int JsonTidbLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((TidbState *)state)->query_cmd_buffer.len || 1 == SC_ATOMIC_GET(tidb_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogTidbLogThread *thread = (LogTidbLogThread *)thread_data;
    TidbTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "tidb", NULL, thread->tidblog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "tidb");
    JsonTidbLogRequest(js, tx, (TidbState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}


/* 响应方向日志函数 */
static int JsonTidbLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((TidbState *)state)->send_key || 0 == SC_ATOMIC_GET(tidb_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogTidbLogThread *thread = (LogTidbLogThread *)thread_data;
    TidbTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "tidb", NULL, thread->tidblog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "tidb");
    JsonTidbLogResponse(js, tx, (TidbState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonTidbLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    TidbTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonTidbLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonTidbLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputTidbLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogTidbFileCtx *tidblog_ctx = (LogTidbFileCtx *)output_ctx->data;
    SCFree(tidblog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputTidbLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogTidbFileCtx *tidblog_ctx = SCCalloc(1, sizeof(*tidblog_ctx));
    if (unlikely(tidblog_ctx == NULL)) {
        return result;
    }
    tidblog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(tidblog_ctx);
        return result;
    }
    output_ctx->data = tidblog_ctx;
    output_ctx->DeInit = OutputTidbLogDeInitCtxSub;

    SCLogInfo("tidb log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TIDB);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonTidbLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogTidbLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for tidb.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->tidblog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->tidblog_ctx->eve_ctx);
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
static TmEcode JsonTidbLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTidbLogThread *thread = (LogTidbLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonTidbLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonTidbLog", "eve-log.tidb",
            OutputTidbLogInitSub, ALPROTO_TIDB, JsonTidbLogger, JsonTidbLogThreadInit,
            JsonTidbLogThreadDeinit, NULL);
}
