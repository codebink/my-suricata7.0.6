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
#include "app-layer-sqlserver.h"

#include "detect-sqlserver.h"

#include "output.h"
#include "output-json.h"
#include "output-json-sqlserver.h"


extern SqlserverConf sqlserver_conf;

typedef struct LogSqlserverFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogSqlserverFileCtx;

typedef struct LogSqlserverLogThread_ {
    LogSqlserverFileCtx *sqlserverlog_ctx;
    OutputJsonThreadCtx *ctx;
} LogSqlserverLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonSqlserverLogRequest(JsonBuilder *js, SqlserverTransaction *sqlservertx, SqlserverState *state)
{
	if (NULL == js || NULL == sqlservertx || NULL == state) {
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", sqlservertx->complete);

	/* 设置 version */
	if (1 == state->version_key) {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)(state->version), state->version_len);
	}else {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)"null", 4);
	}
	
#if 0
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
#endif

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
void JsonSqlserverLogResponse(JsonBuilder *js, SqlserverTransaction *sqlservertx, SqlserverState *state)
{
	if (NULL == js || NULL == sqlservertx || NULL == state || 1 != state->send_key) {
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", sqlservertx->complete);

	/* 设置 version */
	if (1 == state->version_key) {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)(state->version), state->version_len);
	}else {
		jb_set_string_from_bytes(js, "version", (const uint8_t *)"null", 4);
	}

#if 0
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
#endif

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
static int JsonSqlserverLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((SqlserverState *)state)->query_cmd_buffer.len || 1 == SC_ATOMIC_GET(sqlserver_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogSqlserverLogThread *thread = (LogSqlserverLogThread *)thread_data;
    SqlserverTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "sqlserver", NULL, thread->sqlserverlog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "sqlserver");
    JsonSqlserverLogRequest(js, tx, (SqlserverState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}


/* 响应方向日志函数 */
static int JsonSqlserverLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((SqlserverState *)state)->send_key || 0 == SC_ATOMIC_GET(sqlserver_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogSqlserverLogThread *thread = (LogSqlserverLogThread *)thread_data;
    SqlserverTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "sqlserver", NULL, thread->sqlserverlog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "sqlserver");
    JsonSqlserverLogResponse(js, tx, (SqlserverState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonSqlserverLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    SqlserverTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonSqlserverLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonSqlserverLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputSqlserverLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogSqlserverFileCtx *sqlserverlog_ctx = (LogSqlserverFileCtx *)output_ctx->data;
    SCFree(sqlserverlog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputSqlserverLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogSqlserverFileCtx *sqlserverlog_ctx = SCCalloc(1, sizeof(*sqlserverlog_ctx));
    if (unlikely(sqlserverlog_ctx == NULL)) {
        return result;
    }
    sqlserverlog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(sqlserverlog_ctx);
        return result;
    }
    output_ctx->data = sqlserverlog_ctx;
    output_ctx->DeInit = OutputSqlserverLogDeInitCtxSub;

    SCLogInfo("sqlserver log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SQLSERVER);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonSqlserverLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogSqlserverLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for sqlserver.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->sqlserverlog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->sqlserverlog_ctx->eve_ctx);
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
static TmEcode JsonSqlserverLogThreadDeinit(ThreadVars *t, void *data)
{
    LogSqlserverLogThread *thread = (LogSqlserverLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonSqlserverLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonSqlserverLog", "eve-log.sqlserver",
            OutputSqlserverLogInitSub, ALPROTO_SQLSERVER, JsonSqlserverLogger, JsonSqlserverLogThreadInit,
            JsonSqlserverLogThreadDeinit, NULL);
}
