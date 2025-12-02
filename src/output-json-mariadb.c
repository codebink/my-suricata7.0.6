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
#include "app-layer-mariadb.h"

#include "detect-mariadb.h"

#include "output.h"
#include "output-json.h"
#include "output-json-mariadb.h"


extern MariadbConf mariadb_conf;

typedef struct LogMariadbFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogMariadbFileCtx;

typedef struct LogMariadbLogThread_ {
    LogMariadbFileCtx *mariadblog_ctx;
    OutputJsonThreadCtx *ctx;
} LogMariadbLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonMariadbLogRequest(JsonBuilder *js, MariadbTransaction *mariadbtx, MariadbState *state)
{
	if (NULL == js || NULL == mariadbtx || NULL == state) {
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", mariadbtx->complete);

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
#if 1
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
void JsonMariadbLogResponse(JsonBuilder *js, MariadbTransaction *mariadbtx, MariadbState *state)
{
	if (NULL == js || NULL == mariadbtx || NULL == state || 1 != state->send_key) {
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", mariadbtx->complete);

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
#if 1
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
static int JsonMariadbLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((MariadbState *)state)->query_cmd_buffer.len || 1 == SC_ATOMIC_GET(mariadb_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogMariadbLogThread *thread = (LogMariadbLogThread *)thread_data;
    MariadbTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "mariadb", NULL, thread->mariadblog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "mariadb");
    JsonMariadbLogRequest(js, tx, (MariadbState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}


/* 响应方向日志函数 */
static int JsonMariadbLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((MariadbState *)state)->send_key || 0 == SC_ATOMIC_GET(mariadb_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogMariadbLogThread *thread = (LogMariadbLogThread *)thread_data;
    MariadbTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "mariadb", NULL, thread->mariadblog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "mariadb");
    JsonMariadbLogResponse(js, tx, (MariadbState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonMariadbLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    MariadbTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonMariadbLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonMariadbLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputMariadbLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogMariadbFileCtx *mariadblog_ctx = (LogMariadbFileCtx *)output_ctx->data;
    SCFree(mariadblog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputMariadbLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogMariadbFileCtx *mariadblog_ctx = SCCalloc(1, sizeof(*mariadblog_ctx));
    if (unlikely(mariadblog_ctx == NULL)) {
        return result;
    }
    mariadblog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(mariadblog_ctx);
        return result;
    }
    output_ctx->data = mariadblog_ctx;
    output_ctx->DeInit = OutputMariadbLogDeInitCtxSub;

    SCLogInfo("mariadb log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MARIADB);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonMariadbLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogMariadbLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for mariadb.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->mariadblog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->mariadblog_ctx->eve_ctx);
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
static TmEcode JsonMariadbLogThreadDeinit(ThreadVars *t, void *data)
{
    LogMariadbLogThread *thread = (LogMariadbLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonMariadbLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonMariadbLog", "eve-log.mariadb",
            OutputMariadbLogInitSub, ALPROTO_MARIADB, JsonMariadbLogger, JsonMariadbLogThreadInit,
            JsonMariadbLogThreadDeinit, NULL);
}
