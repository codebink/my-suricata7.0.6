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
#include "app-layer-cassandra.h"

#include "detect-cassandra.h"

#include "output.h"
#include "output-json.h"
#include "output-json-cassandra.h"


extern CassandraConf cassandra_conf;

typedef struct LogCassandraFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogCassandraFileCtx;

typedef struct LogCassandraLogThread_ {
    LogCassandraFileCtx *cassandralog_ctx;
    OutputJsonThreadCtx *ctx;
} LogCassandraLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonCassandraLogRequest(JsonBuilder *js, CassandraTransaction *cassandratx, CassandraState *state)
{
	if (NULL == js || NULL == cassandratx || NULL == state || 0 >= state->query_cmd_buffer.len) {
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", cassandratx->complete);

	/* 设置 server_version */
	if (0 < state->server_version.len) {
		jb_set_string_from_bytes(js, "server_version", (const uint8_t *)(state->server_version.buffer), state->server_version.len);
	}else {
		jb_set_string_from_bytes(js, "server_version", (const uint8_t *)"null", 4);
	}

	/* 设置 cql_version */
	if (0 < state->cql_version.len) {
		jb_set_string_from_bytes(js, "cql_version", (const uint8_t *)(state->cql_version.buffer), state->cql_version.len);
	}else {
		jb_set_string_from_bytes(js, "cql_version", (const uint8_t *)"null", 4);
	}

	/* 设置 driver_name */
	if (0 < state->driver_name.len) {
		jb_set_string_from_bytes(js, "driver_name", (const uint8_t *)(state->driver_name.buffer), state->driver_name.len);
	}else {
		jb_set_string_from_bytes(js, "driver_name", (const uint8_t *)"null", 4);
	}

	/* 设置 driver_version */
	if (0 < state->driver_version.len) {
		jb_set_string_from_bytes(js, "driver_version", (const uint8_t *)(state->driver_version.buffer), state->driver_version.len);
	}else {
		jb_set_string_from_bytes(js, "driver_version", (const uint8_t *)"null", 4);
	}

	/* 设置 client_id */
	if (0 < state->client_id.len) {
		jb_set_string_from_bytes(js, "client_id", (const uint8_t *)(state->client_id.buffer), state->client_id.len);
	}else {
		jb_set_string_from_bytes(js, "client_id", (const uint8_t *)"null", 4);
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
void JsonCassandraLogResponse(JsonBuilder *js, CassandraTransaction *cassandratx, CassandraState *state)
{
	if (NULL == js || NULL == cassandratx || NULL == state || 1 != state->send_key) {
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", cassandratx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonCassandraLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((CassandraState *)state)->query_cmd_buffer.len) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogCassandraLogThread *thread = (LogCassandraLogThread *)thread_data;
    CassandraTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "cassandra", NULL, thread->cassandralog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "cassandra");
    JsonCassandraLogRequest(js, tx, (CassandraState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#if 0
/* 响应方向日志函数 */
static int JsonCassandraLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((CassandraState *)state)->send_key) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogCassandraLogThread *thread = (LogCassandraLogThread *)thread_data;
    CassandraTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "cassandra", NULL, thread->cassandralog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "cassandra");
    JsonCassandraLogResponse(js, tx, (CassandraState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#endif

/* 核心日志发送函数 */
static int JsonCassandraLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    CassandraTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonCassandraLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
		/* 暂时只解析了请求，因此注释掉响应事件的发送 */
        //JsonCassandraLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputCassandraLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogCassandraFileCtx *cassandralog_ctx = (LogCassandraFileCtx *)output_ctx->data;
    SCFree(cassandralog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputCassandraLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogCassandraFileCtx *cassandralog_ctx = SCCalloc(1, sizeof(*cassandralog_ctx));
    if (unlikely(cassandralog_ctx == NULL)) {
        return result;
    }
    cassandralog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(cassandralog_ctx);
        return result;
    }
    output_ctx->data = cassandralog_ctx;
    output_ctx->DeInit = OutputCassandraLogDeInitCtxSub;

    SCLogInfo("cassandra log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_CASSANDRA);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonCassandraLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogCassandraLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for cassandra.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->cassandralog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->cassandralog_ctx->eve_ctx);
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
static TmEcode JsonCassandraLogThreadDeinit(ThreadVars *t, void *data)
{
    LogCassandraLogThread *thread = (LogCassandraLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonCassandraLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonCassandraLog", "eve-log.cassandra",
            OutputCassandraLogInitSub, ALPROTO_CASSANDRA, JsonCassandraLogger, JsonCassandraLogThreadInit,
            JsonCassandraLogThreadDeinit, NULL);
}
