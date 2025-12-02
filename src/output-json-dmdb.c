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
#include "app-layer-dmdb.h"

#include "detect-dmdb.h"

#include "output.h"
#include "output-json.h"
#include "output-json-dmdb.h"


extern DmdbConf dmdb_conf;

typedef struct LogDmdbFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogDmdbFileCtx;

typedef struct LogDmdbLogThread_ {
    LogDmdbFileCtx *dmdblog_ctx;
    OutputJsonThreadCtx *ctx;
} LogDmdbLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonDmdbLogRequest(JsonBuilder *js, DmdbTransaction *dmdbtx, DmdbState *state)
{
	if (NULL == js || NULL == dmdbtx || NULL == state || 0 >= state->query_cmd_buffer.len) {
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", dmdbtx->complete);
	
	/* 设置 client_version */
	if (0 < state->client_version.len) {
		jb_set_string_from_bytes(js, "client_version", (const uint8_t *)(state->client_version.buffer), state->client_version.len);
	}else {
		jb_set_string_from_bytes(js, "client_version", (const uint8_t *)"null", 4);
	}

	/* 设置 server_version */
	if (0 < state->server_version.len) {
		jb_set_string_from_bytes(js, "server_version", (const uint8_t *)(state->server_version.buffer), state->server_version.len);
	}else {
		jb_set_string_from_bytes(js, "server_version", (const uint8_t *)"null", 4);
	}

	/* 设置 client_name */
	if (0 < state->client_name.len) {
		jb_set_string_from_bytes(js, "client_name", (const uint8_t *)(state->client_name.buffer), state->client_name.len);
	}else {
		jb_set_string_from_bytes(js, "client_name", (const uint8_t *)"null", 4);
	}

	/* 设置 system_name */
	if (0 < state->system_name.len) {
		jb_set_string_from_bytes(js, "system_name", (const uint8_t *)(state->system_name.buffer), state->system_name.len);
	}else {
		jb_set_string_from_bytes(js, "system_name", (const uint8_t *)"null", 4);
	}

	/* 设置 host_name */
	if (0 < state->host_name.len) {
		jb_set_string_from_bytes(js, "host_name", (const uint8_t *)(state->host_name.buffer), state->host_name.len);
	}else {
		jb_set_string_from_bytes(js, "host_name", (const uint8_t *)"null", 4);
	}

	/* 设置 db_name */
	if (0 < state->db_name.len) {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)(state->db_name.buffer), state->db_name.len);
	}else {
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)"null", 4);
	}	

	/* 设置 user */
	if (0 < state->user.len) {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)(state->user.buffer), state->user.len);
	}else {
		jb_set_string_from_bytes(js, "user", (const uint8_t *)"null", 4);
	}

	/* 设置 client_ip */
	if (0 < state->client_ip.len) {
		jb_set_string_from_bytes(js, "client_ip", (const uint8_t *)(state->client_ip.buffer), state->client_ip.len);
	}else {
		jb_set_string_from_bytes(js, "client_ip", (const uint8_t *)"null", 4);
	}

	/* 设置 link_time */
	if (0 < state->link_time.len) {
		jb_set_string_from_bytes(js, "link_time", (const uint8_t *)(state->link_time.buffer), state->link_time.len);
	}else {
		jb_set_string_from_bytes(js, "link_time", (const uint8_t *)"null", 4);
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

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonDmdbLogResponse(JsonBuilder *js, DmdbTransaction *dmdbtx, DmdbState *state)
{
	if (NULL == js || NULL == dmdbtx || NULL == state || 1 != state->send_key) {
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", dmdbtx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonDmdbLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((DmdbState *)state)->query_cmd_buffer.len) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogDmdbLogThread *thread = (LogDmdbLogThread *)thread_data;
    DmdbTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "dmdb", NULL, thread->dmdblog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "dmdb");
    JsonDmdbLogRequest(js, tx, (DmdbState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#if 0
/* 响应方向日志函数 */
static int JsonDmdbLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((DmdbState *)state)->send_key) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogDmdbLogThread *thread = (LogDmdbLogThread *)thread_data;
    DmdbTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "dmdb", NULL, thread->dmdblog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "dmdb");
    JsonDmdbLogResponse(js, tx, (DmdbState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#endif

/* 核心日志发送函数 */
static int JsonDmdbLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    DmdbTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonDmdbLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
		/* 暂时只解析了请求，因此注释掉响应事件的发送 */
        //JsonDmdbLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputDmdbLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogDmdbFileCtx *dmdblog_ctx = (LogDmdbFileCtx *)output_ctx->data;
    SCFree(dmdblog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputDmdbLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogDmdbFileCtx *dmdblog_ctx = SCCalloc(1, sizeof(*dmdblog_ctx));
    if (unlikely(dmdblog_ctx == NULL)) {
        return result;
    }
    dmdblog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dmdblog_ctx);
        return result;
    }
    output_ctx->data = dmdblog_ctx;
    output_ctx->DeInit = OutputDmdbLogDeInitCtxSub;

    SCLogInfo("dmdb log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DMDB);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonDmdbLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDmdbLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for dmdb.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->dmdblog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->dmdblog_ctx->eve_ctx);
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
static TmEcode JsonDmdbLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDmdbLogThread *thread = (LogDmdbLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonDmdbLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonDmdbLog", "eve-log.dmdb",
            OutputDmdbLogInitSub, ALPROTO_DMDB, JsonDmdbLogger, JsonDmdbLogThreadInit,
            JsonDmdbLogThreadDeinit, NULL);
}
