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
#include "app-layer-kingbase.h"

#include "detect-kingbase.h"

#include "output.h"
#include "output-json.h"
#include "output-json-kingbase.h"


extern KingbaseConf kingbase_conf;

typedef struct LogKingbaseFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogKingbaseFileCtx;

typedef struct LogKingbaseLogThread_ {
    LogKingbaseFileCtx *kingbaselog_ctx;
    OutputJsonThreadCtx *ctx;
} LogKingbaseLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonKingbaseLogRequest(JsonBuilder *js, KingbaseTransaction *kingbasetx, KingbaseState *state)
{
	if (NULL == js || NULL == kingbasetx || NULL == state) {
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", kingbasetx->complete);

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

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonKingbaseLogResponse(JsonBuilder *js, KingbaseTransaction *kingbasetx, KingbaseState *state)
{
	if (NULL == js || NULL == kingbasetx || NULL == state || 1 != state->send_key) {
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", kingbasetx->complete);

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

	/* 关闭对象 */
	jb_close(js);
}


/* 请求方向日志函数 */
static int JsonKingbaseLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((KingbaseState *)state)->query_cmd_buffer.len || 1 == SC_ATOMIC_GET(kingbase_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogKingbaseLogThread *thread = (LogKingbaseLogThread *)thread_data;
    KingbaseTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "kingbase", NULL, thread->kingbaselog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "kingbase");
    JsonKingbaseLogRequest(js, tx, (KingbaseState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}


/* 响应方向日志函数 */
static int JsonKingbaseLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((KingbaseState *)state)->send_key || 0 == SC_ATOMIC_GET(kingbase_conf.result)) {
		return TM_ECODE_OK;
	}

    SCEnter();
    LogKingbaseLogThread *thread = (LogKingbaseLogThread *)thread_data;
    KingbaseTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "kingbase", NULL, thread->kingbaselog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "kingbase");
    JsonKingbaseLogResponse(js, tx, (KingbaseState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonKingbaseLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    KingbaseTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonKingbaseLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonKingbaseLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputKingbaseLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogKingbaseFileCtx *kingbaselog_ctx = (LogKingbaseFileCtx *)output_ctx->data;
    SCFree(kingbaselog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputKingbaseLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogKingbaseFileCtx *kingbaselog_ctx = SCCalloc(1, sizeof(*kingbaselog_ctx));
    if (unlikely(kingbaselog_ctx == NULL)) {
        return result;
    }
    kingbaselog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(kingbaselog_ctx);
        return result;
    }
    output_ctx->data = kingbaselog_ctx;
    output_ctx->DeInit = OutputKingbaseLogDeInitCtxSub;

    SCLogInfo("kingbase log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_KINGBASE);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonKingbaseLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogKingbaseLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for kingbase.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->kingbaselog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->kingbaselog_ctx->eve_ctx);
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
static TmEcode JsonKingbaseLogThreadDeinit(ThreadVars *t, void *data)
{
    LogKingbaseLogThread *thread = (LogKingbaseLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonKingbaseLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonKingbaseLog", "eve-log.kingbase",
            OutputKingbaseLogInitSub, ALPROTO_KINGBASE, JsonKingbaseLogger, JsonKingbaseLogThreadInit,
            JsonKingbaseLogThreadDeinit, NULL);
}
