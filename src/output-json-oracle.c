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
#include "app-layer-oracle.h"

#include "detect-oracle.h"

#include "output.h"
#include "output-json.h"
#include "output-json-oracle.h"


extern OracleConf oracle_conf;

typedef struct LogOracleFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogOracleFileCtx;

typedef struct LogOracleLogThread_ {
    LogOracleFileCtx *oraclelog_ctx;
    OutputJsonThreadCtx *ctx;
} LogOracleLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonOracleLogRequest(JsonBuilder *js, OracleTransaction *oracletx)
{
	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", oracletx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonOracleLogResponse(JsonBuilder *js, OracleTransaction *oracletx)
{

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", oracletx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonOracleLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogOracleLogThread *thread = (LogOracleLogThread *)thread_data;
    OracleTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "oracle", NULL, thread->oraclelog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "oracle");
    JsonOracleLogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 响应方向日志函数 */
static int JsonOracleLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogOracleLogThread *thread = (LogOracleLogThread *)thread_data;
    OracleTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "oracle", NULL, thread->oraclelog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "oracle");
    JsonOracleLogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonOracleLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    OracleTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonOracleLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonOracleLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputOracleLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogOracleFileCtx *oraclelog_ctx = (LogOracleFileCtx *)output_ctx->data;
    SCFree(oraclelog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputOracleLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogOracleFileCtx *oraclelog_ctx = SCCalloc(1, sizeof(*oraclelog_ctx));
    if (unlikely(oraclelog_ctx == NULL)) {
        return result;
    }
    oraclelog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(oraclelog_ctx);
        return result;
    }
    output_ctx->data = oraclelog_ctx;
    output_ctx->DeInit = OutputOracleLogDeInitCtxSub;

    SCLogInfo("oracle log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_ORACLE);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonOracleLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogOracleLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for oracle.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->oraclelog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->oraclelog_ctx->eve_ctx);
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
static TmEcode JsonOracleLogThreadDeinit(ThreadVars *t, void *data)
{
    LogOracleLogThread *thread = (LogOracleLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonOracleLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonOracleLog", "eve-log.oracle",
            OutputOracleLogInitSub, ALPROTO_ORACLE, JsonOracleLogger, JsonOracleLogThreadInit,
            JsonOracleLogThreadDeinit, NULL);
}
