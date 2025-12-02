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
#include "app-layer-db2.h"

#include "detect-db2.h"

#include "output.h"
#include "output-json.h"
#include "output-json-db2.h"


extern Db2Conf db2_conf;

typedef struct LogDb2FileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogDb2FileCtx;

typedef struct LogDb2LogThread_ {
    LogDb2FileCtx *db2log_ctx;
    OutputJsonThreadCtx *ctx;
} LogDb2LogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonDb2LogRequest(JsonBuilder *js, Db2Transaction *db2tx)
{
	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", db2tx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonDb2LogResponse(JsonBuilder *js, Db2Transaction *db2tx)
{

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", db2tx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonDb2LoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogDb2LogThread *thread = (LogDb2LogThread *)thread_data;
    Db2Transaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "db2", NULL, thread->db2log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "db2");
    JsonDb2LogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 响应方向日志函数 */
static int JsonDb2LoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogDb2LogThread *thread = (LogDb2LogThread *)thread_data;
    Db2Transaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "db2", NULL, thread->db2log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "db2");
    JsonDb2LogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonDb2Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    Db2Transaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonDb2LoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonDb2LoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputDb2LogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogDb2FileCtx *db2log_ctx = (LogDb2FileCtx *)output_ctx->data;
    SCFree(db2log_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputDb2LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogDb2FileCtx *db2log_ctx = SCCalloc(1, sizeof(*db2log_ctx));
    if (unlikely(db2log_ctx == NULL)) {
        return result;
    }
    db2log_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(db2log_ctx);
        return result;
    }
    output_ctx->data = db2log_ctx;
    output_ctx->DeInit = OutputDb2LogDeInitCtxSub;

    SCLogInfo("db2 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DB2);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonDb2LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDb2LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for db2.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->db2log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->db2log_ctx->eve_ctx);
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
static TmEcode JsonDb2LogThreadDeinit(ThreadVars *t, void *data)
{
    LogDb2LogThread *thread = (LogDb2LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonDb2LogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonDb2Log", "eve-log.db2",
            OutputDb2LogInitSub, ALPROTO_DB2, JsonDb2Logger, JsonDb2LogThreadInit,
            JsonDb2LogThreadDeinit, NULL);
}
