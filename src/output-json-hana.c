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
#include "app-layer-hana.h"

#include "detect-hana.h"

#include "output.h"
#include "output-json.h"
#include "output-json-hana.h"


extern HanaConf hana_conf;

typedef struct LogHanaFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogHanaFileCtx;

typedef struct LogHanaLogThread_ {
    LogHanaFileCtx *hanalog_ctx;
    OutputJsonThreadCtx *ctx;
} LogHanaLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonHanaLogRequest(JsonBuilder *js, HanaTransaction *hanatx)
{
	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", hanatx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonHanaLogResponse(JsonBuilder *js, HanaTransaction *hanatx)
{

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", hanatx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonHanaLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogHanaLogThread *thread = (LogHanaLogThread *)thread_data;
    HanaTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "hana", NULL, thread->hanalog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "hana");
    JsonHanaLogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 响应方向日志函数 */
static int JsonHanaLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogHanaLogThread *thread = (LogHanaLogThread *)thread_data;
    HanaTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "hana", NULL, thread->hanalog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "hana");
    JsonHanaLogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonHanaLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    HanaTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonHanaLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonHanaLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputHanaLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogHanaFileCtx *hanalog_ctx = (LogHanaFileCtx *)output_ctx->data;
    SCFree(hanalog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputHanaLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogHanaFileCtx *hanalog_ctx = SCCalloc(1, sizeof(*hanalog_ctx));
    if (unlikely(hanalog_ctx == NULL)) {
        return result;
    }
    hanalog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(hanalog_ctx);
        return result;
    }
    output_ctx->data = hanalog_ctx;
    output_ctx->DeInit = OutputHanaLogDeInitCtxSub;

    SCLogInfo("hana log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HANA);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonHanaLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogHanaLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for hana.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->hanalog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->hanalog_ctx->eve_ctx);
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
static TmEcode JsonHanaLogThreadDeinit(ThreadVars *t, void *data)
{
    LogHanaLogThread *thread = (LogHanaLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonHanaLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonHanaLog", "eve-log.hana",
            OutputHanaLogInitSub, ALPROTO_HANA, JsonHanaLogger, JsonHanaLogThreadInit,
            JsonHanaLogThreadDeinit, NULL);
}
