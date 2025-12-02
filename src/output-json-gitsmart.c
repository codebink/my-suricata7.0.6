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
#include "app-layer-gitsmart.h"

#include "detect-gitsmart.h"

#include "output.h"
#include "output-json.h"
#include "output-json-gitsmart.h"


extern GitsmartConf gitsmart_conf;

typedef struct LogGitsmartFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogGitsmartFileCtx;

typedef struct LogGitsmartLogThread_ {
    LogGitsmartFileCtx *gitsmartlog_ctx;
    OutputJsonThreadCtx *ctx;
} LogGitsmartLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonGitsmartLogRequest(JsonBuilder *js, GitsmartTransaction *gitsmarttx)
{
	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", gitsmarttx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonGitsmartLogResponse(JsonBuilder *js, GitsmartTransaction *gitsmarttx)
{

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", gitsmarttx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonGitsmartLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogGitsmartLogThread *thread = (LogGitsmartLogThread *)thread_data;
    GitsmartTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "gitsmart", NULL, thread->gitsmartlog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "gitsmart");
    JsonGitsmartLogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 响应方向日志函数 */
static int JsonGitsmartLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogGitsmartLogThread *thread = (LogGitsmartLogThread *)thread_data;
    GitsmartTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "gitsmart", NULL, thread->gitsmartlog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "gitsmart");
    JsonGitsmartLogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonGitsmartLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    GitsmartTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonGitsmartLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonGitsmartLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputGitsmartLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogGitsmartFileCtx *gitsmartlog_ctx = (LogGitsmartFileCtx *)output_ctx->data;
    SCFree(gitsmartlog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputGitsmartLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogGitsmartFileCtx *gitsmartlog_ctx = SCCalloc(1, sizeof(*gitsmartlog_ctx));
    if (unlikely(gitsmartlog_ctx == NULL)) {
        return result;
    }
    gitsmartlog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(gitsmartlog_ctx);
        return result;
    }
    output_ctx->data = gitsmartlog_ctx;
    output_ctx->DeInit = OutputGitsmartLogDeInitCtxSub;

    SCLogInfo("gitsmart log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_GITSMART);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonGitsmartLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogGitsmartLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for gitsmart.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->gitsmartlog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->gitsmartlog_ctx->eve_ctx);
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
static TmEcode JsonGitsmartLogThreadDeinit(ThreadVars *t, void *data)
{
    LogGitsmartLogThread *thread = (LogGitsmartLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonGitsmartLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonGitsmartLog", "eve-log.gitsmart",
            OutputGitsmartLogInitSub, ALPROTO_GITSMART, JsonGitsmartLogger, JsonGitsmartLogThreadInit,
            JsonGitsmartLogThreadDeinit, NULL);
}
