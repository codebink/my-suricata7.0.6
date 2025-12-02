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
#include "app-layer-mongodb.h"

#include "detect-mongodb.h"

#include "output.h"
#include "output-json.h"
#include "output-json-mongodb.h"


extern MongodbConf mongodb_conf;

typedef struct LogMongodbFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogMongodbFileCtx;

typedef struct LogMongodbLogThread_ {
    LogMongodbFileCtx *mongodblog_ctx;
    OutputJsonThreadCtx *ctx;
} LogMongodbLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonMongodbLogRequest(JsonBuilder *js, MongodbTransaction *mongodbtx)
{
	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", mongodbtx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonMongodbLogResponse(JsonBuilder *js, MongodbTransaction *mongodbtx)
{

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", mongodbtx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonMongodbLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogMongodbLogThread *thread = (LogMongodbLogThread *)thread_data;
    MongodbTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "mongodb", NULL, thread->mongodblog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "mongodb");
    JsonMongodbLogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 响应方向日志函数 */
static int JsonMongodbLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogMongodbLogThread *thread = (LogMongodbLogThread *)thread_data;
    MongodbTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "mongodb", NULL, thread->mongodblog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "mongodb");
    JsonMongodbLogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonMongodbLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    MongodbTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonMongodbLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
        JsonMongodbLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputMongodbLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogMongodbFileCtx *mongodblog_ctx = (LogMongodbFileCtx *)output_ctx->data;
    SCFree(mongodblog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputMongodbLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogMongodbFileCtx *mongodblog_ctx = SCCalloc(1, sizeof(*mongodblog_ctx));
    if (unlikely(mongodblog_ctx == NULL)) {
        return result;
    }
    mongodblog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(mongodblog_ctx);
        return result;
    }
    output_ctx->data = mongodblog_ctx;
    output_ctx->DeInit = OutputMongodbLogDeInitCtxSub;

    SCLogInfo("mongodb log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MONGODB);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonMongodbLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogMongodbLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for mongodb.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->mongodblog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->mongodblog_ctx->eve_ctx);
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
static TmEcode JsonMongodbLogThreadDeinit(ThreadVars *t, void *data)
{
    LogMongodbLogThread *thread = (LogMongodbLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonMongodbLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonMongodbLog", "eve-log.mongodb",
            OutputMongodbLogInitSub, ALPROTO_MONGODB, JsonMongodbLogger, JsonMongodbLogThreadInit,
            JsonMongodbLogThreadDeinit, NULL);
}
