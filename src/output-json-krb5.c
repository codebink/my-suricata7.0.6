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
#include "app-layer-krb5.h"

#include "detect-krb5.h"

#include "output.h"
#include "output-json.h"
#include "output-json-krb5.h"


extern Krb5Conf krb5_conf;

typedef struct LogKrb5FileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogKrb5FileCtx;

typedef struct LogKrb5LogThread_ {
    LogKrb5FileCtx *krb5log_ctx;
    OutputJsonThreadCtx *ctx;
} LogKrb5LogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonKrb5LogRequest(JsonBuilder *js, Krb5Transaction *krb5tx)
{
	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", krb5tx->complete);

	/* 设置 cname */
	if (1 == krb5tx->cname_key) {
		jb_set_string(js, "cname", (const char *)(krb5tx->cname));
	}else {
		jb_set_string(js, "cname", "null");
	}

	/* 设置 realm */
	if (1 == krb5tx->realm_key) {
		jb_set_string(js, "realm", (const char *)(krb5tx->realm));
	}else {
		jb_set_string(js, "realm", "null");
	}

	/* 设置 host */
	if (1 == krb5tx->host_key) {
		jb_set_string(js, "host", (const char *)(krb5tx->host));
	}else {
		jb_set_string(js, "host", "null");
	}

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonKrb5LogResponse(JsonBuilder *js, Krb5Transaction *krb5tx)
{

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", krb5tx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonKrb5LoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogKrb5LogThread *thread = (LogKrb5LogThread *)thread_data;
    Krb5Transaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "krb5", NULL, thread->krb5log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "krb5");
    JsonKrb5LogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

#if 0
/* 响应方向日志函数 */
static int JsonKrb5LoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogKrb5LogThread *thread = (LogKrb5LogThread *)thread_data;
    Krb5Transaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "krb5", NULL, thread->krb5log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "krb5");
    JsonKrb5LogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#endif

/* 核心日志发送函数 */
static int JsonKrb5Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    Krb5Transaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonKrb5LoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
    	//认证信息都在请求包中，响应包无用
        //JsonKrb5LoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputKrb5LogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogKrb5FileCtx *krb5log_ctx = (LogKrb5FileCtx *)output_ctx->data;
    SCFree(krb5log_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 TCP */
static OutputInitResult OutputKrb5LogInitSubTcp(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogKrb5FileCtx *krb5log_ctx = SCCalloc(1, sizeof(*krb5log_ctx));
    if (unlikely(krb5log_ctx == NULL)) {
        return result;
    }
    krb5log_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(krb5log_ctx);
        return result;
    }
    output_ctx->data = krb5log_ctx;
    output_ctx->DeInit = OutputKrb5LogDeInitCtxSub;

    SCLogInfo("krb5 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_KRB5);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* log 初始化函数 UDP */
static OutputInitResult OutputKrb5LogInitSubUdp(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogKrb5FileCtx *krb5log_ctx = SCCalloc(1, sizeof(*krb5log_ctx));
    if (unlikely(krb5log_ctx == NULL)) {
        return result;
    }
    krb5log_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(krb5log_ctx);
        return result;
    }
    output_ctx->data = krb5log_ctx;
    output_ctx->DeInit = OutputKrb5LogDeInitCtxSub;

    SCLogInfo("krb5 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_KRB5);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonKrb5LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogKrb5LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for krb5.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->krb5log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->krb5log_ctx->eve_ctx);
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
static TmEcode JsonKrb5LogThreadDeinit(ThreadVars *t, void *data)
{
    LogKrb5LogThread *thread = (LogKrb5LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 TCP */
void JsonKrb5LogRegisterTcp(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonKrb5Log", "eve-log.krb5",
            OutputKrb5LogInitSubTcp, ALPROTO_KRB5, JsonKrb5Logger, JsonKrb5LogThreadInit,
            JsonKrb5LogThreadDeinit, NULL);
}

/* 核心注册函数 UDP */
void JsonKrb5LogRegisterUdp(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonKrb5Log", "eve-log.krb5",
            OutputKrb5LogInitSubUdp, ALPROTO_KRB5, JsonKrb5Logger, JsonKrb5LogThreadInit,
            JsonKrb5LogThreadDeinit, NULL);
}
