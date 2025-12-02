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
#include "app-layer-ldap.h"

#include "detect-ldap.h"

#include "output.h"
#include "output-json.h"
#include "output-json-ldap.h"


extern LdapConf ldap_conf;

typedef struct LogLdapFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogLdapFileCtx;

typedef struct LogLdapLogThread_ {
    LogLdapFileCtx *ldaplog_ctx;
    OutputJsonThreadCtx *ctx;
} LogLdapLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonLdapLogRequest(JsonBuilder *js, LdapTransaction *ldaptx)
{
	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段，进度暂时无用 */
	//jb_set_bool(js, "complete", ldaptx->complete);

	/* 设置用户名 */
	if (1 == ldaptx->user_name_key) {
		jb_set_string(js, "user_name", (const char *)(ldaptx->user_name));
	}else {
		jb_set_string(js, "user_name", "null");
	}
	
	/* 设置域名 */
	if (1 == ldaptx->domain_name_key) {
		jb_set_string(js, "domain_name", (const char *)(ldaptx->domain_name));
	}else {
		jb_set_string(js, "domain_name", "null");
	}

	/* 设置密码，只有在简 simple 单认证模式时，才能取出密码 */
	if (1 == ldaptx->passwd_key) {
		jb_set_string(js, "passwd", (const char *)(ldaptx->passwd));
	}else {
		jb_set_string(js, "passwd", "null");
	}

	/* 设置请求名称，只有基于 TLS 协议的 LDAP 才会使用该字段 */
	if (1 == ldaptx->req_name_key) {
		jb_set_string(js, "req_name", (const char *)(ldaptx->req_name));
	}else {
		jb_set_string(js, "req_name", "null");
	}

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonLdapLogResponse(JsonBuilder *js, LdapTransaction *ldaptx)
{

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", ldaptx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonLdapLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogLdapLogThread *thread = (LogLdapLogThread *)thread_data;
    LdapTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "ldap", NULL, thread->ldaplog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "ldap");
    JsonLdapLogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

#if 0
/* 响应方向日志函数 */
static int JsonLdapLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogLdapLogThread *thread = (LogLdapLogThread *)thread_data;
    LdapTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "ldap", NULL, thread->ldaplog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "ldap");
    JsonLdapLogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#endif

/* 核心日志发送函数 */
static int JsonLdapLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    LdapTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonLdapLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
    	//ldap 认证信息都在请求包中，响应包无用
        //JsonLdapLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputLdapLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogLdapFileCtx *ldaplog_ctx = (LogLdapFileCtx *)output_ctx->data;
    SCFree(ldaplog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputLdapLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogLdapFileCtx *ldaplog_ctx = SCCalloc(1, sizeof(*ldaplog_ctx));
    if (unlikely(ldaplog_ctx == NULL)) {
        return result;
    }
    ldaplog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ldaplog_ctx);
        return result;
    }
    output_ctx->data = ldaplog_ctx;
    output_ctx->DeInit = OutputLdapLogDeInitCtxSub;

    SCLogInfo("ldap log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_LDAP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonLdapLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogLdapLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for ldap.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->ldaplog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->ldaplog_ctx->eve_ctx);
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
static TmEcode JsonLdapLogThreadDeinit(ThreadVars *t, void *data)
{
    LogLdapLogThread *thread = (LogLdapLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonLdapLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonLdapLog", "eve-log.ldap",
            OutputLdapLogInitSub, ALPROTO_LDAP, JsonLdapLogger, JsonLdapLogThreadInit,
            JsonLdapLogThreadDeinit, NULL);
}
