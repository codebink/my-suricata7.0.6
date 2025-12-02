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
#include "app-layer-radius.h"

#include "detect-radius.h"

#include "output.h"
#include "output-json.h"
#include "output-json-radius.h"


extern RadiusConf radius_conf;

typedef struct LogRadiusFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogRadiusFileCtx;

typedef struct LogRadiusLogThread_ {
    LogRadiusFileCtx *radiuslog_ctx;
    OutputJsonThreadCtx *ctx;
} LogRadiusLogThread;


/* 模块自用和 alert 模块使用的函数 */
void JsonRadiusLogRequest(JsonBuilder *js, RadiusTransaction *radiustx)
{
	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", radiustx->complete);

	/* 设置 user_name */
	if (1 == radiustx->user_name_key) {
		jb_set_string(js, "user_name", radiustx->user_name);
	}else {
		jb_set_string(js, "user_name", "null");
	}
	
	/* 设置 nas_ip */
	if (1 == radiustx->nas_ip_key) {
		jb_set_string(js, "nas_ip", radiustx->nas_ip);
	}else {
		jb_set_string(js, "nas_ip", "null");
	}

	/* 设置 nas_port */
	if (1 == radiustx->nas_port_key) {
		jb_set_uint(js, "nas_port", radiustx->nas_port);
	}else {
		jb_set_uint(js, "nas_port", 0);
	}

	/* 设置 called_station_mac */
	if (1 == radiustx->called_station_mac_key) {
		jb_set_string(js, "called_station_mac", radiustx->called_station_mac);
	}else {
		jb_set_string(js, "called_station_mac", "null");
	}

	/* 设置 calling_station_mac */
	if (1 == radiustx->calling_station_mac_key) {
		jb_set_string(js, "calling_station_mac", radiustx->calling_station_mac);
	}else {
		jb_set_string(js, "calling_station_mac", "null");
	}

	/* 设置 radius_passwd */
	if (1 == radiustx->radius_passwd_key) {
		jb_set_string(js, "radius_passwd", radiustx->radius_passwd);
	}else {
		jb_set_string(js, "radius_passwd", "null");
	}

	/* 关闭对象 */
	jb_close(js);
}

/* 模块自用和 alert 模块使用的函数 */
void JsonRadiusLogResponse(JsonBuilder *js, RadiusTransaction *radiustx)
{

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	jb_set_bool(js, "complete", radiustx->complete);

	/* 关闭对象 */
	jb_close(js);
}

/* 请求方向日志函数 */
static int JsonRadiusLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogRadiusLogThread *thread = (LogRadiusLogThread *)thread_data;
    RadiusTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "radius", NULL, thread->radiuslog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "radius");
    JsonRadiusLogRequest(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

#if 0
/* 响应方向日志函数 */
static int JsonRadiusLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    LogRadiusLogThread *thread = (LogRadiusLogThread *)thread_data;
    RadiusTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "radius", NULL, thread->radiuslog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "radius");
    JsonRadiusLogResponse(js, tx);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}
#endif

/* 核心日志发送函数 */
static int JsonRadiusLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *vtx, uint64_t tx_id)
{
    SCEnter();
    RadiusTransaction *tx = vtx;
    if (tx->is_request && tx->done) {
        JsonRadiusLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } else if (!tx->is_request && tx->done) {
		//认证信息都在请求包中，响应包无用
		//JsonRadiusLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log 反初始化函数 */
static void OutputRadiusLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogRadiusFileCtx *radiuslog_ctx = (LogRadiusFileCtx *)output_ctx->data;
    SCFree(radiuslog_ctx);
    SCFree(output_ctx);
}

/* log 初始化函数 */
static OutputInitResult OutputRadiusLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogRadiusFileCtx *radiuslog_ctx = SCCalloc(1, sizeof(*radiuslog_ctx));
    if (unlikely(radiuslog_ctx == NULL)) {
        return result;
    }
    radiuslog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(radiuslog_ctx);
        return result;
    }
    output_ctx->data = radiuslog_ctx;
    output_ctx->DeInit = OutputRadiusLogDeInitCtxSub;

    SCLogInfo("radius log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_RADIUS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* 线程初始化函数 */
static TmEcode JsonRadiusLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogRadiusLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for radius.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->radiuslog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->radiuslog_ctx->eve_ctx);
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
static TmEcode JsonRadiusLogThreadDeinit(ThreadVars *t, void *data)
{
    LogRadiusLogThread *thread = (LogRadiusLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonRadiusLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonRadiusLog", "eve-log.radius",
            OutputRadiusLogInitSub, ALPROTO_RADIUS, JsonRadiusLogger, JsonRadiusLogThreadInit,
            JsonRadiusLogThreadDeinit, NULL);
}
