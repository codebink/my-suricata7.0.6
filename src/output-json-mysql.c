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
#include "app-layer-mysql.h"

#include "detect-mysql.h"

#include "output.h"
#include "output-json.h"
#include "output-json-mysql.h"


extern MysqlConf mysql_conf;

typedef struct LogMysqlFileCtx_
{
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogMysqlFileCtx;

typedef struct LogMysqlLogThread_
{
    LogMysqlFileCtx *mysqllog_ctx;
    OutputJsonThreadCtx *ctx;
} LogMysqlLogThread;


/* 模块自用和 alert模块使用的函数 */
void JsonMysqlLogRequest(JsonBuilder *js, MysqlTransaction *mysqltx, MysqlState *state)
{
	if (NULL == js || NULL == mysqltx || NULL == state)
	{
		return;
	}

	/* 转义 \" */
	JB_SET_STRING(js, "type", "request");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", mysqltx->complete);

	/* 设置 version */
	if (1 == state->version_key)
	{
		jb_set_string_from_bytes(js, "version", (const uint8_t *)(state->version), state->version_len);
	}
	else
	{
		jb_set_string_from_bytes(js, "version", (const uint8_t *)"null", 4);
	}

	/* 设置 user */
	if (1 == state->user_key)
	{
		jb_set_string_from_bytes(js, "user", (const uint8_t *)(state->user), state->user_len);
	}
	else
	{
		jb_set_string_from_bytes(js, "user", (const uint8_t *)"null", 4);
	}

	/* 设置 passwd */
	if (1 == state->passwd_key)
	{
		jb_set_string_from_bytes(js, "passwd", (const uint8_t *)(state->passwd), state->passwd_len);
	}
	else
	{
		jb_set_string_from_bytes(js, "passwd", (const uint8_t *)"null", 4);
	}

	/* 设置 db_name */
	if (0 < state->db_name.len)
	{
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)(state->db_name.buffer), state->db_name.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)"null", 4);
	}

	/* 设置 table_name */
	if (0 < state->table_name.len)
	{
		jb_set_string_from_bytes(js, "table_name", (const uint8_t *)(state->table_name.buffer), state->table_name.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "table_name", (const uint8_t *)"null", 4);
	}

	/* 设置 sql_cmd */
	if (0 < state->query_cmd_buffer.len) {
		jb_set_string_from_bytes(js, "sql_cmd", (const uint8_t *)(state->query_cmd_buffer.buffer), state->query_cmd_buffer.len);
	}else {
		jb_set_string_from_bytes(js, "sql_cmd", (const uint8_t *)"null", 4);
	}

	/* 设置 fields */
	if (0 < state->fields.len)
	{
		jb_set_string_from_bytes(js, "fields", (const uint8_t *)(state->fields.buffer), state->fields.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "fields", (const uint8_t *)"null", 4);
	}

	/* 设置 result_set */
	if (0 < state->result_set_buffer.len)
	{
		jb_set_string_from_bytes(js, "result_set", (const uint8_t *)(state->result_set_buffer.buffer), state->result_set_buffer.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "result_set", (const uint8_t *)"null", 4);
	}

	/* 关闭对象 */
	jb_close(js);
}


/* 模块自用和 alert 模块使用的函数 */
void JsonMysqlLogResponse(JsonBuilder *js, MysqlTransaction *mysqltx, MysqlState *state)
{
	if (NULL == js || NULL == mysqltx || NULL == state || 1 != state->send_key)
	{
		return;
	}

	JB_SET_STRING(js, "type", "response");

	/* 打开对象 */
	jb_open_object(js, "application");

	/* 设置对象字段 */
	//jb_set_bool(js, "complete", mysqltx->complete);

	/* 设置 version */
	if (1 == state->version_key)
	{
		jb_set_string_from_bytes(js, "version", (const uint8_t *)(state->version), state->version_len);
	}
	else
	{
		jb_set_string_from_bytes(js, "version", (const uint8_t *)"null", 4);
	}

	/* 设置 user */
	if (1 == state->user_key)
	{
		jb_set_string_from_bytes(js, "user", (const uint8_t *)(state->user), state->user_len);
	}
	else
	{
		jb_set_string_from_bytes(js, "user", (const uint8_t *)"null", 4);
	}

	/* 设置 passwd */
	if (1 == state->passwd_key)
	{
		jb_set_string_from_bytes(js, "passwd", (const uint8_t *)(state->passwd), state->passwd_len);
	}
	else
	{
		jb_set_string_from_bytes(js, "passwd", (const uint8_t *)"null", 4);
	}

	/* 设置 db_name */
	if (0 < state->db_name.len)
	{
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)(state->db_name.buffer), state->db_name.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "db_name", (const uint8_t *)"null", 4);
	}

	/* 设置 table_name */
	if (0 < state->table_name.len)
	{
		jb_set_string_from_bytes(js, "table_name", (const uint8_t *)(state->table_name.buffer), state->table_name.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "table_name", (const uint8_t *)"null", 4);
	}

	/* 设置 sql_cmd */
	if (0 < state->query_cmd_buffer.len)
	{
		jb_set_string_from_bytes(js, "sql_cmd", (const uint8_t *)(state->query_cmd_buffer.buffer), state->query_cmd_buffer.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "sql_cmd", (const uint8_t *)"null", 4);
	}

	/* 设置 fields */
	if (0 < state->fields.len)
	{
		jb_set_string_from_bytes(js, "fields", (const uint8_t *)(state->fields.buffer), state->fields.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "fields", (const uint8_t *)"null", 4);
	}

	/* 设置 result_set */
	if (0 < state->result_set_buffer.len)
	{
		jb_set_string_from_bytes(js, "result_set", (const uint8_t *)(state->result_set_buffer.buffer), state->result_set_buffer.len);
	}
	else
	{
		jb_set_string_from_bytes(js, "result_set", (const uint8_t *)"null", 4);
	}

	/* 关闭对象 */
	jb_close(js);
}


/* 请求方向日志函数 */
static int JsonMysqlLoggerToServer(ThreadVars *tv, void *thread_data,  const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 0 >= ((MysqlState *)state)->query_cmd_buffer.len || 1 == SC_ATOMIC_GET(mysql_conf.result))
	{
		return TM_ECODE_OK;
	}

    SCEnter();
    LogMysqlLogThread *thread = (LogMysqlLogThread *)thread_data;
    MysqlTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOSERVER, "mysql", NULL, thread->mysqllog_ctx->eve_ctx);
    if (unlikely(js == NULL))
    {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "mysql");
    JsonMysqlLogRequest(js, tx, (MysqlState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}


/* 响应方向日志函数 */
static int JsonMysqlLoggerToClient(ThreadVars *tv, void *thread_data,const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
	/* 只有完整的解析了响应才发送日志 */
	if (NULL == state || 1 != ((MysqlState *)state)->send_key || 0 == SC_ATOMIC_GET(mysql_conf.result))
	{
		return TM_ECODE_OK;
	}

    SCEnter();
    LogMysqlLogThread *thread = (LogMysqlLogThread *)thread_data;
    MysqlTransaction *tx = vtx;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW_TOCLIENT, "mysql", NULL, thread->mysqllog_ctx->eve_ctx);
    if (unlikely(js == NULL))
    {
        return TM_ECODE_OK;
    }

    jb_open_object(js, "mysql");
    JsonMysqlLogResponse(js, tx, (MysqlState *)state);
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    SCReturnInt(TM_ECODE_OK);
}

/* 核心日志发送函数 */
static int JsonMysqlLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state, void *vtx, uint64_t tx_id)
{
    SCEnter();
    MysqlTransaction *tx = vtx;
    if (tx->is_request && tx->done)
    {
        JsonMysqlLoggerToServer(tv, thread_data, p, f, state, vtx, tx_id);
    } 
    else if (!tx->is_request && tx->done)
    {
        JsonMysqlLoggerToClient(tv, thread_data, p, f, state, vtx, tx_id);
    }
    SCReturnInt(TM_ECODE_OK);
}

/* log反初始化函数 */
static void OutputMysqlLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogMysqlFileCtx *mysqllog_ctx = (LogMysqlFileCtx *)output_ctx->data;
    SCFree(mysqllog_ctx);
    SCFree(output_ctx);
}

/* log初始化函数 */
static OutputInitResult OutputMysqlLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *json_ctx = parent_ctx->data;

    LogMysqlFileCtx *mysqllog_ctx = SCCalloc(1, sizeof(*mysqllog_ctx));
    if (unlikely(mysqllog_ctx == NULL))
    {
        return result;
    }
    mysqllog_ctx->eve_ctx = json_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL))
    {
        SCFree(mysqllog_ctx);
        return result;
    }
    output_ctx->data = mysqllog_ctx;
    output_ctx->DeInit = OutputMysqlLogDeInitCtxSub;

    SCLogInfo("mysql log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MYSQL);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}


/* 线程初始化函数 */
static TmEcode JsonMysqlLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogMysqlLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL))
    {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) 
    {
        SCLogDebug("Error getting context for mysql.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->mysqllog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->mysqllog_ctx->eve_ctx);
    if (thread->ctx == NULL) 
    {
        goto error_exit;
    }

    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

/* 线程反初始化函数 */
static TmEcode JsonMysqlLogThreadDeinit(ThreadVars *t, void *data)
{
    LogMysqlLogThread *thread = (LogMysqlLogThread *)data;
    if (thread == NULL)
    {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

/* 核心注册函数 */
void JsonMysqlLogRegister(void)
{
    OutputRegisterTxSubModule(  LOGGER_JSON_TX, "eve-log", "JsonMysqlLog", "eve-log.mysql",
                                OutputMysqlLogInitSub, ALPROTO_MYSQL, JsonMysqlLogger, 
                                JsonMysqlLogThreadInit, JsonMysqlLogThreadDeinit, NULL);
}
