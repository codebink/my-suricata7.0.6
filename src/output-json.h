/* Copyright (C) 2007-2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef __OUTPUT_JSON_H__
#define __OUTPUT_JSON_H__

#include "suricata-common.h"
#include "util-buffer.h"
#include "util-logopenfile.h"
#include "output.h"
#include "rust.h"

#include "app-layer-htp-xff.h"
#include "suricata-plugin.h"
#include "cJSON.h"


/*-------------- Flow 相关宏定义和外发日志相关结构体 start -------------- */
#define FLOW_INFO_LEN 64
#define FLOW_TIME_LEN 32
#define FLOW_MAX_DEV_NAME_LEN 32
#define FLOW_TMP_LEN 32
#define FLOW_MAX_KEY_LEN 32
#define FLOW_STACK_SIZE 64
#define FLOW_BUFF_LEN 512
#define FLOW_TCPUDP_LEN 3
#define ALL_UTIME_LEN 64

// 栈结构体
typedef struct FlowStack_ {
    cJSON *data[FLOW_STACK_SIZE];
    int top;
} FlowStack;

#define IP_TCP			6
#define IP_UDP			17

#define FLOW_FREESTR(P) if(NULL != P){free(P); P = NULL;}


//消息头
typedef struct _stFream_head
{
	uint8_t 	ucFreamType;    //事件类型
	uint32_t  	uiFreamDataLen; //数据长度
	char 		data[0];		//数据内容
} stFream_head;

// 事件通用头数据结构
typedef struct _common_header
{
	uint64_t		gen_sec;			//上报时间,秒	
	uint64_t	    gen_usec;			//上报时间,微秒
	uint32_t	    se_src_addr;	    //源IP地址
	char		    sz_srcIp[128];	    //源IP地址(IPV6/IPV4)
	uint32_t	    se_dst_addr;	    //目的IP地址
	char		    sz_dstIp[128];	    //目的IP地址(IPV6/IPV4)
	uint16_t 	    se_src_port;     	//源端口
	uint16_t	    se_dst_port;	    //目的端口
	uint32_t		trans_proto_id;		//传输层协议id
	uint32_t		app_proto_id;		//应用层协议id, 暂时不发
} common_header_t;

//流表数据
typedef struct _flowevent {
	common_header_t event_head;

	//uint16_t Encrypted_traffic;  //是否加密流量

	//uint32_t u32retranpacket;    //重传包数

	uint32_t u32upflow;          //上行流量
	uint32_t u32downflow;        //下行流量

	uint32_t u32uppackets;       //上行包数
	uint32_t u32downpackets;     //下行包数


	//uint32_t u32bleow64;         //小于 64B包的数量
	//uint32_t u32o64b256;         //大于等于64 小于256B包的数量
	//uint32_t u32o256b512;
	//uint32_t u32o512b1k;
	//uint32_t u32o1k;


	uint64_t u64sessionid;      //会话id
	uint64_t u64starttime;      //会话开始时间，时间戳
	uint64_t u64endtime;        //会话结束时间

	char strdevname[FLOW_MAX_DEV_NAME_LEN];      //网口标识
	//char dpi_proto[16];                   //dpi协议
	//u_int16_t  dpi_dada_len;
	//char   data[0];
}flowevent;




/*-------------- Flow 相关宏定义和外发日志相关结构体 end -------------- */


void OutputJsonRegister(void);

enum OutputJsonLogDirection {
    LOG_DIR_PACKET = 0,
    LOG_DIR_FLOW,
    LOG_DIR_FLOW_TOCLIENT,
    LOG_DIR_FLOW_TOSERVER,
};

/****/

enum Reconfig_JSON {
   enum_timestamp = 0,
   enum_flow_id,
   enum_event_type,
   enum_src_ip,
   enum_src_port,
   enum_dest_ip,
   enum_dest_port,
   enum_src_mac,
   enum_dest_mac,
   enum_proto,     
   enum_hostname, //10
   enum_http_port,
   enum_url,
   enum_http_user_agent,
   enum_http_content_type,
   enum_http_refer,
   enum_http_method,
   enum_protocol,
   enum_status,
   enum_Cookie,   
   enum_Accept_Language, //20
   enum_Accept_Encoding,
   enum_startTime,
   enum_endTime,
   enum_request,
   enum_response,   //25
   enum_MAX,        //26
};


typedef struct _Reconfig_JSON_MAP_ {
    enum Reconfig_JSON key;
    char htp_value[64]; //htp原始
    char bvm_value[64];
} Reconfig_Http_Json_Map;

/****/

#define JSON_ADDR_LEN 46
#define JSON_PROTO_LEN 16

/* A struct to contain address info for rendering to JSON. */
typedef struct JsonAddrInfo_ {
    char src_ip[JSON_ADDR_LEN];
    char dst_ip[JSON_ADDR_LEN];
    Port sp;
    Port dp;
    char proto[JSON_PROTO_LEN];
} JsonAddrInfo;

extern const JsonAddrInfo json_addr_info_zero;

void JsonAddrInfoInit(const Packet *p, enum OutputJsonLogDirection dir,
        JsonAddrInfo *addr);

/* Suggested output buffer size */
#define JSON_OUTPUT_BUFFER_SIZE 65535

/* helper struct for OutputJSONMemBufferCallback */
typedef struct OutputJSONMemBufferWrapper_ {
    MemBuffer **buffer; /**< buffer to use & expand as needed */
    size_t expand_by;   /**< expand by this size */
} OutputJSONMemBufferWrapper;

typedef struct OutputJsonCommonSettings_
{
    bool include_metadata;
    bool include_community_id;
    bool include_ethernet;
    uint16_t community_id_seed;
} OutputJsonCommonSettings;

/*
 * Global configuration context data
 */
typedef struct OutputJsonCtx_ 
{
    LogFileCtx *file_ctx;
    enum LogFileType json_out;
    OutputJsonCommonSettings cfg;
    HttpXFFCfg *xff_cfg;
    SCEveFileType *plugin;
} OutputJsonCtx;

typedef struct OutputJsonThreadCtx_
{
    OutputJsonCtx *ctx;
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
} OutputJsonThreadCtx;

json_t *SCJsonString(const char *val);

void CreateEveFlowId(JsonBuilder *js, const Flow *f);
void EveFileInfo(JsonBuilder *js, const File *file, const uint64_t tx_id, const uint16_t flags);
void EveTcpFlags(uint8_t flags, JsonBuilder *js);
void EvePacket(const Packet *p, JsonBuilder *js, unsigned long max_length);
JsonBuilder *CreateEveHeader(const Packet *p, enum OutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, OutputJsonCtx *eve_ctx);
JsonBuilder *CreateEveHeaderWithTxId(const Packet *p, enum OutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, uint64_t tx_id, OutputJsonCtx *eve_ctx);
int OutputJSONBuffer(json_t *js, LogFileCtx *file_ctx, MemBuffer **buffer);
int OutputJsonBuilderBuffer(JsonBuilder *js, OutputJsonThreadCtx *ctx);
int OutputJsonBuilderBufferFlow(JsonBuilder *js, OutputJsonThreadCtx *ctx);

//判断http Content-Type 是否有效. prism
int ContentType_IsValid(const char *jstr); 
//对http 构造cjson, 并输出. prism
int OutputJsonBuilderBufferHttp(JsonBuilder *js, OutputJsonThreadCtx *ctx);
//二期事件发送的独立函数，不要改核心函数
int OutputJsonBuilderBufferHttpAll(JsonBuilder *js, OutputJsonThreadCtx *ctx);


OutputInitResult OutputJsonInitCtx(ConfNode *);

OutputInitResult OutputJsonLogInitSub(ConfNode *conf, OutputCtx *parent_ctx);
TmEcode JsonLogThreadInit(ThreadVars *t, const void *initdata, void **data);
TmEcode JsonLogThreadDeinit(ThreadVars *t, void *data);

void EveAddCommonOptions(const OutputJsonCommonSettings *cfg, const Packet *p, const Flow *f,
        JsonBuilder *js, enum OutputJsonLogDirection dir);
void EveAddMetadata(const Packet *p, const Flow *f, JsonBuilder *js);

int OutputJSONMemBufferCallback(const char *str, size_t size, void *data);

OutputJsonThreadCtx *CreateEveThreadCtx(ThreadVars *t, OutputJsonCtx *ctx);
void FreeEveThreadCtx(OutputJsonThreadCtx *ctx);

int ParseTimestamp(char *timestamp, int t_len, struct timeval *tv, int *timezone_offset);

#endif /* __OUTPUT_JSON_H__ */
