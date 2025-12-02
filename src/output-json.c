/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 *
 * Logs detection and monitoring events in JSON format.
 *
 */

#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-var-name.h"
#include "util-macset.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "app-layer-parser.h"
#include "util-classification-config.h"
#include "util-syslog.h"
#include "output-eve-syslog.h"

#include "output.h"
#include "output-json.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-logopenfile.h"
#include "util-log-redis.h"
#include "util-device.h"
#include "util-validate.h"
#include "util-plugin.h"

#include "flow-var.h"
#include "flow-bit.h"
#include "flow-storage.h"

#include "source-pcap-file-helper.h"

#include "suricata-plugin.h"
#include "app-layer-htp.h"
#include "htp/htp_connection_parser_private.h"

#define DEFAULT_LOG_FILENAME "eve.json"
#define MODULE_NAME "OutputJSON"

#define MAX_JSON_SIZE 2048

extern FlowConf flow_conf;


//事件类型
enum eventType 
{
	EVENT_TYPE_SIGN=0,
	EVENT_TYPE_CONTROL,
	EVENT_TYPE_MALICIOUS_URL,
	EVENT_TYPE_MALICIOUS_IP,
	EVENT_TYPE_MALICIOUS_FILE,
	EVENT_TYPE_UNKNOWN_MALICIOUS_FILE,
	EVENT_TYPE_WHITE_FILE,
	EVENT_TYPE_BLOCK,
	EVENT_TYPE_PCAP,	
	EVENT_TYPE_DPI_LINK_STAT,	
	EVENT_TYPE_DPI_BYTE_STAT,	
	EVENT_TYPE_COMMAND_SIGN,
	EVENT_TYPE_COMMAND_MALICIOUS_URL,
	EVENT_TYPE_COMMAND_MALICIOUS_IP,
	EVENT_TYPE_COMMAND_MALICIOUS_FILE,
	EVENT_TYPE_COMMAND_BLOCK,
    EVENT_TYPE_FLOW,
    EVENT_TYPE_FLOW_ABNORMAL,
    EVENT_TYPE_URL_AUTO_STUDY, 
	EVENT_TYPE_DNS,
	EVENT_TYPE_PROXY,
	EVENT_TYPE_FULLFLOW,
	EVENT_TYPE_ARP,
	MAX_EVENT_NUM
};

static void OutputJsonDeInitCtx(OutputCtx *);
static void CreateEveCommunityFlowId(JsonBuilder *js, const Flow *f, const uint16_t seed);
static int CreateJSONEther(
        JsonBuilder *parent, const Packet *p, const Flow *f, enum OutputJsonLogDirection dir);

static const char *TRAFFIC_ID_PREFIX = "traffic/id/";
static const char *TRAFFIC_LABEL_PREFIX = "traffic/label/";
static size_t traffic_id_prefix_len = 0;
static size_t traffic_label_prefix_len = 0;

Reconfig_Http_Json_Map *g_reconfig_http_map_ptr[]= {
   [enum_url]       = &(Reconfig_Http_Json_Map){.key = enum_url, .htp_value = "url", .bvm_value = "url"},
   [enum_src_ip]    = &(Reconfig_Http_Json_Map){.key = enum_src_ip, .htp_value = "src_ip", .bvm_value = "srcIp"},
   [enum_src_port]  = &(Reconfig_Http_Json_Map){.key = enum_src_port, .htp_value = "src_port", .bvm_value = "srcPort"},
   [enum_dest_ip]   = &(Reconfig_Http_Json_Map){.key = enum_dest_ip, .htp_value = "dest_ip", .bvm_value = "dstIp"},
   [enum_dest_port] = &(Reconfig_Http_Json_Map){.key = enum_dest_port, .htp_value = "dest_port", .bvm_value = "dstPort"},
   [enum_startTime] = &(Reconfig_Http_Json_Map){.key = enum_startTime, .htp_value = "startTime", .bvm_value = "startTime"},  //请求时间戳 字符串类型.
   [enum_endTime]   = &(Reconfig_Http_Json_Map){.key = enum_endTime, .htp_value = "endTime", .bvm_value = "endTime"},      //响应时间戳.字符串类型.
   [enum_request]   = &(Reconfig_Http_Json_Map){.key = enum_request, .htp_value = "request", .bvm_value = "request"},      //请求体.
   [enum_response]  = &(Reconfig_Http_Json_Map){.key = enum_response, .htp_value = "response", .bvm_value = "response"},    //响应体.
   [enum_MAX]       = &(Reconfig_Http_Json_Map){.key = enum_MAX, .htp_value = "", .bvm_value = ""}
};



const JsonAddrInfo json_addr_info_zero;

void OutputJsonRegister (void)
{
    // 注册eve-log日志模块
    // 模块名称：OutputFilestore
    // yaml文件中的配置节点名称：eve-log
    // 输出模块初始化函数：OutputJsonInitCtx
    OutputRegisterModule(MODULE_NAME, "eve-log", OutputJsonInitCtx);

    traffic_id_prefix_len = strlen(TRAFFIC_ID_PREFIX);
    traffic_label_prefix_len = strlen(TRAFFIC_LABEL_PREFIX);

    // Register output file types that use the new eve filetype registration  API.
    // 注册使用新eve文件类型注册API的输出文件类型
    SyslogInitialize();
}

json_t *SCJsonString(const char *val)
{
    if (val == NULL){
        return NULL;
    }
    json_t * retval = json_string(val);
    char retbuf[MAX_JSON_SIZE] = {0};
    if (retval == NULL) {
        uint32_t u = 0;
        uint32_t offset = 0;
        for (u = 0; u < strlen(val); u++) {
            if (isprint(val[u])) {
                PrintBufferData(retbuf, &offset, MAX_JSON_SIZE-1, "%c",
                        val[u]);
            } else {
                PrintBufferData(retbuf, &offset, MAX_JSON_SIZE-1,
                        "\\x%02X", val[u]);
            }
        }
        retbuf[offset] = '\0';
        retval = json_string(retbuf);
    }
    return retval;
}

/* Default Sensor ID value */
static int64_t sensor_id = -1; /* -1 = not defined */

void EveFileInfo(JsonBuilder *jb, const File *ff, const uint64_t tx_id, const uint16_t flags)
{
    jb_set_string_from_bytes(jb, "filename", ff->name, ff->name_len);

    if (ff->sid_cnt > 0) {
        jb_open_array(jb, "sid");
        for (uint32_t i = 0; ff->sid != NULL && i < ff->sid_cnt; i++) {
            jb_append_uint(jb, ff->sid[i]);
        }
        jb_close(jb);
    }

#ifdef HAVE_MAGIC
    if (ff->magic)
        jb_set_string(jb, "magic", (char *)ff->magic);
#endif
    jb_set_bool(jb, "gaps", ff->flags & FILE_HAS_GAPS);
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            JB_SET_STRING(jb, "state", "CLOSED");
            if (ff->flags & FILE_MD5) {
                jb_set_hex(jb, "md5", (uint8_t *)ff->md5, (uint32_t)sizeof(ff->md5));
            }
            if (ff->flags & FILE_SHA1) {
                jb_set_hex(jb, "sha1", (uint8_t *)ff->sha1, (uint32_t)sizeof(ff->sha1));
            }
            break;
        case FILE_STATE_TRUNCATED:
            JB_SET_STRING(jb, "state", "TRUNCATED");
            break;
        case FILE_STATE_ERROR:
            JB_SET_STRING(jb, "state", "ERROR");
            break;
        default:
            JB_SET_STRING(jb, "state", "UNKNOWN");
            break;
    }

    if (ff->flags & FILE_SHA256) {
        jb_set_hex(jb, "sha256", (uint8_t *)ff->sha256, (uint32_t)sizeof(ff->sha256));
    }

    if (flags & FILE_STORED) {
        JB_SET_TRUE(jb, "stored");
        jb_set_uint(jb, "file_id", ff->file_store_id);
    } else {
        JB_SET_FALSE(jb, "stored");
        if (flags & FILE_STORE) {
            JB_SET_TRUE(jb, "storing");
        }
    }

    jb_set_uint(jb, "size", FileTrackedSize(ff));
    if (ff->end > 0) {
        jb_set_uint(jb, "start", ff->start);
        jb_set_uint(jb, "end", ff->end);
    }
    jb_set_uint(jb, "tx_id", tx_id);
}

static void EveAddPacketVars(const Packet *p, JsonBuilder *js_vars)
{
    if (p == NULL || p->pktvar == NULL) {
        return;
    }
    PktVar *pv = p->pktvar;
    bool open = false;
    while (pv != NULL) {
        if (pv->key || pv->id > 0) {
            if (!open) {
                jb_open_array(js_vars, "pktvars");
                open = true;
            }
            jb_start_object(js_vars);

            if (pv->key != NULL) {
                uint32_t offset = 0;
                uint8_t keybuf[pv->key_len + 1];
                PrintStringsToBuffer(keybuf, &offset,
                        sizeof(keybuf),
                        pv->key, pv->key_len);
                uint32_t len = pv->value_len;
                uint8_t printable_buf[len + 1];
                offset = 0;
                PrintStringsToBuffer(printable_buf, &offset,
                        sizeof(printable_buf),
                        pv->value, pv->value_len);
                jb_set_string(js_vars, (char *)keybuf, (char *)printable_buf);
            } else {
                const char *varname = VarNameStoreLookupById(pv->id, VAR_TYPE_PKT_VAR);
                uint32_t len = pv->value_len;
                uint8_t printable_buf[len + 1];
                uint32_t offset = 0;
                PrintStringsToBuffer(printable_buf, &offset,
                        sizeof(printable_buf),
                        pv->value, pv->value_len);
                jb_set_string(js_vars, varname, (char *)printable_buf);
            }
            jb_close(js_vars);
        }
        pv = pv->next;
    }
    if (open) {
        jb_close(js_vars);
    }
}

/**
 * \brief Check if string s has prefix prefix.
 *
 * \retval true if string has prefix
 * \retval false if string does not have prefix
 *
 * TODO: Move to file with other string handling functions.
 */
static bool SCStringHasPrefix(const char *s, const char *prefix)
{
    if (strncmp(s, prefix, strlen(prefix)) == 0) {
        return true;
    }
    return false;
}

static void EveAddFlowVars(const Flow *f, JsonBuilder *js_root, JsonBuilder **js_traffic)
{
    if (f == NULL || f->flowvar == NULL) {
        return;
    }
    JsonBuilder *js_flowvars = NULL;
    JsonBuilder *js_traffic_id = NULL;
    JsonBuilder *js_traffic_label = NULL;
    JsonBuilder *js_flowints = NULL;
    JsonBuilder *js_flowbits = NULL;
    GenericVar *gv = f->flowvar;
    while (gv != NULL) {
        if (gv->type == DETECT_FLOWVAR || gv->type == DETECT_FLOWINT) {
            FlowVar *fv = (FlowVar *)gv;
            if (fv->datatype == FLOWVAR_TYPE_STR && fv->key == NULL) {
                const char *varname = VarNameStoreLookupById(fv->idx,
                        VAR_TYPE_FLOW_VAR);
                if (varname) {
                    if (js_flowvars == NULL) {
                        js_flowvars = jb_new_array();
                        if (js_flowvars == NULL)
                            break;
                    }

                    uint32_t len = fv->data.fv_str.value_len;
                    uint8_t printable_buf[len + 1];
                    uint32_t offset = 0;
                    PrintStringsToBuffer(printable_buf, &offset,
                            sizeof(printable_buf),
                            fv->data.fv_str.value, fv->data.fv_str.value_len);

                    jb_start_object(js_flowvars);
                    jb_set_string(js_flowvars, varname, (char *)printable_buf);
                    jb_close(js_flowvars);
                }
            } else if (fv->datatype == FLOWVAR_TYPE_STR && fv->key != NULL) {
                if (js_flowvars == NULL) {
                    js_flowvars = jb_new_array();
                    if (js_flowvars == NULL)
                        break;
                }

                uint8_t keybuf[fv->keylen + 1];
                uint32_t offset = 0;
                PrintStringsToBuffer(keybuf, &offset,
                        sizeof(keybuf),
                        fv->key, fv->keylen);

                uint32_t len = fv->data.fv_str.value_len;
                uint8_t printable_buf[len + 1];
                offset = 0;
                PrintStringsToBuffer(printable_buf, &offset,
                        sizeof(printable_buf),
                        fv->data.fv_str.value, fv->data.fv_str.value_len);

                jb_start_object(js_flowvars);
                jb_set_string(js_flowvars, (const char *)keybuf, (char *)printable_buf);
                jb_close(js_flowvars);
            } else if (fv->datatype == FLOWVAR_TYPE_INT) {
                const char *varname = VarNameStoreLookupById(fv->idx,
                        VAR_TYPE_FLOW_INT);
                if (varname) {
                    if (js_flowints == NULL) {
                        js_flowints = jb_new_object();
                        if (js_flowints == NULL)
                            break;
                    }
                    jb_set_uint(js_flowints, varname, fv->data.fv_int.value);
                }

            }
        } else if (gv->type == DETECT_FLOWBITS) {
            FlowBit *fb = (FlowBit *)gv;
            const char *varname = VarNameStoreLookupById(fb->idx,
                    VAR_TYPE_FLOW_BIT);
            if (varname) {
                if (SCStringHasPrefix(varname, TRAFFIC_ID_PREFIX)) {
                    if (js_traffic_id == NULL) {
                        js_traffic_id = jb_new_array();
                        if (unlikely(js_traffic_id == NULL)) {
                            break;
                        }
                    }
                    jb_append_string(js_traffic_id, &varname[traffic_id_prefix_len]);
                } else if (SCStringHasPrefix(varname, TRAFFIC_LABEL_PREFIX)) {
                    if (js_traffic_label == NULL) {
                        js_traffic_label = jb_new_array();
                        if (unlikely(js_traffic_label == NULL)) {
                            break;
                        }
                    }
                    jb_append_string(js_traffic_label, &varname[traffic_label_prefix_len]);
                } else {
                    if (js_flowbits == NULL) {
                        js_flowbits = jb_new_array();
                        if (unlikely(js_flowbits == NULL))
                            break;
                    }
                    jb_append_string(js_flowbits, varname);
                }
            }
        }
        gv = gv->next;
    }
    if (js_flowbits) {
        jb_close(js_flowbits);
        jb_set_object(js_root, "flowbits", js_flowbits);
        jb_free(js_flowbits);
    }
    if (js_flowints) {
        jb_close(js_flowints);
        jb_set_object(js_root, "flowints", js_flowints);
        jb_free(js_flowints);
    }
    if (js_flowvars) {
        jb_close(js_flowvars);
        jb_set_object(js_root, "flowvars", js_flowvars);
        jb_free(js_flowvars);
    }

    if (js_traffic_id != NULL || js_traffic_label != NULL) {
        *js_traffic = jb_new_object();
        if (likely(*js_traffic != NULL)) {
            if (js_traffic_id != NULL) {
                jb_close(js_traffic_id);
                jb_set_object(*js_traffic, "id", js_traffic_id);
                jb_free(js_traffic_id);
            }
            if (js_traffic_label != NULL) {
                jb_close(js_traffic_label);
                jb_set_object(*js_traffic, "label", js_traffic_label);
                jb_free(js_traffic_label);
            }
            jb_close(*js_traffic);
        }
    }
}

void EveAddMetadata(const Packet *p, const Flow *f, JsonBuilder *js)
{
    if ((p && p->pktvar) || (f && f->flowvar)) {
        JsonBuilder *js_vars = jb_new_object();
        if (js_vars) {
            if (f && f->flowvar) {
                JsonBuilder *js_traffic = NULL;
                EveAddFlowVars(f, js_vars, &js_traffic);
                if (js_traffic != NULL) {
                    jb_set_object(js, "traffic", js_traffic);
                    jb_free(js_traffic);
                }
            }
            if (p && p->pktvar) {
                EveAddPacketVars(p, js_vars);
            }
            jb_close(js_vars);
            jb_set_object(js, "metadata", js_vars);
            jb_free(js_vars);
        }
    }
}

void EveAddCommonOptions(       const OutputJsonCommonSettings *cfg, const Packet *p, const Flow *f,
                                JsonBuilder *js, enum OutputJsonLogDirection dir)
{
    if (cfg->include_metadata)
    {
        EveAddMetadata(p, f, js);
    }
    
    if (cfg->include_ethernet)
    {
        CreateJSONEther(js, p, f, dir);
    }
    
    if (cfg->include_community_id && f != NULL)
    {
        CreateEveCommunityFlowId(js, f, cfg->community_id_seed);
    }
    
    if (f != NULL && f->tenant_id > 0)
    {
        jb_set_uint(js, "tenant_id", f->tenant_id);
    }
}

/**
 * \brief Jsonify a packet
 *
 * \param p Packet
 * \param js JSON object
 * \param max_length If non-zero, restricts the number of packet data bytes handled.
 */
void EvePacket(const Packet *p, JsonBuilder *js, unsigned long max_length)
{
    unsigned long max_len = max_length == 0 ? GET_PKT_LEN(p) : max_length;
    jb_set_base64(js, "packet", GET_PKT_DATA(p), max_len);

    if (!jb_open_object(js, "packet_info")) {
        return;
    }
    if (!jb_set_uint(js, "linktype", p->datalink)) {
        return;
    }
    jb_close(js);
}

/** \brief jsonify tcp flags field
 *  Only add 'true' fields in an attempt to keep things reasonably compact.
 */
void EveTcpFlags(const uint8_t flags, JsonBuilder *js)
{
    if (flags & TH_SYN)
        JB_SET_TRUE(js, "syn");
    if (flags & TH_FIN)
        JB_SET_TRUE(js, "fin");
    if (flags & TH_RST)
        JB_SET_TRUE(js, "rst");
    if (flags & TH_PUSH)
        JB_SET_TRUE(js, "psh");
    if (flags & TH_ACK)
        JB_SET_TRUE(js, "ack");
    if (flags & TH_URG)
        JB_SET_TRUE(js, "urg");
    if (flags & TH_ECN)
        JB_SET_TRUE(js, "ecn");
    if (flags & TH_CWR)
        JB_SET_TRUE(js, "cwr");
}

void JsonAddrInfoInit(const Packet *p, enum OutputJsonLogDirection dir, JsonAddrInfo *addr)
{
    char srcip[46] = {0}, dstip[46] = {0};
    Port sp, dp;

    switch (dir) {
        case LOG_DIR_PACKET:
            if (PKT_IS_IPV4(p)) {
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                        srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                        dstip, sizeof(dstip));
            } else if (PKT_IS_IPV6(p)) {
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                        srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                        dstip, sizeof(dstip));
            } else {
                /* Not an IP packet so don't do anything */
                return;
            }
            sp = p->sp;
            dp = p->dp;
            break;
        case LOG_DIR_FLOW:
        case LOG_DIR_FLOW_TOSERVER: //client to server . wzz
            if ((PKT_IS_TOSERVER(p))) {
                if (PKT_IS_IPV4(p)) {
                    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                            dstip, sizeof(dstip));
                } else if (PKT_IS_IPV6(p)) {
                    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                            dstip, sizeof(dstip));
                }
                sp = p->sp;
                dp = p->dp;
            } else {
                if (PKT_IS_IPV4(p)) {
                    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                            dstip, sizeof(dstip));
                } else if (PKT_IS_IPV6(p)) {
                    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                            dstip, sizeof(dstip));
                }
                sp = p->dp;
                dp = p->sp;
            }
            break;
        case LOG_DIR_FLOW_TOCLIENT:  //server to client . wzz.
            if ((PKT_IS_TOCLIENT(p))) {
                if (PKT_IS_IPV4(p)) {
                    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                            dstip, sizeof(dstip));
                } else if (PKT_IS_IPV6(p)) {
                    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                            dstip, sizeof(dstip));
                }
                sp = p->sp;
                dp = p->dp;
            } else {
                if (PKT_IS_IPV4(p)) {
                    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p),
                            dstip, sizeof(dstip));
                } else if (PKT_IS_IPV6(p)) {
                    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p),
                            srcip, sizeof(srcip));
                    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p),
                            dstip, sizeof(dstip));
                }
                sp = p->dp;
                dp = p->sp;
            }
            break;
        default:
            DEBUG_VALIDATE_BUG_ON(1);
            return;
    }

    strlcpy(addr->src_ip, srcip, JSON_ADDR_LEN);
    strlcpy(addr->dst_ip, dstip, JSON_ADDR_LEN);

    switch (p->proto) {
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            addr->sp = sp;
            addr->dp = dp;
            break;
        default:
            break;
    }

    if (SCProtoNameValid(IP_GET_IPPROTO(p))) {
        strlcpy(addr->proto, known_proto[IP_GET_IPPROTO(p)], sizeof(addr->proto));
    } else {
        snprintf(addr->proto, sizeof(addr->proto), "%" PRIu32, IP_GET_IPPROTO(p));
    }
}

#define COMMUNITY_ID_BUF_SIZE 64

static bool CalculateCommunityFlowIdv4(const Flow *f,
        const uint16_t seed, unsigned char *base64buf)
{
    struct {
        uint16_t seed;
        uint32_t src;
        uint32_t dst;
        uint8_t proto;
        uint8_t pad0;
        uint16_t sp;
        uint16_t dp;
    } __attribute__((__packed__)) ipv4;

    uint32_t src = f->src.addr_data32[0];
    uint32_t dst = f->dst.addr_data32[0];
    uint16_t sp = f->sp;
    if (f->proto == IPPROTO_ICMP)
        sp = f->icmp_s.type;
    sp = htons(sp);
    uint16_t dp = f->dp;
    if (f->proto == IPPROTO_ICMP)
        dp = f->icmp_d.type;
    dp = htons(dp);

    ipv4.seed = htons(seed);
    if (ntohl(src) < ntohl(dst) || (src == dst && sp < dp)) {
        ipv4.src = src;
        ipv4.dst = dst;
        ipv4.sp = sp;
        ipv4.dp = dp;
    } else {
        ipv4.src = dst;
        ipv4.dst = src;
        ipv4.sp = dp;
        ipv4.dp = sp;
    }
    ipv4.proto = f->proto;
    ipv4.pad0 = 0;

    uint8_t hash[20];
    if (SCSha1HashBuffer((const uint8_t *)&ipv4, sizeof(ipv4), hash, sizeof(hash)) == 1) {
        strlcpy((char *)base64buf, "1:", COMMUNITY_ID_BUF_SIZE);
        unsigned long out_len = COMMUNITY_ID_BUF_SIZE - 2;
        if (Base64Encode(hash, sizeof(hash), base64buf+2, &out_len) == SC_BASE64_OK) {  //base64编码.
            return true;
        }
    }
    return false;
}

static bool CalculateCommunityFlowIdv6(const Flow *f,
        const uint16_t seed, unsigned char *base64buf)
{
    struct {
        uint16_t seed;
        uint32_t src[4];
        uint32_t dst[4];
        uint8_t proto;
        uint8_t pad0;
        uint16_t sp;
        uint16_t dp;
    } __attribute__((__packed__)) ipv6;

    uint16_t sp = f->sp;
    if (f->proto == IPPROTO_ICMPV6)
        sp = f->icmp_s.type;
    sp = htons(sp);
    uint16_t dp = f->dp;
    if (f->proto == IPPROTO_ICMPV6)
        dp = f->icmp_d.type;
    dp = htons(dp);

    ipv6.seed = htons(seed);
    int cmp_r = memcmp(&f->src, &f->dst, sizeof(f->src));
    if ((cmp_r < 0) || (cmp_r == 0 && sp < dp)) {
        memcpy(&ipv6.src, &f->src.addr_data32, 16);
        memcpy(&ipv6.dst, &f->dst.addr_data32, 16);
        ipv6.sp = sp;
        ipv6.dp = dp;
    } else {
        memcpy(&ipv6.src, &f->dst.addr_data32, 16);
        memcpy(&ipv6.dst, &f->src.addr_data32, 16);
        ipv6.sp = dp;
        ipv6.dp = sp;
    }
    ipv6.proto = f->proto;
    ipv6.pad0 = 0;

    uint8_t hash[20];
    if (SCSha1HashBuffer((const uint8_t *)&ipv6, sizeof(ipv6), hash, sizeof(hash)) == 1) {
        strlcpy((char *)base64buf, "1:", COMMUNITY_ID_BUF_SIZE);
        unsigned long out_len = COMMUNITY_ID_BUF_SIZE - 2;
        if (Base64Encode(hash, sizeof(hash), base64buf+2, &out_len) == SC_BASE64_OK) {
            return true;
        }
    }
    return false;
}

static void CreateEveCommunityFlowId(JsonBuilder *js, const Flow *f, const uint16_t seed)
{
    unsigned char buf[COMMUNITY_ID_BUF_SIZE];
    if (f->flags & FLOW_IPV4) {
        if (CalculateCommunityFlowIdv4(f, seed, buf)) {
            jb_set_string(js, "community_id", (const char *)buf);
        }
    } else if (f->flags & FLOW_IPV6) {
        if (CalculateCommunityFlowIdv6(f, seed, buf)) {
            jb_set_string(js, "community_id", (const char *)buf);
        }
    }
}

void CreateEveFlowId(JsonBuilder *js, const Flow *f)
{
    if (f == NULL) {
        return;
    }
    int64_t flow_id = FlowGetId(f);
    jb_set_uint(js, "flow_id", flow_id);
    if (f->parent_id) {
        jb_set_uint(js, "parent_id", f->parent_id);
    }
}

static inline void JSONFormatAndAddMACAddr(JsonBuilder *js, const char *key,
                                   uint8_t *val, bool is_array)
{
    char eth_addr[19];
    (void) snprintf(eth_addr, 19, "%02x:%02x:%02x:%02x:%02x:%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);
    if (is_array) {
        jb_append_string(js, eth_addr);
    } else {
        jb_set_string(js, key, eth_addr);
    }
}

/* only required to traverse the MAC address set */
typedef struct JSONMACAddrInfo {
    JsonBuilder *src, *dst;
} JSONMACAddrInfo;

static int MacSetIterateToJSON(uint8_t *val, MacSetSide side, void *data)
{
    JSONMACAddrInfo *info = (JSONMACAddrInfo*) data;
    if (side == MAC_SET_DST) {
        JSONFormatAndAddMACAddr(info->dst, NULL, val, true);
    } else {
        JSONFormatAndAddMACAddr(info->src, NULL, val, true);
    }
    return 0;
}

static int CreateJSONEther(
        JsonBuilder *js, const Packet *p, const Flow *f, enum OutputJsonLogDirection dir)
{
    if (p != NULL) {
        /* this is a packet context, so we need to add scalar fields */
        if (p->ethh != NULL) {
            jb_open_object(js, "ether");
            uint8_t *src;
            uint8_t *dst;
            switch (dir) {
                case LOG_DIR_FLOW_TOSERVER:
                    // fallthrough
                case LOG_DIR_FLOW:
                    if (PKT_IS_TOCLIENT(p)) {
                        src = p->ethh->eth_dst;
                        dst = p->ethh->eth_src;
                    } else {
                        src = p->ethh->eth_src;
                        dst = p->ethh->eth_dst;
                    }
                    break;
                case LOG_DIR_FLOW_TOCLIENT:
                    if (PKT_IS_TOSERVER(p)) {
                        src = p->ethh->eth_dst;
                        dst = p->ethh->eth_src;
                    } else {
                        src = p->ethh->eth_src;
                        dst = p->ethh->eth_dst;
                    }
                    break;
                case LOG_DIR_PACKET:
                default:
                    src = p->ethh->eth_src;
                    dst = p->ethh->eth_dst;
                    break;
            }
            JSONFormatAndAddMACAddr(js, "src_mac", src, false);
            JSONFormatAndAddMACAddr(js, "dest_mac", dst, false);
            jb_close(js);
        }
    } else if (f != NULL) {
        /* we are creating an ether object in a flow context, so we need to
           append to arrays */
        MacSet *ms = FlowGetStorageById(f, MacSetGetFlowStorageID());
        if (ms != NULL && MacSetSize(ms) > 0) {
            jb_open_object(js, "ether");
            JSONMACAddrInfo info;
            info.dst = jb_new_array();
            info.src = jb_new_array();
            int ret = MacSetForEach(ms, MacSetIterateToJSON, &info);
            if (unlikely(ret != 0)) {
                /* should not happen, JSONFlowAppendMACAddrs is sane */
                jb_free(info.dst);
                jb_free(info.src);
                jb_close(js);
                return ret;
            }
            jb_close(info.dst);
            jb_close(info.src);
            /* case is handling netflow too so may need to revert */
            if (dir == LOG_DIR_FLOW_TOCLIENT) {
                jb_set_object(js, "dest_macs", info.src);
                jb_set_object(js, "src_macs", info.dst);
            } else {
                DEBUG_VALIDATE_BUG_ON(dir != LOG_DIR_FLOW_TOSERVER && dir != LOG_DIR_FLOW);
                jb_set_object(js, "dest_macs", info.dst);
                jb_set_object(js, "src_macs", info.src);
            }
            jb_free(info.dst);
            jb_free(info.src);
            jb_close(js);
        }
    }
    return 0;
}

JsonBuilder *CreateEveHeader(const Packet *p, enum OutputJsonLogDirection dir, const char *event_type, JsonAddrInfo *addr, OutputJsonCtx *eve_ctx)
{
    char timebuf[64];
    const Flow *f = (const Flow *)p->flow;

    JsonBuilder *js = jb_new_object();
    if (unlikely(js == NULL))
    {
        return NULL;
    }

    /* 添加timestamp字段 */
    CreateIsoTimeString(p->ts, timebuf, sizeof(timebuf)); //从数据包中取时间戳.
    jb_set_string(js, "timestamp", timebuf);

    /* 添加flow_id字段 */
    CreateEveFlowId(js, f);

    /* 添加sensor id字段 */
    if (sensor_id >= 0)
    {
        jb_set_uint(js, "sensor_id", sensor_id);
    }

    /* 添加in_iface字段 */
    if (p->livedev) 
    {
        //jb_set_string(js, "in_iface", p->livedev->dev);
		jb_set_string(js, "in_iface", flow_conf.in_iface);
    }

    /* 添加pcap_cnt字段 */
    if (p->pcap_cnt != 0)
    {
        jb_set_uint(js, "pcap_cnt", p->pcap_cnt);
    }
    
    /* 添加event_type字段 */
    if (event_type)
    {
        jb_set_string(js, "event_type", event_type);
    }

    /* 添加vlan字段 */
    if (p->vlan_idx > 0)
    {
        jb_open_array(js, "vlan");
        jb_append_uint(js, p->vlan_id[0]);
        if (p->vlan_idx > 1)
        {
            jb_append_uint(js, p->vlan_id[1]);
        }
        if (p->vlan_idx > 2)
        {
            jb_append_uint(js, p->vlan_id[2]);
        }
        jb_close(js);
    }

    /* 添加五元组字段 */
    JsonAddrInfo addr_info = json_addr_info_zero;
    if (addr == NULL)
    {
        JsonAddrInfoInit(p, dir, &addr_info);
        addr = &addr_info;
    }
    jb_set_string(js, "src_ip", addr->src_ip);
    jb_set_uint(js, "src_port", addr->sp);
    jb_set_string(js, "dest_ip", addr->dst_ip);
    jb_set_uint(js, "dest_port", addr->dp);
    jb_set_string(js, "proto", addr->proto);

    /* 添加icmp协议相关字段 */
    switch (p->proto) 
    {
        case IPPROTO_ICMP:
            if (p->icmpv4h) 
            {
                jb_set_uint(js, "icmp_type", p->icmpv4h->type);
                jb_set_uint(js, "icmp_code", p->icmpv4h->code);
            }
            break;
        case IPPROTO_ICMPV6:
            if (p->icmpv6h) 
            {
                jb_set_uint(js, "icmp_type", p->icmpv6h->type);
                jb_set_uint(js, "icmp_code", p->icmpv6h->code);
            }
            break;
    }

    /* 添加pkt_src字段 */
    jb_set_string(js, "pkt_src", PktSrcToString(p->pkt_src));

    if (eve_ctx != NULL)
    {
        EveAddCommonOptions(&eve_ctx->cfg, p, f, js, dir);
    }

    return js;
}

JsonBuilder *CreateEveHeaderWithTxId(const Packet *p, enum OutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, uint64_t tx_id, OutputJsonCtx *eve_ctx)
{
    JsonBuilder *js = CreateEveHeader(p, dir, event_type, addr, eve_ctx);
    if (unlikely(js == NULL))
        return NULL;

    /* tx id for correlation with other events */
    jb_set_uint(js, "tx_id", tx_id);

    return js;
}

int OutputJSONMemBufferCallback(const char *str, size_t size, void *data)
{
    OutputJSONMemBufferWrapper *wrapper = data;
    MemBuffer **memb = wrapper->buffer;

    if (MEMBUFFER_OFFSET(*memb) + size >= MEMBUFFER_SIZE(*memb)) {
        MemBufferExpand(memb, wrapper->expand_by);
    }

    MemBufferWriteRaw((*memb), str, size);
    return 0;
}

int OutputJSONBuffer(json_t *js, LogFileCtx *file_ctx, MemBuffer **buffer)
{
    if (file_ctx->sensor_name) {
        json_object_set_new(js, "host",
                            json_string(file_ctx->sensor_name));
    }

    if (file_ctx->is_pcap_offline) {
        json_object_set_new(js, "pcap_filename", json_string(PcapFileGetFilename()));
    }

    if (file_ctx->prefix) {
        MemBufferWriteRaw((*buffer), file_ctx->prefix, file_ctx->prefix_len);
    }

    OutputJSONMemBufferWrapper wrapper = {
        .buffer = buffer,
        .expand_by = JSON_OUTPUT_BUFFER_SIZE
    };

    int r = json_dump_callback(js, OutputJSONMemBufferCallback, &wrapper,
            file_ctx->json_flags);
    if (r != 0)
        return TM_ECODE_OK;

    LogFileWrite(file_ctx, *buffer);
    return 0;
}

static uint64_t timeval_to_timestamp(struct timeval *tv) 
{
	uint64_t ret = 0;
	double tmp;
	double timestamp;
	
    timestamp = (double)tv->tv_sec + (double)tv->tv_usec / 1000000.0;
    tmp =  round(timestamp);
	ret = (uint64_t)tmp;

	return ret;
}


// 函数：检查字符串是否是有效的 IPv4 地址
static int is_ipv4(const char *str, uint32_t *ip_addr) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, str, &(sa.sin_addr));
    if (result == 1 && ip_addr != NULL) {
        *ip_addr = sa.sin_addr.s_addr;
    }
    return result != 0;
}

// 函数：检查字符串是否是有效的 IPv6 地址
static int is_ipv6(const char *str) {
    struct sockaddr_in6 sa6;
    int result = inet_pton(AF_INET6, str, &(sa6.sin6_addr));
    return result != 0;
}

// 函数：确定字符串是 IPv4 地址还是 IPv6 地址
static int check_ip_version(const char *ip, uint32_t *ipv4_addr) {
    if (is_ipv4(ip, ipv4_addr)) {
        return 4;
    } else if (is_ipv6(ip)) {
        return 6;
    }

	return -1;
}


int ParseTimestamp(char *timestamp, int t_len, struct timeval *tv, int *timezone_offset) 
{
	if (NULL == timestamp || FLOW_TIME_LEN <=  strlen(timestamp) || 0 >= t_len || FLOW_TIME_LEN <= t_len || NULL == tv || NULL == timezone_offset) {
		return 1;
	}
	
    struct tm tm = {0};
	time_t t;
	const char *tz_ptr = NULL;
    char *usec_ptr = NULL;
    char tz_sign;
    int tz_hours = 0;
	int tz_minutes = 0;
	char temp[FLOW_TIME_LEN] = {0};

    // 提取日期和时间部分
    strncpy(temp, timestamp, strlen(timestamp));

    // 解析日期和时间部分
    if (strptime(temp, "%Y-%m-%dT%H:%M:%S", &tm) == NULL) {
        //perror("strptime failed");
        return 1;
    }

    // 提取微秒部分
    usec_ptr = strchr(timestamp, '.');
    if (usec_ptr) {
        tv->tv_usec = strtol(usec_ptr + 1, NULL, 10);
        // 调整微秒数到6位
        while (strlen(usec_ptr + 1) < 6) {
            tv->tv_usec *= 10;
            usec_ptr++;
        }
    } else {
        tv->tv_usec = 0;
    }

    // 将tm转换为time_t类型的秒数
    t = mktime(&tm);
    
    // 提取时区偏移
    tz_ptr = strchr(timestamp, '+');
    if (tz_ptr == NULL) {
        tz_ptr = strchr(timestamp, '-');
        if (tz_ptr) {
            tz_sign = '-';
            tz_ptr++;
        } else {
            tz_sign = ' ';
            *timezone_offset = 0;
        }
    } else {
        tz_sign = '+';
        tz_ptr++;
    }

    if (tz_sign != ' ') {
        sscanf(tz_ptr, "%02d%02d", &tz_hours, &tz_minutes);
        *timezone_offset = tz_hours * 3600 + tz_minutes * 60;
        if (tz_sign == '-') {
            *timezone_offset = -(*timezone_offset);
        }
        // 转换为 UTC 时间，已经是正确时间了，这时区时间暂时不使用
        //t -= *timezone_offset;  
    } else {
        *timezone_offset = 0;
    }

    // 设置tv_sec
    tv->tv_sec = t;
	
	return 0;
}

// 初始化栈
static void init_stack(FlowStack *stack) {
    stack->top = -1;
}

// 压栈
static int push(FlowStack *stack, cJSON *item) {
    if (stack->top >= FLOW_STACK_SIZE - 1) {
        return 0;
    }
    stack->data[++(stack->top)] = item;
    return 1;
}

// 弹栈
static cJSON *pop(FlowStack *stack) {
    if (stack->top < 0) {
        return NULL;
    }
    return stack->data[(stack->top)--];
}

// 非递归函数，用于查找键值对
static cJSON *iterative_find_key(cJSON *root, const char *key) {
    if (!root || !key) {
        return NULL;
    }

    char tmp_str[FLOW_MAX_KEY_LEN] = {0};
    char tmp_key[FLOW_MAX_KEY_LEN] = {0};

    FlowStack stack;
    init_stack(&stack);
    push(&stack, root);

    cJSON *current_element;

    while ((current_element = pop(&stack)) != NULL) {
        if (current_element->string != NULL) {
            // 异常判断
            if (FLOW_MAX_KEY_LEN <= strlen(current_element->string) || FLOW_MAX_KEY_LEN <= strlen(key)) {
                return NULL;
            }

            // 使对比的两个字符串都有充分的缓存空间不会段错误
            memset(tmp_str, 0, FLOW_MAX_KEY_LEN);
            memset(tmp_key, 0, FLOW_MAX_KEY_LEN);
            memcpy(tmp_str, current_element->string, strlen(current_element->string));
            memcpy(tmp_key, key, strlen(key));

            if (strcmp(tmp_str, tmp_key) == 0) {
                return current_element;
            }
        }

        // 遍历子对象
        cJSON *child = current_element->child;
        while (child != NULL) {
            push(&stack, child);
            child = child->next;
        }
    }

    return NULL;
}



/*
	名字：char * JsonGetValueBasedOnkey(const char *json_str, char *key, char *value, int *value_len)
	功能：解析 json 格式的字符串，根据名称 key，取出值 value
	参数：
		1 char *json_str(传入型参数): json 格式字符串
		2 char *key(传入型参数): json 格式字符串中的具体名称
		3 char *value(传入传出型参数): json 格式规则字符串中的具体字符串
		4 int *value_len(传入传出型参数): 字符串 value 传入传出参数缓冲区的长度，需要在函数调用前分配好缓冲区，函数返回时该参数保存实际长度
	返回:
		char *类型, 传入传出参数 value 字符串地址, 异常时返回 NULL
	时间：2022/02/28
	研发：D.D
	版本：1.0.0.1
*/
static char *JsonGetValueBasedOnkeyFlow(const char *json_str, char *key, char *value, int *value_len) {
	char *tmp_str = NULL;
	int old_len = 0;

    // 初始化输出缓冲区
    old_len = *value_len;
    memset(value, 0, *value_len);

    // 将 JSON 字符串解析为 JSON 对象
    cJSON *root = cJSON_Parse(json_str);
    if (root == NULL) {
        return NULL;
    }

    // 查找指定键的值
    cJSON *val = iterative_find_key(root, key);
    if (val == NULL) {
        cJSON_Delete(root);
        return NULL;
    }

    // 特别处理数组类型的值
    if (cJSON_IsArray(val)) {
        cJSON *element;
        int total_length = 0;
        cJSON_ArrayForEach(element, val) {
            char *data = cJSON_PrintUnformatted(element);
            if (data == NULL) {
                cJSON_Delete(root);
                return NULL;
            }

            int data_length = strlen(data);
            if (total_length + data_length + 1 >= *value_len) {
                cJSON_free(data);
                cJSON_Delete(root);
                return NULL;
            }

            // 将获取的值复制到输出缓冲区
            strcat(value, data);
            strcat(value, ",");
            total_length += data_length + 1;
            cJSON_free(data);
        }
        // 移除最后一个逗号
        value[total_length - 1] = '\0';
        *value_len = total_length - 1;
    } else {
        char *data = cJSON_PrintUnformatted(val);
        if (data == NULL) {
            cJSON_Delete(root);
            return NULL;
        }

        if ((int)strlen(data) >= *value_len) {
            cJSON_free(data);
            cJSON_Delete(root);
            return NULL;
        }

        strncpy(value, data, *value_len - 1);
        *value_len = strlen(data);
        cJSON_free(data);
    }

    cJSON_Delete(root);

	if (1 < strlen(value) && 0x22 == value[0]) {
		/* 返回前去掉两边的转义字符 \" */
		if (3 > strlen(value) || 0x22 != value[strlen(value) - 1]) {
			return NULL;
		}

		/* 提取不包含两边 0x20 的纯字符串 */
		tmp_str = (char *)calloc(strlen(value) + 1, sizeof(char));
		if (NULL == tmp_str) {
			return NULL;
		}
		memcpy(tmp_str, value, strlen(value));
	    memset(value, 0, old_len);	
		memcpy(value, (tmp_str + 1), strlen(tmp_str) - 2);

		FLOW_FREESTR(tmp_str);
	}

	if (0 == strlen(value)) {
		return NULL;
	}else {
    	return value;
	}

}


/***********
 *FUNC:
 * 判断是否 Content-Type 是否属于 "application/json" 或者 "text/xml"
 *
 * 有效返回1 , 其他无效或者失败.
 * ********/
 int ContentType_IsValid(const char * jb_str )
 {
	if (NULL == jb_str) {
		return -1;
	}
 
	int ret = -1;
	char *value = NULL; 
	char *name = NULL;
	cJSON *root = NULL; 
	cJSON *child_item = NULL;
	cJSON *http_item = NULL;
	cJSON *content_type_item = NULL;
	cJSON *response_headers = NULL;
	cJSON *val = NULL;
	cJSON *p_name = NULL;

	/* 获取根节点并判断 */
	root = cJSON_Parse(jb_str); 
	if (NULL == root) {
		return -1;
	}

	/* http Content-Type 关键字匹配则发送. */
	const char *Content_Type_Validkey[]= {
		(const char *){"text/html"}, //仅仅测试用.
		(const char *){"application/json"}, 
		(const char *){"text/xml"}  
	};

	/* 获取 value 并判断异常 */
	http_item = cJSON_GetObjectItem(root, "http");
	if (NULL == http_item) {
		goto LABLE_;
	}

	if(cJSON_IsObject(http_item)) {

		/* 判断请求是否有合规的Content-Type */
		content_type_item = cJSON_GetObjectItem(http_item, "Content-Type");
		if (NULL == content_type_item) {
			goto LABLE_;
		}

		/* 只有指针非空时才能操作 */
		if(cJSON_IsString(content_type_item)) {
			value = cJSON_Print(content_type_item); //带"" 
			if (NULL == value) {
				goto LABLE_;
			}

			/* 异常判断 */
			if(strlen(value) <= strlen(Content_Type_Validkey[0])) {
				ret = -2; //无效.
				goto LABLE_;
			}

			/* 异常判断 */
			if(strlen(value) <= strlen(Content_Type_Validkey[1])) {
				ret = -3; //无效.
				goto LABLE_;
			}

			if(strstr(value, Content_Type_Validkey[0])
				|| strstr(value, Content_Type_Validkey[1])) {

				ret = 1; //有效.
				goto LABLE_;
			}

			/* 释放指针时使用写好防止野指针的宏 */
			FLOW_FREESTR(value);

		}

		/* 判断响应是否有合规的Content-Type  */
		response_headers = cJSON_GetObjectItem(http_item, "response_headers");
		if (NULL == response_headers) {
			goto LABLE_;
		}

		/* 只有指针非空时才能操作 */
		if(cJSON_IsArray(response_headers)) {
			cJSON_ArrayForEach(child_item, response_headers) {
				
			 
				//value = cJSON_GetObjectItem(child_item, "value")->valuestring; //不带 ""
				val = NULL;
				val = cJSON_GetObjectItem(child_item, "value");
				if(NULL == val) { 
					continue; 
				}

				 
				p_name = NULL;
				p_name = cJSON_GetObjectItem(child_item, "name");
				if (NULL == p_name) {
					goto LABLE_;
				}

				name = NULL;
				name = p_name->valuestring; //不带 ""
				if (NULL == name) {
					goto LABLE_;
				}

				/* 循环，使用前你不要释放一下吗，要不就内存泄露了吗 */
				FLOW_FREESTR(value);
				value = cJSON_Print(val); //带"", 因为Content_Type_Validkey[] 都带 \" \"
				if (NULL == value) {
					goto LABLE_;
				}

				/* 异常判断 */
				if (strlen(name) <= strlen("Content-Type")
					|| strlen(value) <= strlen(Content_Type_Validkey[0])
					|| strlen(value) <= strlen(Content_Type_Validkey[1])
					) {
					goto LABLE_;
				}

                 if( (0 == strcmp(name, "Content-Type") )
				 	&& ( strstr(value, Content_Type_Validkey[0]) || strstr(value, Content_Type_Validkey[1]) ) ) {
                     ret = 1; //有效.
                     goto LABLE_;
                 }
			}
		}
	}

LABLE_:

	if(root) {
		cJSON_Delete(root);
	}

	/* 释放指针时使用写好防止野指针的宏 */
	FLOW_FREESTR(value);

	return ret;
}


/*****************
 *FUNC:
 * 构造bvm json  字符串..
 * 成功返回输出json格式字符串长度.
 * ***************/
static int Reconfig_Json(const char *json_str, MemBuffer **buffer)
{
    int ret=-1;
    enum Reconfig_JSON rj;
    char  *outdata=NULL;
    char *data =NULL, tmp[64]={0}; 
    cJSON *root =NULL, *bvm_root=NULL;
    
    if(!json_str )
    {  return ret; }

    if(!(root=cJSON_Parse(json_str)))
    { return ret; }


    if(!(bvm_root=cJSON_CreateObject()))
    { return ret; }

    for(rj=0; rj < enum_MAX; rj++)
    {
        data=NULL;
        cJSON *obj_item = root; 
        switch(rj)
        {
            case enum_url:
            {
                obj_item = cJSON_GetObjectItem(root, "http");
                __attribute__((fallthrough));
            }
            case enum_src_ip:
            case enum_src_port:
            case enum_dest_ip:
            case enum_dest_port:
            case enum_startTime:
            case enum_endTime:
            case enum_request:
            case enum_response:
            {
                if(NULL == obj_item) //无效则后继跳过.
                { break; }

                cJSON *htp_val = cJSON_GetObjectItem(obj_item, g_reconfig_http_map_ptr[rj]->htp_value);
                if(NULL == htp_val){
                    continue;
                }
                //char *data = cJSON_Print(htp_val); wzz 20240815. //去掉前后 \"
                if(cJSON_IsString(htp_val)){
                    data = cJSON_GetStringValue(htp_val);
                }else if(cJSON_IsNumber(htp_val)){
                   //uint32_t num =(uint32_t) cJSON_GetNumberValue(htp_val); 
                   int num = htp_val->valueint; 
                   snprintf(tmp, sizeof(tmp)-1, "%d", num);
                   data = tmp;
                }
                if(NULL == data){
                    cJSON_AddNullToObject(bvm_root, g_reconfig_http_map_ptr[rj]->bvm_value); //对应的key添加null
                    continue;
                }
                cJSON_AddStringToObject(bvm_root, g_reconfig_http_map_ptr[rj]->bvm_value, data); 
               // free(data);
            }                
                break;
            default:
                break;
        }

    }
//
    cJSON *req = cJSON_GetObjectItem(bvm_root, "request");
    cJSON *resp = cJSON_GetObjectItem(bvm_root, "response");
    if( req && resp )
    {
        //outdata = cJSON_Print(bvm_root); wzz 20240815 //去掉cJSON 格式.
        outdata = cJSON_PrintUnformatted(bvm_root);
        if( NULL != outdata ) 
        {
            ret = strlen(outdata);
            MemBufferWriteRaw((*buffer), outdata, (uint32_t)ret);
			
			// 注意：务必释放 cJSON_PrintUnformatted 函数 dump 的内存空间，这是一个容易忽视的内存泄露点
			cJSON_free(outdata);
        }
    }

    cJSON_Delete(root);
    cJSON_Delete(bvm_root);

    return ret;
}


/* 最小范围构造日志 */
int OutputJsonBuilderBufferFlow(JsonBuilder *js, OutputJsonThreadCtx *ctx)
{	
	char value[FLOW_INFO_LEN] = {0};
	int value_len = FLOW_INFO_LEN;
	char *p_ret = NULL;
	char *buff = NULL;
	char *pos = NULL;
	uint32_t buff_len = 0;
	int ret = 0;
	int t_ret = 0;
	stFream_head firhead;
	flowevent streamdata;

	struct timeval tv;
	int timezone_offset;

	uint32_t ipv4_addr = 0;

	LogFileCtx *file_ctx = ctx->file_ctx;
	MemBuffer **buffer = &ctx->buffer;
	if (file_ctx->sensor_name) {
		jb_set_string(js, "host", file_ctx->sensor_name);
	}

	if (file_ctx->is_pcap_offline) {
		jb_set_string(js, "pcap_filename", PcapFileGetFilename());
	}

	jb_close(js);

	MemBufferReset(*buffer);

	if (file_ctx->prefix) {
		MemBufferWriteRaw((*buffer), file_ctx->prefix, file_ctx->prefix_len);
	}

	size_t jslen = jb_len(js);
	if (MEMBUFFER_OFFSET(*buffer) + jslen >= MEMBUFFER_SIZE(*buffer)) {
		MemBufferExpand(buffer, jslen);
	}

	MemBufferWriteRaw((*buffer), jb_ptr(js), jslen);

	/* 分配发送缓冲区 */
	buff_len = sizeof(stFream_head) + sizeof(flowevent);
	buff = (char *)calloc((buff_len + 1), sizeof(char));
	if (NULL == buff) {
		return 1;
	}

	/* 游标指向审计事件缓冲区头部 */
	pos = buff;

	/* 填充消息类型头部 */
	memset(&firhead, 0, sizeof(stFream_head));
	firhead.ucFreamType = EVENT_TYPE_FLOW;
	firhead.uiFreamDataLen = sizeof(flowevent);

	/* 填充消息头部，pos 跳过消息头部 */
	memcpy(buff, &firhead, sizeof(stFream_head));
	pos += sizeof(stFream_head);

	/* 清空消息体，准备填充 */
	memset(&streamdata, 0, sizeof(flowevent));

	/* 从 buff 中取出最小范围的几个需要发送的字段，首先取出 proto 只 发送 TCP 或 UDP flow 事件 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"proto", value, &value_len);
	if (NULL != p_ret) {
		/* 异常判断 */
		if (FLOW_TCPUDP_LEN != strlen(value)) {
			ret = 1;
			goto end_err;
		}

		/* 只有 TCP 和 UDP 才发送 flow 审计事件 */
		if (0 == strncasecmp(value, "tcp", FLOW_TCPUDP_LEN)) {
			streamdata.event_head.trans_proto_id = IP_TCP;
		}else if (0 == strncasecmp(value, "udp", FLOW_TCPUDP_LEN)) {
			/* 一期只发 TCP 协议的 HTTP flow 事件 */
			//streamdata.event_head.trans_proto_id = IP_UDP;
			ret = 1;
			goto end_err;			
		}else {
			ret = 1;
			goto end_err;
		}

	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出应用层协议，如 "http" */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"app_proto", value, &value_len);
	if (NULL != p_ret) {
		t_ret = strlen(value);
		if (4 == t_ret && 0 == strncasecmp(value, "http", 4)) {
			streamdata.event_head.app_proto_id = 5;
		}else {
			/* 一期只发 TCP 协议的 HTTP flow 事件 */
			//streamdata.event_head.app_proto_id = 0;
			ret = 1;
			goto end_err;
		}
	}else {
		ret = 1;
		goto end_err;

	}


	/* 从 buff 中取出时间 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"timestamp", value, &value_len);
	if (NULL != p_ret) {
		t_ret = ParseTimestamp(value, strlen(value), &tv, &timezone_offset);
		if (0 == t_ret) {
			streamdata.event_head.gen_sec = tv.tv_sec;
			streamdata.event_head.gen_usec = tv.tv_usec;
		}else {
			ret = 1;
			goto end_err;
		}
	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出源IP */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	ipv4_addr = 0;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"src_ip", value, &value_len);
	if (NULL != p_ret) {
		t_ret = check_ip_version((const char *)value, &ipv4_addr);
		if (4 == t_ret) {
			streamdata.event_head.se_src_addr = ipv4_addr;
			memcpy(streamdata.event_head.sz_srcIp, value, strlen(value));
		}else if (6 == t_ret) {
			memcpy(streamdata.event_head.sz_srcIp, value, strlen(value));
		}else {
			ret = 1;
			goto end_err;
		}
	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出目的IP */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	ipv4_addr = 0;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"dest_ip", value, &value_len);
	if (NULL != p_ret) {
		t_ret = check_ip_version((const char *)value, &ipv4_addr);
		if (4 == t_ret) {
			streamdata.event_head.se_dst_addr = ipv4_addr;
			memcpy(streamdata.event_head.sz_dstIp, value, strlen(value));
		}else if (6 == t_ret) {
			memcpy(streamdata.event_head.sz_dstIp, value, strlen(value));
		}else {
			ret = 1;
			goto end_err;
		}
	}else {
		ret = 1;
		goto end_err;

	}


	/* 从 buff 中取出源端口 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"src_port", value, &value_len);
	if (NULL != p_ret) {
		streamdata.event_head.se_src_port = atoi(value);
	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出目的端口 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"dest_port", value, &value_len);
	if (NULL != p_ret) {
		streamdata.event_head.se_dst_port = atoi(value);
	}else {
		ret = 1;
		goto end_err;

	}


	/* 从 buff 中取出上行流量 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"bytes_toserver", value, &value_len);
	if (NULL != p_ret) {
		streamdata.u32upflow = atoi(value);
	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出下行流量 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"bytes_toclient", value, &value_len);
	if (NULL != p_ret) {
		streamdata.u32downflow = atoi(value);
	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出上行包数 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"pkts_toserver", value, &value_len);
	if (NULL != p_ret) {
		streamdata.u32uppackets = atoi(value);
	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出下行包数 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"pkts_toclient", value, &value_len);
	if (NULL != p_ret) {
		streamdata.u32downpackets = atoi(value);
	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出会话ID */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"flow_id", value, &value_len);
	if (NULL != p_ret) {
		double double_value = strtod(value, NULL);
		long long int_value = (long long)double_value;
		streamdata.u64sessionid = (uint64_t)int_value;
	}else {
		ret = 1;
		goto end_err;

	}

	/* 从 buff 中取出开始时间 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"start", value, &value_len);
	if (NULL != p_ret) {
		t_ret = ParseTimestamp(value, strlen(value), &tv, &timezone_offset);
		if (0 == t_ret) {
			streamdata.u64starttime = timeval_to_timestamp(&tv);
		}else {
			ret = 1;
			goto end_err;
		}
	}else {
		ret = 1;
		goto end_err;
	}


	/* 从 buff 中取出结束时间 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"end", value, &value_len);
	if (NULL != p_ret) {
		t_ret = ParseTimestamp(value, strlen(value), &tv, &timezone_offset);
		if (0 == t_ret) {
			streamdata.u64endtime = timeval_to_timestamp(&tv);
		}else {
			ret = 1;
			goto end_err;
		}
	}else {
		ret = 1;
		goto end_err;

	}

#if 0
	/* 从 buff 中取出网卡名称 */
	memset(value, 0, FLOW_INFO_LEN);
	value_len = FLOW_INFO_LEN;
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"in_iface", value, &value_len);
	if (NULL != p_ret) {
		if (FLOW_MAX_DEV_NAME_LEN > strlen(value)) {
			memcpy(streamdata.strdevname, value, strlen(value));
		}else {
			ret = 1;
			goto end_err;
		}
	}else {
		ret = 1;
		goto end_err;

	}
#endif

	/* 从 配置文件 中取出网卡名称 */
	memcpy(streamdata.strdevname, flow_conf.in_iface, strlen(flow_conf.in_iface));

	/* 消息体添加到发送 buff */
	memcpy(pos, &streamdata, sizeof(flowevent));

	/* 通过 TCP 发送 */
	LogFileWriteToMgrTcp(file_ctx, buff, buff_len);

	/* 测试用 通过 Redis 发送 */
	//LogFileWriteToMgr(file_ctx, *buffer);

end_err:

	/* 释放动态分配的消息 buff */
	FLOW_FREESTR(buff);

	return ret;
}



int OutputJsonBuilderBufferHttp(JsonBuilder *js, OutputJsonThreadCtx *ctx)
{
	int ret =0;

    LogFileCtx *file_ctx = ctx->file_ctx;
    MemBuffer **buffer = &ctx->buffer;
    //if (file_ctx->sensor_name) {
        //jb_set_string(js, "host", file_ctx->sensor_name);
    //}

    //if (file_ctx->is_pcap_offline) {
        //jb_set_string(js, "pcap_filename", PcapFileGetFilename());
    //}

    jb_close(js);

    MemBufferReset(*buffer);

    if (file_ctx->prefix) {
        MemBufferWriteRaw((*buffer), file_ctx->prefix, file_ctx->prefix_len);
    }

    size_t jslen = jb_len(js);
    if (MEMBUFFER_OFFSET(*buffer) + jslen >= MEMBUFFER_SIZE(*buffer)) {
        MemBufferExpand(buffer, jslen);
    }

    //MemBufferWriteRaw((*buffer), jb_ptr(js), jslen);

    char *jstr = SCCalloc(jslen+1, sizeof(char));
    memcpy(jstr, jb_ptr(js), jslen);

    //判断http 是否有效Content-Type
    if(ContentType_IsValid(jstr) != 1) { 
        SCFree(jstr);
        return 1;
    }

	/* 从 buff 中取出最小范围的几个需要发送的字段 */
    ret = Reconfig_Json(jstr, buffer); //wzz
	if (ret > 0 && buffer) {
	    /* 其他字段获取方式同上 */
        LogFileWrite(file_ctx, *buffer);
    }

	SCFree(jstr);
    return 0;
}

//二期事件发送的独立函数，不要改核心函数
int OutputJsonBuilderBufferHttpAll(JsonBuilder *js, OutputJsonThreadCtx *ctx)
{
	int len = 0;
	char *p_ret = NULL;
	int t_ret = 0;
	int timezone_offset;
	char value[FLOW_INFO_LEN] = {0};
	char u_time[ALL_UTIME_LEN] = {0};
	int value_len = FLOW_INFO_LEN;
	uint64_t timestamp = 0;
	struct timeval tv;

    LogFileCtx *file_ctx = ctx->file_ctx;
    MemBuffer **buffer = &ctx->buffer;
    if (file_ctx->sensor_name) {
        jb_set_string(js, "host", file_ctx->sensor_name);
    }

    if (file_ctx->is_pcap_offline) {
        jb_set_string(js, "pcap_filename", PcapFileGetFilename());
    }

    jb_close(js);

    MemBufferReset(*buffer);
    size_t jslen = jb_len(js);

// for  BVM 判断是否是合规http. by Content-type . 
    char *jstr = SCCalloc(jslen+1, sizeof(char));
    memcpy(jstr, jb_ptr(js), jslen);

    //判断http 是否有效Content-Type , 1 有效，其他无效.
    if(ContentType_IsValid(jstr) != 1) { 
        SCFree(jstr);
        return 1;
    }
    SCFree(jstr);
//
    if (file_ctx->prefix) {
        MemBufferWriteRaw((*buffer), file_ctx->prefix, file_ctx->prefix_len);
    }

    if (MEMBUFFER_OFFSET(*buffer) + jslen >= MEMBUFFER_SIZE(*buffer)) {
        MemBufferExpand(buffer, jslen);
    }

	/* 扩充 32 个字节，用于存储 u_timestamp:1234567890123456 精确到微秒的时间戳*/
	MemBufferExpand(buffer, ALL_UTIME_LEN);
	
    MemBufferWriteRaw((*buffer), jb_ptr(js), jslen);
	
	/* 从 buff 中取出时间 */
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"timestamp", value, &value_len);
	if (NULL != p_ret) {
		t_ret = ParseTimestamp(value, strlen(value), &tv, &timezone_offset);
		if (0 == t_ret) {
			/* 这里已经取出    精确到微妙的时间 */
			timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;

			/* 下面在要发送的 json 日志中添加 int_timestamp 字段 */
			len = snprintf(u_time, sizeof(u_time), ",\"u_timestamp\":\"%lu\"}", timestamp);
			if (strlen(u_time) == (size_t)len) {
				memcpy((char*)((*buffer)->buffer) + (*buffer)->offset - 1, u_time, strlen(u_time));
				(*buffer)->offset += strlen(u_time) - 1; 			
			}else {
				goto end;
			}

		}else {

			goto end;
		}
	}else {

		goto end;
	}
	
	
    LogFileWrite(file_ctx, *buffer);

end:
	
    return 0;
}

int OutputJsonBuilderBuffer(JsonBuilder *js, OutputJsonThreadCtx *ctx)
{
	int len = 0;
	char *p_ret = NULL;
	int t_ret = 0;
	int timezone_offset;
	char value[FLOW_INFO_LEN] = {0};
	char u_time[ALL_UTIME_LEN] = {0};
	int value_len = FLOW_INFO_LEN;
	uint64_t timestamp = 0;
	struct timeval tv;

    LogFileCtx *file_ctx = ctx->file_ctx;
    MemBuffer **buffer = &ctx->buffer;
    if (file_ctx->sensor_name) 
    {
        jb_set_string(js, "host", file_ctx->sensor_name);
    }

    if (file_ctx->is_pcap_offline)
    {
        jb_set_string(js, "pcap_filename", PcapFileGetFilename());
    }
    jb_close(js);

    MemBufferReset(*buffer);

    if (file_ctx->prefix)
    {
        MemBufferWriteRaw((*buffer), file_ctx->prefix, file_ctx->prefix_len);
    }

    size_t jslen = jb_len(js);
    if (MEMBUFFER_OFFSET(*buffer) + jslen >= MEMBUFFER_SIZE(*buffer))
    {
        MemBufferExpand(buffer, jslen);
    }

	/* 扩充 32 个字节，用于存储 u_timestamp:1234567890123456 精确到微秒的时间戳*/
	MemBufferExpand(buffer, ALL_UTIME_LEN);
	
    MemBufferWriteRaw((*buffer), jb_ptr(js), jslen);

	/* 从 buff 中取出时间 */
	p_ret = JsonGetValueBasedOnkeyFlow((const char*)((*buffer)->buffer), (char *)"timestamp", value, &value_len);
	if (NULL != p_ret)
	{
		t_ret = ParseTimestamp(value, strlen(value), &tv, &timezone_offset);
		if (0 == t_ret) 
		{
			/* 这里已经取出    精确到微妙的时间 */
			timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;

			/* 下面在要发送的 json 日志中添加 int_timestamp 字段 */
			len = snprintf(u_time, sizeof(u_time), ",\"u_timestamp\":\"%lu\"}", timestamp);
			if (strlen(u_time) == (size_t)len) {
				memcpy((char*)((*buffer)->buffer) + (*buffer)->offset - 1, u_time, strlen(u_time));
				(*buffer)->offset += strlen(u_time) - 1; 			
			}else {
				goto end;
			}

		}else {

			goto end;
		}
	}else {

		goto end;
	}

	
    LogFileWrite(file_ctx, *buffer);

end:

    return 0;
}

static inline enum LogFileType FileTypeFromConf(const char *typestr)
{
    enum LogFileType log_filetype = LOGFILE_TYPE_NOTSET;

    if (typestr == NULL) 
    {
        log_filetype = LOGFILE_TYPE_FILE;
    }
    else if (strcmp(typestr, "file") == 0 || strcmp(typestr, "regular") == 0)
    {
        log_filetype = LOGFILE_TYPE_FILE;
    } 
    else if (strcmp(typestr, "unix_dgram") == 0)
    {
        log_filetype = LOGFILE_TYPE_UNIX_DGRAM;
    } 
    else if (strcmp(typestr, "unix_stream") == 0)
    {
        log_filetype = LOGFILE_TYPE_UNIX_STREAM;
    } 
    else if (strcmp(typestr, "redis") == 0)
    {
#ifdef HAVE_LIBHIREDIS
        log_filetype = LOGFILE_TYPE_REDIS;
#else
        FatalError("redis JSON output option is not compiled");
#endif
    }
    SCLogDebug("type %s, file type value %d", typestr, log_filetype);
    return log_filetype;
}

static int LogFileTypePrepare( OutputJsonCtx *json_ctx, enum LogFileType log_filetype, ConfNode *conf)
{
    if (log_filetype == LOGFILE_TYPE_FILE 
        || log_filetype == LOGFILE_TYPE_UNIX_DGRAM
        || log_filetype == LOGFILE_TYPE_UNIX_STREAM) 
    {
        // 打开一个通用的输出“日志文件”，它可以是一个常规文件或套接字
        if (SCConfLogOpenGeneric(conf, json_ctx->file_ctx, DEFAULT_LOG_FILENAME, 1) < 0)
        {
            return -1;
        }
        // 注册文件轮换通知标志
        OutputRegisterFileRotationFlag(&json_ctx->file_ctx->rotation_flag);
    }
#ifdef HAVE_LIBHIREDIS
    else if (log_filetype == LOGFILE_TYPE_REDIS) 
    {
        SCLogRedisInit();
        ConfNode *redis_node = ConfNodeLookupChild(conf, "redis");
        if (!json_ctx->file_ctx->sensor_name)
        {
            char hostname[1024];
            gethostname(hostname, 1023);
            json_ctx->file_ctx->sensor_name = SCStrdup(hostname);
        }
        if(json_ctx->file_ctx->sensor_name == NULL)
        {
            return -1;
        }

        if (SCConfLogOpenRedis(redis_node, json_ctx->file_ctx) < 0)
        {
            return -1;
        }
    }
#endif
    else if (log_filetype == LOGFILE_TYPE_PLUGIN) // syslog
    {
        if (json_ctx->file_ctx->threaded) 
        {
            /* Prepare for threaded log output. */
            if (!SCLogOpenThreadedFile(NULL, NULL, json_ctx->file_ctx))
            {
                return -1;
            }
        }
        void *init_data = NULL;
        if (json_ctx->plugin->Init(conf, json_ctx->file_ctx->threaded, &init_data) < 0)
        {
            return -1;
        }
        json_ctx->file_ctx->plugin.plugin = json_ctx->plugin;
        json_ctx->file_ctx->plugin.init_data = init_data;
    }


	/* 初始化 TCP 连接和互斥锁 */
	//FlowTcpConnInit(json_ctx->file_ctx);
	
    return 0;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputInitResult OutputJsonInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    OutputCtx *output_ctx = NULL;

    /* 创建OutputJsonCtx类型的对象, 后续为其成员变量赋值 */
    OutputJsonCtx *json_ctx = SCCalloc(1, sizeof(OutputJsonCtx));
    if (unlikely(json_ctx == NULL)) 
    {
        SCLogDebug("could not create new OutputJsonCtx");
        return result;
    }

    /* First lookup a sensor-name value in this outputs configuration node (deprecated). If that fails, lookup the global one. */
    /* 首先在此输出配置节点（已弃用）中查找sensor-name属性的值。如果失败，则查找全局的 */
    const char *sensor_name = ConfNodeLookupChildValue(conf, "sensor-name");
    if (sensor_name != NULL)
    {
        SCLogWarning("Found deprecated eve-log setting \"sensor-name\". Please set sensor-name globally.");
    }
    else
    {
        (void)ConfGet("sensor-name", &sensor_name);
    }

	/* 新建日志文件上下文结构，如果成功，才可以进一步初始化里面的互斥锁 */
    json_ctx->file_ctx = LogFileNewCtx();
    if (unlikely(json_ctx->file_ctx == NULL))
    {
        SCLogDebug("AlertJsonInitCtx: Could not create new LogFileCtx");
        goto error_exit;
    }

    if (sensor_name)
    {
        json_ctx->file_ctx->sensor_name = SCStrdup(sensor_name);
        if (json_ctx->file_ctx->sensor_name == NULL)
        {
            goto error_exit;
        }
    } 
    else
    {
        json_ctx->file_ctx->sensor_name = NULL;
    }

    /* 新建输出模块中维护私有数据的output_ctx数据类型对象, 并为其成员进行赋值 */
    output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
    {
        goto error_exit;
    }

    output_ctx->data = json_ctx; // 指向上面创建和赋值后的OutputJsonCtx类型的对象
    output_ctx->DeInit = OutputJsonDeInitCtx; // 清理函数

    /* 根据配置文件中的配置内容, 对OutputJsonCtx类型的对象json_ctx中的成员进行赋值 */
    if (conf) 
    {
        /* outputs.eve-log.filetype字段解析，以及处理逻辑. 一期比较零散，TCP连接类型就不在这里加了 */
        const char *output_s = ConfNodeLookupChildValue(conf, "filetype");
        // Backwards compatibility, 向后兼容性
        if (output_s == NULL) 
        {
            output_s = ConfNodeLookupChildValue(conf, "type");
        }
        
        enum LogFileType log_filetype = FileTypeFromConf(output_s);
        if (log_filetype == LOGFILE_TYPE_NOTSET)
        {
#ifdef HAVE_PLUGINS
            SCEveFileType *plugin = SCPluginFindFileType(output_s);
            if (plugin != NULL)
            {
                log_filetype = LOGFILE_TYPE_PLUGIN;
                json_ctx->plugin = plugin;
            } 
            else
#endif
                FatalError("Invalid JSON output option: %s", output_s);
        }
        
        /* outputs.eve-log.prefix字段解析，以及处理逻辑 */
        const char *prefix = ConfNodeLookupChildValue(conf, "prefix");
        if (prefix != NULL)
        {
            SCLogInfo("Using prefix '%s' for JSON messages", prefix);
            json_ctx->file_ctx->prefix = SCStrdup(prefix);
            if (json_ctx->file_ctx->prefix == NULL)
            {
                FatalError("Failed to allocate memory for eve-log.prefix setting.");
            }
            json_ctx->file_ctx->prefix_len = strlen(prefix);
        }

        /* outputs.eve-log.threaded字段解析，以及处理逻辑 */
        const ConfNode *threaded = ConfNodeLookupChild(conf, "threaded");
        if (threaded && threaded->val && ConfValIsTrue(threaded->val)) 
        {
            SCLogConfig("Threaded EVE logging configured");
            json_ctx->file_ctx->threaded = true;
        } 
        else
        {
            json_ctx->file_ctx->threaded = false;
        }

		/* 根据outputs.eve-log.filetype字段,进行文件或相关连接的预处理,新加入TCP连接 */
        if (LogFileTypePrepare(json_ctx, log_filetype, conf) < 0) 
        {
            goto error_exit;
        }

        /* 解析和处理sensor-id字段 */
        const char *sensor_id_s = ConfNodeLookupChildValue(conf, "sensor-id");
        if (sensor_id_s != NULL) 
        {
            if (StringParseUint64((uint64_t *)&sensor_id, 10, 0, sensor_id_s) < 0) 
            {
                FatalError("Failed to initialize JSON output, invalid sensor-id: %s", sensor_id_s);
            }
        }

        /* Check if top-level metadata should be logged. */
        // 解析outputs.eve-log.metadata字段, 检查是否应该记录顶级metadata
        const ConfNode *metadata = ConfNodeLookupChild(conf, "metadata");
        if (metadata && metadata->val && ConfValIsFalse(metadata->val)) 
        {
            SCLogConfig("Disabling eve metadata logging.");
            json_ctx->cfg.include_metadata = false;
        }
        else
        {
            json_ctx->cfg.include_metadata = true;
        }

        /* Check if ethernet information should be logged. */
        // 解析outputs.eve-log.ethernet字段, 检查是否应该记录以太网头信息
        const ConfNode *ethernet = ConfNodeLookupChild(conf, "ethernet");
        if (ethernet && ethernet->val && ConfValIsTrue(ethernet->val)) 
        {
            SCLogConfig("Enabling Ethernet MAC address logging.");
            json_ctx->cfg.include_ethernet = true;
        } 
        else
        {
            json_ctx->cfg.include_ethernet = false;
        }

        /* See if we want to enable the community id */
        // 解析outputs.eve-log.community-id 和 outputs.eve-log.community-id-seed字段, 处理community id功能
        const ConfNode *community_id = ConfNodeLookupChild(conf, "community-id");
        if (community_id && community_id->val && ConfValIsTrue(community_id->val))
        {
            SCLogConfig("Enabling eve community_id logging.");
            json_ctx->cfg.include_community_id = true;
        } 
        else
        {
            json_ctx->cfg.include_community_id = false;
        }
        const char *cid_seed = ConfNodeLookupChildValue(conf, "community-id-seed");
        if (cid_seed != NULL)
        {
            if (StringParseUint16(&json_ctx->cfg.community_id_seed, 10, 0, cid_seed) < 0)
            {
                FatalError("Failed to initialize JSON output, invalid community-id-seed: %s", cid_seed);
            }
        }

        /* Do we have a global eve xff configuration? */
        // 解析outputs.eve-log.xff节点配置, 处理HTTP X-Forwarded-For功能
        const ConfNode *xff = ConfNodeLookupChild(conf, "xff");
        if (xff != NULL)
        {
            json_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
            if (likely(json_ctx->xff_cfg != NULL))
            {
                HttpXFFGetCfg(conf, json_ctx->xff_cfg);
            }
        }

        // 解析outputs.eve-log.pcap-file字段, 检查在RUNMODE_PCAP_FILE模式下,是否应该记录处理的pcap文件的名称
        const char *pcapfile_s = ConfNodeLookupChildValue(conf, "pcap-file");
        if (pcapfile_s != NULL && ConfValIsTrue(pcapfile_s))
        {
            json_ctx->file_ctx->is_pcap_offline = (RunmodeGetCurrent() == RUNMODE_PCAP_FILE || RunmodeGetCurrent() == RUNMODE_UNIX_SOCKET);
        }
        json_ctx->file_ctx->type = log_filetype;
    }

    SCLogDebug("returning output_ctx %p", output_ctx);

    result.ctx = output_ctx;
    result.ok = true;
    return result;

error_exit:
    if (json_ctx->file_ctx)
    {
        if (json_ctx->file_ctx->prefix)
        {
            SCFree(json_ctx->file_ctx->prefix);
        }
        LogFileFreeCtx(json_ctx->file_ctx);
    }
    SCFree(json_ctx);

    if (output_ctx) 
    {
        SCFree(output_ctx);
    }
    
    return result;
}

static void OutputJsonDeInitCtx(OutputCtx *output_ctx)
{
    OutputJsonCtx *json_ctx = (OutputJsonCtx *)output_ctx->data;
    LogFileCtx *logfile_ctx = json_ctx->file_ctx;
    if (logfile_ctx->dropped) 
    {
        SCLogWarning("%" PRIu64 " events were dropped due to slow or disconnected socket", logfile_ctx->dropped);
    }
    if (json_ctx->xff_cfg != NULL)
    {
        SCFree(json_ctx->xff_cfg);
    }

	/* 注意一定要先调用这个函数，因为下面的函数会释放logfile_ctx */
	//LogFileFreeTcpCtx(logfile_ctx);

	/* 注意一定要 后 调用这个函数，因为调用完logfile_ctx会被释放 */
    LogFileFreeCtx(logfile_ctx);
	
    SCFree(json_ctx);
    SCFree(output_ctx);
}
