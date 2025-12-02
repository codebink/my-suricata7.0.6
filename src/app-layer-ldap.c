#include "suricata-common.h"
#include "suricata.h"
#include "stream.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-hashlist.h"

#include "util-print.h"
#include "util-spm-bs.h"
#include "util-enum.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "app-layer-ldap.h"

LdapConf ldap_conf;


/* 热加载函数 */
void LdapReload(void)
{
	/* 获取是否打开日志开关 */
	ConfNode *node = NULL;

	/* 插件开关 */
	node = NULL;
	node = ConfGetNode(LDAP_ENABLED_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(ldap_conf.ldap_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(ldap_conf.ldap_enable, 0);
	}

	/* 获取是否打开日志开关 */
	node = ConfGetNode(LDAP_LOG_NODE);
	if (node && node->val != NULL) {
		SC_ATOMIC_SET(ldap_conf.log_enable, ConfValIsTrue(node->val));
	}else {
		SC_ATOMIC_SET(ldap_conf.log_enable, 0);
	}	
}


#ifdef ENABLE_DECODER_DEBUG
/*
	名字：void get_local_time(char *time_buff)
	功能：获取本地时间
	参数：
		1 char *time_buff(传入传出型参数):本地时间,格式 2016/09/22 12:21:30
	返回:
		char *类型,时间字符串地址, NULL 异常
	时间：2016/09/22
	研发：deer
	版本：1.0.0.1
*/
static char *get_local_time(char *time_buff)
{
	if (NULL == time_buff) {
		return NULL;
	}

	int			year;
	int			month;
	int			day;
	int			hourl;
	int			min;
	int			sec;

	/* 时间句柄,结构体 */
	time_t		nowtime;
	struct tm	*timeinfo;

	/* 获取本地时间 */
	time(&nowtime);
	timeinfo = localtime(&nowtime);

	/* 取出年 月 日 星期 时 分 秒 */
	year = timeinfo->tm_year + 1900;
	month = timeinfo->tm_mon + 1;
	day = timeinfo->tm_mday;

	hourl = timeinfo->tm_hour;
	min = timeinfo->tm_min;
	sec = timeinfo->tm_sec;

	sprintf(time_buff, "%4d/%02d/%02d %02d:%02d:%02d", year, month, day, hourl, min, sec);

	return time_buff;
}


/*
	功能：打印信息审计，用于调试
	参数：
		1 LdapTransaction *tx: Ldap 的私有结构

	返回：void
*/
static void print_ldap_event(Flow *f, LdapTransaction *tx, uint16_t direction)
{
	/* 参数检查 */
	if (NULL == tx) {
		return;
	}

	char msg_buf[1024] = {0};
	LdapTransaction *ldap_data = NULL;

	char src_ip[INET6_ADDRSTRLEN] = {0};   //源IP 最大长度 46
	char dst_ip[INET6_ADDRSTRLEN] = {0};   //目的IP 同上
	uint16_t src_port = 0;                 //源 port
	uint16_t dst_port = 0;                 //目的 port

	/* 根据 flow 中的 flags 判断方向 */
	if (STREAM_TOSERVER == direction) {
		if (FLOW_IS_IPV4(f)) {
			PrintInet(AF_INET, (const void *)&f->src.addr_data32[0], src_ip, sizeof(src_ip));
			PrintInet(AF_INET, (const void *)&f->dst.addr_data32[0], dst_ip, sizeof(dst_ip));
		} else if (FLOW_IS_IPV6(f)) {
			PrintInet(AF_INET6, (const void *)f->src.addr_data32, src_ip, sizeof(src_ip));
			PrintInet(AF_INET6, (const void *)f->dst.addr_data32, dst_ip, sizeof(dst_ip));
		}

		/* 获取端口 */
		src_port = f->sp;
		dst_port = f->dp;
	}else {
		if (FLOW_IS_IPV4(f)) {
			PrintInet(AF_INET, (const void *)&f->dst.addr_data32[0], src_ip, sizeof(src_ip));
			PrintInet(AF_INET, (const void *)&f->src.addr_data32[0], dst_ip, sizeof(dst_ip));
		} else if (FLOW_IS_IPV6(f)) {
			PrintInet(AF_INET6, (const void *)f->dst.addr_data32, src_ip, sizeof(src_ip));
			PrintInet(AF_INET6, (const void *)f->src.addr_data32, dst_ip, sizeof(dst_ip));
		}

		/* 获取端口 */
		src_port = f->dp;
		dst_port = f->sp;
	}

	/* 私有结构，负载，负载长度 */
	ldap_data = tx;

	/* 时间 2016/09/22 12:21:30 */
	get_local_time(ldap_data->time_buff);
	
	/* 打印 */
	snprintf(msg_buf, sizeof(msg_buf), "done=%u", \
			ldap_data->done \
			);

	/* 打印公共字段 */
	DEBUG_DLOG("-----8888888888----- date: %s, s_ip: %s, s_port: %u, d_ip: %s, d_port: %u, dir: %d, protocal: %s, msg_buf: %s", \
				ldap_data->time_buff,\
				src_ip, src_port,\
				dst_ip, dst_port,\
				ldap_data->is_request, ldap_data->proto,\
				msg_buf \
				);

	return;
}
#endif






/* Ts 和 Tc 是指 Request 和 Response 方向协议识别和异常判断，合并到一起了，以后需要时还要拆分成两个函数，因为请求包和响应包结构不同 */
static AppProto LdapProbingParserTsTc(Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
	if (NULL == input || 0 >= input_len) {
		return ALPROTO_UNKNOWN;
	}

	//const uint8_t *p_data = NULL;
	uint16_t p_len = 0;

	/* 如果没有打开则强制不再识别识别, 后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(ldap_conf.ldap_enable)) {
		return ALPROTO_UNKNOWN;
	}
	
	/* 负载和负载长度 */
	//p_data = input;
	p_len = input_len;

	/* 异常判断 */
	if (p_len < LDAP_MIN_FRAME_LEN) {
		return ALPROTO_UNKNOWN;
	}

	return ALPROTO_LDAP;
}

/* 分配一个 ldap 状态对象，表示一个 ldap TCP 会话 */
static void *LdapStateAlloc(void *orig_state, AppProto proto_orig)
{
	SCEnter();
	LdapState *ldap;

	ldap = (LdapState *)SCCalloc(1, sizeof(LdapState));
	if (unlikely(ldap == NULL)) {
		return NULL;
	}
	TAILQ_INIT(&ldap->tx_list);

	SCReturnPtr(ldap, "void");
}

/* 分配一个 ldap transaction */
static LdapTransaction *LdapTxAlloc(LdapState *ldap, bool request)
{
	LdapTransaction *tx = SCCalloc(1, sizeof(LdapTransaction));
	if (unlikely(tx == NULL)) {
		return NULL;
	}
	ldap->transaction_max++;
	ldap->curr = tx;
	tx->ldap = ldap;
	tx->tx_num = ldap->transaction_max;
	tx->is_request = request;
	if (tx->is_request) {
		tx->tx_data.detect_flags_tc |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	} else {
		tx->tx_data.detect_flags_ts |= APP_LAYER_TX_SKIP_INSPECT_FLAG;
	}

	TAILQ_INSERT_TAIL(&ldap->tx_list, tx, next);

	return tx;
}


/* 找出 temp 在 target 的位置 */
static int ldap_find_index(const char *patt_str, uint32_t patt_len, char curr_tmp, uint32_t *index)
{
	if ((NULL == patt_str) || (1 > patt_len)) {
		/* 参数不正确也视为没有找到 index */
		return 1;
	}

	uint32_t i = 0;

	for (i = (patt_len -1); (int)i >= 0; i--) {
		if (patt_str[i] == curr_tmp) {
			*index = i;
			return 0;
		}
	}

	return 1;
}

/* 获取分隔符位置 */
static int ldap_get_location(char *src, uint32_t s_len, char c_t, uint32_t *local)
{
	if (NULL == src || 1 > s_len) {
		return -1;
	}
	
	uint32_t i = 0;
	for (i = 0; i < s_len; i++) {
		if (src[i] == c_t) {
			break;
		}
	}
	
	if (i >= s_len) {
		return -1;
	}
	
	*local = i;
	
	return i;
}

/* sunday 算法 */
static int ldap_sunday_alg(LdapTransaction *data, char *src_str, uint32_t src_len, const char *patt_str, uint32_t patt_len)
{
	if ((NULL == src_str) || (1 > src_len) || (NULL == patt_str) || (1 > patt_len) || (src_len <= patt_len)) {
		return -1;
	}

	uint32_t i = 0;	
	uint32_t j = 0;
	uint32_t tmp = 0;
	uint32_t ret = 0;
	uint32_t index = 0;
	uint32_t local = 0;
	int local_ret = 0;
	uint32_t dc_len = 0;

	while(i < src_len){
		if (j >= patt_len) {
			return -1;
		}
	
		/* 比对, 如果相等, 保存距离起始位置长度 */
		if(src_str[i] == patt_str[j]){
			if(j == patt_len - 1){
				//DEBUG_DLOG("匹配成功...i:%d, location:%d \n", i, i + 1 - patt_len);
				
				/* 当查找 cn 时只匹配一次，然后就退出，匹配 dc 时，需要拼接多个 dc */
				if (0 == strcasecmp(patt_str, "cn=")) {
					/* 获取紧邻的 ',' 距离当前已匹配的模式串首部的位置  */
					local = 0;
					
					/* 异常判断 */
					if (src_len < (i + 1 - patt_len) + patt_len) {
						return -1;
					}
					
					//local_ret = 0;
					local_ret = ldap_get_location((src_str + (i + 1 - patt_len) + patt_len), (src_len - (i + 1 - patt_len) - patt_len), ',', &local);
					//DEBUG_DLOG("----- cn local: %d\n", local);
					
					/* 取出 cn */
					if (-1 == local_ret) {
						if ((src_len - (i + 1 - patt_len) - patt_len) >= LDAP_VALUE_LEN65) {
							memcpy(data->user_name, (src_str + (i + 1 - patt_len) + patt_len), LDAP_VALUE_LEN65 - 1);
						}else {
							memcpy(data->user_name, (src_str + (i + 1 - patt_len) + patt_len), (src_len - (i + 1 - patt_len) - patt_len));
						}
					}else {
						if (local >= LDAP_VALUE_LEN65) {
							memcpy(data->user_name, (src_str + (i + 1 - patt_len) + patt_len), LDAP_VALUE_LEN65 - 1);
						}else {
							memcpy(data->user_name, (src_str + (i + 1 - patt_len) + patt_len), local);
						}
			
					}
					data->user_name_key = 1;
					//DEBUG_DLOG("-----ldap_cn user_name: %s\n", data->user_name);		

					return 0;
				}else if (0 == strcasecmp(patt_str, "dc=")) {
					/* 如果模式串为 "dc=", 则拼接原串中的所有 dc, 但是不能超过最大 dc len */
					local = 0;
					
					/* 异常判断 */
					if (src_len < (i + 1 - patt_len) + patt_len) {
						return -1;
					}
					
					//local_ret = 0;
					local_ret = ldap_get_location((src_str + (i + 1 - patt_len) + patt_len), (src_len - (i + 1 - patt_len) - patt_len), ',', &local);
					//DEBUG_DLOG("----- dc local: %d, local_ret: %d\n", local, local_ret);				
					
					/* 拼接 dc */
					if (-1 == local_ret) {
						if (0 != strlen((char *)(data->domain_name))) {
							dc_len += 1;
							
							/* 异常判断 */
							if (strlen((char *)(data->domain_name)) + 1 <= LDAP_VALUE_LEN65 - 1) {
								strcat((char *)(data->domain_name), ".");
							}
						}
						
						dc_len += (src_len - (i + 1 - patt_len) - patt_len);
						
						/* 异常判断 */
						if (strlen((char *)(data->domain_name)) + (src_len - (i + 1 - patt_len) - patt_len) <= LDAP_VALUE_LEN65 - 1) {
							strncat((char *)(data->domain_name), (src_str + (i + 1 - patt_len) + patt_len), (src_len - (i + 1 - patt_len) - patt_len));
							data->domain_name_key = 1;
						}
						
						//DEBUG_DLOG("----- 1 ldap_dc domain_name: %s\n", data->domain_name);	
					}else {
						if (0 != strlen((char *)(data->domain_name))) {
							dc_len += 1;
							
							/* 异常判断 */
							if (strlen((char *)(data->domain_name)) + 1 <= LDAP_VALUE_LEN65 - 1) {
								strcat((char *)(data->domain_name), ".");
							}
						}
						
						dc_len += local;
						
						/* 异常判断 */
						if (strlen((char *)(data->domain_name)) + local <= LDAP_VALUE_LEN65 - 1) {
							strncat((char *)(data->domain_name), (src_str + (i + 1 - patt_len) + patt_len), local);
							data->domain_name_key = 1;
						}
						
						//DEBUG_DLOG("----- 2 ldap_dc domain_name: %s\n", data->domain_name);						
					}
					
				}else {
					;
				}
			}
			
			i++;
			j++;
			
			/* 异常判断 */
			if (patt_len <= j) {
				j = 0;
			}
		}else{
			/* 发现不相等的位置, tmp 为当前遍历到的字符后面的第一个字符位置 */
			//tmp = 0;
			tmp = patt_len - j + i;
			if (tmp >= src_len) {
				return -1;
			}
			
			index = 0;
			//ret = 0;
			ret = ldap_find_index(patt_str, patt_len, src_str[tmp], &index);
			if(ret == 1){
				/* 未找到位置后移 */
				i = tmp + 1;
				j = 0;
			}else{
				/* 找到位置 */
				i = tmp - index;
				j = 0;
			}
		}
	}
	
	return 0;
}

static int ldap_cn_dc_find(char *src_str, uint32_t src_len, const char *patt_str, uint32_t patt_len)
{
	if ((NULL == src_str) || (1 > src_len) || (NULL == patt_str) || (1 > patt_len) || (src_len <= patt_len)) {
		return 1;
	}

	uint32_t i = 0;	
	uint32_t j = 0;
	uint32_t tmp = 0;
	uint32_t ret = 0;
	uint32_t index = 0;
	//uint32_t dc_len = 0;
	
	while(i < src_len){
		if (j >= patt_len) {
			return -1;
		}
	
		/* 比对, 如果相等, 保存距离起始位置长度 */
		if(src_str[i] == patt_str[j]){
			if(j == patt_len - 1){
				//DEBUG_DLOG("匹配成功...i:%d, location:%d \n", i, i + 1 - patt_len);
				if (0 == strcasecmp(patt_str, "cn=")) {
					return 0;
				}else if (0 == strcasecmp(patt_str, "dc=")) {
					return 0;
				}
			}
			
			i++;
			j++;
		}else{
			/* 发现不相等的位置, tmp 为当前遍历到的字符后面的第一个字符位置 */
			//tmp = 0;
			tmp = patt_len - j + i;
			if (tmp >= src_len) {
				return -1;
			}
			//ret = 0;			
			index = 0;

			ret = ldap_find_index(patt_str, patt_len, src_str[tmp], &index);
			if(ret == 1){
				/* 未找到位置后移 */
				i = tmp + 1;
				j = 0;
			}else{
				/* 找到位置 */
				i = tmp - index;
				j = 0;
			}
		}
	}

	return 1;
}



/* 解析 响应 包 */
static int LdapParseResp(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, LdapTransaction *ldap_data)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	/* 只解析请求，不解析响应，响应中没有需要的信息 */

	return 1;
}

/* 解析 请求 包 */
static int LdapParseReq(Flow *f, void *statev, AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len, void *local_data, LdapTransaction *ldap_data)
{
	if (NULL == f || NULL == pstate || NULL == input || 0 >= input_len) {
		return 1;
	}

	const uint8_t *p_data = NULL;
	uint32_t p_len = 0;
	uint32_t pos = 0;
	uint32_t tmp_len = 0;

	uint32_t cn_ret = 0;
	uint32_t dc_ret = 0;
	uint32_t CN_RET = 0;
	uint32_t DC_RET = 0;
	
	const char *patt_cn = "cn=";
	const char *patt_dc = "dc=";
	const char *PATT_CN = "CN=";
	const char *PATT_DC = "DC=";
	char name[LDAP_VALUE_LEN257] = {0};
	uint32_t name_len = 0;
	
	/* 负载和负载长度，注意 input 中，字符串结尾可能存在脏数据，并且 input_len 也不准并超长，因此要求一下负载真实长度 */
	p_data = input;
	p_len = input_len;

	/* 判断是否为  bindRequest(0) 或 extendedReq(23) 数据包 */
	if (IS_LDAP_BIND_REQUEST(p_data)) {
		/* pos 移动到后面数据总长度字段 */
		pos += 1;
		
		/* 取出后面数据总长度 */
		tmp_len = LDAP_GET_VALUE_HOST8(p_data + pos);
		
		/* 异常判断 */
		if (tmp_len > p_len - pos - 1) {
			return 1;
		}
		
		/* pos 移动到后面数据总长度字段 */
		pos += 1 + 2 + 1 + 1;		

		/* 取出后面数据总长度 */
		tmp_len = LDAP_GET_VALUE_HOST8(p_data + pos);
		
		/* 异常判断 */
		if (tmp_len > p_len - pos - 1) {
			return 1;
		}
		
		/* pos 移动到 0x04 固定特征 */
		pos += 1 + 2 + 1;				
		
		/* 异常判断 */
		if (pos + 1 > p_len) {
			return 1;
		}		
		
		/* 异常判断 */
		if (0x04 != (p_data + pos)[0]) {
			return 1;
		}		
		
		/* pos 移动到用户名和域名信息长度字段 */
		pos += 1;

		/* 异常判断 */
		if (pos + 1 > p_len) {
			return 1;
		}
		
		/* 取出后面数据总长度 */
		tmp_len = LDAP_GET_VALUE_HOST8(p_data + pos);		
		
		/* pos 移动到用户名和域名信息 */
		pos += 1;	

		/* 异常判断 */
		if (pos + tmp_len > p_len) {
			return 1;
		}		
	
		/* 保存 name */
		if (tmp_len >= LDAP_VALUE_LEN257) {
			memcpy(name, (p_data + pos), LDAP_VALUE_LEN257 - 1);
			name_len = LDAP_VALUE_LEN257 - 1;
		}else {
			memcpy(name, (p_data + pos), tmp_len);
			name_len = tmp_len;
		}

		/* 从 name 中提取 cn dc */
		if (3 < name_len) {
			//TLOG_DEBUG("\n---88888888--- name: %s\n", name);
			cn_ret = ldap_cn_dc_find(name, name_len, patt_cn, 3);
			dc_ret = ldap_cn_dc_find(name, name_len, patt_dc, 3);
			CN_RET = ldap_cn_dc_find(name, name_len, PATT_CN, 3);
			DC_RET = ldap_cn_dc_find(name, name_len, PATT_DC, 3);
			if ((0 != cn_ret) && (0 != dc_ret) && (0 != CN_RET) && (0 != DC_RET)) {
				return 1;
			}else {
				/* 取出 cn */
				if (0 == cn_ret) {
					ldap_sunday_alg(ldap_data, name, name_len, patt_cn, 3);
				}else if (0 == CN_RET) {
					ldap_sunday_alg(ldap_data, name, name_len, PATT_CN, 3);
				}

				/* 取出 dc */
				if (0 == dc_ret) {
					ldap_sunday_alg(ldap_data, name, name_len, patt_dc, 3);	
				}else if (0 == DC_RET) {
					ldap_sunday_alg(ldap_data, name, name_len, PATT_DC, 3);	
				}
			}
			
			//TLOG_DEBUG("\n---88888888--- user_name: %s\n", ldap_data->user_name);
			//TLOG_DEBUG("\n---88888888--- domain_name: %s\n", ldap_data->domain_name);
		}else {
			return 1;
		}
	
		/* 跳过 name */
		pos += tmp_len;

		/* 异常判断 */
		if (pos + 1 > p_len) {
			return 1;
		}		
		
		/* 判断是否为 simple 模式，只有这种模式才能取出 passwd */
		if (0x80 == (p_data + pos)[0]) {
			/* pos 移动到 passwd 长度字段 */
			pos += 1;

			/* 异常判断 */
			if (pos + 1 > p_len) {
				return 1;
			}
			
			/* 取出 passwd len */
			tmp_len = LDAP_GET_VALUE_HOST8(p_data + pos);			

			/* 异常判断 */
			if (pos + 1 + tmp_len > p_len) {
				return 1;
			}
			
			/* 取出 passwd */
			if (tmp_len >= LDAP_VALUE_LEN65) {
				memcpy(ldap_data->passwd, (p_data + pos + 1), LDAP_VALUE_LEN65 - 1);
			}else {
				memcpy(ldap_data->passwd, (p_data + pos + 1), tmp_len);
			}

			ldap_data->passwd_key = 1;
		}
		
	}else if (IS_LDAP_EXTENDED_REQ(p_data)) {
		/* pos 移动到后面数据总长度字段 */
		pos += 1;
		
		/* 取出后面数据总长度 */
		tmp_len = LDAP_GET_VALUE_HOST8(p_data + pos);
		
		/* 异常判断 */
		if (tmp_len > p_len - pos - 1) {
			return 1;
		}
		
		/* pos 移动到后面数据总长度字段 */
		pos += 1 + 2 + 1 + 1;		

		/* 取出后面数据总长度 */
		tmp_len = LDAP_GET_VALUE_HOST8(p_data + pos);
		
		/* 异常判断 */
		if (tmp_len > p_len - pos - 1) {
			return 1;
		}		
		
		/* pos 移动到 0x80 固定特征 */
		pos += 1;				
		
		/* 异常判断 */
		if (pos + 1 > p_len) {
			return 1;
		}		
		
		/* 异常判断 */
		if ((p_data + pos)[0] != 0x80) {
			return 1;
		}	

		/* pos 移动到 requestName len */
		pos += 1;				
		
		/* 异常判断 */
		if (pos + 1 > p_len) {
			return 1;
		}	

		/* 取出后面数据总长度 */
		tmp_len = LDAP_GET_VALUE_HOST8(p_data + pos);		

		/* 异常判断 */
		if (tmp_len > p_len - pos - 1) {
			return 1;
		}

		/* pos 移动到 requestName */
		pos += 1;	
		
		/* 取出 requestName */
		memset(ldap_data->req_name, 0, LDAP_VALUE_LEN65);
		if (tmp_len >= LDAP_VALUE_LEN65) {
			memcpy(ldap_data->req_name, (p_data + pos), LDAP_VALUE_LEN65 - 1);
		}else {
			memcpy(ldap_data->req_name, (p_data + pos), tmp_len);
		}
		ldap_data->req_name_key = 1;
		
	}else {
		return 1;
	}

	return 0;
}


/* 请求包 解析函数 */
static AppLayerResult LdapParseRequest(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	LdapTransaction *tx = NULL;
	//LdapTransaction *ttx = NULL;

	LdapState *ldap_state = NULL;
	LdapTransaction *ldap_data = NULL;

	const uint8_t *input = NULL;
	uint32_t input_len = 0;

	int ret = 1;

	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(ldap_conf.ldap_enable)) {
		goto error;
	}

	/* 获取 state 和 input 和 input_len */
	ldap_state = (LdapState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);

	/* 异常判断 */
	if (NULL == input) {
		if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) {
			/* 这是一个流结束的信号，如果需要，做任何清理工作，这里通常不需要什么 */
			SCReturnStruct(APP_LAYER_OK);
		}

		goto error;
	}

	/* 异常判断 */
	if (1 > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 异常判断 */
	if (LDAP_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = LdapTxAlloc(ldap_state, true);
	ldap_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(ldap_data->proto, "tcp", 3);
	ldap_data->is_request = true;

#if 0
	/* 注意: 可能响应先来，因此请求也需要查一下有没有分配 tx, 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &ldap_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	ldap_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//ldap_state->transaction_max = 0;
		
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = LdapTxAlloc(ldap_state, true);
		ldap_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(ldap_data->proto, "tcp", 3);
	}
	ldap_data->is_request = true;
#endif
/************************* 解析私有数据 start ************************/	
	/* 解析请求或响应，带有再次纠错功能，即使丢包后方向被识别反，这里也能纠错 */
	if (f->sp > f->dp) {
		ret = LdapParseReq(f, state, pstate, input, input_len, local_data, ldap_data);
	}else if (f->sp < f->dp) {
		ret = LdapParseResp(f, state, pstate, input, input_len, local_data, ldap_data);
	}else {
		ret = 1;
	}

	if (0 != ret) {
		goto end;
	}

	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	ldap_data->done = 1;
	ldap_data->complete = 0;
	
/************************* 解析私有数据 end ************************/	


#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_ldap_event(f, ldap_data, STREAM_TOSERVER);
#endif

end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 响应包 解析函数 */
static AppLayerResult LdapParseResponse(Flow *f, void *state, AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data)
{
	if (NULL == f || NULL == state || NULL == pstate) {
		goto error;
	}

	LdapTransaction *tx = NULL;
	//LdapTransaction *ttx = NULL;
	
	LdapState *ldap_state = NULL;
	LdapTransaction *ldap_data = NULL;
	
	const uint8_t *input = NULL;
	uint32_t input_len = 0;
	
	int ret = 1;

	/* 如果没有打开则强制不再识别识别,后续的逻辑将不再处理 */
	if (0 == SC_ATOMIC_GET(ldap_conf.ldap_enable)) {
		goto error;
	}
	
	/* 获取 state 和 input 和 input_len */
	ldap_state = (LdapState *)state;
	input = StreamSliceGetData(&stream_slice);
	input_len = StreamSliceGetDataLen(&stream_slice);
	
	/* 可能连接关闭了 */
	if ((NULL == input || 1 > input_len) && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 异常判断 */
	if (NULL == input || 1 > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}
	
	/* 异常判断 */
	if (LDAP_MIN_FRAME_LEN > input_len) {
		SCReturnStruct(APP_LAYER_OK);
	}

	/* 分配一个事务，插入 state list，请求时传入 true, 响应时传入 false */
	tx = LdapTxAlloc(ldap_state, false);
	ldap_data = tx;
	if (unlikely(tx == NULL)) {
		goto error;
	}
	memcpy(ldap_data->proto, "tcp", 3);
	ldap_data->is_request = false;

#if 0
    /* 注意: 就是找请求包保存的私有结构 node，这在审计系统的请求和响应合并时特别有用 */
	TAILQ_FOREACH(ttx, &ldap_state->tx_list, next) {
		tx = ttx;
	}

	/* 没找到请求包保存的私有结构 */
	ldap_data = tx;
	if (tx == NULL) {
		/* 查不出来说明 tx 都已释放了，计数应为 0，清零 */
		//ldap_state->transaction_max = 0;
	
		/* 孤立的会话，重新创建事务节点插入 list */
		tx = LdapTxAlloc(ldap_state, false);
		ldap_data = tx;
		if (unlikely(tx == NULL)) {
			SCReturnStruct(APP_LAYER_ERROR);
		}
		memcpy(ldap_data->proto, "tcp", 3);
	}
	ldap_data->is_request = false;
#endif	
	/************************* 解析私有数据 start ************************/	
	/* 请求和响应共用一个 tx，因此响应的时候需要清理下 tx 中的旧的私有数据再使用 */
	memset(tx->user_name, 0, LDAP_VALUE_LEN65);
	memset(tx->domain_name, 0, LDAP_VALUE_LEN65);
	memset(tx->passwd, 0, LDAP_VALUE_LEN65);
	memset(tx->req_name, 0, LDAP_VALUE_LEN65);
	tx->user_name_key = 0;
	tx->domain_name_key = 0;
	tx->passwd_key = 0;
	tx->req_name_key = 0;

	/* 解析请求或响应，带有再次纠错功能，即使丢包后方向被识别反，这里也能纠错 */
	if (f->sp < f->dp) {
		ret = LdapParseReq(f, state, pstate, input, input_len, local_data, ldap_data);
	}else if (f->sp > f->dp) {
		ret = LdapParseResp(f, state, pstate, input, input_len, local_data, ldap_data);
	}else {
		ret = 1;
	}

	if (0 != ret) {
		goto end;
	}
	
	/* 如果解析彻底完成，记得设置完成标志，否则后面所有日志将不会发送 */
	ldap_data->done = 1;
	ldap_data->complete = 1;
		
	/************************* 解析私有数据 end ************************/ 	
	
	
#ifdef ENABLE_DECODER_DEBUG
	/* 打印，记得发布时取消宏定义 */
	print_ldap_event(f, ldap_data, STREAM_TOCLIENT);
#endif


end:
	SCReturnStruct(APP_LAYER_OK);

error:
	SCReturnStruct(APP_LAYER_ERROR);
}

/* 获取 tx */
static void *LdapGetTx(void *alstate, uint64_t tx_id)
{
	SCEnter();
	LdapState *ldap = (LdapState *)alstate;
	LdapTransaction *tx = NULL;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH(tx, &ldap->tx_list, next) {
		if (tx_num != tx->tx_num) {
			continue;
		}
		SCReturnPtr(tx, "void");
	}

	SCReturnPtr(NULL, "void");
}

/* 获取 tx 计数 */
static uint64_t LdapGetTxCnt(void *state)
{
	SCEnter();
	uint64_t count = ((uint64_t)((LdapState *)state)->transaction_max);
	SCReturnUInt(count);
}

/* 释放一个 ldap tx */
static void LdapTxFree(LdapTransaction *tx)
{
	SCEnter();

	AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

	if (tx->tx_data.de_state != NULL) {
		DetectEngineStateFree(tx->tx_data.de_state);
	}

	SCFree(tx);
	SCReturn;
}

/* 通过 ID 释放特定 ldap 状态上的一个事务 */
static void LdapStateTxFree(void *state, uint64_t tx_id)
{
	SCEnter();
	LdapState *ldap = state;
	LdapTransaction *tx = NULL, *ttx;
	uint64_t tx_num = tx_id + 1;

	TAILQ_FOREACH_SAFE(tx, &ldap->tx_list, next, ttx) {

		if (tx->tx_num != tx_num) {
			continue;
		}

		//最好不要使用这个 curr，这个就是容易段错误的根源
		if (tx == ldap->curr) {
			ldap->curr = NULL;
		}

		TAILQ_REMOVE(&ldap->tx_list, tx, next);
		LdapTxFree(tx);
		break;
	}

	SCReturn;
}

/* 释放 ldap state */
static void LdapStateFree(void *state)
{
	SCEnter();
	LdapState *ldap = state;
	LdapTransaction *tx;
	if (state != NULL) {
		while ((tx = TAILQ_FIRST(&ldap->tx_list)) != NULL) {
			TAILQ_REMOVE(&ldap->tx_list, tx, next);
			LdapTxFree(tx);
		}
		if (ldap->request_buffer.buffer != NULL) {
			SCFree(ldap->request_buffer.buffer);
		}
		if (ldap->response_buffer.buffer != NULL) {
			SCFree(ldap->response_buffer.buffer);
		}
		SCFree(ldap);
	}
	SCReturn;
}

/* 由应用层调用来获取状态进度 */
static int LdapGetAlstateProgress(void *tx, uint8_t direction)
{
	/* 直接返回，用完 tx 就释放提高性能 */
	return 1;

	LdapTransaction *ldaptx = (LdapTransaction *)tx;
	int retval = 0;

	/* 原生逻辑是进度完成再释放，性能低 */
	if (ldaptx->complete) {
		retval = 1;
	}	

	SCReturnInt(retval);
}

/* 获取 tx_data */
static AppLayerTxData *LdapGetTxData(void *vtx)
{
	LdapTransaction *tx = (LdapTransaction *)vtx;
	return &tx->tx_data;
}

/* 获取 state_data */
static AppLayerStateData *LdapGetStateData(void *vstate)
{
	LdapState *state = (LdapState *)vstate;
	return &state->state_data;
}

/* 迭代器 */
static AppLayerGetTxIterTuple LdapGetTxIterator(const uint8_t ipproto, const AppProto alproto,
	void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
	LdapState *dnp_state = (LdapState *)alstate;
	AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
	if (dnp_state) {
		LdapTransaction *tx_ptr;
		if (state->un.ptr == NULL) {
			tx_ptr = TAILQ_FIRST(&dnp_state->tx_list);
		} else {
			tx_ptr = (LdapTransaction *)state->un.ptr;
		}
		if (tx_ptr) {
			while (tx_ptr->tx_num < min_tx_id + 1) {
				tx_ptr = TAILQ_NEXT(tx_ptr, next);
				if (!tx_ptr) {
					return no_tuple;
				}
			}
			if (tx_ptr->tx_num >= max_tx_id + 1) {
				return no_tuple;
			}
			state->un.ptr = TAILQ_NEXT(tx_ptr, next);
			AppLayerGetTxIterTuple tuple = {
				.tx_ptr = tx_ptr,
				.tx_id = tx_ptr->tx_num - 1,
				.has_next = (state->un.ptr != NULL),
			};
			return tuple;
		}
	}
	return no_tuple;
}

/* 核心注册函数 */
void RegisterLdapParsers(void)
{
	const char *proto_name = "ldap";

	AppLayerProtoDetectRegisterProtocol(ALPROTO_LDAP, proto_name);

	/* 注册异常判断与协议识别函数 */
	if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_LDAP, 0, LDAP_MIN_FRAME_LEN, LdapProbingParserTsTc, LdapProbingParserTsTc)) {
		/* 请求方向 */
		AppLayerProtoDetectPPRegister(IPPROTO_TCP, LDAP_DEFAULT_PORT, ALPROTO_LDAP, 0, LDAP_MIN_FRAME_LEN, STREAM_TOSERVER, LdapProbingParserTsTc, LdapProbingParserTsTc);	
	}

	/* 加载配置 */
	if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
		SCLogConfig("Registering ldap/tcp parsers.");
		
		LdapReload();

	}else {
		SCLogConfig("Parser disabled for protocol %s. Protocol detection still on.", proto_name);

		SC_ATOMIC_SET(ldap_conf.ldap_enable , 0);
		SC_ATOMIC_SET(ldap_conf.log_enable, 0);
	}

	/* 注册状态分配和释放函数, 每个新的Ldap流分配一个状态，使用一套分配释放函数 */
	AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_LDAP, LdapStateAlloc, LdapStateFree);

	/* 注册 Request 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_LDAP, STREAM_TOSERVER, LdapParseRequest);

	/* 注册 Response 解析函数 */
	AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_LDAP, STREAM_TOCLIENT, LdapParseResponse);

	/* 加入请求和响应方向注册 */
	AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_LDAP, STREAM_TOSERVER | STREAM_TOCLIENT);

	/* 注册事务计数、获取、释放等函数 */
	AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_LDAP, LdapGetTx);
	AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_LDAP, LdapGetTxCnt);
	AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_LDAP, LdapStateTxFree);
	AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_LDAP, LdapGetTxData);

	/* 新发现的，注册 tx 迭代器函数，有的协议没用这个函数 */
	AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_LDAP, LdapGetTxIterator);

	/* 获取 Alstate 进度完成状态, 旧版有相同功能函数 */
	AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_LDAP, 1, 1);
	AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_LDAP, LdapGetAlstateProgress);

	/* 新函数，注册获取 state_data 函数 */
	AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_LDAP, LdapGetStateData);
	
	SCReturn;
}

