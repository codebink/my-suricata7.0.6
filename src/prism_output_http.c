
#include "suricata-common.h"
#include "detect.h"

#include "conf.h"
#include "util-base64.h"
#include "util-misc.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "htp/htp_connection_parser_private.h"

#include "prism_output_http.h"

//默认header 长度 2K
#define BVM_HTTP_HEADER_MAX_LENGTH 20480
//默认body 长度 4k
#define BVM_HTTP_BODY_MAX_LENGTH 40960
//默认 payload 长度 6k (header + body)
#define BVM_PAYLOAD_MAX_LENGTH  61440

extern  HttpConf http_conf;

#define HTTP_OUTPUT_FREESTR(P) if(NULL != P){free(P); P = NULL;}


/***************
 *FUNC:
 *  base64encode.
 *base64编码.
 * 
 * out      生成的base64字符串.
 * out_size 生成的base64字符串长度.
 *
 * 成功 返回base64编码后的长度>0., 失败返回-1.
 * NOTICE: out参数 须调用者释放 SCFree(*out);
 * *************/
static int StringToBase64(const char *str, size_t slen, char **out, size_t *out_size)
{
    if(!str || slen ==0 || !out_size )
    { return -1; }

    unsigned long len = Base64EncodeBufferSize(slen);
    uint8_t *encoded_data = SCCalloc( sizeof(char), len); 
    if(unlikely(encoded_data == NULL))
    { return -1; }

    if (Base64Encode((uint8_t *)str, slen, encoded_data, &len) != SC_BASE64_OK)
    {
        SCFree(encoded_data);
        return -1;
    }
    *out = (char *)encoded_data;
    *out_size = len; 

    return len;
}

#if 0
/*************
 *FUNC:
 * 获取配置值.
 * 1 成功, 其他失败. 
 * ***********/
static int ConfGetU32Val(const char *key, uint32_t *val)
{
    ConfNode *p=NULL;

    if(!key || !val)
    { return -1;  }

    if( !(p=ConfGetNode(key)) )
    { return -1; }    

    if(ParseSizeStringU32(p->val, val) < 0) 
    {
        SCLogError("ConfGetU32Val key:[%s] not val\n", key);
        return -1;
    }
    return 1;
}
#endif

/*******
 *FUNC:
 * 构造BVM http 请求/响应 base64(header + body) .
 * 成功返回1 , 其他失败.
 * ****/
int ConstructBvmHttpReqRespBase64(const Packet *pkg, htp_tx_t *htx, JsonBuilder *js, uint64_t tx_id )
{

	if(NULL == pkg || NULL == js || NULL == htx) { 
		return -1; 
	}

	/* 所有局部变量都要初始化为 0 或 NULL */
	int ret = -1;
	const Flow *flow = NULL;
	HtpState *htp_state = NULL;

    uint32_t totalsize = 0; //累计长度.
    uint32_t req_headersize = 0;
	uint32_t resp_headersize = 0;
	uint32_t req_bodysize = 0;
	uint32_t resp_bodysize = 0;
	uint32_t maxlimit = 0; 
    uint32_t get_req_bodysize = 0;
	uint32_t get_resp_bodysize = 0;    //从htp获取得到的真实request/response body 长度. 
	const uint8_t *body_data = NULL;   //从htp获取得到的真实request/response body string.

	char *http_request_header = NULL;
	char *http_response_header = NULL; //header ptr
	char *http_request_body = NULL;
	char *http_response_body = NULL;   //body ptr
	char *req_total = NULL; 
	char *resp_total=NULL;       //全部请求部分, 全部响应部分.
	char *base64ptr = NULL;
	size_t base64len = 0;

	htp_tx_t *tx = NULL;
	HtpTxUserData *htud = NULL;

	uint64_t body_offset = 0;
	

	/* 异常判断 */
	flow = (const Flow *)pkg->flow;
	if(NULL == flow 
		|| (FlowGetAppProtocol(flow) != ALPROTO_HTTP1 && FlowGetAppProtocol(flow) != ALPROTO_HTTP2 )) { 
		return -1; 
	}

	htp_state = (HtpState *) FlowGetAppState(flow);
	if(NULL == htp_state) { 
		return -1; 
	}

	//获取配置长度.
	req_headersize = (uint32_t)(SC_ATOMIC_GET(http_conf.req_headersize));
	resp_headersize = (uint32_t)(SC_ATOMIC_GET(http_conf.resp_headersize));
	req_bodysize = (uint32_t)(SC_ATOMIC_GET(http_conf.req_bodysize));
	resp_bodysize = (uint32_t)(SC_ATOMIC_GET(http_conf.resp_bodysize));

	//获取 tx
	tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, tx_id);
	if(NULL == tx) { 
		return -1; 
	}

	htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
	if(NULL == htud) { 
		return -1; 
	}
    
	//申请mem.
	http_request_header = SCCalloc(sizeof(char), req_headersize+8 );
	if (NULL == http_request_header) {
		 goto FREELABLE;
	}

    http_request_body = SCCalloc( sizeof(char), req_bodysize+8 );
	if (NULL == http_request_body) {
		goto FREELABLE;
	}

	http_response_header = SCCalloc( sizeof(char), resp_headersize+8 );
	if (NULL == http_response_header) {
		goto FREELABLE;
	}

	http_response_body = SCCalloc(sizeof(char), resp_bodysize+8 );
	if (NULL == http_response_body) {
		goto FREELABLE;
	}

	/* 异常判断 */
	if (NULL == htud->request_body.sb) {
		goto FREELABLE;
	}

	
	//给 请求body 赋值.
	body_data = NULL;
	get_req_bodysize = 0;
	body_offset = 0;
	if (StreamingBufferGetData(htud->request_body.sb, &body_data, &get_req_bodysize, &body_offset) == 0) {
		SCLogDebug("ConstructBvmHttpReqRespBase64  request_body len:[%u]\n ", get_req_bodysize );
	} 

									
	if(NULL != body_data  && get_req_bodysize > 0) {
		maxlimit = get_req_bodysize > req_bodysize ? req_bodysize : get_req_bodysize;
		memcpy(http_request_body, body_data, maxlimit); //获取请求body 值.
		get_req_bodysize = maxlimit ;                   //请求body 值长度.
	}    

	/* 异常判断 */
	if (NULL == htud->response_body.sb) {
		goto FREELABLE;
	}

    //给 响应body 赋值.
    body_data = NULL;
	get_resp_bodysize = 0;
	body_offset = 0;
	if (StreamingBufferGetData(htud->response_body.sb, &body_data, &get_resp_bodysize, &body_offset) == 0) {
		SCLogDebug("ConstructBvmHttpReqRespBase64  resp_body len:[%u]\n ", get_resp_bodysize );
	} 

	
	if(NULL != body_data && get_resp_bodysize > 0) {
		maxlimit = get_resp_bodysize > resp_bodysize ? resp_bodysize : get_resp_bodysize;
		memcpy(http_response_body, body_data, maxlimit); //获取响应body 值.
		get_resp_bodysize = maxlimit;                    //响应body 值长度.
	}

	/* 异常判断 */
	if (NULL == tx->request_line) {
		goto FREELABLE;
	}

	//获取请求header. 注意请求行 与 请求头 之间要人为添加 \r\n
	maxlimit = 0;
	totalsize = 0;
	if(tx->request_line && tx->request_line->len > 0 ) {
		maxlimit = tx->request_line->len > req_headersize-3 ? req_headersize-3 : tx->request_line->len;
		memcpy(http_request_header, bstr_ptr(tx->request_line), maxlimit); //请求行.

		/* 异常判断 */
		if (maxlimit + 2 >= req_headersize) {
			goto FREELABLE;
		}
		
		memcpy(http_request_header + maxlimit, "\r\n", 2); //请求行+\r\n.
		totalsize = maxlimit + 2; //请求行长度.
	}

	/* 异常判断 */
	if (NULL == htud->request_headers_raw || 1 > htud->request_headers_raw_len) {
		goto FREELABLE;
	}

	//+请求头
	//maxlimit = 请求行 + 请求头
	maxlimit = 0;
	if(htud->request_headers_raw && htud->request_headers_raw_len) {
		maxlimit = htud->request_headers_raw_len + totalsize > req_headersize ? req_headersize : 
                        htud->request_headers_raw_len + tx->request_line->len ;
		/* 异常判断 */
		if (maxlimit > req_headersize) {
			goto FREELABLE;
		}

		/* 异常判断 */
		if (req_headersize - totalsize <= maxlimit - totalsize) {
			goto FREELABLE;
		}

		/* 异常判断 */
		if (maxlimit - totalsize > htud->request_headers_raw_len) {
			goto FREELABLE;
		}

		if(maxlimit > totalsize){
			memcpy(http_request_header + totalsize, htud->request_headers_raw, maxlimit - totalsize);
		}
		totalsize = maxlimit;  //请求行 + 请求头.
    }

    //请求头+请求body
    req_total = SCCalloc(sizeof(char), totalsize + get_req_bodysize+8); //请求部分. 
	if (NULL == req_total) {
		goto FREELABLE;
	}

	/* 异常判断 */
	if (totalsize > req_headersize || get_req_bodysize > req_bodysize) {
		goto FREELABLE;
	}
	
    memcpy(req_total, http_request_header, totalsize); //请求行+请求头.
    memcpy(req_total+totalsize, http_request_body, get_req_bodysize); //全部请求部分 =  请求行 + 请求头 + 请求body .

	//size_t jslen = jb_len(js);
	if(StringToBase64(req_total, totalsize+get_req_bodysize, &base64ptr, &base64len) >0) {
        jb_set_string(js, "request", base64ptr);
    
        //DEBUG_DLOG("ConstructBvmHttpReqRespBase64 req_total size:[%u] req_total :[%s]\n base64len:[%u], base64ptr:[%s]\n",
               //(unsigned int) totalsize+get_req_bodysize,req_total,  (unsigned int)base64len, base64ptr);

        HTTP_OUTPUT_FREESTR(base64ptr);
        base64ptr=NULL;
        ret=1;
    }

	/* 异常判断 */
	if (NULL == tx->response_line) {
		goto FREELABLE;
	}

	//获取响应header line.
	maxlimit=0;
	totalsize=0;
	if(tx->response_line ) {
		maxlimit = tx->response_line->len > resp_headersize-3 ? resp_headersize-3 : tx->response_line->len;
		memcpy(http_response_header, bstr_ptr(tx->response_line), maxlimit);
	
		/* 异常判断 */
		if (maxlimit + 2 >= resp_headersize) {
			goto FREELABLE;
		}

		memcpy(http_response_header + maxlimit, "\r\n", 2);
		totalsize = maxlimit + 2; //响应行长度.
	}

	/* 异常判断 */
	if (NULL == htud->response_headers_raw) {
		goto FREELABLE;
	}

	//+响应头
	//maxlimit = 响应行 +  响应头.
	if(htud->response_headers_raw) {
		maxlimit = htud->response_headers_raw_len + totalsize > resp_headersize ? resp_headersize : 
                    htud->response_headers_raw_len + totalsize ;   

		/* 异常判断 */
		if (resp_headersize - totalsize <= maxlimit - totalsize) {
			goto FREELABLE;
		}

		/* 异常判断 */
		if (maxlimit - totalsize > htud->response_headers_raw_len) {
			goto FREELABLE;
		}

		memcpy(http_response_header+totalsize, htud->response_headers_raw, maxlimit - totalsize);
		totalsize = maxlimit; //响应行 + 响应头.
	}

    //响应头+响应body
    resp_total = SCCalloc(sizeof(char), totalsize+get_resp_bodysize+8); //响应头 + 响应body = 响应部分. 

	/* 异常判断 */
	if (totalsize > resp_headersize) {
		goto FREELABLE;
	}

	/* 异常判断 */
	if (get_resp_bodysize > resp_bodysize) {
		goto FREELABLE;
	}
	
	memcpy(resp_total,  http_response_header,  totalsize); //响应行 + 响应头.
	memcpy(resp_total+totalsize, http_response_body, get_resp_bodysize); //全部响应部分 = 响应行 + 响应头 + 响应body.

	//size_t jslen = jb_len(js);
	if(StringToBase64(resp_total, totalsize+get_resp_bodysize, &base64ptr, &base64len) >0) //原始字符串转为base64后会变长. 
    {
        jb_set_string(js, "response", base64ptr);
    
        //DEBUG_DLOG ("ConstructBvmHttpReqRespBase64 resp_total size:[%u] resp_total :[%s]\n base64len:[%u], base64ptr:[%s]\n",
              //(unsigned int) totalsize+get_resp_bodysize, resp_total, (unsigned int)base64len, base64ptr);

        HTTP_OUTPUT_FREESTR(base64ptr);
        base64ptr=NULL;
        ret=1;
    }
    //

FREELABLE:
    if(http_request_header ) {   
        HTTP_OUTPUT_FREESTR(http_request_header);
    }
    if(http_request_body){
        HTTP_OUTPUT_FREESTR(http_request_body);
    }
    if(http_response_header){
        HTTP_OUTPUT_FREESTR(http_response_header);
    }
    if(http_response_body){
        HTTP_OUTPUT_FREESTR(http_response_body);
    }
    if(req_total){
        HTTP_OUTPUT_FREESTR(req_total);
    }
    if(resp_total){
        HTTP_OUTPUT_FREESTR(resp_total);
    }
    
    return ret;
}


/*******
 *FUNC:
 * 计算时间戳 : 依据数据包中请求/响应时间差, 计算时间戳 .
 * 成功返回1 , 其他失败.
 * ****/
int GetTimeStamp(const Packet *p, const Flow *f, JsonBuilder *js )
{
    char timebuf[64]={0};

    if(!p || !js || !f){
        return -1; 
    }

    //计算时间差值.
    HtpState *htp_state = (HtpState *)(f->alstate); 
    struct timeval difftimestamp, timestamp_req, timestamp_resp;
    difftimestamp.tv_sec = htp_state->connp->resp_timestamp.tv_sec - htp_state->connp->req_timestamp.tv_sec ;
    difftimestamp.tv_usec = htp_state->connp->resp_timestamp.tv_usec - htp_state->connp->req_timestamp.tv_usec ;

    //请求时间戳
    timestamp_req.tv_sec = SCTIME_SECS(p->ts);
    timestamp_req.tv_usec = SCTIME_USECS(p->ts);
    long int req_st = timestamp_req.tv_sec *1000 + timestamp_req.tv_usec/1000;
    snprintf(timebuf, sizeof(timebuf)-1, "%ld", req_st);
    jb_set_string(js, "startTime", timebuf); 
    bzero(timebuf, sizeof(timebuf));

    //响应时间戳
    timestamp_resp.tv_sec = timestamp_req.tv_sec + difftimestamp.tv_sec;
    timestamp_resp.tv_usec = timestamp_req.tv_usec + difftimestamp.tv_usec;
    long int resp_st = timestamp_resp.tv_sec*1000 + timestamp_resp.tv_usec/1000;
    if(resp_st == req_st ){
        resp_st += 1;
    }
    snprintf(timebuf, sizeof(timebuf)-1, "%ld", resp_st);
    jb_set_string(js, "endTime", timebuf); 


    return 1;
}

/**************
 *FUNC:
 * BVM 二期构造请求/响应 开始时间/结束时间.to http:{ xx }
 *
 *
 * 返回值：
 * 1 成功，其他失败.
 *
 * ************/
int ConstructBvmHttpReqRespBase64V2(const Packet *pkg, htp_tx_t *htx, JsonBuilder *js, uint64_t tx_id )
{
    int ret=-1;
    if(!js ||!htx || !pkg)
        return ret;

    const Flow *flow = (const Flow *)pkg->flow;

    jb_open_object(js, "append_http");

    if((ret = GetTimeStamp(pkg, flow, js)) != 1 ) 
    {
        SCLogNotice("BvmHttpReqRespBase64V2->jb_open_object() failed\n");
        return ret;
    }
    if((ret = ConstructBvmHttpReqRespBase64(pkg, htx, js, tx_id)) != 1)
    {
        //SCLogNotice("BvmHttpReqRespBase64V2->ConstructBvmHttpReqRespBase64() failed\n");
        return ret;
    }
    

    jb_close(js);

    return ret;
}

