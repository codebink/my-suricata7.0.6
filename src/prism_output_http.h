
#ifndef __PRISM_OUTPUT_HTTP_H__
#define __PRISM_OUTPUT_HTTP_H__

/*******
 *FUNC:
 * 构造BVM http 请求/响应 base64(header + body) 并加入 js中 .
 * 成功返回1 , 其他失败.
 * ****/
int ConstructBvmHttpReqRespBase64(const Packet *pkg, htp_tx_t *htx, JsonBuilder *js, uint64_t tx_id) ;

/*******
 *FUNC:
 * 计算时间戳 : 依据数据包中请求/响应时间差, 计算时间戳 .
 * 成功返回1 , 其他失败.
 * ****/
int GetTimeStamp(const Packet *pkg, const Flow *f, JsonBuilder *js ) ;

/**************
 *FUNC:
 * BVM 二期构造请求/响应 开始时间/结束时间.to http:{ xx }
 *
 *
 * 返回值：
 * 1 成功，其他失败.
 *
 * ************/
int ConstructBvmHttpReqRespBase64V2( const Packet *pkg, htp_tx_t *htx, JsonBuilder *js, uint64_t tx_id ) ;

#endif

