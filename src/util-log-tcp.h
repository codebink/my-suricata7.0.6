#ifndef __UTIL_LOG_TCP_H__
#define __UTIL_LOG_TCP_H__

#include "conf.h"            /* ConfNode   */

#define TCP_IP_LEN 64 

/* 连接信息结构 */
typedef struct TcpConn_ {
	int sockfd;              //套接字描述符
} TcpConn;

/* Reload 模块开关和日志开关 */
typedef struct TcpConf_ {
    char server[TCP_IP_LEN]; //服务端 IP
    uint16_t  port;          //服务端 port
}TcpConf;

/* Reload 函数 */
void TcpReload(void);


int FlowTcpConnInit(void *ctx);
int FlowTcpClose(void *ctx);
int FlowTcpWrite(void *ctx, char *buff, uint32_t buff_len);


#endif /* __UTIL_LOG_TCP_H__ */
