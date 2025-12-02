#include "suricata-common.h"
#include "util-logopenfile.h"
#include "util-log-tcp.h"
#include "util-byte.h"
#include "util-debug.h"

/* TCP reload 使用的开关 */
#define TCP_SERVER "app-layer.protocols.flow-log.tcp-server"
#define TCP_PORT "app-layer.protocols.flow-log.tcp-port"

TcpConf tcp_conf;

/* 热加载函数 */
void TcpReload(void)
{
	ConfNode *node = NULL;

	/* 服务端 IP */
	node = NULL;
	node = ConfGetNode(TCP_SERVER);
	if (node && node->val != NULL) {
		if (TCP_IP_LEN <= strlen(node->val)) {
			/* 未来可打个服务端 IP 错误日志 */
		}else {
			memcpy(tcp_conf.server, node->val, strlen(node->val));
		}
	}else {
		/* 未来可打个服务端 IP 错误日志 */
	}

	/* 获取是否打开日志开关 */
	node = NULL;
	node = ConfGetNode(TCP_PORT);
	if (node && node->val != NULL) {
		tcp_conf.port = atoi(node->val);
	}else {
		/* 未来可打个服务端 IP 错误日志 */
	}
}

/* tcp 连接打开 */
static int FlowTcpOpen(void *ctx)
{
	if (NULL == ctx) {
		return 1;
	}

	LogFileCtx *log_ctx = (LogFileCtx *)ctx;

    int sockfd;
    struct sockaddr_in server_addr;

    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		/* 未来加入打印 err */
		return 1;
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tcp_conf.port);
    if (inet_pton(AF_INET, tcp_conf.server, &server_addr.sin_addr) <= 0) {
        /* 未来加入打印 err */
        close(sockfd);
		return 1;
    }

    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        /* 未来加入打印 err */
        close(sockfd);
		return 1;
    }

	log_ctx->tcp_conn.sockfd = sockfd;

	return 0;
}

/* tcp 连接重新打开 */
static int FlowTcpReopen(void *ctx)
{
	if (NULL == ctx) {
		return 1;
	}

	LogFileCtx *log_ctx = (LogFileCtx *)ctx;

    int sockfd;
    struct sockaddr_in server_addr;

	/* 首先关闭异常的连接描述符,操作系统默认打开的是 0,1,2 防止关闭上述描述符 */
	if (2 < log_ctx->tcp_conn.sockfd) {
		close(log_ctx->tcp_conn.sockfd);
	}

    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		/* 未来加入打印 err */
		return 1;
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tcp_conf.port);
    if (inet_pton(AF_INET, tcp_conf.server, &server_addr.sin_addr) <= 0) {
        /* 未来加入打印 err */
        close(sockfd);
		return 1;
    }

    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        /* 未来加入打印 err */
        close(sockfd);
		return 1;
    }

	log_ctx->tcp_conn.sockfd = sockfd;

	return 0;
}


/* tcp 连接关闭 */
int FlowTcpClose(void *ctx)
{
	if (NULL == ctx) {
		return 1;
	}

	LogFileCtx *log_ctx = (LogFileCtx *)ctx;

	/* 只有成功初始化的互斥锁才能销毁 */
	if (1 == log_ctx->tcp_mutex_key) {
		SCMutexDestroy(&log_ctx->tcp_mutex);
	}

	/* 关闭 TCP 连接 */	
	close(log_ctx->tcp_conn.sockfd);
	return 0;
}

/* tcp flow 事件发送 */
int FlowTcpWrite(void *ctx, char *buff, uint32_t buff_len)
{
	if (NULL == ctx || NULL == buff || 1 > buff_len) {
		return 1;
	}

	LogFileCtx *log_ctx = (LogFileCtx *)ctx;
	int bytes_sent;

    // 发送消息
    bytes_sent = send(log_ctx->tcp_conn.sockfd, buff, buff_len, 0);
    if (bytes_sent < 0) {
        /* 如果管道破裂或连接被重置，尝试重新打开连接 */
        FlowTcpReopen(ctx);
		
		/* 再发送一次 */
		bytes_sent = send(log_ctx->tcp_conn.sockfd, buff, buff_len, 0);
    }

	return 0;
}

/* tcp 连接初始化 */
int FlowTcpConnInit(void *ctx)
{
	if (NULL == ctx) {
		return 1;
	}

	LogFileCtx *log_ctx = (LogFileCtx *)ctx;

	/* eve-log 是否是上述类型，都不影响使用 TCP 连接外发 flow，TCP 外发与上述类型是平行的关系，首先初始化 互斥锁 */
	SCMutexInit(&(log_ctx->tcp_mutex), NULL);
	log_ctx->tcp_mutex_key = 1;

	TcpReload();

	FlowTcpOpen(log_ctx);

	return 0;
}




