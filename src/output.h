/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 */

#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include "decode.h"
#include "tm-modules.h"

#define DEFAULT_LOG_MODE_APPEND     "yes"
#define DEFAULT_LOG_FILETYPE        "regular"


/* 日志输出线程缓存 */
typedef struct OutputLoggerThreadStore_
{
    void *thread_data;
    struct OutputLoggerThreadStore_ *next;
} OutputLoggerThreadStore;


/************************************************************************************************************************************************* 
 *大类日志输出模块头文件
 *（一） packet、tx、file、filedata和streaming五个大类日志。这五类日志，由每个TMM_FLOWWORKER线程模块使用，也就是每个work线程使用后。
 *          注册阶段，以root日志形式注册到registered_loggers列表中；
 *          初始化时，遍历registered_loggers列表，进行初始化和设置；然后调用OutputSetupActiveLoggers函数，将活跃的RootLogger添加到active_loggers列表；
 *          运行阶段，遍历active_loggers列表，获取大类日志模块RootLogger，遍历对应RootLogger中的静态list，调用每个具体输出模块的输出函数
 *（二） flow日志， 由每个TMM_FLOWWORKER线程模块和TMM_FLOWRECYCLER模块管理和使用，也就是work线程和FlowRecycler线程使用。
 *          初始化时：
 *          （1）在FlowWorkerThreadInit和FlowRecyclerThreadInit中调用flow日志模块初始化函数OutputFlowLogThreadInit；
 *          （2）然后调用SetupOutput->OutputRegisterFlowLogger，将具体的日志输出模块添加到flow日志模块使用静态列表static OutputFlowLogger *list中。
 *          运行阶段
 *          （1）在CheckWorkQueue、FlowGetUsedFlow或Recycler函数中调用OutputFlowLog函数
 *          （2）OutputFlowLog函数内部遍历list，调用每个具体输出模块的输出函数
 *（三）stats日志，由TMM_STATSLOGGER模块管理和使用，也就是由统计线程使用。统计线程可以通过配置文件中的stats.enbale配置开启或者关闭。
 *          注册阶段
 *          （1）与其他六大类日志模块不同，stats日志会启动独立线程输出stats日志，因此会注册线程模型
 *          初始化时
 *          （1）在StatsMgmtThread函数中调用OutputStatsLogThreadInit进行初始化；
 *          （2）调用SetupOutput->OutputRegisterStatsLogger，将具体的日志输出模块添加到stats日志模块使用静态列表static OutputStatsLogger *list中；
 *          运行阶段
 *          （1）在StatsMgmtThread函数的while循环中，通过StatsOutput->OutputStatsLog输出日志 
 *************************************************************************************************************************************************/
#include "output-packet.h"
#include "output-tx.h"
#include "output-file.h"
#include "output-filedata.h"
#include "output-streaming.h"
#include "output-flow.h"
#include "output-stats.h"


/*  OutputInit返回值数据结构 */
typedef struct OutputInitResult_
{
    OutputCtx *ctx;
    bool ok;
} OutputInitResult;
typedef OutputInitResult (*OutputInitFunc)(ConfNode *);
typedef OutputInitResult (*OutputInitSubFunc)(ConfNode *, OutputCtx *);
typedef TmEcode  (*OutputLogFunc)(ThreadVars *, Packet *, void *);
typedef uint32_t (*OutputGetActiveCountFunc)(void);


/* 输出模块结构体 */
typedef struct OutputModule_
{
    LoggerId logger_id;             
    const char *name;               // 输出模块名称
    const char *conf_name;          // yaml文件中的配置节点名称
    const char *parent_name;        // 父输出模块名称
    OutputInitFunc InitFunc;        // 输出模块初始化函数
    OutputInitSubFunc InitSubFunc;  // 输出子模块初始化函数

    ThreadInitFunc ThreadInit;      // 线程初始化函数
    ThreadDeinitFunc ThreadDeinit;  // 线程去初始化函数
    ThreadExitPrintStatsFunc ThreadExitPrintStats; // 线程退出时输出统计信息函数

    /**
     * 说明: 
     *   1.注册非root日志输出模块时，会创建一个OutputModule类型变量，并为结构体中的成员变量赋值（注意：一个OutputModule类型变量中只会赋值一种日志处理函数(xxxLogFunc)），然后将创建OutputModule类型变量插入到output_modules列表。
     *   2.初始化时，会遍历output_modules中，对于每一个OutputModule类型变量，会根据logger处理函数，将OutputModule类型变量插入到对应大类日志的静态list中。详见SetupOutput函数。
     */
    PacketLogger PacketLogFunc;                     // packet logger处理函数
    PacketLogCondition PacketConditionFunc;         // packet logger条件函数，对于packet，返回true,才会记录日志
    TxLogger TxLogFunc;                             // tx logger处理函数
    TxLoggerCondition TxLogCondition;               // tx logger条件函数，对于tx，返回true,才会记录日志
    FileLogger FileLogFunc;                         // file logger处理函数
    FiledataLogger FiledataLogFunc;                 // filedata logger处理函数
    StreamingLogger StreamingLogFunc;               // streaming logger处理函数
    FlowLogger FlowLogFunc;                         // flow logger处理函数
    StatsLogger StatsLogFunc;                       // stats log处理函数
    AppProto alproto;                               // 应用层协议
    enum OutputStreamingType stream_type;           // 输出de Streaming类型
    int tc_log_progress;                            // s->c标识
    int ts_log_progress;                            // c->s标识

    TAILQ_ENTRY(OutputModule_) entries;
} OutputModule;
/* 声明已注册的输出模块列表output_modules，定义在output.c中 */
typedef TAILQ_HEAD(OutputModuleList_, OutputModule_) OutputModuleList;
extern OutputModuleList output_modules;


/* 注册一个输出模块 */
void OutputRegisterModule(const char *, const char *, OutputInitFunc);


/* 注册一个packe输出模块 */
void OutputRegisterPacketModule(LoggerId id, const char *name, const char *conf_name, 
                                        OutputInitFunc InitFunc, PacketLogger LogFunc, PacketLogCondition ConditionFunc, 
                                        ThreadInitFunc, ThreadDeinitFunc, ThreadExitPrintStatsFunc);
/* 注册一个packe输出子模块 */
void OutputRegisterPacketSubModule(LoggerId id, const char *parent_name, const char *name, const char *conf_name, 
                                            OutputInitSubFunc InitFunc, PacketLogger LogFunc, PacketLogCondition ConditionFunc,
                                            ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);


/* 注册一个tx输出模块 */
void OutputRegisterTxModule( LoggerId id, const char *name, const char *conf_name,
                                    OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
                                    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个tx输出子模块 */
void OutputRegisterTxSubModule( LoggerId id, const char *parent_name, const char *name, const char *conf_name,
                                        OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
                                        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个带有条件的tx输出模块 */
void OutputRegisterTxModuleWithCondition( LoggerId id, const char *name, const char *conf_name,
                                                    OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, TxLoggerCondition TxLogCondition,
                                                    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个带有条件的tx输出子模块 */
void OutputRegisterTxSubModuleWithCondition( LoggerId id, const char *parent_name, const char *name, const char *conf_name,
                                                        OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, TxLoggerCondition TxLogCondition,
                                                        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个带进度的tx输出模块 */
void OutputRegisterTxModuleWithProgress( LoggerId id, const char *name, const char *conf_name, 
                                                    OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, int tc_log_progress, int ts_log_progress,
                                                    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个带进度的tx输出子模块 */
void OutputRegisterTxSubModuleWithProgress(LoggerId id, const char *parent_name, const char *name, const char *conf_name,
                                                        OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, int tc_log_progress, int ts_log_progress, 
                                                        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);


/* 注册一个file输出模块 */
void OutputRegisterFileModule(LoggerId id, const char *name, const char *conf_name,
                                     OutputInitFunc InitFunc, FileLogger FileLogFunc,
                                     ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个file输出子模块 */
void OutputRegisterFileSubModule(LoggerId id, const char *parent_name, const char *name, const char *conf_name,
                                         OutputInitSubFunc InitFunc, FileLogger FileLogFunc,
                                         ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);


/* 注册一个filedata输出模块 */
void OutputRegisterFiledataModule( LoggerId id, const char *name, const char *conf_name,
                                            OutputInitFunc InitFunc, FiledataLogger FiledataLogFunc,
                                            ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个filedata输出子模块 */
void OutputRegisterFiledataSubModule( LoggerId, const char *parent_name, const char *name, const char *conf_name,
                                                OutputInitSubFunc InitFunc, FiledataLogger FiledataLogFunc,
                                                ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);


/* 注册一个streaming输出模块 */
void OutputRegisterStreamingModule(LoggerId id, const char *name, const char *conf_name,
                                            OutputInitFunc InitFunc, StreamingLogger StreamingLogFunc, enum OutputStreamingType stream_type,
                                            ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个streaming输出子模块 */
void OutputRegisterStreamingSubModule( LoggerId id, const char *parent_name, const char *name, const char *conf_name,
                                                OutputInitSubFunc InitFunc, StreamingLogger StreamingLogFunc, enum OutputStreamingType stream_type,
                                                ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);


/* 注册一个flow输出子模块 */
void OutputRegisterFlowSubModule( LoggerId id, const char *parent_name, const char *name, const char *conf_name, 
                                            OutputInitSubFunc InitFunc, FlowLogger FlowLogFunc,
                                            ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);


/* 注册一个stats输出模块 */
void OutputRegisterStatsModule( LoggerId id, const char *name, const char *conf_name,
                                        OutputInitFunc InitFunc, StatsLogger StatsLogFunc,
                                        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 注册一个stats输出子模块 */
void OutputRegisterStatsSubModule( LoggerId id, const char *parent_name, const char *name, const char *conf_name,
                                            OutputInitSubFunc InitFunc, StatsLogger StatsLogFunc, 
                                            ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats);
/* 根据名称获取输出模块 */
OutputModule *OutputGetModuleByConfName(const char *name);
/* 注销所有输出模块 */
void OutputDeregisterAll(void);


int  OutputDropLoggerEnable(void);
void OutputDropLoggerDisable(void);


/* 注册文件轮换通知标志 */
void OutputRegisterFileRotationFlag(int *flag);
/* 取消注册文件轮换标志 */
void OutputUnregisterFileRotationFlag(int *flag);
/* 通知所有已注册的文件轮换通知标志 */
void OutputNotifyFileRotation(void);


/* 注册rootLogger函数 */
void OutputRegisterRootLogger(ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit, ThreadExitPrintStatsFunc ThreadExitPrintStats, OutputLogFunc LogFunc, OutputGetActiveCountFunc ActiveCntFunc);
/* 注册日志模块： 包括所有root大类日志和非root日志 
 * 1）注册root大类日志时，会调用OutputRegisterRootLogger函数
 * 2）注册非root日志时，会调用上面声明的 OutputRegisterxxxModule函数
 */
void TmModuleLoggerRegister(void);


/* 设置活跃的大类日志 */
void OutputSetupActiveLoggers(void);
/* 清除active_loggers列表中已注册的活跃的日志大类 */
void OutputClearActiveLoggers(void);


/* 日志线程输出模块输出函数（总接口）
 * 只有三个调用处：
 *  1）flow-worker.c: FlowWorker()
 *  2）flow-worker.c: FlowWorkerFlowTimeout()
 *  3）flow-worker.c: FlowWorkerStreamTCPUpdate() 
 */
TmEcode OutputLoggerLog(ThreadVars *, Packet *, void *);
/* 日志输出线程模块初始化 */
TmEcode OutputLoggerThreadInit(ThreadVars *, const void *, void **);
/* 日志输出线程模块去初始化 */
TmEcode OutputLoggerThreadDeinit(ThreadVars *, void *);
/* 日志输出线程模块退出，输出统计信息 */
void    OutputLoggerExitPrintStats(ThreadVars *, void *);


#endif /* ! __OUTPUT_H__ */
