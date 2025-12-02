/* Copyright (C) 2020-2021 Open Information Security Foundation
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

#ifndef __SURICATA_PLUGIN_H__
#define __SURICATA_PLUGIN_H__

#include <stdint.h>
#include <stdbool.h>

#include "conf.h"

/**
 * The size of the data chunk inside each packet structure a plugin has for private data (Packet->plugin_v).
 * 插件中每个数据包结构内用于存储私有数据的数据块大小（Packet->plugin_v）
 */
#define PLUGIN_VAR_SIZE 64

/**
 * Structure to define a Suricata plugin.
 * 用于定义 Suricata 插件的结构
 */
typedef struct SCPlugin_ 
{
    const char *name;
    const char *license;
    const char *author;
    void (*Init)(void);
} SCPlugin;

typedef SCPlugin *(*SCPluginRegisterFunc)(void);

/**
 * 定义eve-log模式下输出文件类型为plugin时,使用的结构
 */
typedef struct SCEveFileType_ 
{
    /* 输出类型名称，用于在eve-log配置的filetype选项指定输出。*/
    const char *name;
    
    /* 首次访问时调用初始化 */
    int (*Init)(ConfNode *conf, bool threaded, void **init_data);
    /*  每次写入file对象时调用*/
    int (*Write)(const char *buffer, int buffer_len, void *init_data, void *thread_data);
    /* 最终关闭时调用*/
    void (*Deinit)(void *init_data);
    
    /* 每个线程使用file对象的调用，进行初始化 */
    int (*ThreadInit)(void *init_data, int thread_id, void **thread_data);
    /* 每个线程使用file对象的调用，进行   去初始化*/
    int (*ThreadDeinit)(void *init_data, void *thread_data);

    TAILQ_ENTRY(SCEveFileType_) entries;
} SCEveFileType;
/* 注册Eve输出文件类型插件 */
bool SCRegisterEveFileType(SCEveFileType *);

typedef struct SCCapturePlugin_
{
    char *name;
    void (*Init)(const char *args, int plugin_slot, int receive_slot, int decode_slot);
    int (*ThreadInit)(void *ctx, int thread_id, void **thread_ctx);
    int (*ThreadDeinit)(void *ctx, void *thread_ctx);
    const char *(*GetDefaultMode)(void);
    TAILQ_ENTRY(SCCapturePlugin_) entries;
} SCCapturePlugin;

int SCPluginRegisterCapture(SCCapturePlugin *);

#endif /* __SURICATA_PLUGIN_H */
