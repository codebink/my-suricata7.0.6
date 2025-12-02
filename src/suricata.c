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
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifndef OS_WIN32
#ifdef HAVE_SYS_RESOURCE_H
// setrlimit
#include <sys/resource.h>
#endif
#endif

#if HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "suricata.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "decode.h"
#include "defrag.h"
#include "flow.h"
#include "stream-tcp.h"
#include "ippair.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-alert.h"
#include "detect-engine-port.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"
#include "detect-fast-pattern.h"

#include "datasets.h"

#include "feature.h"

#include "flow-bypass.h"
#include "flow-manager.h"
#include "flow-timeout.h"
#include "flow-worker.h"

#include "flow-bit.h"
#include "host-bit.h"
#include "ippair-bit.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-htp-range.h"

#include "output.h"
#include "output-filestore.h"

#include "respond-reject.h"

#include "runmode-af-packet.h"
#include "runmode-af-xdp.h"
#include "runmode-netmap.h"
#include "runmode-unittests.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"
#include "source-nflog.h"
#include "source-ipfw.h"
#include "source-pcap.h"
#include "source-pcap-file.h"
#include "source-pcap-file-helper.h"
#include "source-pfring.h"
#include "source-erf-file.h"
#include "source-erf-dag.h"
#include "source-napatech.h"
#include "source-af-packet.h"
#include "source-af-xdp.h"
#include "source-netmap.h"
#include "source-dpdk.h"
#include "source-windivert.h"
#include "source-windivert-prototypes.h"

#include "unix-manager.h"

#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-reference-config.h"

#include "tmqh-packetpool.h"
#include "tm-queuehandlers.h"

#include "util-byte.h"
#include "util-conf.h"
#include "util-coredump-config.h"
#include "util-cpu.h"
#include "util-daemon.h"
#include "util-device.h"
#include "util-dpdk.h"
#include "util-ebpf.h"
#include "util-exception-policy.h"
#include "util-host-os-info.h"
#include "util-hugepages.h"
#include "util-ioctl.h"
#include "util-landlock.h"
#include "util-luajit.h"
#include "util-macset.h"
#include "util-misc.h"
#include "util-mpm-hs.h"
#include "util-path.h"
#include "util-pidfile.h"
#include "util-plugin.h"
#include "util-privs.h"
#include "util-profiling.h"
#include "util-proto-name.h"
#include "util-running-modes.h"
#include "util-signal.h"
#include "util-time.h"
#include "util-validate.h"
#include "util-var-name.h"

#ifdef WINDIVERT
#include "decode-sll.h"
#include "win32-syscall.h"
#endif

/*
 * we put this here, because we only use it here in main.
 */
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;
volatile sig_atomic_t sigusr2_count = 0;

/*
 * Flag to indicate if the engine is at the initialization
 * or already processing packets. 3 stages: SURICATA_INIT,
 * SURICATA_RUNTIME and SURICATA_FINALIZE
 */
SC_ATOMIC_DECLARE(unsigned int, engine_stage);

/* Max packets processed simultaneously per thread. */
#define DEFAULT_MAX_PENDING_PACKETS 1024

/** suricata engine control flags */
volatile uint8_t suricata_ctl_flags = 0;

/** Run mode selected */
int run_mode = RUNMODE_UNKNOWN;

/** Engine mode: inline (ENGINE_MODE_IPS) or just
  * detection mode (ENGINE_MODE_IDS by default) */
static enum EngineMode g_engine_mode = ENGINE_MODE_UNKNOWN;

/** Host mode: set if box is sniffing only
 * or is a router */
uint8_t host_mode = SURI_HOST_IS_SNIFFER_ONLY;

/** Maximum packets to simultaneously process. */
uint16_t max_pending_packets;

/** global indicating if detection is enabled */
int g_detect_disabled = 0;

/** set caps or not */
int sc_set_caps = FALSE;

bool g_system = false;

/** disable randomness to get reproducible results across runs */
#ifndef AFLFUZZ_NO_RANDOM
int g_disable_randomness = 0;
#else
int g_disable_randomness = 1;
#endif

/** determine (without branching) if we include the vlan_ids when hashing or
  * comparing flows */
uint16_t g_vlan_mask = 0xffff;

/** determine (without branching) if we include the livedev ids when hashing or
 * comparing flows */
uint16_t g_livedev_mask = 0xffff;

/* flag to disable hashing almost globally, to be similar to disabling nss
 * support */
bool g_disable_hashing = false;

/** Suricata instance */
SCInstance suricata;

int SuriHasSigFile(void)
{
    return (suricata.sig_file != NULL);
}

int EngineModeIsUnknown(void)
{
    return (g_engine_mode == ENGINE_MODE_UNKNOWN);
}

int EngineModeIsIPS(void)
{
    DEBUG_VALIDATE_BUG_ON(g_engine_mode == ENGINE_MODE_UNKNOWN);
    return (g_engine_mode == ENGINE_MODE_IPS);
}

int EngineModeIsIDS(void)
{
    DEBUG_VALIDATE_BUG_ON(g_engine_mode == ENGINE_MODE_UNKNOWN);
    return (g_engine_mode == ENGINE_MODE_IDS);
}

void EngineModeSetIPS(void)
{
    g_engine_mode = ENGINE_MODE_IPS;
}

void EngineModeSetIDS(void)
{
    g_engine_mode = ENGINE_MODE_IDS;
}

#ifdef UNITTESTS
int RunmodeIsUnittests(void)
{
    if (run_mode == RUNMODE_UNITTEST)
        return 1;

    return 0;
}
#endif

int RunmodeGetCurrent(void)
{
    return run_mode;
}

/** signal handlers
 *
 *  WARNING: don't use the SCLog* API in the handlers. The API is complex
 *  with memory allocation possibly happening, calls to syslog, json message
 *  construction, etc.
 */

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static void SignalHandlerSigint(/*@unused@*/ int sig)
{
    sigint_count = 1;
}
static void SignalHandlerSigterm(/*@unused@*/ int sig)
{
    sigterm_count = 1;
}
#ifndef OS_WIN32
#if HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
static void SignalHandlerUnexpected(int sig_num, siginfo_t *info, void *context)
{
    char msg[SC_LOG_MAX_LOG_MSG_LEN];
    unw_cursor_t cursor;
    /* Restore defaults for signals to avoid loops */
    signal(SIGABRT, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    int r;
    if ((r = unw_init_local(&cursor, (unw_context_t *)(context)) != 0)) {
        SCLogError("unable to obtain stack trace: unw_init_local: %s", unw_strerror(r));
        goto terminate;
    }

    char *temp = msg;
    int cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - msg), "stacktrace:sig %d:", sig_num);
    temp += cw;
    r = 1;
    while (r > 0) {
        if (unw_is_signal_frame(&cursor) == 0) {
            unw_word_t off;
            char name[256];
            if (unw_get_proc_name(&cursor, name, sizeof(name), &off) == UNW_ENOMEM) {
                cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - msg), "[unknown]:");
            } else {
                cw = snprintf(
                        temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - msg), "%s+0x%08" PRIx64, name, off);
            }
            temp += cw;
        }

        r = unw_step(&cursor);
        if (r > 0) {
            cw = snprintf(temp, SC_LOG_MAX_LOG_MSG_LEN - (temp - msg), ";");
            temp += cw;
        }
    }
    SCLogError("%s", msg);

terminate:
    // Propagate signal to watchers, if any
    kill(getpid(), sig_num);
}
#undef UNW_LOCAL_ONLY
#endif /* HAVE_LIBUNWIND */
#endif /* !OS_WIN32 */
#endif

#ifndef OS_WIN32
/**
 * SIGUSR2 handler.  Just set sigusr2_count.  The main loop will act on
 * it.
 */
static void SignalHandlerSigusr2(int sig)
{
    if (sigusr2_count < 2)
        sigusr2_count++;
}

/**
 * SIGHUP handler.  Just set sighup_count.  The main loop will act on
 * it.
 */
static void SignalHandlerSigHup(/*@unused@*/ int sig)
{
    sighup_count = 1;
}
#endif

void GlobalsInitPreConfig(void)
{
	/** 
	 * 初始化时间。
	 * 包括：获取当前时间所用的spin lock，以及设置时区(调用tzset()即可) 
	 */
    TimeInit();
    /**
     * 为快速模式匹配注册关键字 
	 * 调用SupportFastPatternForSigMatchList函数，按照优先级大小插入到sm_fp_support_smlist_list链表中 
	 */
    SupportFastPatternForSigMatchTypes();
    /* 阈值配置全局初始化 */
    SCThresholdConfGlobalInit();
    SCProtoNameInit();
    FrameConfigInit();
}

static void GlobalsDestroy(SCInstance *suri)
{
    HostShutdown();
    HTPFreeConfig();
    HTPAtExitPrintStats();

    AppLayerHtpPrintStats();

    /* TODO this can do into it's own func */
    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();
    if (de_ctx) 
    {
        DetectEngineMoveToFreeList(de_ctx);
        DetectEngineDeReference(&de_ctx);
    }
    DetectEngineClearMaster();

    AppLayerDeSetup();
    DatasetsSave();
    DatasetsDestroy();
    TagDestroyCtx();

    LiveDeviceListClean();
    OutputDeregisterAll();
    FeatureTrackingRelease();
    SCProtoNameRelease();
    TimeDeinit();
    TmqhCleanup();
    TmModuleRunDeInit();
    ParseSizeDeinit();

#ifdef HAVE_DPDK
    DPDKCleanupEAL();
#endif

#ifdef HAVE_AF_PACKET
    AFPPeersListClean();
#endif

#ifdef NFQ
    NFQContextsClean();
#endif

#ifdef BUILD_HYPERSCAN
    MpmHSGlobalCleanup();
#endif

    ConfDeInit();
#ifdef HAVE_LUAJIT
    LuajitFreeStatesPool();
#endif
    DetectParseFreeRegexes();

    SCPidfileRemove(suri->pid_filename);
    SCFree(suri->pid_filename);
    suri->pid_filename = NULL;

    VarNameStoreDestroy();
    SCLogDeInitLogModule();
}

/**
 * \brief Used to send OS specific notification of running threads
 *
 * \retval TmEcode TM_ECODE_OK on success; TM_ECODE_FAILED on failure.
 */
static void OnNotifyRunning(void)
{
#if HAVE_LIBSYSTEMD
    if (sd_notify(0, "READY=1") < 0) {
        SCLogWarning("failed to notify systemd");
        /* Please refer to:
         * https://www.freedesktop.org/software/systemd/man/sd_notify.html#Return%20Value
         * for discussion on why failure should not be considered an error */
    }
#endif
}

/** \brief make sure threads can stop the engine by calling this
 *  function. Purpose: pcap file mode needs to be able to tell the
 *  engine the file eof is reached. */
void EngineStop(void)
{
    suricata_ctl_flags |= SURICATA_STOP;
}

/**
 * \brief Used to indicate that the current task is done.
 *
 * This is mainly used by pcap-file to tell it has finished
 * to treat a pcap files when running in unix-socket mode.
 */
void EngineDone(void)
{
    suricata_ctl_flags |= SURICATA_DONE;
}

static int SetBpfString(int argc, char *argv[])
{
    char *bpf_filter = NULL;
    uint32_t bpf_len = 0;
    int tmpindex = 0;

    /* attempt to parse remaining args as bpf filter */
    tmpindex = argc;
    while(argv[tmpindex] != NULL) {
        bpf_len+=strlen(argv[tmpindex]) + 1;
        tmpindex++;
    }

    if (bpf_len == 0)
        return TM_ECODE_OK;

    bpf_filter = SCMalloc(bpf_len);
    if (unlikely(bpf_filter == NULL))
        return TM_ECODE_FAILED;
    memset(bpf_filter, 0x00, bpf_len);

    tmpindex = optind;
    while(argv[tmpindex] != NULL) {
        strlcat(bpf_filter, argv[tmpindex],bpf_len);
        if(argv[tmpindex + 1] != NULL) {
            strlcat(bpf_filter," ", bpf_len);
        }
        tmpindex++;
    }

    if(strlen(bpf_filter) > 0) {
        if (ConfSetFinal("bpf-filter", bpf_filter) != 1) {
            SCLogError("Failed to set bpf filter.");
            SCFree(bpf_filter);
            return TM_ECODE_FAILED;
        }
    }
    SCFree(bpf_filter);

    return TM_ECODE_OK;
}

static void SetBpfStringFromFile(char *filename)
{
    char *bpf_filter = NULL;
    char *bpf_comment_tmp = NULL;
    char *bpf_comment_start =  NULL;
    uint32_t bpf_len = 0;
    SCStat st;
    FILE *fp = NULL;
    size_t nm = 0;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        SCLogError("Failed to open file %s", filename);
        exit(EXIT_FAILURE);
    }

    if (SCFstatFn(fileno(fp), &st) != 0) {
        SCLogError("Failed to stat file %s", filename);
        exit(EXIT_FAILURE);
    }
    bpf_len = st.st_size + 1;

    bpf_filter = SCMalloc(bpf_len);
    if (unlikely(bpf_filter == NULL)) {
        SCLogError("Failed to allocate buffer for bpf filter in file %s", filename);
        exit(EXIT_FAILURE);
    }
    memset(bpf_filter, 0x00, bpf_len);

    nm = fread(bpf_filter, 1, bpf_len - 1, fp);
    if ((ferror(fp) != 0) || (nm != (bpf_len - 1))) {
        SCLogError("Failed to read complete BPF file %s", filename);
        SCFree(bpf_filter);
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    bpf_filter[nm] = '\0';

    if(strlen(bpf_filter) > 0) {
        /*replace comments with space*/
        bpf_comment_start = bpf_filter;
        while((bpf_comment_tmp = strchr(bpf_comment_start, '#')) != NULL) {
            while((*bpf_comment_tmp !='\0') &&
                (*bpf_comment_tmp != '\r') && (*bpf_comment_tmp != '\n'))
            {
                *bpf_comment_tmp++ = ' ';
            }
            bpf_comment_start = bpf_comment_tmp;
        }
        /*remove remaining '\r' and '\n' */
        while((bpf_comment_tmp = strchr(bpf_filter, '\r')) != NULL) {
            *bpf_comment_tmp = ' ';
        }
        while((bpf_comment_tmp = strchr(bpf_filter, '\n')) != NULL) {
            *bpf_comment_tmp = ' ';
        }
        /* cut trailing spaces */
        while (strlen(bpf_filter) > 0 &&
                bpf_filter[strlen(bpf_filter)-1] == ' ')
        {
            bpf_filter[strlen(bpf_filter)-1] = '\0';
        }
        if (strlen(bpf_filter) > 0) {
            if (ConfSetFinal("bpf-filter", bpf_filter) != 1) {
                SCFree(bpf_filter);
                FatalError("failed to set bpf filter");
            }
        }
    }
    SCFree(bpf_filter);
}

static void PrintUsage(const char *progname)
{
#ifdef REVISION
    printf("%s %s (%s)\n", PROG_NAME, PROG_VER, xstr(REVISION));
#else
    printf("%s %s\n", PROG_NAME, PROG_VER);
#endif
    printf("USAGE: %s [OPTIONS] [BPF FILTER]\n\n", progname);
    printf("\t-c <path>                            : path to configuration file\n");
    printf("\t-T                                   : test configuration file (use with -c)\n");
    printf("\t-i <dev or ip>                       : run in pcap live mode\n");
    printf("\t-F <bpf filter file>                 : bpf filter file\n");
    printf("\t-r <path>                            : run in pcap file/offline mode\n");
#ifdef NFQ
    printf("\t-q <qid[:qid]>                       : run in inline nfqueue mode (use colon to specify a range of queues)\n");
#endif /* NFQ */
#ifdef IPFW
    printf("\t-d <divert port>                     : run in inline ipfw divert mode\n");
#endif /* IPFW */
    printf("\t-s <path>                            : path to signature file loaded in addition to suricata.yaml settings (optional)\n");
    printf("\t-S <path>                            : path to signature file loaded exclusively (optional)\n");
    printf("\t-l <dir>                             : default log directory\n");
#ifndef OS_WIN32
    printf("\t-D                                   : run as daemon\n");
#else
    printf("\t--service-install                    : install as service\n");
    printf("\t--service-remove                     : remove service\n");
    printf("\t--service-change-params              : change service startup parameters\n");
#endif /* OS_WIN32 */
    printf("\t-k [all|none]                        : force checksum check (all) or disabled it (none)\n");
    printf("\t-V                                   : display Suricata version\n");
    printf("\t-v                                   : be more verbose (use multiple times to increase verbosity)\n");
#ifdef UNITTESTS
    printf("\t-u                                   : run the unittests and exit\n");
    printf("\t-U, --unittest-filter=REGEX          : filter unittests with a regex\n");
    printf("\t--list-unittests                     : list unit tests\n");
    printf("\t--fatal-unittests                    : enable fatal failure on unittest error\n");
    printf("\t--unittests-coverage                 : display unittest coverage report\n");
#endif /* UNITTESTS */
    printf("\t--list-app-layer-protos              : list supported app layer protocols\n");
    printf("\t--list-keywords[=all|csv|<kword>]    : list keywords implemented by the engine\n");
    printf("\t--list-runmodes                      : list supported runmodes\n");
    printf("\t--runmode <runmode_id>               : specific runmode modification the engine should run.  The argument\n"
           "\t                                       supplied should be the id for the runmode obtained by running\n"
           "\t                                       --list-runmodes\n");
    printf("\t--engine-analysis                    : print reports on analysis of different sections in the engine and exit.\n"
           "\t                                       Please have a look at the conf parameter engine-analysis on what reports\n"
           "\t                                       can be printed\n");
    printf("\t--pidfile <file>                     : write pid to this file\n");
    printf("\t--init-errors-fatal                  : enable fatal failure on signature init error\n");
    printf("\t--disable-detection                  : disable detection engine\n");
    printf("\t--dump-config                        : show the running configuration\n");
    printf("\t--dump-features                      : display provided features\n");
    printf("\t--build-info                         : display build information\n");
    printf("\t--pcap[=<dev>]                       : run in pcap mode, no value select interfaces from suricata.yaml\n");
    printf("\t--pcap-file-continuous               : when running in pcap mode with a directory, continue checking directory for pcaps until interrupted\n");
    printf("\t--pcap-file-delete                   : when running in replay mode (-r with directory or file), will delete pcap files that have been processed when done\n");
    printf("\t--pcap-file-recursive                : will descend into subdirectories when running in replay mode (-r)\n");
#ifdef HAVE_PCAP_SET_BUFF
    printf("\t--pcap-buffer-size                   : size of the pcap buffer value from 0 - %i\n",INT_MAX);
#endif /* HAVE_SET_PCAP_BUFF */
#ifdef HAVE_DPDK
    printf("\t--dpdk                               : run in dpdk mode, uses interfaces from "
           "suricata.yaml\n");
#endif
#ifdef HAVE_AF_PACKET
    printf("\t--af-packet[=<dev>]                  : run in af-packet mode, no value select interfaces from suricata.yaml\n");
#endif
#ifdef HAVE_AF_XDP
    printf("\t--af-xdp[=<dev>]                     : run in af-xdp mode, no value select "
           "interfaces from suricata.yaml\n");
#endif
#ifdef HAVE_NETMAP
    printf("\t--netmap[=<dev>]                     : run in netmap mode, no value select interfaces from suricata.yaml\n");
#endif
#ifdef HAVE_PFRING
    printf("\t--pfring[=<dev>]                     : run in pfring mode, use interfaces from suricata.yaml\n");
    printf("\t--pfring-int <dev>                   : run in pfring mode, use interface <dev>\n");
    printf("\t--pfring-cluster-id <id>             : pfring cluster id \n");
    printf("\t--pfring-cluster-type <type>         : pfring cluster type for PF_RING 4.1.2 and later cluster_round_robin|cluster_flow\n");
#endif /* HAVE_PFRING */
    printf("\t--simulate-ips                       : force engine into IPS mode. Useful for QA\n");
#ifdef HAVE_LIBCAP_NG
    printf("\t--user <user>                        : run suricata as this user after init\n");
    printf("\t--group <group>                      : run suricata as this group after init\n");
#endif /* HAVE_LIBCAP_NG */
    printf("\t--erf-in <path>                      : process an ERF file\n");
#ifdef HAVE_DAG
    printf("\t--dag <dagX:Y>                       : process ERF records from DAG interface X, stream Y\n");
#endif
#ifdef HAVE_NAPATECH
    printf("\t--napatech                           : run Napatech Streams using the API\n");
#endif
#ifdef BUILD_UNIX_SOCKET
    printf("\t--unix-socket[=<file>]               : use unix socket to control suricata work\n");
#endif
#ifdef WINDIVERT
    printf("\t--windivert <filter>                 : run in inline WinDivert mode\n");
    printf("\t--windivert-forward <filter>         : run in inline WinDivert mode, as a gateway\n");
#endif
#ifdef HAVE_LIBNET11
    printf("\t--reject-dev <dev>                   : send reject packets from this interface\n");
#endif
    printf("\t--include <path>                     : additional configuration file\n");
    printf("\t--set name=value                     : set a configuration value\n");
    printf("\n");
    printf("\nTo run the engine with default configuration on "
            "interface eth0 with signature file \"signatures.rules\", run the "
            "command as:\n\n%s -c suricata.yaml -s signatures.rules -i eth0 \n\n",
            progname);
}

static void PrintBuildInfo(void)
{
    const char *bits;
    const char *endian;
    char features[2048] = "";
    const char *tls;

    printf("This is %s version %s\n", PROG_NAME, GetProgramVersion());
#ifdef DEBUG
    strlcat(features, "DEBUG ", sizeof(features));
#endif
#ifdef DEBUG_VALIDATION
    strlcat(features, "DEBUG_VALIDATION ", sizeof(features));
#endif
#ifdef UNITTESTS
    strlcat(features, "UNITTESTS ", sizeof(features));
#endif
#ifdef NFQ
    strlcat(features, "NFQ ", sizeof(features));
#endif
#ifdef IPFW
    strlcat(features, "IPFW ", sizeof(features));
#endif
#ifdef HAVE_PCAP_SET_BUFF
    strlcat(features, "PCAP_SET_BUFF ", sizeof(features));
#endif
#ifdef HAVE_PFRING
    strlcat(features, "PF_RING ", sizeof(features));
#endif
#ifdef HAVE_AF_PACKET
    strlcat(features, "AF_PACKET ", sizeof(features));
#endif
#ifdef HAVE_NETMAP
    strlcat(features, "NETMAP ", sizeof(features));
#endif
#ifdef HAVE_PACKET_FANOUT
    strlcat(features, "HAVE_PACKET_FANOUT ", sizeof(features));
#endif
#ifdef HAVE_DAG
    strlcat(features, "DAG ", sizeof(features));
#endif
#ifdef HAVE_LIBCAP_NG
    strlcat(features, "LIBCAP_NG ", sizeof(features));
#endif
#ifdef HAVE_LIBNET11
    strlcat(features, "LIBNET1.1 ", sizeof(features));
#endif
#ifdef HAVE_HTP_URI_NORMALIZE_HOOK
    strlcat(features, "HAVE_HTP_URI_NORMALIZE_HOOK ", sizeof(features));
#endif
#ifdef PCRE2_HAVE_JIT
    strlcat(features, "PCRE_JIT ", sizeof(features));
#endif
    /* For compatibility, just say we have HAVE_NSS. */
    strlcat(features, "HAVE_NSS ", sizeof(features));
    /* HTTP2_DECOMPRESSION is not an optional feature in this major version */
    strlcat(features, "HTTP2_DECOMPRESSION ", sizeof(features));
#ifdef HAVE_LUA
    strlcat(features, "HAVE_LUA ", sizeof(features));
#endif
#ifdef HAVE_JA3
    strlcat(features, "HAVE_JA3 ", sizeof(features));
#endif
#ifdef HAVE_JA4
    strlcat(features, "HAVE_JA4 ", sizeof(features));
#endif
#ifdef HAVE_LUAJIT
    strlcat(features, "HAVE_LUAJIT ", sizeof(features));
#endif
    strlcat(features, "HAVE_LIBJANSSON ", sizeof(features));
#ifdef PROFILING
    strlcat(features, "PROFILING ", sizeof(features));
#endif
#ifdef PROFILE_LOCKING
    strlcat(features, "PROFILE_LOCKING ", sizeof(features));
#endif
#if defined(TLS_C11) || defined(TLS_GNU)
    strlcat(features, "TLS ", sizeof(features));
#endif
#if defined(TLS_C11)
    strlcat(features, "TLS_C11 ", sizeof(features));
#elif defined(TLS_GNU)
    strlcat(features, "TLS_GNU ", sizeof(features));
#endif
#ifdef HAVE_MAGIC
    strlcat(features, "MAGIC ", sizeof(features));
#endif
    strlcat(features, "RUST ", sizeof(features));
#if defined(SC_ADDRESS_SANITIZER)
    strlcat(features, "ASAN ", sizeof(features));
#endif
#if defined(HAVE_POPCNT64)
    strlcat(features, "POPCNT64 ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    }

    printf("Features: %s\n", features);

    /* SIMD stuff */
    memset(features, 0x00, sizeof(features));
#if defined(__SSE4_2__)
    strlcat(features, "SSE_4_2 ", sizeof(features));
#endif
#if defined(__SSE4_1__)
    strlcat(features, "SSE_4_1 ", sizeof(features));
#endif
#if defined(__SSE3__)
    strlcat(features, "SSE_3 ", sizeof(features));
#endif
#if defined(__SSE2__)
    strlcat(features, "SSE_2 ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    }
    printf("SIMD support: %s\n", features);

    /* atomics stuff */
    memset(features, 0x00, sizeof(features));
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1)
    strlcat(features, "1 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2)
    strlcat(features, "2 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4)
    strlcat(features, "4 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)
    strlcat(features, "8 ", sizeof(features));
#endif
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16)
    strlcat(features, "16 ", sizeof(features));
#endif
    if (strlen(features) == 0) {
        strlcat(features, "none", sizeof(features));
    } else {
        strlcat(features, "byte(s)", sizeof(features));
    }
    printf("Atomic intrinsics: %s\n", features);

#if __WORDSIZE == 64
    bits = "64-bits";
#elif __WORDSIZE == 32
    bits = "32-bits";
#else
    bits = "<unknown>-bits";
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
    endian = "Big-endian";
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    endian = "Little-endian";
#else
    endian = "<unknown>-endian";
#endif

    printf("%s, %s architecture\n", bits, endian);
#ifdef __GNUC__
    printf("GCC version %s, C version %"PRIiMAX"\n", __VERSION__, (intmax_t)__STDC_VERSION__);
#else
    printf("C version %"PRIiMAX"\n", (intmax_t)__STDC_VERSION__);
#endif

#if __SSP__ == 1
    printf("compiled with -fstack-protector\n");
#endif
#if __SSP_ALL__ == 2
    printf("compiled with -fstack-protector-all\n");
#endif
/*
 * Workaround for special defines of _FORTIFY_SOURCE like
 * FORTIFY_SOURCE=((defined __OPTIMIZE && OPTIMIZE > 0) ? 2 : 0)
 * which is used by Gentoo for example and would result in the error
 * 'defined' undeclared when _FORTIFY_SOURCE used via %d in printf func
 *
 */
#if _FORTIFY_SOURCE == 2
    printf("compiled with _FORTIFY_SOURCE=2\n");
#elif _FORTIFY_SOURCE == 1
    printf("compiled with _FORTIFY_SOURCE=1\n");
#elif _FORTIFY_SOURCE == 0
    printf("compiled with _FORTIFY_SOURCE=0\n");
#endif
#ifdef CLS
    printf("L1 cache line size (CLS)=%d\n", CLS);
#endif
#if defined(TLS_C11)
    tls = "_Thread_local";
#elif defined(TLS_GNU)
    tls = "__thread";
#else
#error "Unsupported thread local"
#endif
    printf("thread local storage method: %s\n", tls);

    printf("compiled with %s, linked against %s\n",
           HTP_VERSION_STRING_FULL, htp_get_version());
    printf("\n");
#include "build-info.h"
}

int coverage_unittests;
int g_ut_modules;
int g_ut_covered;

void RegisterAllModules(void)
{
    /* commanders */
    TmModuleUnixManagerRegister();
    /* managers */
    TmModuleFlowManagerRegister();
    TmModuleFlowRecyclerRegister();
    TmModuleBypassedFlowManagerRegister();
    /* nfq */
    TmModuleReceiveNFQRegister();
    TmModuleVerdictNFQRegister();
    TmModuleDecodeNFQRegister();
    /* ipfw */
    TmModuleReceiveIPFWRegister();
    TmModuleVerdictIPFWRegister();
    TmModuleDecodeIPFWRegister();
    /* pcap live */
    TmModuleReceivePcapRegister();
    TmModuleDecodePcapRegister();
    /* pcap file */
    TmModuleReceivePcapFileRegister();
    TmModuleDecodePcapFileRegister();
    /* af-packet */
    TmModuleReceiveAFPRegister();
    TmModuleDecodeAFPRegister();
    /* af-xdp */
    TmModuleReceiveAFXDPRegister();
    TmModuleDecodeAFXDPRegister();
    /* netmap */
    TmModuleReceiveNetmapRegister();
    TmModuleDecodeNetmapRegister();
    /* pfring */
    TmModuleReceivePfringRegister();
    TmModuleDecodePfringRegister();
    /* dag file */
    TmModuleReceiveErfFileRegister();
    TmModuleDecodeErfFileRegister();
    /* dag live */
    TmModuleReceiveErfDagRegister();
    TmModuleDecodeErfDagRegister();
    /* napatech */
    TmModuleNapatechStreamRegister();
    TmModuleNapatechDecodeRegister();

    /* flow worker */
    TmModuleFlowWorkerRegister();
    /* respond-reject */
    TmModuleRespondRejectRegister();

    /* log api */
    TmModuleLoggerRegister();
    TmModuleStatsLoggerRegister();

    TmModuleDebugList();
    /* nflog */
    TmModuleReceiveNFLOGRegister();
    TmModuleDecodeNFLOGRegister();

    /* windivert */
    TmModuleReceiveWinDivertRegister();
    TmModuleVerdictWinDivertRegister();
    TmModuleDecodeWinDivertRegister();

    /* Dpdk */
    TmModuleReceiveDPDKRegister();
    TmModuleDecodeDPDKRegister();
}

static TmEcode LoadYamlConfig(SCInstance *suri)
{
    SCEnter();

    if (suri->conf_filename == NULL)
    {
        suri->conf_filename = DEFAULT_CONF_FILE;
    }

    if (ConfYamlLoadFile(suri->conf_filename) != 0)
    {
        /* Error already displayed. */
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (suri->additional_configs) 
    {
        for (int i = 0; suri->additional_configs[i] != NULL; i++) 
        {
            SCLogConfig("Loading additional configuration file %s", suri->additional_configs[i]);
            ConfYamlHandleInclude(ConfGetRootNode(), suri->additional_configs[i]);
        }
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ParseInterfacesList(const int runmode, char *pcap_dev)
{
    SCEnter();

    /* run the selected runmode */
    /* 根据所选的runmode，运行 */
    // PCAP_DEV运行模式
    if (runmode == RUNMODE_PCAP_DEV) 
    {
        if (strlen(pcap_dev) == 0) {
            int ret = LiveBuildDeviceList("pcap");
            if (ret == 0) 
            {
                SCLogError("No interface found in config for pcap");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
    } 
    // PFRING运行模式
    else if (runmode == RUNMODE_PFRING)
    {
        /* FIXME add backward compat support,添加向后兼容支持 */
        /* iface has been set on command line,网络接口已经在命令行中设置 */ 
        if (strlen(pcap_dev))
        {
            if (ConfSetFinal("pfring.live-interface", pcap_dev) != 1) 
            {
                SCLogError("Failed to set pfring.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
        else 
        {
            /* not an error condition if we have a 1.0 config */
            /* 不报error错误的条件: 有1.0配置 */
            LiveBuildDeviceList("pfring");
        }
#ifdef HAVE_DPDK
    } 
    // DPDK运行模式
    else if (runmode == RUNMODE_DPDK)
    {
        char iface_selector[] = "dpdk.interfaces";
        int ret = LiveBuildDeviceList(iface_selector);
        if (ret == 0) 
        {
            SCLogError("No interface found in config for %s", iface_selector);
            SCReturnInt(TM_ECODE_FAILED);
        }
#endif
#ifdef HAVE_AF_PACKET
    }
    // AF_PACKET运行模式
    else if (runmode == RUNMODE_AFP_DEV) 
    {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) 
        {
            if (ConfSetFinal("af-packet.live-interface", pcap_dev) != 1) 
            {
                SCLogError("Failed to set af-packet.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } 
        else 
        {
            int ret = LiveBuildDeviceList("af-packet");
            if (ret == 0) 
            {
                SCLogError("No interface found in config for af-packet");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
#endif
#ifdef HAVE_AF_XDP
    } 
    // XDP运行模式
    else if (runmode == RUNMODE_AFXDP_DEV) 
    {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) 
        {
            if (ConfSetFinal("af-xdp.live-interface", pcap_dev) != 1) 
            {
                SCLogError("Failed to set af-xdp.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } 
        else 
        {
            int ret = LiveBuildDeviceList("af-xdp");
            if (ret == 0)
            {
                SCLogError("No interface found in config for af-xdp");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
#endif
#ifdef HAVE_NETMAP
    }
    // NETMAP运行模式
    else if (runmode == RUNMODE_NETMAP)
    {
        /* iface has been set on command line */
        if (strlen(pcap_dev))
        {
            if (ConfSetFinal("netmap.live-interface", pcap_dev) != 1)
            {
                SCLogError("Failed to set netmap.live-interface");
                SCReturnInt(TM_ECODE_FAILED);
            }
        } 
        else
        {
            int ret = LiveBuildDeviceList("netmap");
            if (ret == 0) 
            {
                SCLogError("No interface found in config for netmap");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
#endif
#ifdef HAVE_NFLOG
    }
    // NFLOG运行模式
    else if (runmode == RUNMODE_NFLOG)
    {
        int ret = LiveBuildDeviceListCustom("nflog", "group");
        if (ret == 0)
        {
            SCLogError("No group found in config for nflog");
            SCReturnInt(TM_ECODE_FAILED);
        }
#endif
    }

    SCReturnInt(TM_ECODE_OK);
}

static void SCInstanceInit(SCInstance *suri, const char *progname)
{
    memset(suri, 0x00, sizeof(*suri));

    suri->progname = progname;
    suri->run_mode = RUNMODE_UNKNOWN;

    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
    suri->sig_file = NULL;
    suri->sig_file_exclusive = FALSE;
    suri->pid_filename = NULL;
    suri->regex_arg = NULL;

    suri->keyword_info = NULL;
    suri->runmode_custom_mode = NULL;
#ifndef OS_WIN32
    suri->user_name = NULL;
    suri->group_name = NULL;
    suri->do_setuid = FALSE;
    suri->do_setgid = FALSE;
#endif /* OS_WIN32 */
    suri->userid = 0;
    suri->groupid = 0;
    suri->delayed_detect = 0;
    suri->daemon = 0;
    suri->offline = 0;
    suri->verbose = 0;
    /* use -1 as unknown */
    suri->checksum_validation = -1;
#if HAVE_DETECT_DISABLED==1
    g_detect_disabled = suri->disabled_detect = 1;
#else
    g_detect_disabled = suri->disabled_detect = 0;
#endif
}

const char *GetDocURL(void)
{
    const char *prog_ver = GetProgramVersion();
    if (strstr(prog_ver, "RELEASE") != NULL)
    {
        return DOC_URL "suricata-" PROG_VER;
    }
    
    return DOC_URL "latest";
}

/** \brief get string with program version
 *
 *  Get the program version as passed to us from AC_INIT
 *
 *  Add 'RELEASE' is no '-dev' in the version. Add the REVISION if passed
 *  to us.
 *
 *  Possible outputs:
 *  release:      '5.0.1 RELEASE'
 *  dev with rev: '5.0.1-dev (64a789bbf 2019-10-18)'
 *  dev w/o rev:  '5.0.1-dev'
 */
const char *GetProgramVersion(void)
{
    if (strstr(PROG_VER, "-dev") == NULL)
    {
        return PROG_VER " RELEASE";
    } 
    else
    {
#ifdef REVISION
        return PROG_VER " (" xstr(REVISION) ")";
#else
        return PROG_VER;
#endif
    }
}

static TmEcode PrintVersion(void)
{
    printf("This is %s version %s\n", PROG_NAME, GetProgramVersion());
    return TM_ECODE_OK;
}

static TmEcode LogVersion(SCInstance *suri)
{
    const char *mode = suri->system ? "SYSTEM" : "USER";
    SCLogNotice("This is %s version %s running in %s mode", PROG_NAME, GetProgramVersion(), mode);
    return TM_ECODE_OK;
}

static void SCSetStartTime(SCInstance *suri)
{
    memset(&suri->start_time, 0, sizeof(suri->start_time));
    gettimeofday(&suri->start_time, NULL);
}

static void SCPrintElapsedTime(struct timeval *start_time)
{
    if (start_time == NULL)
        return;
    struct timeval end_time;
    memset(&end_time, 0, sizeof(end_time));
    gettimeofday(&end_time, NULL);
    uint64_t milliseconds = ((end_time.tv_sec - start_time->tv_sec) * 1000) +
        (((1000000 + end_time.tv_usec - start_time->tv_usec) / 1000) - 1000);
    SCLogInfo("time elapsed %.3fs", (float)milliseconds/(float)1000);
}

static int ParseCommandLineAfpacket(SCInstance *suri, const char *in_arg)
{
#ifdef HAVE_AF_PACKET
    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_AFP_DEV;
        if (in_arg) {
            LiveRegisterDeviceName(in_arg);
            memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
            strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
        }
    } else if (suri->run_mode == RUNMODE_AFP_DEV) {
        if (in_arg) {
            LiveRegisterDeviceName(in_arg);
        } else {
            SCLogInfo("Multiple af-packet option without interface on each is useless");
        }
    } else {
        SCLogError("more than one run mode "
                   "has been specified");
        PrintUsage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
#else
    SCLogError("AF_PACKET not enabled. On Linux "
               "host, make sure to pass --enable-af-packet to "
               "configure when building.");
    return TM_ECODE_FAILED;
#endif
}

static int ParseCommandLineAfxdp(SCInstance *suri, const char *in_arg)
{
#ifdef HAVE_AF_XDP
    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_AFXDP_DEV;
        if (in_arg) {
            LiveRegisterDeviceName(in_arg);
            memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
            strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
        }
    } else if (suri->run_mode == RUNMODE_AFXDP_DEV) {
        if (in_arg) {
            LiveRegisterDeviceName(in_arg);
        } else {
            SCLogInfo("Multiple af-xdp options without interface on each is useless");
        }
    } else {
        SCLogError("more than one run mode "
                   "has been specified");
        PrintUsage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
#else
    SCLogError("AF_XDP not enabled. On Linux "
               "host, make sure correct libraries are installed,"
               " see documentation for information.");
    return TM_ECODE_FAILED;
#endif
}

static int ParseCommandLineDpdk(SCInstance *suri, const char *in_arg)
{
#ifdef HAVE_DPDK
    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_DPDK;
    } else if (suri->run_mode == RUNMODE_DPDK) {
        SCLogInfo("Multiple dpdk options have no effect on Suricata");
    } else {
        SCLogError("more than one run mode "
                   "has been specified");
        PrintUsage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
#else
    SCLogError("DPDK not enabled. On Linux "
               "host, make sure to pass --enable-dpdk to "
               "configure when building.");
    return TM_ECODE_FAILED;
#endif
}

static int ParseCommandLinePcapLive(SCInstance *suri, const char *in_arg)
{
#if defined(OS_WIN32) && !defined(HAVE_LIBWPCAP)
    /* If running on Windows without Npcap, bail early as live capture is not supported. */
    FatalError("Live capture not available. To support live capture compile against Npcap.");
#endif
    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));

    if (in_arg != NULL) {
        /* some windows shells require escaping of the \ in \Device. Otherwise
         * the backslashes are stripped. We put them back here. */
        if (strlen(in_arg) > 9 && strncmp(in_arg, "DeviceNPF", 9) == 0) {
            snprintf(suri->pcap_dev, sizeof(suri->pcap_dev), "\\Device\\NPF%s", in_arg+9);
        } else {
            strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
            PcapTranslateIPToDevice(suri->pcap_dev, sizeof(suri->pcap_dev));
        }

        if (strcmp(suri->pcap_dev, in_arg) != 0) {
            SCLogInfo("translated %s to pcap device %s", in_arg, suri->pcap_dev);
        } else if (strlen(suri->pcap_dev) > 0 && isdigit((unsigned char)suri->pcap_dev[0])) {
            SCLogError("failed to find a pcap device for IP %s", in_arg);
            return TM_ECODE_FAILED;
        }
    }

    if (suri->run_mode == RUNMODE_UNKNOWN) {
        suri->run_mode = RUNMODE_PCAP_DEV;
        if (in_arg) {
            LiveRegisterDeviceName(suri->pcap_dev);
        }
    } else if (suri->run_mode == RUNMODE_PCAP_DEV) {
        LiveRegisterDeviceName(suri->pcap_dev);
    } else {
        SCLogError("more than one run mode "
                   "has been specified");
        PrintUsage(suri->progname);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
}

/**
 * Helper function to check if log directory is writable
 */
static bool IsLogDirectoryWritable(const char* str)
{
    if (access(str, W_OK) == 0)
        return true;
    return false;
}


/* 处理命令行参数 */
static TmEcode ParseCommandLine(int argc, char** argv, SCInstance *suri)
{
    int opt;

    int dump_config = 0;
    int dump_features = 0;
    int list_app_layer_protocols = 0;
    int list_unittests = 0;
    int list_runmodes = 0;
    int list_keywords = 0;
    int build_info = 0;
    int conf_test = 0;
    int engine_analysis = 0;
    int ret = TM_ECODE_OK;

#ifdef UNITTESTS
    coverage_unittests = 0;
    g_ut_modules = 0;
    g_ut_covered = 0;
#endif

    // clang-format off
    struct option long_opts[] = {
        {"dump-config", 0, &dump_config, 1},
        {"dump-features", 0, &dump_features, 1},
        {"pfring", optional_argument, 0, 0},
        {"pfring-int", required_argument, 0, 0},
        {"pfring-cluster-id", required_argument, 0, 0},
        {"pfring-cluster-type", required_argument, 0, 0},
#ifdef HAVE_DPDK
        {"dpdk", 0, 0, 0},
#endif
        {"af-packet", optional_argument, 0, 0},
        {"af-xdp", optional_argument, 0, 0},
        {"netmap", optional_argument, 0, 0},
        {"pcap", optional_argument, 0, 0},
        {"pcap-file-continuous", 0, 0, 0},
        {"pcap-file-delete", 0, 0, 0},
        {"pcap-file-recursive", 0, 0, 0},
        {"simulate-ips", 0, 0 , 0},
        {"no-random", 0, &g_disable_randomness, 1},
        {"strict-rule-keywords", optional_argument, 0, 0},

        {"capture-plugin", required_argument, 0, 0},
        {"capture-plugin-args", required_argument, 0, 0},

#ifdef BUILD_UNIX_SOCKET
        {"unix-socket", optional_argument, 0, 0},
#endif
        {"pcap-buffer-size", required_argument, 0, 0},
        {"unittest-filter", required_argument, 0, 'U'},
        {"list-app-layer-protos", 0, &list_app_layer_protocols, 1},
        {"list-unittests", 0, &list_unittests, 1},
        {"list-runmodes", 0, &list_runmodes, 1},
        {"list-keywords", optional_argument, &list_keywords, 1},
        {"runmode", required_argument, NULL, 0},
        {"engine-analysis", 0, &engine_analysis, 1},
#ifdef OS_WIN32
		{"service-install", 0, 0, 0},
		{"service-remove", 0, 0, 0},
		{"service-change-params", 0, 0, 0},
#endif /* OS_WIN32 */
        {"pidfile", required_argument, 0, 0},
        {"init-errors-fatal", 0, 0, 0},
        {"disable-detection", 0, 0, 0},
        {"disable-hashing", 0, 0, 0},
        {"fatal-unittests", 0, 0, 0},
        {"unittests-coverage", 0, &coverage_unittests, 1},
        {"user", required_argument, 0, 0},
        {"group", required_argument, 0, 0},
        {"erf-in", required_argument, 0, 0},
        {"dag", required_argument, 0, 0},
        {"napatech", 0, 0, 0},
        {"build-info", 0, &build_info, 1},
        {"data-dir", required_argument, 0, 0},
#ifdef WINDIVERT
        {"windivert", required_argument, 0, 0},
        {"windivert-forward", required_argument, 0, 0},
#endif
#ifdef HAVE_LIBNET11
        {"reject-dev", required_argument, 0, 0},
#endif
        {"set", required_argument, 0, 0},
#ifdef HAVE_NFLOG
        {"nflog", optional_argument, 0, 0},
#endif
        {"simulate-packet-flow-memcap", required_argument, 0, 0},
        {"simulate-applayer-error-at-offset-ts", required_argument, 0, 0},
        {"simulate-applayer-error-at-offset-tc", required_argument, 0, 0},
        {"simulate-packet-loss", required_argument, 0, 0},
        {"simulate-packet-tcp-reassembly-memcap", required_argument, 0, 0},
        {"simulate-packet-tcp-ssn-memcap", required_argument, 0, 0},
        {"simulate-packet-defrag-memcap", required_argument, 0, 0},
        {"simulate-alert-queue-realloc-failure", 0, 0, 0},
        {"include", required_argument, 0, 0},

        {NULL, 0, NULL, 0}
    };
    // clang-format on

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:TDhi:l:q:d:r:us:S:U:VF:vk:";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) 
    {
        switch (opt)
        {
        case 0:
            if (strcmp((long_opts[option_index]).name , "pfring") == 0 ||
                strcmp((long_opts[option_index]).name , "pfring-int") == 0) 
            {
#ifdef HAVE_PFRING
                suri->run_mode = RUNMODE_PFRING;
                if (optarg != NULL) {
                    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
                    strlcpy(suri->pcap_dev, optarg, ((strlen(optarg) < sizeof(suri->pcap_dev)) ? (strlen(optarg) + 1) : sizeof(suri->pcap_dev)));
                    LiveRegisterDeviceName(optarg);
                }
#else
                SCLogError("PF_RING not enabled. Make sure to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif 
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-id") == 0)
            {
#ifdef HAVE_PFRING
                if (ConfSetFinal("pfring.cluster-id", optarg) != 1) 
                {
                    SCLogError("failed to set pfring.cluster-id");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError("PF_RING not enabled. Make sure to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif
            }
            else if(strcmp((long_opts[option_index]).name , "pfring-cluster-type") == 0)
            {
#ifdef HAVE_PFRING
                if (ConfSetFinal("pfring.cluster-type", optarg) != 1) 
                {
                    SCLogError("failed to set pfring.cluster-type");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError("PF_RING not enabled. Make sure to pass --enable-pfring to configure when building.");
                return TM_ECODE_FAILED;
#endif 
            }
            else if (strcmp((long_opts[option_index]).name , "capture-plugin") == 0)
            {
                suri->run_mode = RUNMODE_PLUGIN;
                suri->capture_plugin_name = optarg;
            }
            else if (strcmp((long_opts[option_index]).name , "capture-plugin-args") == 0)
            {
                suri->capture_plugin_args = optarg;
            } 
            else if (strcmp((long_opts[option_index]).name, "dpdk") == 0) 
            {
                if (ParseCommandLineDpdk(suri, optarg) != TM_ECODE_OK)
                {
                    return TM_ECODE_FAILED;
                }
            } 
            else if (strcmp((long_opts[option_index]).name, "af-packet") == 0)
            {
                if (ParseCommandLineAfpacket(suri, optarg) != TM_ECODE_OK) 
                {
                    return TM_ECODE_FAILED;
                }
            } 
            else if (strcmp((long_opts[option_index]).name, "af-xdp") == 0)
            {
                if (ParseCommandLineAfxdp(suri, optarg) != TM_ECODE_OK)
                {
                    return TM_ECODE_FAILED;
                }
            } 
            else if (strcmp((long_opts[option_index]).name, "netmap") == 0)
            {
#ifdef HAVE_NETMAP
                if (suri->run_mode == RUNMODE_UNKNOWN) 
                {
                    suri->run_mode = RUNMODE_NETMAP;
                    if (optarg)
                    {
                        LiveRegisterDeviceName(optarg);
                        memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
                        strlcpy(suri->pcap_dev, optarg, ((strlen(optarg) < sizeof(suri->pcap_dev)) ? (strlen(optarg) + 1) : sizeof(suri->pcap_dev)));
                    }
                } 
                else if (suri->run_mode == RUNMODE_NETMAP)
                {
                    if (optarg) 
                    {
                        LiveRegisterDeviceName(optarg);
                    } 
                    else
                    {
                        SCLogInfo("Multiple netmap option without interface on each is useless");
                        break;
                    }
                } 
                else
                {
                    SCLogError("more than one run mode has been specified");
                    PrintUsage(argv[0]);
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError("NETMAP not enabled.");
                return TM_ECODE_FAILED;
#endif
            }
            else if (strcmp((long_opts[option_index]).name, "nflog") == 0)
            {
#ifdef HAVE_NFLOG
                if (suri->run_mode == RUNMODE_UNKNOWN)
                {
                    suri->run_mode = RUNMODE_NFLOG;
                    LiveBuildDeviceListCustom("nflog", "group");
                }
#else
                SCLogError("NFLOG not enabled.");
                return TM_ECODE_FAILED;
#endif
            } 
            else if (strcmp((long_opts[option_index]).name, "pcap") == 0)
            {
                if (ParseCommandLinePcapLive(suri, optarg) != TM_ECODE_OK)
                {
                    return TM_ECODE_FAILED;
                }
            } 
            else if (strcmp((long_opts[option_index]).name, "simulate-ips") == 0)
            {
                SCLogInfo("Setting IPS mode");
                EngineModeSetIPS();
            } 
            else if (strcmp((long_opts[option_index]).name, "init-errors-fatal") == 0)
            {
                if (ConfSetFinal("engine.init-failure-fatal", "1") != 1)
                {
                    SCLogError("failed to set engine init-failure-fatal");
                    return TM_ECODE_FAILED;
                }
#ifdef BUILD_UNIX_SOCKET
            } 
            else if (strcmp((long_opts[option_index]).name , "unix-socket") == 0) 
            {
                if (suri->run_mode == RUNMODE_UNKNOWN)
                {
                    suri->run_mode = RUNMODE_UNIX_SOCKET;
                    if (optarg)
                    {
                        if (ConfSetFinal("unix-command.filename", optarg) != 1)
                        {
                            SCLogError("failed to set unix-command.filename");
                            return TM_ECODE_FAILED;
                        }

                    }
                } 
                else
                {
                    SCLogError("more than one run mode has been specified");
                    PrintUsage(argv[0]);
                    return TM_ECODE_FAILED;
                }
#endif
            }
            else if(strcmp((long_opts[option_index]).name, "list-app-layer-protocols") == 0) 
            {
                /* listing all supported app layer protocols */
            }
            else if(strcmp((long_opts[option_index]).name, "list-unittests") == 0)
            {
#ifdef UNITTESTS
                suri->run_mode = RUNMODE_LIST_UNITTEST;
#else
                SCLogError("unit tests not enabled. Make sure to pass --enable-unittests to configure when building");
                return TM_ECODE_FAILED;
#endif
            }
            else if (strcmp((long_opts[option_index]).name, "list-runmodes") == 0)
            {
                suri->run_mode = RUNMODE_LIST_RUNMODES;
                return TM_ECODE_OK;
            }
            else if (strcmp((long_opts[option_index]).name, "list-keywords") == 0)
            {
                if (optarg)
                {
                    if (strcmp("short",optarg))
                    {
                        suri->keyword_info = optarg;
                    }
                }
            }
            else if (strcmp((long_opts[option_index]).name, "runmode") == 0)
            {
                suri->runmode_custom_mode = optarg;
            }
            else if(strcmp((long_opts[option_index]).name, "engine-analysis") == 0)
            {
                // do nothing for now
            }
#ifdef OS_WIN32
            else if(strcmp((long_opts[option_index]).name, "service-install") == 0)
            {
                suri->run_mode = RUNMODE_INSTALL_SERVICE;
                return TM_ECODE_OK;
            }
            else if(strcmp((long_opts[option_index]).name, "service-remove") == 0)
            {
                suri->run_mode = RUNMODE_REMOVE_SERVICE;
                return TM_ECODE_OK;
            }
            else if(strcmp((long_opts[option_index]).name, "service-change-params") == 0)
            {
                suri->run_mode = RUNMODE_CHANGE_SERVICE_PARAMS;
                return TM_ECODE_OK;
            }
#endif /* OS_WIN32 */
            else if(strcmp((long_opts[option_index]).name, "pidfile") == 0)
            {
                suri->pid_filename = SCStrdup(optarg);
                if (suri->pid_filename == NULL)
                {
                    SCLogError("strdup failed: %s", strerror(errno));
                    return TM_ECODE_FAILED;
                }
            }
            else if(strcmp((long_opts[option_index]).name, "disable-detection") == 0)
            {
                g_detect_disabled = suri->disabled_detect = 1;
            } 
            else if (strcmp((long_opts[option_index]).name, "disable-hashing") == 0)
            {
                g_disable_hashing = true;
            } 
            else if (strcmp((long_opts[option_index]).name, "fatal-unittests") == 0)
            {
#ifdef UNITTESTS
                unittests_fatal = 1;
#else
                SCLogError("unit tests not enabled. Make sure to pass --enable-unittests to configure when building");
                return TM_ECODE_FAILED;
#endif 
            }
            else if (strcmp((long_opts[option_index]).name, "user") == 0)
            {
#ifndef HAVE_LIBCAP_NG
                SCLogError("libcap-ng is required to drop privileges, but it was not compiled into Suricata.");
                return TM_ECODE_FAILED;
#else
                suri->user_name = optarg;
                suri->do_setuid = TRUE;
#endif 
            } 
            else if (strcmp((long_opts[option_index]).name, "group") == 0)
            {
#ifndef HAVE_LIBCAP_NG
                SCLogError("libcap-ng is required to drop privileges, but it was not compiled into Suricata.");
                return TM_ECODE_FAILED;
#else
                suri->group_name = optarg;
                suri->do_setgid = TRUE;
#endif 
            } 
            else if (strcmp((long_opts[option_index]).name, "erf-in") == 0)
            {
                suri->run_mode = RUNMODE_ERF_FILE;
                if (ConfSetFinal("erf-file.file", optarg) != 1)
                {
                    SCLogError("failed to set erf-file.file");
                    return TM_ECODE_FAILED;
                }
            }
            else if (strcmp((long_opts[option_index]).name, "dag") == 0)
            {
#ifdef HAVE_DAG
                if (suri->run_mode == RUNMODE_UNKNOWN)
                {
                    suri->run_mode = RUNMODE_DAG;
                }
                else if (suri->run_mode != RUNMODE_DAG)
                {
                    SCLogError("more than one run mode has been specified");
                    PrintUsage(argv[0]);
                    return TM_ECODE_FAILED;
                }
                LiveRegisterDeviceName(optarg);
#else
                SCLogError("libdag and a DAG card are required to receive packets using --dag.");
                return TM_ECODE_FAILED;
#endif 
            } 
            else if (strcmp((long_opts[option_index]).name, "napatech") == 0) 
            {
#ifdef HAVE_NAPATECH
                suri->run_mode = RUNMODE_NAPATECH;
#else
                SCLogError("libntapi and a Napatech adapter are required to capture packets using --napatech.");
                return TM_ECODE_FAILED;
#endif
            } 
            else if (strcmp((long_opts[option_index]).name, "pcap-buffer-size") == 0)
            {
#ifdef HAVE_PCAP_SET_BUFF
                if (ConfSetFinal("pcap.buffer-size", optarg) != 1) 
                {
                    SCLogError("failed to set pcap-buffer-size");
                    return TM_ECODE_FAILED;
                }
#else
                SCLogError("The version of libpcap you have doesn't support setting buffer size.");
#endif
            } 
            else if (strcmp((long_opts[option_index]).name, "build-info") == 0)
            {
                suri->run_mode = RUNMODE_PRINT_BUILDINFO;
                return TM_ECODE_OK;
            } 
            else if (strcmp((long_opts[option_index]).name, "windivert-forward") == 0)
            {
#ifdef WINDIVERT
                if (suri->run_mode == RUNMODE_UNKNOWN) 
                {
                    suri->run_mode = RUNMODE_WINDIVERT;
                    if (WinDivertRegisterQueue(true, optarg) == -1)
                    {
                        exit(EXIT_FAILURE);
                    }
                } 
                else if (suri->run_mode == RUNMODE_WINDIVERT)
                {
                    if (WinDivertRegisterQueue(true, optarg) == -1)
                    {
                        exit(EXIT_FAILURE);
                    }
                } else {
                    SCLogError("more than one run mode "
                               "has been specified");
                    PrintUsage(argv[0]);
                    exit(EXIT_FAILURE);
                }
            }
            else if(strcmp((long_opts[option_index]).name, "windivert") == 0)
            {
                if (suri->run_mode == RUNMODE_UNKNOWN)
                {
                    suri->run_mode = RUNMODE_WINDIVERT;
                    if (WinDivertRegisterQueue(false, optarg) == -1)
                    {
                        exit(EXIT_FAILURE);
                    }
                } 
                else if (suri->run_mode == RUNMODE_WINDIVERT)
                {
                    if (WinDivertRegisterQueue(false, optarg) == -1)
                    {
                        exit(EXIT_FAILURE);
                    }
                } 
                else
                {
                    SCLogError("more than one run mode has been specified");
                    PrintUsage(argv[0]);
                    exit(EXIT_FAILURE);
                }
#else
                SCLogError("WinDivert not enabled. Make sure to pass --enable-windivert to configure when building.");
                return TM_ECODE_FAILED;
#endif
            }
            else if(strcmp((long_opts[option_index]).name, "reject-dev") == 0)
            {
#ifdef HAVE_LIBNET11
                BUG_ON(optarg == NULL); /* for static analysis */
                extern char *g_reject_dev;
                extern uint16_t g_reject_dev_mtu;
                g_reject_dev = optarg;
                int mtu = GetIfaceMTU(g_reject_dev);
                if (mtu > 0) 
                {
                    g_reject_dev_mtu = (uint16_t)mtu;
                }
#else
                SCLogError("Libnet 1.1 support not enabled. Compile Suricata with libnet support.");
                return TM_ECODE_FAILED;
#endif
            }
            else if (strcmp((long_opts[option_index]).name, "set") == 0) 
            {
                if (optarg != NULL)
                {
                    /* Quick validation. */
                    char *val = strchr(optarg, '=');
                    if (val == NULL)
                    {
                        FatalError("Invalid argument for --set, must be key=val.");
                    }
                    if (!ConfSetFromString(optarg, 1))
                    {
                        FatalError("failed to set configuration value %s", optarg);
                    }
                }
            }
            else if (strcmp((long_opts[option_index]).name, "pcap-file-continuous") == 0)
            {
                if (ConfSetFinal("pcap-file.continuous", "true") != 1)
                {
                    SCLogError("Failed to set pcap-file.continuous");
                    return TM_ECODE_FAILED;
                }
            }
            else if (strcmp((long_opts[option_index]).name, "pcap-file-delete") == 0) 
            {
                if (ConfSetFinal("pcap-file.delete-when-done", "true") != 1)
                {
                    SCLogError("Failed to set pcap-file.delete-when-done");
                    return TM_ECODE_FAILED;
                }
            }
            else if (strcmp((long_opts[option_index]).name, "pcap-file-recursive") == 0)
            {
                if (ConfSetFinal("pcap-file.recursive", "true") != 1) 
                {
                    SCLogError("failed to set pcap-file.recursive");
                    return TM_ECODE_FAILED;
                }
            }
            else if (strcmp((long_opts[option_index]).name, "data-dir") == 0)
            {
                if (optarg == NULL)
                {
                    SCLogError("no option argument (optarg) for -d");
                    return TM_ECODE_FAILED;
                }

                if (ConfigSetDataDirectory(optarg) != TM_ECODE_OK)
                {
                    SCLogError("Failed to set data directory.");
                    return TM_ECODE_FAILED;
                }
                if (ConfigCheckDataDirectory(optarg) != TM_ECODE_OK)
                {
                    SCLogError("The data directory \"%s\" supplied at the command-line (-d %s) doesn't exist. Shutting down the engine.",optarg, optarg);
                    return TM_ECODE_FAILED;
                }
                suri->set_datadir = true;
            } 
            else if (strcmp((long_opts[option_index]).name , "strict-rule-keywords") == 0)
            {
                if (optarg == NULL) 
                {
                    suri->strict_rule_parsing_string = SCStrdup("all");
                } 
                else 
                {
                    suri->strict_rule_parsing_string = SCStrdup(optarg);
                }
                if (suri->strict_rule_parsing_string == NULL)
                {
                    FatalError("failed to duplicate 'strict' string");
                }
            } 
            else if (strcmp((long_opts[option_index]).name, "include") == 0)
            {
                if (suri->additional_configs == NULL)
                {
                    suri->additional_configs = SCCalloc(2, sizeof(char *));
                    if (suri->additional_configs == NULL)
                    {
                        FatalError( "Failed to allocate memory for additional configuration files: %s", strerror(errno));
                    }
                    suri->additional_configs[0] = optarg;
                } 
                else
                {
                    for (int i = 0;; i++) 
                    {
                        if (suri->additional_configs[i] == NULL)
                        {
                            const char **additional_configs = SCRealloc(suri->additional_configs, (i + 2) * sizeof(char *));
                            if (additional_configs == NULL)
                            {
                                FatalError("Failed to allocate memory for additional configuration files: %s", strerror(errno));
                            } 
                            else
                            {
                                suri->additional_configs = additional_configs;
                            }
                            suri->additional_configs[i] = optarg;
                            suri->additional_configs[i + 1] = NULL;
                            break;
                        }
                    }
                }
            } 
            else 
            {
                int r = ExceptionSimulationCommandLineParser( (long_opts[option_index]).name, optarg);
                if (r < 0)
                {
                    return TM_ECODE_FAILED;
                }
            }
            break;
        case 'c':
            suri->conf_filename = optarg;
            break;
        case 'T':
            conf_test = 1;
            if (ConfSetFinal("engine.init-failure-fatal", "1") != 1)
            {
                SCLogError("failed to set engine init-failure-fatal");
                return TM_ECODE_FAILED;
            }
            break;
#ifndef OS_WIN32
        case 'D':
            suri->daemon = 1;
            break;
#endif /* OS_WIN32 */
        case 'h':
            suri->run_mode = RUNMODE_PRINT_USAGE;
            return TM_ECODE_OK;
        case 'i':
            if (optarg == NULL) 
            {
                SCLogError("no option argument (optarg) for -i");
                return TM_ECODE_FAILED;
            }
#ifdef HAVE_AF_PACKET
            if (ParseCommandLineAfpacket(suri, optarg) != TM_ECODE_OK)
            {
                return TM_ECODE_FAILED;
            }
#else /* not afpacket */
            
#if defined HAVE_PFRING || HAVE_NETMAP /* warn user if netmap or pf-ring are available */
            int i = 0;
#ifdef HAVE_PFRING
            i++;
#endif
#ifdef HAVE_NETMAP
            i++;
#endif
            SCLogWarning("faster capture option%s %s available:"
#ifdef HAVE_PFRING
                         " PF_RING (--pfring-int=%s)"
#endif
#ifdef HAVE_NETMAP
                         " NETMAP (--netmap=%s)"
#endif
                         ". Use --pcap=%s to suppress this warning",
                    i == 1 ? "" : "s", i == 1 ? "is" : "are"
#ifdef HAVE_PFRING
                    ,
                    optarg
#endif
#ifdef HAVE_NETMAP
                    ,
                    optarg
#endif
                    ,
                    optarg);
#endif /* have faster methods */

            if (ParseCommandLinePcapLive(suri, optarg) != TM_ECODE_OK)
            {
                return TM_ECODE_FAILED;
            }
#endif
            break;
            
        case 'l':
            if (optarg == NULL)
            {
                SCLogError("no option argument (optarg) for -l");
                return TM_ECODE_FAILED;
            }

            if (ConfigSetLogDirectory(optarg) != TM_ECODE_OK)
            {
                SCLogError("Failed to set log directory.");
                return TM_ECODE_FAILED;
            }
            if (ConfigCheckLogDirectoryExists(optarg) != TM_ECODE_OK)
            {
                SCLogError("The logging directory \"%s\" supplied at the command-line (-l %s) doesn't exist. Shutting down the engine.",
                        optarg, optarg);
                return TM_ECODE_FAILED;
            }
            if (!IsLogDirectoryWritable(optarg)) 
            {
                SCLogError("The logging directory \"%s\" supplied at the command-line (-l %s) is not writable. Shutting down the engine.", optarg, optarg);
                return TM_ECODE_FAILED;
            }
            suri->set_logdir = true;

            break;
        case 'q':
#ifdef NFQ
            if (suri->run_mode == RUNMODE_UNKNOWN)
            {
                suri->run_mode = RUNMODE_NFQ;
                EngineModeSetIPS();
                if (NFQParseAndRegisterQueues(optarg) == -1)
                {
                    return TM_ECODE_FAILED;
                }
            } 
            else if (suri->run_mode == RUNMODE_NFQ)
            {
                if (NFQParseAndRegisterQueues(optarg) == -1)
                {
                    return TM_ECODE_FAILED;
                }
            } 
            else 
            {
                SCLogError("more than one run mode has been specified");
                PrintUsage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            SCLogError("NFQUEUE not enabled. Make sure to pass --enable-nfqueue to configure when building.");
            return TM_ECODE_FAILED;
#endif 
            break;

        case 'd':
#ifdef IPFW
            if (suri->run_mode == RUNMODE_UNKNOWN)
            {
                suri->run_mode = RUNMODE_IPFW;
                EngineModeSetIPS();
                if (IPFWRegisterQueue(optarg) == -1)
                {
                    return TM_ECODE_FAILED;
                }
            } 
            else if (suri->run_mode == RUNMODE_IPFW)
            {
                if (IPFWRegisterQueue(optarg) == -1)
                {
                    return TM_ECODE_FAILED;
                }
            } 
            else {
                SCLogError("more than one run mode has been specified");
                PrintUsage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            SCLogError("IPFW not enabled. Make sure to pass --enable-ipfw to configure when building.");
            return TM_ECODE_FAILED;
#endif
            break;
                  
        case 'r':
            BUG_ON(optarg == NULL); /* for static analysis */
            if (suri->run_mode == RUNMODE_UNKNOWN) 
            {
                suri->run_mode = RUNMODE_PCAP_FILE;
            } 
            else
            {
                SCLogError("more than one run mode has been specified");
                PrintUsage(argv[0]);
                return TM_ECODE_FAILED;
            }
            SCStat buf;
            if (SCStatFn(optarg, &buf) != 0)
            {
                SCLogError("pcap file '%s': %s", optarg, strerror(errno));
                return TM_ECODE_FAILED;
            }
            if (ConfSetFinal("pcap-file.file", optarg) != 1)
            {
                SCLogError("ERROR: Failed to set pcap-file.file\n");
                return TM_ECODE_FAILED;
            }

            break;
        case 's':
            if (suri->sig_file != NULL) 
            {
                SCLogError("can't have multiple -s options or mix -s and -S.");
                return TM_ECODE_FAILED;
            }
            suri->sig_file = optarg;
            break;
        case 'S':
            if (suri->sig_file != NULL)
            {
                SCLogError("can't have multiple -S options or mix -s and -S.");
                return TM_ECODE_FAILED;
            }
            suri->sig_file = optarg;
            suri->sig_file_exclusive = TRUE;
            break;
        case 'u':
#ifdef UNITTESTS
            if (suri->run_mode == RUNMODE_UNKNOWN)
            {
                suri->run_mode = RUNMODE_UNITTEST;
            } 
            else 
            {
                SCLogError("more than one run mode has been specified");
                PrintUsage(argv[0]);
                return TM_ECODE_FAILED;
            }
#else
            SCLogError("unit tests not enabled. Make sure to pass --enable-unittests to configure when building.");
            return TM_ECODE_FAILED;
#endif /* UNITTESTS */
            break;
        case 'U':
#ifdef UNITTESTS
            suri->regex_arg = optarg;

            if(strlen(suri->regex_arg) == 0)
            {
                suri->regex_arg = NULL;
            }
#endif
            break;
        case 'V':
            suri->run_mode = RUNMODE_PRINT_VERSION;
            return TM_ECODE_OK;
        case 'F':
            if (optarg == NULL)
            {
                SCLogError("no option argument (optarg) for -F");
                return TM_ECODE_FAILED;
            }

            SetBpfStringFromFile(optarg);
            break;
        case 'v':
            suri->verbose++;
            break;
        case 'k':
            if (optarg == NULL) 
            {
                SCLogError("no option argument (optarg) for -k");
                return TM_ECODE_FAILED;
            }
            if (!strcmp("all", optarg))
            {
                suri->checksum_validation = 1;
            }
            else if (!strcmp("none", optarg))
            {
                suri->checksum_validation = 0;
            }
            else
            {
                SCLogError("option '%s' invalid for -k", optarg);
                return TM_ECODE_FAILED;
            }
            break;
        default:
            PrintUsage(argv[0]);
            return TM_ECODE_FAILED;
        }
    }

    if (suri->disabled_detect && suri->sig_file != NULL) 
    {
        SCLogError("can't use -s/-S when detection is disabled");
        return TM_ECODE_FAILED;
    }

    /* save the runmode from the command-line (if any) */
    suri->aux_run_mode = suri->run_mode;

    if (list_app_layer_protocols)
    {
        suri->run_mode = RUNMODE_LIST_APP_LAYERS;
    }
    if (list_keywords)
    {
        suri->run_mode = RUNMODE_LIST_KEYWORDS;
    }
    if (list_unittests)
    {
        suri->run_mode = RUNMODE_LIST_UNITTEST;
    }
    if (dump_config)
    {
        suri->run_mode = RUNMODE_DUMP_CONFIG;
    }
    if (dump_features)
    {
        suri->run_mode = RUNMODE_DUMP_FEATURES;
    }
    if (conf_test)
    {
        suri->run_mode = RUNMODE_CONF_TEST;
    }
    if (engine_analysis)
    {
        suri->run_mode = RUNMODE_ENGINE_ANALYSIS;
    }

    suri->offline = IsRunModeOffline(suri->run_mode);
    g_system = suri->system = IsRunModeSystem(suri->run_mode);

    ret = SetBpfString(optind, argv);
    if (ret != TM_ECODE_OK)
    {
        return ret;
    }

    return TM_ECODE_OK;
}

#ifdef OS_WIN32
static int WindowsInitService(int argc, char **argv)
{
    if (SCRunningAsService()) {
        char path[MAX_PATH];
        char *p = NULL;
        strlcpy(path, argv[0], MAX_PATH);
        if ((p = strrchr(path, '\\'))) {
            *p = '\0';
        }
        if (!SetCurrentDirectory(path)) {
            SCLogError("Can't set current directory to: %s", path);
            return -1;
        }
        SCLogInfo("Current directory is set to: %s", path);
        SCServiceInit(argc, argv);
    }

    /* Windows socket subsystem initialization */
    WSADATA wsaData;
    if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData)) {
        SCLogError("Can't initialize Windows sockets: %d", WSAGetLastError());
        return -1;
    }

    return 0;
}
#endif /* OS_WIN32 */

static int MayDaemonize(SCInstance *suri)
{
    if (suri->daemon == 1 && suri->pid_filename == NULL) 
    {
        const char *pid_filename;

        if (ConfGet("pid-file", &pid_filename) == 1) 
        {
            SCLogInfo("Use pid file %s from config file.", pid_filename);
        } 
        else
        {
            pid_filename = DEFAULT_PID_FILENAME;
        }
        /* The pid file name may be in config memory, but is needed later. */
        suri->pid_filename = SCStrdup(pid_filename);
        if (suri->pid_filename == NULL)
        {
            SCLogError("strdup failed: %s", strerror(errno));
            return TM_ECODE_FAILED;
        }
    }

    if (suri->pid_filename != NULL && SCPidfileTestRunning(suri->pid_filename) != 0)
    {
        SCFree(suri->pid_filename);
        suri->pid_filename = NULL;
        return TM_ECODE_FAILED;
    }

    if (suri->daemon == 1)
    {
        Daemonize();
    }

    if (suri->pid_filename != NULL) 
    {
        if (SCPidfileCreate(suri->pid_filename) != 0)
        {
            SCFree(suri->pid_filename);
            suri->pid_filename = NULL;
            SCLogError("Unable to create PID file, concurrent run of Suricata can occur.");
            SCLogError("PID file creation WILL be mandatory for daemon mode in future version");
        }
    }

    return TM_ECODE_OK;
}

/* Initialize the user and group Suricata is to run as. 初始化Suricata运行的用户和组*/
static int InitRunAs(SCInstance *suri)
{
#ifndef OS_WIN32
    /* Try to get user/group to run suricata as if command line as not decide of that */
    if (suri->do_setuid == FALSE && suri->do_setgid == FALSE)
    {
        const char *id;
        if (ConfGet("run-as.user", &id) == 1)
        {
            suri->do_setuid = TRUE;
            suri->user_name = id;
        }
        if (ConfGet("run-as.group", &id) == 1)
        {
            suri->do_setgid = TRUE;
            suri->group_name = id;
        }
    }
    /* Get the suricata user ID to given user ID, 将suricata用户ID设为给定的用户ID */
    if (suri->do_setuid == TRUE)
    {
        SCGetUserID(suri->user_name, suri->group_name, &suri->userid, &suri->groupid);
        sc_set_caps = TRUE; //sc_set_caps标识是否对主线程进行特权去除(drop privilege)，主要是出于安全性考虑。初始化为FALSE，此处设为TRUE。
    /* Get the suricata group ID to given group ID，将suricata组ID设为给定的用户ID */
    } 
    else if (suri->do_setgid == TRUE)
    {
        SCGetGroupID(suri->group_name, &suri->groupid);
        sc_set_caps = TRUE;
    }
#endif
    return TM_ECODE_OK;
}

static int InitSignalHandler(SCInstance *suri)
{
    /* registering signals we use */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    UtilSignalHandlerSetup(SIGINT, SignalHandlerSigint);
    UtilSignalHandlerSetup(SIGTERM, SignalHandlerSigterm);
#if HAVE_LIBUNWIND
    int enabled;
    if (ConfGetBool("logging.stacktrace-on-signal", &enabled) == 0) 
    {
        enabled = 1;
    }

    if (enabled) 
    {
        SCLogInfo("Preparing unexpected signal handling");
        struct sigaction stacktrace_action;
        memset(&stacktrace_action, 0, sizeof(stacktrace_action));
        stacktrace_action.sa_sigaction = SignalHandlerUnexpected;
        stacktrace_action.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &stacktrace_action, NULL);
        sigaction(SIGABRT, &stacktrace_action, NULL);
    }
#endif /* HAVE_LIBUNWIND */
#endif
#ifndef OS_WIN32
    UtilSignalHandlerSetup(SIGHUP, SignalHandlerSigHup);
    UtilSignalHandlerSetup(SIGPIPE, SIG_IGN);
    UtilSignalHandlerSetup(SIGSYS, SIG_IGN);
#endif /* OS_WIN32 */

    return TM_ECODE_OK;
}

/* initialization code for both the main modes and for unix socket mode.
 *
 * Will be run once per pcap in unix-socket mode */
    

 /* 用于主模式和Unix套接字模式的初始化代码。
  *
  * 在unix-socket模式下每个pcap运行一次
  */

void PreRunInit(const int runmode)
{
    HttpRangeContainersInit();
    
    if (runmode == RUNMODE_UNIX_SOCKET)
    {
        return;
    }

	/** 
	  * 初始化性能计数器模块。
	  * 这个模块实现了累加计数器(例如统计收到的数据包个数、字节数)、平均值计数器(统计平均包长、处理时间)、
	  * 最大计数器(最大包长、处理时间)、基于时间间隔的计数器(当前流量速率)等，默认输出到日志目录下的stats.log文件。 
	  */
    StatsInit();
    /** 
	  * 几个Profiling模块的初始化函数。
	  * Profiling模块提供内建的模块性能分析功能，
	  * 可以用来分析模块性能、各种锁的实际使用情况(竞争时间)、规则的性能等
	  */
#ifdef PROFILE_RULES
    SCProfilingRulesGlobalInit();
#endif
#ifdef PROFILING
    SCProfilingKeywordsGlobalInit();
    SCProfilingPrefilterGlobalInit();
    SCProfilingSghsGlobalInit();
#endif /* PROFILING */
#ifdef PROFILE_RULES
    SCProfilingInit();
#endif
    /* 初始化IP分片重组模块 */
    DefragInit();
    /* 初始化flow模块配置，主要是完成线程回调函数的注册，为了后面启动线程做准备 */
    FlowInitConfig(FLOW_QUIET);
    /* 初始化IP对 */
    IPPairInitConfig(FLOW_QUIET);
    /* 初始化stream全局配置数据 */
    StreamTcpInitConfig(STREAM_VERBOSE);
    AppLayerParserPostStreamSetup();
    AppLayerRegisterGlobalCounters();
    OutputFilestoreRegisterGlobalCounters();
}

/* tasks we need to run before packets start flowing, but after we dropped privs */
/* 在数据开始流动之前，但在放弃一些权限之后，需要运行的任务 */
void PreRunPostPrivsDropInit(const int runmode)
{
    /* 读取统计配置，进行相关设置 */
    StatsSetupPostConfigPreOutput();
    /* 初始化输出模块 */
    RunModeInitializeOutputs();
    DatasetsInit();

    if (runmode == RUNMODE_UNIX_SOCKET) 
    {
        /* As the above did some necessary startup initialization, it also setup some outputs where only one is allowed, 
         * so deinitialize to the state that unix-mode does after every pcap. 
         */
        /* 由于上面进行了一些必要的启动初始化，它还设置了一些只允许一个的输出，
         * 因此在每次pcap之后将其取消初始化为unix-mode的状态
         */
         
        PostRunDeinit(RUNMODE_PCAP_FILE, NULL);
        return;
    }

    /* 配置统计数据日志输出功能 */
    StatsSetupPostConfigPostOutput();
}

/* clean up / shutdown code for both the main modes and for unix socket mode.
 *
 * Will be run once per pcap in unix-socket mode */

/* 用于主模式和Unix套接字模式的去初始化代码
 *
 * 在unix-socket模式下每个pcap运行一次
 */
void PostRunDeinit(const int runmode, struct timeval *start_time)
{
    if (runmode == RUNMODE_UNIX_SOCKET)
    {
        return;
    }

    /* needed by FlowForceReassembly */
    PacketPoolInit();

    /* handle graceful shutdown of the flow engine, it's helper threads and the packet threads */
    /* 处理流引擎、辅助线程和数据包线程的正常关闭 */
    FlowDisableFlowManagerThread();
    TmThreadDisableReceiveThreads();
    FlowForceReassembly(); // 强制对仍有未处理的分段的流进行重组
    TmThreadDisablePacketThreads();
    SCPrintElapsedTime(start_time); // 打印进程运行的总时间（elapsed time）
    FlowDisableFlowRecyclerThread();

    /* kill the stats threads */
    /* 杀死统计线程 */
    TmThreadKillThreadsFamily(TVT_MGMT);
    TmThreadClearThreadsFamily(TVT_MGMT);

    /* kill packet threads -- already in 'disabled' state */
     /* 杀掉数据包线程 -- 已处于“禁用”状态 */
    TmThreadKillThreadsFamily(TVT_PPT);
    TmThreadClearThreadsFamily(TVT_PPT);

    /* 销毁数据包池 */
    PacketPoolDestroy();

    /* mgt and ppt threads killed, we can run non thread-safe shutdown functions */
    /* MGT 和 PPT 线程被杀死，我们可以运行非线程安全的shutdown函数 */
    StatsReleaseResources();
    DecodeUnregisterCounters();
    RunModeShutDown();
    FlowShutdown();
    IPPairShutdown();
    HostCleanup();
    StreamTcpFreeConfig(STREAM_VERBOSE);
    DefragDestroy();
    HttpRangeContainersDestroy();

    TmqResetQueues();
#ifdef PROFILING
    if (profiling_rules_enabled)
    {
        SCProfilingDump();
    }
    SCProfilingDestroy();
#endif
}


static int StartInternalRunMode(SCInstance *suri, int argc, char **argv)
{
    /* Treat internal running mode, 处理内部运行模式 */
    switch(suri->run_mode) 
    {
        case RUNMODE_LIST_KEYWORDS:
            return ListKeywords(suri->keyword_info);
        case RUNMODE_LIST_APP_LAYERS:
            if (suri->conf_filename != NULL)
            {
                return ListAppLayerProtocols(suri->conf_filename);
            } else {
                return ListAppLayerProtocols(DEFAULT_CONF_FILE);
            }
        case RUNMODE_PRINT_VERSION:
            PrintVersion();
            return TM_ECODE_DONE;
        case RUNMODE_PRINT_BUILDINFO:
            PrintBuildInfo();
            return TM_ECODE_DONE;
        case RUNMODE_PRINT_USAGE:
            PrintUsage(argv[0]);
            return TM_ECODE_DONE;
        case RUNMODE_LIST_RUNMODES:
            RunModeListRunmodes();
            return TM_ECODE_DONE;
        case RUNMODE_LIST_UNITTEST:
            RunUnittests(1, suri->regex_arg);
        case RUNMODE_UNITTEST:
            RunUnittests(0, suri->regex_arg);
#ifdef OS_WIN32
        case RUNMODE_INSTALL_SERVICE:
            if (SCServiceInstall(argc, argv))
            {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service has been successfully installed.");
            return TM_ECODE_DONE;
        case RUNMODE_REMOVE_SERVICE:
            if (SCServiceRemove(argc, argv)) {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service has been successfully removed.");
            return TM_ECODE_DONE;
        case RUNMODE_CHANGE_SERVICE_PARAMS:
            if (SCServiceChangeParams(argc, argv))
            {
                return TM_ECODE_FAILED;
            }
            SCLogInfo("Suricata service startup parameters has been successfully changed.");
            return TM_ECODE_DONE;
#endif /* OS_WIN32 */
        default:
            /* simply continue for other running mode */
            break;
    }
    return TM_ECODE_OK;
}

static int FinalizeRunMode(SCInstance *suri, char **argv)
{
    switch (suri->run_mode) 
    {
        case RUNMODE_UNKNOWN:
            PrintUsage(argv[0]);
            return TM_ECODE_FAILED;
        default:
            break;
    }
    /* Set the global run mode and offline flag. */
    /* 设置全局运行模式和脱机标志 */
    run_mode = suri->run_mode;

    if (!CheckValidDaemonModes(suri->daemon, suri->run_mode)) 
    {
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

static void SetupDelayedDetect(SCInstance *suri)
{
    /* In offline mode delayed init of detect is a bad idea */
    /* 脱机模式下，延迟初始化检测是一个坏主意 */
    if (suri->offline)
    {
        suri->delayed_detect = 0;
    } 
    else 
    {
        if (ConfGetBool("detect.delayed-detect", &suri->delayed_detect) != 1)
        {
            ConfNode *denode = NULL;
            ConfNode *decnf = ConfGetNode("detect-engine");
            if (decnf != NULL) 
            {
                TAILQ_FOREACH(denode, &decnf->head, next)
                {
                    if (strcmp(denode->val, "delayed-detect") == 0)
                    {
                        (void)ConfGetChildValueBool(denode, "delayed-detect", &suri->delayed_detect);
                    }
                }
            }
        }
    }

    SCLogConfig("Delayed detect %s", suri->delayed_detect ? "enabled" : "disabled");
    if (suri->delayed_detect) 
    {
        SCLogInfo("Packets will start being processed before signatures are active.");
    }

}

/* 加载检测规则 */
static int LoadSignatures(DetectEngineCtx *de_ctx, SCInstance *suri)
{
    if (SigLoadSignatures(de_ctx, suri->sig_file, suri->sig_file_exclusive) < 0)
    {
        SCLogError("Loading signatures failed.");
        if (de_ctx->failure_fatal)
        {
            return TM_ECODE_FAILED;
        }
    }

    return TM_ECODE_OK;
}

static int ConfigGetCaptureValue(SCInstance *suri)
{
    /* Pull the max pending packets from the config, if not found fall back on a sane default. */
    /* 从配置中提取最大待处理数据包，如果未找到，则返回合理的默认值 */
    intmax_t tmp_max_pending_packets;
    if (ConfGetInt("max-pending-packets", &tmp_max_pending_packets) != 1)
    {
        tmp_max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;
    }
    if (tmp_max_pending_packets < 1 || tmp_max_pending_packets >= UINT16_MAX) 
    {
        SCLogError("Maximum max-pending-packets setting is 65534 and must be greater than 0. Please check %s for errors", suri->conf_filename);
        return TM_ECODE_FAILED;
    } 
    else
    {
        max_pending_packets = (uint16_t)tmp_max_pending_packets;
    }

    SCLogDebug("Max pending packets set to %" PRIu16, max_pending_packets);

    /* Pull the default packet size from the config, if not found fall back on a sane default. */
    /* 从配置中提取默认数据包大小，如果未找到，则恢复为合理的默认值 */
    const char *temp_default_packet_size;
    if ((ConfGet("default-packet-size", &temp_default_packet_size)) != 1)
    {
        int lthread;
        int nlive;
        int strip_trailing_plus = 0;
        switch (suri->run_mode) 
        {
#ifdef WINDIVERT
            case RUNMODE_WINDIVERT:
            {
                /* by default, WinDivert collects from all devices */
                const int mtu = GetGlobalMTUWin32();

                if (mtu > 0) 
                {
                    /* SLL_HEADER_LEN is the longest header + 8 for VLAN */
                    default_packet_size = mtu + SLL_HEADER_LEN + 8;
                    break;
                }
                default_packet_size = DEFAULT_PACKET_SIZE;
                break;
            }
#endif /* WINDIVERT */
            case RUNMODE_NETMAP:
                /* in netmap igb0+ has a special meaning, however the interface really is igb0 */
                strip_trailing_plus = 1;
                /* fall through */
            case RUNMODE_PCAP_DEV:
            case RUNMODE_AFP_DEV:
            case RUNMODE_AFXDP_DEV:
            case RUNMODE_PFRING:
                nlive = LiveGetDeviceCount();
                for (lthread = 0; lthread < nlive; lthread++)
                {
                    const char *live_dev = LiveGetDeviceName(lthread);
                    char dev[128]; /* need to be able to support GUID names on Windows */
                    (void)strlcpy(dev, live_dev, sizeof(dev));

                    if (strip_trailing_plus)
                    {
                        size_t len = strlen(dev);
                        if (len && (dev[len-1] == '+' || dev[len-1] == '^' || dev[len-1] == '*'))
                        {
                            dev[len-1] = '\0';
                        }
                    }
                    LiveDevice *ld = LiveGetDevice(dev);
                    unsigned int iface_max_packet_size = GetIfaceMaxPacketSize(ld);
                    if (iface_max_packet_size > default_packet_size)
                    {
                        default_packet_size = iface_max_packet_size;
                    }
                }
                if (default_packet_size)
                {
                    break;
                }
                /* fall through */
            default:
                default_packet_size = DEFAULT_PACKET_SIZE;
        }
    }
    else 
    {
        if (ParseSizeStringU32(temp_default_packet_size, &default_packet_size) < 0) 
        {
            SCLogError("Error parsing max-pending-packets from conf file - %s.  Killing engine", temp_default_packet_size);
            return TM_ECODE_FAILED;
        }
    }

    SCLogDebug("Default packet size set to %"PRIu32, default_packet_size);

    return TM_ECODE_OK;
}


static void PostRunStartedDetectSetup(const SCInstance *suri)
{
#ifndef OS_WIN32
    /* registering signal handlers we use. We setup usr2 here, so that one
     * can't call it during the first sig load phase or while threads are still
     * starting up. */
    /* 注册我们使用的信号处理程序。我们在这里设置了 usr2，以便在第一个信号加载阶段或线程仍在启动时无法调用它 */
    if (DetectEngineEnabled() && suri->delayed_detect == 0) 
    {
        UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2);
        UtilSignalUnblock(SIGUSR2);
    }
#endif
    if (suri->delayed_detect) 
    {
        /* force 'reload', this will load the rules and swap engines */
        /* 强制"reload"，这将加载规则并交换引擎 */
        DetectEngineReload(suri);
        SCLogNotice("Signature(s) loaded, Detect thread(s) activated.");
#ifndef OS_WIN32
        UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2);
        UtilSignalUnblock(SIGUSR2);
#endif
    }
}

void PostConfLoadedDetectSetup(SCInstance *suri)
{
    DetectEngineCtx *de_ctx = NULL;
    if (!suri->disabled_detect) 
    {
        SetupDelayedDetect(suri);
        int mt_enabled = 0;
        (void)ConfGetBool("multi-detect.enabled", &mt_enabled);
        int default_tenant = 0;
        if (mt_enabled)
        {
            (void)ConfGetBool("multi-detect.default", &default_tenant);
        }
        if (DetectEngineMultiTenantSetup(suri->unix_socket_enabled) == -1)
        {
            FatalError("initializing multi-detect detection engine contexts failed.");
        }
        if (suri->delayed_detect && suri->run_mode != RUNMODE_CONF_TEST)
        {
            de_ctx = DetectEngineCtxInitStubForDD();
        }
        else if (mt_enabled && !default_tenant && suri->run_mode != RUNMODE_CONF_TEST)
        {
            de_ctx = DetectEngineCtxInitStubForMT();
        } 
        else
        {
            de_ctx = DetectEngineCtxInit();
        }
        if (de_ctx == NULL)
        {
            FatalError("initializing detection engine failed.");
        }

        // 判断检测引擎类型是NORMAL
        if (de_ctx->type == DETECT_ENGINE_TYPE_NORMAL)
        {
            // 加载规则集，并判断结果
            if (LoadSignatures(de_ctx, suri) != TM_ECODE_OK)
            {
                exit(EXIT_FAILURE);
            }
        }

        gettimeofday(&de_ctx->last_reload, NULL);
        DetectEngineAddToMaster(de_ctx);
        DetectEngineBumpVersion();
    }
}

static void PostConfLoadedSetupHostMode(void)
{
    const char *hostmode = NULL;

    /* 设置host-mode时的处理分支 */
    if (ConfGet("host-mode", &hostmode) == 1)
    {
        if (!strcmp(hostmode, "router"))
        {
            host_mode = SURI_HOST_IS_ROUTER;
        } 
        else if (!strcmp(hostmode, "sniffer-only"))
        {
            host_mode = SURI_HOST_IS_SNIFFER_ONLY;
        } 
        else
        {
            if (strcmp(hostmode, "auto") != 0)
            {
                WarnInvalidConfEntry("host-mode", "%s", "auto");
            }
            
            if (EngineModeIsIPS())
            {
                host_mode = SURI_HOST_IS_ROUTER;
            }
            else
            {
                host_mode = SURI_HOST_IS_SNIFFER_ONLY;
            }
        }
    }
    /* 未设置host-mode时的处理分支 */
    else 
    {
        if (EngineModeIsIPS())
        {
            host_mode = SURI_HOST_IS_ROUTER;
            SCLogInfo("No 'host-mode': suricata is in IPS mode, using default setting 'router'");
        } 
        else
        {
            host_mode = SURI_HOST_IS_SNIFFER_ONLY;
            SCLogInfo("No 'host-mode': suricata is in IDS mode, using default setting 'sniffer-only'");
        }
    }
}

static void SetupUserMode(SCInstance *suri)
{
    /* apply 'user mode' config updates here */
    /* 应用"user mode"配置更新 */
    if (suri->system == false)
    {
        if (suri->set_logdir == false)
        {
            /* override log dir to current work dir */
            /* 设置日志目录为当前工作目录 */
            if (ConfigSetLogDirectory((char *)".") != TM_ECODE_OK)
            {
                FatalError("could not set USER mode logdir");
            }
        }
        if (suri->set_datadir == false)
        {
            /* override data dir to current work dir */
            /* 将数据目录覆盖为当前工作目录 */
            if (ConfigSetDataDirectory((char *)".") != TM_ECODE_OK)
            {
                FatalError("could not set USER mode datadir");
            }
        }
    }
}

/**
 * This function is meant to contain code that needs to be run once the configuration has been loaded.
 * 该函数旨在包含加载配置后需要运行的代码。
 */
int PostConfLoadedSetup(SCInstance *suri)
{
    /* do this as early as possible #1577 #1955 */
#ifdef HAVE_LUAJIT
    if (LuajitSetupStatesPool() != 0)
    {
        SCReturnInt(TM_ECODE_FAILED);
    }
#endif

    /* load the pattern matchers, 加载匹配模式串 */

	/** 
	  * 通过注册方式，设置多模式匹配表。
	  * 该表中每一项就是一个实现了某种多模式匹配算法(如WuManber、AC)的匹配器。 
	  * 以注册AC匹配器为例，MpmTableSetup会调用MpmACRegister函数实现AC注册，函数内部其实只是填充mpm_table中对应AC的那一项(mpm_table[MPM_AC])的各个字段。
	  * 如：匹配器名称("ac")、初始化函数(SCACInitCtx)、增加模式函数(SCACAddPatternCS)、实际的搜索执行函数(SCACSearch)。
	  */
    MpmTableSetup();
    /** 	
      * 通过注册方式, 设置单模式匹配表
      */
    SpmTableSetup();

    /* 设置网卡卸载功能 */
    int disable_offloading;
    if (ConfGetBool("capture.disable-offloading", &disable_offloading) == 0)
    {
        disable_offloading = 1;
    }
    if (disable_offloading)
    {
        LiveSetOffloadDisable();
    }
    else
    {
        LiveSetOffloadWarn();
    }

	/* 设置数据校验和验证功能 */
    if (suri->checksum_validation == -1) 
    {
        const char *cv = NULL;
        if (ConfGet("capture.checksum-validation", &cv) == 1)
        {
            if (strcmp(cv, "none") == 0)
            {
                suri->checksum_validation = 0;
            } 
            else if (strcmp(cv, "all") == 0)
            {
                suri->checksum_validation = 1;
            }
        }
    }
    switch (suri->checksum_validation)
    {
        case 0:
            ConfSet("stream.checksum-validation", "0");
            break;
        case 1:
            ConfSet("stream.checksum-validation", "1");
            break;
    }

	/** 
	  * 设置运行模式
	  * 使用ConfSet函数设置的配置值可能会被后续调用覆盖，或者如果该值在配置文件中多次出现
	  */
    if (suri->runmode_custom_mode)
    {
        ConfSet("runmode", suri->runmode_custom_mode);
    }

	/**
	  * 初始化存储模块 
	  * 这个模块可以用来临时存储一些数据，数据类型目前有两种：host、flow。具体在何种场景下用，目前未知
	  */
    StorageInit();
#ifdef HAVE_PACKET_EBPF
    if (suri->run_mode == RUNMODE_AFP_DEV)
    {
        EBPFRegisterExtension();
        LiveDevRegisterExtension();
    }
#endif
    RegisterFlowBypassInfo();

    MacSetRegisterFlowStorage();

#ifdef HAVE_PLUGINS
    SCPluginsLoad(suri->capture_plugin_name, suri->capture_plugin_args);
#endif

	/** 
	  * 创建已注册的设备
	  * 创建pre_live_devices列表中所有需要的在线设备, 通过LiveRegisterDevice()函数创建
	  */
    LiveDeviceFinalize(); // must be after EBPF extension registration，必须在EBPF扩展注册之后执行

	/* 如果L2为IPS, 则设置引擎为IPS模式 */
    RunModeEngineIsIPS( suricata.run_mode, suricata.runmode_custom_mode, suricata.capture_plugin_name);

	/* 如果引擎模式未知，则设置引擎为IDS模式 */
    if (EngineModeIsUnknown()) 
    { 
        // if still uninitialized, set the default
        SCLogInfo("Setting engine mode to IDS mode by default");
        EngineModeSetIDS();
    }

    SetMasterExceptionPolicy();

    /* Must occur prior to output mod registration and app layer setup. */
    /* 注册特征追踪, 必须在输出模块注册和应用层设置之前进行 */
    FeatureTrackingRegister();

	/**
	  * 设置应用层协议解析和识别功能
      * 注册应用协议解析器，设置应用层协议识别用到的匹配器 
      */
    AppLayerSetup();

    /* Suricata will use this umask if provided. By default it will use the umask passed on from the shell. */
    /* 如果配置文件中设置了umask，则使用配置文件中设置的umask。默认使用shell中的umask */
    const char *custom_umask;
    if (ConfGet("umask", &custom_umask) == 1) 
    {
        uint16_t mask;
        if (StringParseUint16(&mask, 8, (uint16_t)strlen(custom_umask), custom_umask) > 0)
        {
            umask((mode_t)mask);
        }
    }


    if (ConfigGetCaptureValue(suri) != TM_ECODE_OK) 
    {
        SCReturnInt(TM_ECODE_FAILED);
    }

#ifdef NFQ
    if (suri->run_mode == RUNMODE_NFQ)
    {
        NFQInitConfig(false);
    }
#endif

    /* Load the Host-OS lookup. */
	/** 
	  * 从配置文件中载入host os policy(主机OS策略)信息
	  * 网络入侵通常是针对某些特定OS的漏洞，因此如果能够获取部署环境中主机的OS信息，肯定对入侵检测大有裨益。
	  * 具体这些信息是怎么使用的，暂时也还不清楚。
	  */
    SCHInfoLoadFromConfig();

    if (suri->run_mode == RUNMODE_ENGINE_ANALYSIS)
    {
        SCLogInfo("== Carrying out Engine Analysis ==");
        const char *temp = NULL;
        if (ConfGet("engine-analysis", &temp) == 0) 
        {
            SCLogInfo("no engine-analysis parameter(s) defined in conf file.  Please define/enable them in the conf to use this feature.");
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    /* hardcoded initialization code */
    /** 
      * 加载规则关键字
	  * 初始化检测引擎，主要是注册检测引擎所支持的规则格式(跟Snort规则基本一致)中的关键字，比如sid、priority、msg、within、distance等等
	  */
    SigTableSetup(); /* load the rule keywords */
    SigTableApplyStrictCommandLineOption(suri->strict_rule_parsing_string);
	/** 
	  * 初始化queue handler(队列处理函数)，这个是衔接线程模块和数据包队列之间的桥梁。
	  * 目前共有5类handler：simple, nfq, packetpool, flow, ringbuffer
	  * 每类handler内部都有一个InHandler和OutHandler，一个用于从上一级队列中获取数据包，另一个用于处理完毕后将数据包送入下一级队列。
	  */
    TmqhSetup();

	/**
	  * 与规则中的tag关键字的实现相关，里用到了Storage模块。
	  * 调用HostStorageRegister和FlowStorageRegister注册了几个(与流/主机绑定的？)存储区域
	  */
    TagInitCtx();
    PacketAlertTagInit();
    /**
      * 与规则中的ThresholdInit关键字的实现相关，里用到了Storage模块。
      * 调用HostStorageRegister和FlowStorageRegister注册了几个(与流/主机绑定的？)存储区域
      */
    ThresholdInit();
    HostBitInitCtx();
    IPPairBitInitCtx();

	/* 检查配置文件中"vars"选项下所预定义的一些IP地址(如局域网地址块)、端口变量(如HTTP端口号)是否符合格式要求。*/
    if (DetectAddressTestConfVars() < 0)
    {
        SCLogError( "basic address vars test failed. Please check %s for errors", suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (DetectPortTestConfVars() < 0)
    {
        SCLogError("basic port vars test failed. Please check %s for errors", suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }


	/**
	  * 这是个非常重要的函数, 里面注册了Suricata所支持的所有线程模块(Thread Module) 
	  *
	  * 以pcap相关模块为例: 
	  *  -TmModuleReceivePcapRegister函数注册了Pcap捕获模块，
	  *  -TmModuleDecodePcapRegister函数注册了Pcap数据包解码模块。
	  * 所谓注册，就是在tmm_modules模块数组中对应的那项中填充TmModule结构的所有字段，这些字段包括：模块名字、线程初始化函数、包处理或包获取函数、线程退出清理函数、一些标志位等等。
	  */
    RegisterAllModules();
    /* 设置suricata内部模块与libhtp(HTTP处理库)对接关系的函数 */
    AppLayerHtpNeedFileInspection();

	/* 关闭storage模块的注册，为已注册的storage实际分配存储空间 */
    StorageFinalize();

	/* 调用之前注册的线程模块的初始化函数进行初始化 */
    TmModuleRunInit();

	/**
	  * 检查是否进入Daemon模式
	  *
	  * 若需要进入Daemon模式，则会检测pidfile是否已经存在(daemon下只能有一个实例运行)，然后进行Daemonize，最后创建一个pidfile。
	  * Daemonize的主要思路是：
	  *  - fork子进程
	  *  - 子进程调用setsid创建一个新的session，关闭stdin、stdout、stderr，并告诉父进程 
	  *  - 父进程等待子进程通知，然后退出 
	  *  – 子进程继续执行
	  */
    if (MayDaemonize(suri) != TM_ECODE_OK)
    {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /** 
      * 初始化信号捕获处理函数 
      *
      * 首先为SIGINT(ctrl-c触发)和SIGTERM(不带参数kill时触发)这两个常规退出信号分别注册handler。处理方式是设置程序的状态标志为STOP，即让程序优雅地退出。
      * 程序会忽略SIGPIPE(这个信号通常是在Socket通信时向已关闭的连接另一端发送数据时收到)和SIGSYS(当进程尝试执行一个不存在的系统调用时收到)信号，以加强程序的容错性和健壮性。 
      */

    if (InitSignalHandler(suri) != TM_ECODE_OK)
    {
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Check for the existence of the default logging directory which we pick from suricata.yaml.  If not found, shut the engine down */
    /* 检查从suricata.yaml中选择的默认日志记录目录是否存在。 如果未找到，则退出引擎 */
    suri->log_dir = ConfigGetLogDirectory();

    if (ConfigCheckLogDirectoryExists(suri->log_dir) != TM_ECODE_OK)
    {
        SCLogError("The logging directory \"%s\" supplied by %s (default-log-dir) doesn't exist. Shutting down the engine",
                    suri->log_dir, suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }
    if (!IsLogDirectoryWritable(suri->log_dir))
    {
        SCLogError("The logging directory \"%s\" supplied by %s (default-log-dir) is not writable. Shutting down the engine",
                    suri->log_dir, suri->conf_filename);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (suri->disabled_detect)
    {
        SCLogConfig("detection engine disabled");
        /* disable raw reassembly */
        (void)ConfSetFinal("stream.reassembly.raw", "false");
    }

    HostInitConfig(HOST_VERBOSE);

    CoredumpLoadConfig();

	/* 配置Decode模块相关全局变量 */
    DecodeGlobalConfig();

    /* hostmode depends on engine mode being set */
    /* 主机模式取决于所设置的引擎模式 */
    PostConfLoadedSetupHostMode();

	/* 主模式和unix-socket模式的初始化代码 */
    PreRunInit(suri->run_mode);

    SCReturnInt(TM_ECODE_OK);
}

static void SuricataMainLoop(SCInstance *suri)
{
    while(1) 
    {
        if (sigterm_count || sigint_count) 
        {
            suricata_ctl_flags |= SURICATA_STOP;
        }

        if (suricata_ctl_flags & SURICATA_STOP) 
        {
            SCLogNotice("Signal Received.  Stopping engine.");
            break;
        }

        TmThreadCheckThreadState();

        if (sighup_count > 0) 
        {
            OutputNotifyFileRotation();
            sighup_count--;
        }

        if (sigusr2_count > 0) 
        {
            if (!(DetectEngineReloadIsStart())) 
            {
                DetectEngineReloadStart();
                DetectEngineReload(suri);
                DetectEngineReloadSetIdle();
                sigusr2_count--;
            }

        } 
        else if (DetectEngineReloadIsStart()) 
        {
            DetectEngineReload(suri);
            DetectEngineReloadSetIdle();
        }

        usleep(10* 1000);
    }
}

/**
 * \brief Global initialization common to all runmodes. 所有运行模式通用的全局初始化
 *
 * This can be used by fuzz targets.
 */

int InitGlobal(void)
{
    rs_init(&suricata_context);


	/**
	  * 初始化原子变量 engine_stage_sc_atomic__的值为0
	  * 记录程序当前的运行阶段：SURICATA_INIT、SURICATA_RUNTIME、SURICATA_FINALIZE 
	  */
    SC_ATOMIC_INIT(engine_stage);

    /**
      * initialize the logging subsys 
      * 初始化日志模块
      * 因为后续的执行流程中将使用日志输出，所以需要最先初始化该模块
      */
    SCLogInitLogModule(NULL);

	/** 
	  * 设置当前主线程名字为Suricata-Main。 
	  * 线程名字还是挺重要的，至少在gdb调试时, info threads可以看到各个线程名，从而可以精确地找到想要查看的线程。
	  * 另外，在top -H 时，也能够显示出线程名字。
	  */
    //SCSetThreadName("Suricata-Main");
    SCSetThreadName("Prism-Main");

    /* Ignore SIGUSR2 as early as possible. We redeclare interest
     * once we're done launching threads. The goal is to either die
     * completely or handle any and all SIGUSR2s correctly.
     */
    /** 
      * 设置SIGUSR2信号捕捉函数为IGN
      *
      * 尽早忽略SIGUSR2信号。启动完线程后，会重新声明interest。目标是要么彻底终止，要么正确处理所有SIGUSR2信号。
      */
#ifndef OS_WIN32
    UtilSignalHandlerSetup(SIGUSR2, SIG_IGN);
    if (UtilSignalBlock(SIGUSR2)) 
    {
        SCLogError("SIGUSR2 initialization error");
        return EXIT_FAILURE;
    }
#endif

	/**
	  * 初始化ParserSize模块
	  *
	  * 使用正则表达式来解析类似"10Mb"这种大小参数，其中正则引擎用的是pcre，
	  * 因此初始化时就是调用pcre_compile、pcre_study对已经写好的正则表达式进行编译和预处理。
	  */
    ParseSizeInit();
	/** 
	  * 注册各种运行模式
	  *
	  * Suricata对"运行模式"这个概念也进行了封装。运行模式存储在runmodes数组中，定义为RunModes runmodes[RUNMODE_USER_MAX]。
	  *
	  * 首先，数组中每一项(例如runmodes[RUNMODE_PCAP_DEV])对应一组运行模式，模式组包括(RunModes类型): IDS+Pcap"模式组、"File+Pcap"模式组、"UnixSocket"模式组等。
	  * 另外还有其他一些内部模式，如："列出关键字"模式、"打印版本号"模式等，这些没有存储在runmodes数组中)。
	  *
	  * 然后，每一个模式组，其中可以包含若干个运行模式(RunMode类型)，例如：single、auto、autofp、workers。
	  *
	  * 运行模式的注册，则是为各个模式组(如RunModeIdsPcapRegister)添加其所支持的运行模式(通过调用RunModeRegisterNewRunMode)，并定义该组的默认运行模式，
	  * 以及非常重要的：注册各个模式下的初始化函数(如RunModeIdsPcapSingle)，等后续初始化阶段确定了具体的运行模式后，就会调用这里注册的对应的初始化函数，对该模式下的运行环境进行进一步配置。
	  */
    RunModeRegisterRunModes();

    /* Initialize the configuration module. */
    /** 
      * 初始化配置模块
      * 为配置节点树建立root节点
      */
    ConfInit();

    /* 初始换变量名存储 */
    VarNameStoreInit();

    /* 清零所有模块存储 */
    memset(tmm_modules, 0, TMM_SIZE * sizeof(TmModule));

    return 0;
}

int SuricataMain(int argc, char **argv)
{
	/**
	  * 初始化suricata全局实例变量
	  *
	  * SCInstance类型的suricata变量用来保存程序当前的一些状态、标志等上下文环境，通常是用来作为参数传递给各个模块的子函数，因此为了更好的封装性而放到一个结构体变量中，而不是使用零散的长串参数或一堆全局变量。
	  * SCInstanceInit函数，顾名思义，即是对suri中各个字段进行初始化。
	  * 注意，这里对所有字段都进行了显示初始化，因为虽然一个memset清零已经基本达到目的了，但显示地将各个成员设成0、NULL、FALSE，对于可读性来说还是有好处的，可以明确地说明各个字段的初始值，且对扩展性也会有好处。
	  * 例如若后续初始化需要设置一些非0值(如用-1表示无效值)，直接更改就好了。
	  */
    SCInstanceInit(&suricata, argv[0]);

	/**
	  * 对于所有运行模式通用部分的全局初始化，包括以下初始化：
	  *
	  * 1.初始化rust和C的接口
	  * 2.初始化原子变量engine_stage, 用来记录程序当前的运行阶段
	  * 3.初始化日志模块 
	  * 4.设置主线程名字为suricata-Main
	  * 5.设置SIGUSR2信号捕捉函数为IGN
	  * 6.初始化ParserSize模块
	  * 7.***注册各种运行模式***
	  * 8.初始化配置模块
	  * 9.初始换变量名存储模块
	  */
    if (InitGlobal() != 0)
    {
        exit(EXIT_FAILURE);
    }

#ifdef OS_WIN32
    /* service initialization */
    if (WindowsInitService(argc, argv) != 0)
    {
        exit(EXIT_FAILURE);
    }
#endif /* OS_WIN32 */

	/**
	  * 解析命令行参数
	  *
      * "-v"选项可多次使用，每个v都能将当前日志等级提升一级。
      * 与包捕获相关的选项(如"-i"、"pfring"、"netmap")，都会调用LiveRegisterDevice，以注册一个数据包捕获设备接口。全局的所有已注册的设备接口存储在变量live_devices中，类型为LiveDevice。
      * 注意，用多设备同时捕获数据包这个特性在Suricata中目前还只是实验性的。
      */
    if (ParseCommandLine(argc, argv, &suricata) != TM_ECODE_OK)
    {
        exit(EXIT_FAILURE);
    }

	/**
	  * 为运行模式的处理划上句号
	  *
      * 主要是要是对unknown运行模式进行报错，设置offline标志、设置全局run_mode变量，检查当前模式是否与daemon标志冲突
      * 注意,Pcap文件模式及单元测试模式都不能在daemon开启下进行
      */
    if (FinalizeRunMode(&suricata, argv) != TM_ECODE_OK)
    {
        exit(EXIT_FAILURE);
    }

	/** 
	  * 开始处理内部运行模式
	  *
	  * 若运行模式为内部模式，则进入该模式执行，完毕后退出程序
	  */
    switch (StartInternalRunMode(&suricata, argc, argv))
    {
        case TM_ECODE_DONE:
            exit(EXIT_SUCCESS);
        case TM_ECODE_FAILED:
            exit(EXIT_FAILURE);
    }

    /* Initializations for global vars, queues, etc (memsets, mutex init..) */
    /* 初始化全局变量、队列和配置 */
    GlobalsInitPreConfig();

    /* Load yaml configuration file if provided. */
	/**
	  * 加载配置文件, 获取到所有配置保存到节点树中 
      *
      * Yaml格式解析是通过libyaml库来完成的，解析的结果存储在配置节点树(见conf.c)中。
      * 对include机制的支持；在第一遍调用ConfYamlLoadFile载入主配置文件后，
      * 将在当前配置节点树中搜寻"include"节点，并对其每个子节点的值(即通过include语句所指定的子配置文件路径)，同样调用ConfYamlLoadFile进行载入。
      */
    if (LoadYamlConfig(&suricata) != TM_ECODE_OK)
    {
        exit(EXIT_FAILURE);
    }

	/* 若运行模式为DUMP_CONFIG，则调用ConfDump打印出当前的所有配置信息，然后程序退出。*/
    if (suricata.run_mode == RUNMODE_DUMP_CONFIG)
    {
        ConfDump();
        exit(EXIT_SUCCESS);
    }

	/* 根据配置，设置追踪开关 */	
    int tracking = 1;
    if (ConfGetBool("vlan.use-for-tracking", &tracking) == 1 && !tracking)
    {
        /* Ignore vlan_ids when comparing flows. */
        g_vlan_mask = 0x0000;
    }
    SCLogDebug("vlan tracking is %s", tracking == 1 ? "enabled" : "disabled");
    if (ConfGetBool("livedev.use-for-tracking", &tracking) == 1 && !tracking)
    {
        /* Ignore livedev id when comparing flows. */
        g_livedev_mask = 0x0000;
    }

    /* 应用"user mode"配置的值更新配置 */
    SetupUserMode(&suricata);
	/** 
	  * 初始化suricata运行时的用户身份和所属组信息
	  *
	  * 通过设置sc_set_caps标识为TRUE，标识是否对主线程进行特权去除，去除权限操作在SCDropMainThreadCaps函数中执行
	  */
    InitRunAs(&suricata);

    /* Since our config is now loaded we can finish configurating the logging module. */
	/** 
	  * 再次初始化日志模块
	  *
	  * 程序将会根据配置文件中日志输出配置(logging.outputs)填充SCLogInitData类型的结构体，
	  * 调用SCLogInitLogModule重新初始化日志模块
	  */
    SCLogLoadConfig(suricata.daemon, suricata.verbose, suricata.userid, suricata.groupid);

	/* 打印版本信息。这是Suricata启动开始后第一条打印信息 */
    LogVersion(&suricata);
    /* 打印当前机器的CPU/核个数，这些信息是通过sysconf系统函数获取的。*/
    UtilCpuPrintSummary();
    /* 初始化多线程设置 */
    RunModeInitializeThreadSettings();

    if (suricata.run_mode == RUNMODE_CONF_TEST)
    {
        SCLogInfo("Running suricata under test mode");
    }

    /* 解析网口列表 */
    if (ParseInterfacesList(suricata.aux_run_mode, suricata.pcap_dev) != TM_ECODE_OK)
    {
        exit(EXIT_FAILURE);
    }

    /* 执行PostConfLoadedSetup，运行那些在配置载入完成后就需要立马执行的代码，这里面涉及的流程和函数非常多。 */
    if (PostConfLoadedSetup(&suricata) != TM_ECODE_OK)
    {
        exit(EXIT_FAILURE);
    }

	/** 
	  * 去除主线程的一些权限。
	  *
	  * 主线程的权限应该会被新建的子线程继承，因此只需要在主线程设置即可。
      * 这个是通过libcap-ng实现的：
      *  首先调用capng_clear清空所有权限;
      *  然后根据运行模式添加一些必要权限(主要是为了抓包);
      *  最后调用capng_change_id设置新的uid和gid。
      */ 
    SCDropMainThreadCaps(suricata.userid, suricata.groupid);

    /* Re-enable coredumps after privileges are dropped. */
    /**
      * 去除权限后，再次设置CoreDump状态。
      *
	  * Linux下可用prctl函数获取和设置进程dumpable状态，设置corefile大小则是通过通用的setrlimit函数
	  */
    CoredumpEnable();

    if (suricata.run_mode != RUNMODE_UNIX_SOCKET && !suricata.disabled_detect) 
    {
        suricata.unix_socket_enabled = ConfUnixSocketIsEnable();
    }

    /* 在数据开始流动之前，但在放弃一些权限之后，需要运行的任务 */
    PreRunPostPrivsDropInit(suricata.run_mode);

    LandlockSandboxing(&suricata);

    /* 执行那些在配置载入完成后，需要立即进行的检测引擎相关的设置 */
    PostConfLoadedDetectSetup(&suricata);
    
    if (suricata.run_mode == RUNMODE_ENGINE_ANALYSIS)
    {
        goto out;
    } 
    else if (suricata.run_mode == RUNMODE_CONF_TEST)
    {
        SCLogNotice("Configuration provided was successfully loaded. Exiting.");
        goto out;
    } 
    else if (suricata.run_mode == RUNMODE_DUMP_FEATURES)
    {
        FeatureDump();
        goto out;
    }

    SystemHugepageSnapshot *prerun_snap = NULL;
    if (run_mode == RUNMODE_DPDK)
    {
        prerun_snap = SystemHugepageSnapshotCreate();
    }

	/**
	  * 设置引擎启动时间
	  *
      * 调用gettimeofday保存当前时间，存储在suri->start_time中，作为系统的启动时间。
	  */
    SCSetStartTime(&suricata);

	/**
	  * 运行模式调度 
	  *
	  * 首先，根据配置文件和程序中的默认值来配置运行模式(single、auto这些)，而运行模式类型(PCAP_DEV、PCAPFILE这些)也在之前已经确定了，
	  * 因此运行模式已经固定下来。即通过runmode和custom_mode两个重要参数,从runmodes表中获取到特定的RunMode.
	  * 
	  * 接着，调用RunMode中的RunModeFunc，进入当前运行模式的初始化函数。
	  * 
	  * 以PCAP_DEV类型下的autofp模式为例，该模式的初始化函数为：RunModeIdsPcapAutoFp，详见该函数实现(已添加注释)
	  */
    RunModeDispatch(suricata.run_mode, suricata.runmode_custom_mode, suricata.capture_plugin_name, suricata.capture_plugin_args);
    if (suricata.run_mode != RUNMODE_UNIX_SOCKET)
    {
        UnixManagerThreadSpawnNonRunmode(suricata.unix_socket_enabled);
    }

    /* Wait till all the threads have been initialized */
    /**
      * 等待所有子线程初始化完成
	  * 检查是否初始化完成的方式是遍历tv_root，调用TmThreadsCheckFlag检查子线程的状态标志。
	  */
    if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED)
    {
        FatalError("Engine initialization failed,  aborting...");
    }


    /* 根据配置,设置security.limit-noproc   (setrlimit()) */
    int limit_nproc = 0;
    if (ConfGetBool("security.limit-noproc", &limit_nproc) == 0)
    {
        limit_nproc = 0;
    }

#if defined(SC_ADDRESS_SANITIZER)
    if (limit_nproc)
    {
        SCLogWarning("\"security.limit-noproc\" (setrlimit()) not set when using address sanitizer");
        limit_nproc = 0;
    }
#endif

    if (limit_nproc)
    {
#if defined(HAVE_SYS_RESOURCE_H)
#ifdef linux
        if (geteuid() == 0)
        {
            SCLogWarning("setrlimit has no effet when running as root.");
        }
#endif
        struct rlimit r = { 0, 0 };
        if (setrlimit(RLIMIT_NPROC, &r) != 0)
        {
            SCLogWarning("setrlimit failed to prevent process creation.");
        }
#else
        SCLogWarning("setrlimit unavailable.");
#endif
    }

	/**
	  * 更新engine_stage为SURICATA_RUNTIME，即程序已经初始化完成，进入运转状态。
	  * 这里的更新用的是原子CAS操作，防止并发更新导致状态不一致 
	  */
    SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);
	/* 设置max_pending_return_packets的值 */
    PacketPoolPostRunmodes();

    /* Un-pause all the paused threads */
	/** 让目前处于paused状态的线程继续执行
	  * 在TmThreadCreate中，线程的初始状态设置为了PAUSE，因此初始化完成后就会等待主线程调用TmThreadContinue让其继续。
	  * 从这以后，各线程就开始正式执行其主流程了。
	  */
    TmThreadContinueThreads();

    /* Must ensure all threads are fully operational before continuing with init process */
    /* 必须确保在继续执行init处理之前所有线程都已完全运行 */
    if (TmThreadWaitOnThreadRunning() != TM_ECODE_OK)
    {
        exit(EXIT_FAILURE);
    }

    /* Print notice and send OS specific notification of threads in running state */
    OnNotifyRunning();

	/* 若设置了delayed_detect，则现在开始调用DetectEngineReload重新加载规则集，激活检测线程，并注册rule_reload信号处理函数。*/
    PostRunStartedDetectSetup(&suricata);

    // only DPDK uses hpages at the moment
    /* 只有在DPDK模式下, 才会在此时使用大页信息 */
    if (run_mode == RUNMODE_DPDK) 
    { 
        SystemHugepageSnapshot *postrun_snap = SystemHugepageSnapshotCreate();
        SystemHugepageEvaluateHugepages(prerun_snap, postrun_snap);
        SystemHugepageSnapshotDestroy(prerun_snap);
        SystemHugepageSnapshotDestroy(postrun_snap);
    }
    SCPledge();

	/**
	  * 主线程函数
	  *
      * 主函数内部为死循环。若收到退出信号SIGINT和SIGTERM后, 对应的信号捕捉函数会设置全局变量sigint_count和sigtrem_count为1。 
      * 若sigint_count或者sigtrem_count不为0，则设置suricata_ctl_flags|=SURICATA_STOP，退出循环，并进行后续的资源清理工作，然后程序退出。
      * 否则就执行循环体中的后续操作后，sleep 10ms 继续循环。
	  */
    SuricataMainLoop(&suricata);


    /****** 主线程的主函数中的死循环结束后，程序就进入了程序退出清理阶段 ******/

    /* Update the engine stage/status flag */
    /* 更新engine_stage为SURICATA_DEINIT */
    SC_ATOMIC_SET(engine_stage, SURICATA_DEINIT);

	/* kill掉unix管理线程 */
    UnixSocketKillSocketThread();

    /* 清理/关闭主模式和Unix套接字模式， 如：杀掉统计线程和包处理线程、销毁数据包池、关闭流引擎等等 */
    PostRunDeinit(suricata.run_mode, &suricata.start_time);
    
    /* kill remaining threads */
    /** kill掉剩余的所有子线程 
      * 杀死线程的函数为TmThreadKillThread，这个函数会同时向子线程发出KILL和DEINIT信号，然后等待子线程进入CLOSED状态，之后，
      * 再调用线程的清理函数(InShutdownHandler)以及其对应的ouqh的清理函数(OutHandlerCtxFree)，最后调用pthread_join等待子线程退出。
      */
    TmThreadKillThreads();

out:

    /**
      * 执行一大堆清理函数
      * 如：关闭Host engine、清理HTP模块并打印状态、移除PID文件、关闭检测引擎、清理应用层识别模块、
      *     清理Tag环境、关闭所有输出模块， ...，等等
      */
    GlobalsDestroy(&suricata);
    
	/* 调用exit以EXIT_SUCCESS为退出状态终止程序 */
    exit(EXIT_SUCCESS);
}
