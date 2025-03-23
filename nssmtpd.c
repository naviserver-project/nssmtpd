/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License (the "GPL"), in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under either the License or the GPL.
 *
 */

/*
 *   NaviServer SMTP server/proxy
 *
 *   Author Vlad Seryakov vlad@crystalballinc.com
 *   Gustaf Neumann neumann@wu.ac.at
 *
 */

#include "ns.h"

#ifndef TCL_INDEX_NONE
# define TCL_INDEX_NONE -1
#endif

#ifndef TCL_SIZE_T
# ifdef NS_TCL_PRE9
#  define TCL_SIZE_T           int
# else
#  define TCL_SIZE_T           Tcl_Size
# endif
#endif

#include <setjmp.h>

#ifdef USE_SAVI
#include "csavi3c.h"
#endif

#ifdef USE_CLAMAV
#include "clamav.h"
#endif

#ifdef USE_DSPAM
#include <dspam/libdspam.h>
#endif

#ifdef HAVE_OPENSSL_EVP_H
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#ifndef NS_FALL_THROUGH
# define NS_FALL_THROUGH
#endif

#ifndef NS_INLINE
# define NS_INLINE
#endif

#ifndef NS_EAGAIN
# define NS_EAGAIN EAGAIN
#endif

#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#if !defined(NS_DRIVER_VERSION_5)
#define Ns_ReturnCodeString(rc) (((rc) == NS_OK ? "NS_OK" : ((rc) == NS_ERROR ? "NS_ERROR" : "OTHER_ERROR")))
#endif

/* SMTP commands */
#define SMTP_HELO           1
#define SMTP_MAIL           2
#define SMTP_RCPT           3
#define SMTP_DATA           4
#define SMTP_RSET           5
#define SMTP_VRFY           6
#define SMTP_EXRN           7
#define SMTP_QUIT           8
#define SMTP_HELP           9
#define SMTP_NOOP           10
#define SMTP_READ           11
#define SMTP_STARTTLS       12

/* Server flags */
#define SMTPD_VERIFIED       0x0000001u
#define SMTPD_LOCAL          0x0000002u
#define SMTPD_RELAY          0x0000004u
#define SMTPD_DELIVERED      0x0000008u
#define SMTPD_ABORT          0x0000010u
#define SMTPD_VIRUSCHECK     0x0000020u
#define SMTPD_SPAMCHECK      0x0000040u
#define SMTPD_NEEDDOMAIN     0x0000100u
#define SMTPD_SEGV           0x0001000u
#define SMTPD_FASTPROXY      0x0004000u
#define SMTPD_RESOLVE        0x0008000u
#define SMTPD_NEEDHELO       0x0010000u
#define SMTPD_GOTHELO        0x0020000u
#define SMTPD_GOTMAIL        0x0040000u
#define SMTPD_GOTSPAM        0x0080000u
#define SMTPD_GOTVIRUS       0x0100000u
#define SMTPD_GOTSTARTTLS    0x0200000u
#define SMTPD_GOTAUTHPLAIN   0x0400000u

#define SMTPD_VERSION              "2.4"
#define SMTPD_HDR_FILE             "X-Smtpd-File"
#define SMTPD_HDR_VIRUS_STATUS     "X-Smtpd-Virus-Status"
#define SMTPD_HDR_SIGNATURE        "X-Smtpd-Signature"

// Email address
typedef struct _smtpdEmail {
    const char *name;
    const char *domain;
    const char *mailbox;
} smtpdEmail;

// IP access list
typedef struct _smtpdIpaddr {
    struct _smtpdIpaddr *next;
    struct NS_SOCKADDR_STORAGE addr;
    struct NS_SOCKADDR_STORAGE mask;
} smtpdIpaddr;

// SMTP Headers
typedef struct _smtpdHdr {
    struct _smtpdHdr *next;
    char *name;
    char *value;
} smtpdHdr;

// Relay list
typedef struct _smtpdRelay {
    struct _smtpdRelay *next;
    const char *name;
    char *host;
    unsigned short port;
} smtpdRelay;

// Recipient list
typedef struct _smtpdRcpt {
    struct _smtpdRcpt *next, *prev;
    const char *addr;
    unsigned int flags;
    const char *data;
    struct {
        unsigned short port;
        const char *host;
    } relay;
    float spam_score;
} smtpdRcpt;

typedef struct _smtpdConfig {
    /*
     * The first two elements are the same as in the Config structure in
     * nssock. We use this to be able to reuse Ns_DriverSockListen and
     * Ns_DriverSockAccept.
     */
    int deferaccept;  /* Enable the TCP_DEFER_ACCEPT optimization. */
    int nodelay;      /* Enable the TCP_NODEALY optimization. */

    const char *server;
    unsigned int id;
    unsigned int flags;
    int debug;
    size_t bufsize;
    int maxline;
    int maxdata;
    int maxrcpt;
    int readtimeout;
    int writetimeout;
    char *relayhost;
    char *relayuser;
    char *relaypassword;
    const char *address;
    char *spamdhost;
    const char *initproc;
    const char *heloproc;
    const char *mailproc;
    const char *rcptproc;
    const char *dataproc;
    const char *errorproc;
    Ns_Mutex relaylock;
    Ns_Mutex lock;
    smtpdRelay *relaylist;
    Tcl_HashTable sessions;
    smtpdIpaddr *local;
    Ns_Mutex locallock;
    Ns_Driver *driver;
#ifdef USE_CLAMAV
    struct cl_node *ClamAvRoot;
    struct cl_limits ClamAvLimits;
#endif
#ifdef HAVE_OPENSSL_EVP_H
    const char *certificate;
    const char *cafile;
    const char *capath;
    const char *ciphers;
    const char *ciphersuites;
    const char *protocols;
#endif
    unsigned short relayport;
    unsigned short port;
    unsigned short spamdport;
    struct {
        Ns_Mutex lock;
        const char *logFileName;
        const char *logRollfmt;
        int  logMaxbackup;
        int  fd;
        bool logging;
    } sendlog;
} smtpdConfig;

typedef struct _smtpdConn {
    struct _smtpdConn *next;
    uintptr_t id;
    int cmd;
    unsigned int flags;
    const char *host;
    Ns_Sock *sock;
    Tcl_DString line;
    Tcl_DString reply;
    Tcl_Interp *interp;
    smtpdConfig *config;
    struct {
        char *addr;
        const char *data;
    } from;
    struct {
        int count;
        smtpdRcpt *list;
    } rcpt;
    struct {
        size_t offset;
        Tcl_DString data;
        smtpdHdr *headers;
    } body;
    struct {
        ssize_t pos;
        char *ptr;
        char data[1];
    } buf;
} smtpdConn;

//  DNS record types
#define	DNS_HEADER_LEN          12
#define DNS_TYPE_A              1
#define DNS_TYPE_NS             2
#define DNS_TYPE_CNAME          5
#define DNS_TYPE_SOA            6
#define DNS_TYPE_WKS            11
#define DNS_TYPE_PTR            12
#define DNS_TYPE_HINFO          13
#define DNS_TYPE_MINFO          14
#define DNS_TYPE_MX             15
#define DNS_TYPE_TXT            16
#define DNS_TYPE_AAAA           28
#define DNS_TYPE_SRV            33
#define DNS_TYPE_ANY            255
#define DNS_DEFAULT_TTL         (60 * 60)
#define DNS_CLASS_INET          1

// RCODE types
#define RCODE_NOERROR            0
#define RCODE_QUERYERR           1
#define RCODE_SRVFAIL            2
#define RCODE_NXDOMAIN           3
#define RCODE_NOTIMP             4
#define RCODE_REFUSED            5
#define RCODE_NOTAUTH            9

// OPCODE types
#define OPCODE_QUERY              0
#define OPCODE_IQUERY             1
#define OPCODE_STATUS             2
#define OPCODE_COMPLETION         3
#define OPCODE_NOTIFY             4
#define OPCODE_UPDATE             5

// Macros for manipulating the flags field
#define DNS_GET_RCODE(x)        (((x) & 0x000f))
#define DNS_GET_RA(x)           (((x) & 0x0080) >> 7)
#define DNS_GET_RD(x)           (((x) & 0x0100) >> 8)
#define DNS_GET_TC(x)           (((x) & 0x0200) >> 9)
#define DNS_GET_AA(x)           (((x) & 0x0400) >> 10)
#define DNS_GET_OPCODE(x)       (((x) & 0xe800) >> 11)
#define DNS_GET_QR(x)           (((x) & 0x8000) >> 15)

#define DNS_SET_RCODE(x,y)      ((x) = ((x) & ~0x000f) | ((y) & 0x000f))
#define DNS_SET_RA(x,y)         ((x) = ((x) & ~0x0080) | (((y) << 7) & 0x0080))
#define DNS_SET_RD(x,y)         ((x) = ((x) & ~0x0100) | (((y) << 8) & 0x0100))
#define DNS_SET_TC(x,y)         ((x) = ((x) & ~0x0200) | (((y) << 9) & 0x0200))
#define DNS_SET_AA(x,y)         ((x) = ((x) & ~0x0400) | (((y) << 10) & 0x0400))
#define DNS_SET_OPCODE(x,y)     ((x) = ((x) & ~0xe800) | (((y) << 11) & 0xe800))
#define DNS_SET_QR(x,y)         ((x) = ((x) & ~0x8000) | (((y) << 15) & 0x8000))

#define DNS_BUF_SIZE            1524
#define DNS_REPLY_SIZE          514
#define DNS_BUFSIZE             536

typedef struct _dnsServer {
    struct _dnsServer *next;
    const char *name;
    //unsigned long ipaddr;
    time_t fail_time;
    unsigned long fail_count;
} dnsServer;

typedef struct _dnsSOA {
    const char *mname;
    const char *rname;
    unsigned long serial;
    unsigned long refresh;
    unsigned long retry;
    unsigned long expire;
    unsigned long ttl;
} dnsSOA;

typedef struct _dnsMX {
    const char *name;
    unsigned short preference;
} dnsMX;

typedef struct _dnsName {
    struct _dnsName *next;
    const char *name;
    short offset;
} dnsName;

typedef struct _dnsRecord {
    struct _dnsRecord *next, *prev;
    const char *name;
    unsigned short type;
    unsigned short class;
    unsigned long ttl;
    short len;
    union {
        const char *name;
        struct in_addr ipaddr;
        dnsMX *mx;
        dnsSOA *soa;
    } data;
    unsigned long timestamp;
    unsigned short rcode;
} dnsRecord;

typedef struct _dnsPacket {
    unsigned short id;
    unsigned short u;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
    dnsName *nmlist;
    dnsRecord *qdlist;
    dnsRecord *anlist;
    dnsRecord *nslist;
    dnsRecord *arlist;
    struct {
        unsigned short allocated;
        unsigned short size;
        const char *rec;
        char *ptr;
        char *data;
    } buf;
} dnsPacket;

static bool parseEmail(smtpdEmail *addr, char *str);
static char *encode64(const char *in, TCL_SIZE_T len);
static char *decode64(const char *in, TCL_SIZE_T len, size_t *outlen);
static char *encodeqp(const char *in, size_t len);
static char *decodeqp(const char *in, TCL_SIZE_T len, size_t *outlen);
static char *encodehex(const char *buf, size_t len);
static char *decodehex(const char *str, size_t *len);
static int parsePhrase(char **inp, char **phrasep, const char *specials);
static int parseDomain(char **inp, char **domainp, char **commentp);
static int parseRoute(char **inp, char **routep);
static char *parseSpace(char *s);
static int parseInt(char *val);

static void dnsInit(const char *name, ...);
static void dnsRecordFree(dnsRecord *pkt);
static void dnsRecordDestroy(dnsRecord **pkt);
static dnsRecord *dnsRecordAppend(dnsRecord **list, dnsRecord *pkt);
static dnsPacket *dnsParseHeader(void *packet, size_t size);
static dnsRecord *dnsParseRecord(dnsPacket *pkt, int query);
static dnsPacket *dnsParsePacket(unsigned char *packet, size_t size);
static int dnsParseName(dnsPacket *pkt, char **ptr, char *buf, int len, int pos, int level);
static void dnsEncodeName(dnsPacket *pkt, const char *name);
static void dnsEncodeGrow(dnsPacket *pkt, size_t size, const char *proc);
static void dnsEncodeHeader(dnsPacket *pkt);
static void dnsEncodePtr(dnsPacket *pkt, int offset);
static void dnsEncodeShort(dnsPacket *pkt, int num);
static void dnsEncodeLong(dnsPacket *pkt, unsigned long num);
static void dnsEncodeData(dnsPacket *pkt, void *ptr, int len);
static void dnsEncodeBegin(dnsPacket *pkt);
static void dnsEncodeEnd(dnsPacket *pkt);
static void dnsEncodeRecord(dnsPacket *pkt, dnsRecord *list);
static void dnsEncodePacket(dnsPacket *pkt);
static void dnsPacketFree(dnsPacket *pkt, int type);
static dnsPacket *dnsLookup(const char *name, unsigned short type, int *errcode);

static Ns_DriverListenProc SmtpdListenProc;
static Ns_DriverAcceptProc SmtpdAcceptProc;
static Ns_DriverRequestProc SmtpdRequestProc;
static Ns_DriverCloseProc SmtpdCloseProc;

static void SmtpdInit(void *arg);
static Ns_TclTraceProc SmtpdInterpInit;
static TCL_OBJCMDPROC_T SmtpdCmd;
static void SmtpdThread(smtpdConn *conn);
static TCL_SIZE_T SmtpdRelayData(smtpdConn *conn, const char *host, unsigned short port);
static Ns_ReturnCode SmtpdSend(smtpdConfig *server, Tcl_Interp *interp, const char *sender,
                               Tcl_Obj *rcptObj, const char *dataVarName,
                               const char *host, unsigned short port);
static smtpdConn *SmtpdConnCreate(smtpdConfig *server, Ns_Sock *sock);
static void SmtpdConnReset(smtpdConn *conn);
static void SmtpdConnFree(smtpdConn *conn);
static void SmtpdConnPrint(smtpdConn *conn);
static void SmtpdRcptFree(smtpdConn *conn, char *addr, int index, unsigned int flags);
static int SmtpdConnEval(smtpdConn *conn, const char *proc);
static void SmtpdConnParseData(smtpdConn *conn);
static const char *SmtpdGetHeader(smtpdConn *conn, const char *name);
#if defined(USE_DSPAM) || defined (USE_SAVI) || defined(USE_CLAMAV)
static void SmtpdConnAddHeader(smtpdConn *conn, char *name, char *value, int alloc);
#endif
static ssize_t SmtpdRecv(Ns_Sock *sock, char *buffer, size_t length, Ns_Time *timeoutPtr, Ns_ReturnCode *rcPtr);
static ssize_t SmtpdRead(smtpdConn *conn, void *vbuf, ssize_t len, Ns_ReturnCode *rcPtr);
static ssize_t SmtpdUnixSend(Ns_Sock *sock, const char *buffer, size_t length);
static ssize_t SmtpdWrite(smtpdConn *conn, const void *vbuf, ssize_t len);
static Ns_ReturnCode SmtpdWriteDString(smtpdConn *conn, Tcl_DString *dsPtr);
static Ns_ReturnCode SmtpdPuts(smtpdConn *conn, const char *string);
static Ns_ReturnCode SmtpdWriteData(smtpdConn *conn, const char *buf, ssize_t len);
static ssize_t SmtpdReadLine(smtpdConn *conn, Tcl_DString *dsPtr, Ns_ReturnCode *rcPtr);
static Ns_ReturnCode SmtpdReadMultiLine(smtpdConn *conn, Tcl_DString *dsPtr, unsigned int *ehloFlagsPtr)
    NS_GNUC_NONNULL(1) NS_GNUC_NONNULL(2);
static void SmtpdJoinMultiLine(Tcl_DString *dsPtr) NS_GNUC_NONNULL(1);

static Ns_ReturnCode SmtpdEHLOCommand(smtpdConn *conn, smtpdConn *relay)
    NS_GNUC_NONNULL(1) NS_GNUC_NONNULL(2);
static Ns_ReturnCode SmtpdAuthPlainCommand(smtpdConn *conn, smtpdConn *relay, const char *user, const char *password)
    NS_GNUC_NONNULL(1) NS_GNUC_NONNULL(2) NS_GNUC_NONNULL(3) NS_GNUC_NONNULL(4);
static bool SmtpLineTrimCR(Tcl_DString *dsPtr) NS_GNUC_NONNULL(1);
static char *SmtpdStrPos(char *as1, const char *as2);
static char *SmtpdStrNPos(char *as1, char *as2, size_t len);
static char *SmtpdStrTrim(char *str);
static smtpdIpaddr *SmtpdParseIpaddr(char *str);
static smtpdIpaddr *SmtpdCheckIpaddr(smtpdIpaddr *list, const char *ipString);
static bool SmtpdCheckDomain(smtpdConn *conn, const char *domain);
static bool SmtpdCheckRelay(smtpdConn *conn, smtpdEmail *addr, char **host, unsigned short *port);
static int SmtpdCheckSpam(smtpdConn *conn);
static int SmtpdCheckVirus(smtpdConn *conn, char *data, TCL_SIZE_T datalen, char *location);
static void SmtpdPanic(const char *fmt, ...);
static void SmtpdSegv(int sig);
static unsigned int SmtpdFlags(const char *name);
static NS_INLINE bool Retry(int errorCode);

static void SmtpdSendLog(smtpdConfig *config, Ns_Time *startTimePtr,
                         const char *sender, Tcl_Obj *rcptObj,
                         const char *host, unsigned short port,
                         const char *status, const char *errorCode, size_t bytesSent)
    NS_GNUC_NONNULL(1) NS_GNUC_NONNULL(2)
    NS_GNUC_NONNULL(3) NS_GNUC_NONNULL(4)
    NS_GNUC_NONNULL(5)
    NS_GNUC_NONNULL(7) NS_GNUC_NONNULL(8);

static Ns_SchedProc SchedLogRollCallback;
static Ns_LogCallbackProc SendLogRoll;
static Ns_LogCallbackProc SendLogOpen;
static Ns_LogCallbackProc SendLogClose;

NS_EXPORT int Ns_ModuleVersion = 1;
NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;

// Free list of connection structures
static smtpdConn *connList = NULL;
static Ns_Mutex connLock;
static int segvTimeout;
static const char hex[] = "0123456789ABCDEF";

// Static DNS stuff
static int dnsDebug = 0;
static unsigned long dnsTTL = 86400;

static Ns_Mutex dnsMutex = NULL;
static dnsServer *dnsServers  = NULL;
static int dnsResolverRetries = 3;
static int dnsResolverTimeout = 5;
static int dnsFailureTimeout  = 300;

// Default port
static const unsigned short DEFAULT_PORT = 25;

static Ns_LogSeverity SmtpdDebug;    /* Severity at which to log verbose debugging. */

NS_EXPORT Ns_ReturnCode Ns_ModuleInit(const char *server, const char *module)
{
    char             *path, *addr2, *portString;
    const char       *addr;
    int               bufsize;
    smtpdRelay       *relay;
    Ns_DriverInitData init = {0};
    smtpdConfig      *serverPtr;
    static bool       initialized = NS_FALSE;

    SmtpdDebug = Ns_CreateLogSeverity("Debug(smtpd)");
    path = ns_strdup(Ns_ConfigGetPath(server, module, (char *)0));

    serverPtr = ns_calloc(1, sizeof(smtpdConfig));

    /*
     * Initialize and name mutexes
     */
    Ns_MutexSetName2(&serverPtr->lock, "smtp:lock", module);
    Ns_MutexSetName2(&serverPtr->relaylock, "smtp:relaylock", module);
    Ns_MutexSetName2(&serverPtr->locallock, "smtp:locallock", module);
    Ns_MutexSetName2(&serverPtr->sendlog.lock, "smtp:sendlog", module);

    if (!initialized) {
        Ns_MutexInit(&dnsMutex);
        Ns_MutexSetName(&dnsMutex, "smtpd:dns");
        Ns_MutexInit(&connLock);
        Ns_MutexSetName(&connLock, "smtpd:connLock");
        initialized = NS_TRUE;
    }

    serverPtr->sendlog.logging = Ns_ConfigBool(path, "logging", NS_FALSE);
    if (serverPtr->sendlog.logging) {
        const char  *filename;
        Tcl_DString  defaultLogFileName;

        Tcl_DStringInit(&defaultLogFileName);
        filename = Ns_ConfigString(path, "logfile", NULL);
        if (filename == NULL) {
            Tcl_DStringAppend(&defaultLogFileName, "smtpsend-", 9);
            Tcl_DStringAppend(&defaultLogFileName, server, TCL_INDEX_NONE);
            Tcl_DStringAppend(&defaultLogFileName, ".log", 4);
            filename = defaultLogFileName.string;
        }

        if (Ns_PathIsAbsolute(filename) == NS_TRUE) {
            serverPtr->sendlog.logFileName = ns_strdup(filename);

        } else {
            Tcl_DString ds;
            Ns_Set     *set;

            Tcl_DStringInit(&ds);
            (void) Ns_HomePath(&ds, "logs", "/", filename, (char *)0L);
            serverPtr->sendlog.logFileName = Ns_DStringExport(&ds);

            /*
             * The path was completed. Make the result queryable.
             */
            set = Ns_ConfigCreateSection(path);
            Ns_SetIUpdateSz(set, "logfile", 7, serverPtr->sendlog.logFileName, TCL_INDEX_NONE);
        }

        Tcl_DStringFree(&defaultLogFileName);

        serverPtr->sendlog.logRollfmt = ns_strcopy(Ns_ConfigGetValue(path, "logrollfmt"));
        serverPtr->sendlog.logMaxbackup = Ns_ConfigIntRange(path, "logmaxbackup",
                                                            100, 1, INT_MAX);
        /*
         *  Schedule various log roll and shutdown options.
         */

        if (Ns_ConfigBool(path, "logroll", NS_TRUE)) {
            int hour = Ns_ConfigIntRange(path, "logrollhour", 0, 0, 23);

            Ns_ScheduleDaily(SchedLogRollCallback, serverPtr,
                             0, hour, 0, NULL);
        }

        if (Ns_ConfigBool(path, "logrollonsignal", NS_FALSE)) {
            Ns_RegisterAtSignal((Ns_Callback *)(ns_funcptr_t)SchedLogRollCallback, serverPtr);
        }


        SendLogOpen(serverPtr);
    }

    serverPtr->deferaccept = Ns_ConfigBool(path, "deferaccept", NS_FALSE);
    serverPtr->nodelay = Ns_ConfigBool(path, "nodelay", NS_FALSE);
    serverPtr->server = server;
    Tcl_InitHashTable(&serverPtr->sessions, TCL_ONE_WORD_KEYS);
    serverPtr->address = ns_strcopy(Ns_ConfigGetValue(path, "address"));

    {
        int i;
        if (Ns_ConfigGetInt(path, "port", &i)) {
            serverPtr->port = (unsigned short) i;
        } else {
            serverPtr->port = DEFAULT_PORT;
        }
    }
    if (!Ns_ConfigGetInt(path, "debug", &serverPtr->debug)) {
        serverPtr->debug = 1;
    }
    if (!Ns_ConfigGetInt(path, "readtimeout", &serverPtr->readtimeout)) {
        serverPtr->readtimeout = 60;
    }
    if (!Ns_ConfigGetInt(path, "writetimeout", &serverPtr->writetimeout)) {
        serverPtr->writetimeout = 60;
    }
    if (!Ns_ConfigGetInt(path, "bufsize", &bufsize)) {
        serverPtr->bufsize = 1024 * 4;
    } else {
        serverPtr->bufsize = (size_t) bufsize;
    }
    if (!Ns_ConfigGetInt(path, "maxrcpt", &serverPtr->maxrcpt)) {
        serverPtr->maxrcpt = 100;
    }
    if (!Ns_ConfigGetInt(path, "maxline", &serverPtr->maxline)) {
        serverPtr->maxline = 4096;
    }
    if (!Ns_ConfigGetInt(path, "maxdata", &serverPtr->maxdata)) {
        serverPtr->maxdata = 1024 * 1024 * 10;
    }
    serverPtr->relayhost = ns_strcopy(Ns_ConfigGetValue(path, "relay"));
    serverPtr->spamdhost = ns_strcopy(Ns_ConfigGetValue(path, "spamd"));
    serverPtr->initproc = ns_strcopy(Ns_ConfigGetValue(path, "initproc"));
    serverPtr->heloproc = ns_strcopy(Ns_ConfigGetValue(path, "heloproc"));
    serverPtr->mailproc = ns_strcopy(Ns_ConfigGetValue(path, "mailproc"));
    serverPtr->rcptproc = ns_strcopy(Ns_ConfigGetValue(path, "rcptproc"));
    serverPtr->dataproc = ns_strcopy(Ns_ConfigGetValue(path, "dataproc"));
    serverPtr->errorproc = ns_strcopy(Ns_ConfigGetValue(path, "errorproc"));
    dnsInit("nameserver", Ns_ConfigGetValue(path, "nameserver"), 0);

#ifdef HAVE_OPENSSL_EVP_H
    serverPtr->certificate = ns_strcopy(Ns_ConfigGetValue(path, "certificate"));
    serverPtr->cafile = ns_strcopy(Ns_ConfigGetValue(path, "cafile"));
    serverPtr->capath = ns_strcopy(Ns_ConfigGetValue(path, "capath"));
    serverPtr->ciphers = ns_strcopy(Ns_ConfigGetValue(path, "ciphers"));
    serverPtr->ciphersuites = ns_strcopy(Ns_ConfigGetValue(path, "ciphersuites"));
    serverPtr->protocols = ns_strcopy(Ns_ConfigGetValue(path, "protocols"));
#endif

    /* Parse flags */
    if ((addr = Ns_ConfigGetValue(path, "flags"))) {
        char *n;

        while (addr) {
            if ((n = strchr(addr, ','))) {
                *n++ = '\0';
            }
            serverPtr->flags |= SmtpdFlags(addr);
            addr = n;
        }
        Ns_Log(Notice, "ns_smtpd: flags = 0x%x", serverPtr->flags);
    }

    /* Add local domains to relay table */
    serverPtr->relaylist = ns_calloc(1, sizeof(smtpdRelay));
    serverPtr->relaylist->name = ns_strdup("localhost");

    {
        const char *host = Ns_InfoHostname();

        while (host != NULL) {
            addr2 = strchr(host, '.');
            if (addr2 != NULL) {
                relay = ns_calloc(1, sizeof(smtpdRelay));
                relay->name = ns_strdup(host);
                relay->next = serverPtr->relaylist;
                serverPtr->relaylist = relay;
                Ns_Log(Notice, "ns_smtpd: adding local relay domain: %s", host);
                addr2++;
            }
            host = addr2;
        }
    }

    /* SMTP relay support */
    serverPtr->relayport = DEFAULT_PORT;

    if (serverPtr->relayhost != NULL) {
        Ns_URL url;
        const char *errorMsg;

        //Ns_Log(Notice, "smtpd relayhost: parseurl '%s'", serverPtr->relayhost);
        (void) Ns_ParseUrl(serverPtr->relayhost, NS_FALSE, &url, &errorMsg);
        //Ns_Log(Notice, "smtpd relayhost: parseurl rc %s %s", Ns_ReturnCodeString(rc), errorMsg);
        if (url.host == NULL && url.protocol != NULL) {
            serverPtr->relayhost = url.protocol;
            if (url.tail != NULL) {
                serverPtr->relayport = (unsigned short) strtol(url.tail, NULL, 10);
            }
            Ns_Log(Notice, "smtpd relayhost: old-style  parameter '%s:%hu'", serverPtr->relayhost, serverPtr->relayport);
        } else {
            if (url.host != NULL) {
                serverPtr->relayhost = url.host;
                if (url.port != NULL) {
                    serverPtr->relayport = (unsigned short) strtol(url.port, NULL, 10);
                }
                Ns_Log(Notice, "smtpd relayhost: new-style parameter '%s:%hu'", serverPtr->relayhost, serverPtr->relayport);
            } else {
                Ns_Log(Notice, "smtpd relayhost: use default port '%s:%hu'", serverPtr->relayhost, serverPtr->relayport);
            }
            if (url.userinfo != NULL) {
                char *p = strchr(url.userinfo, INTCHAR(':'));
                //Ns_Log(Notice, "smtpd relayhost: got userinfo <%s>", url.userinfo);
                serverPtr->relayuser = url.userinfo;
                serverPtr->relaypassword = p+1;
                *p = '\0';
                //Ns_Log(Notice, "smtpd: got user '%s' pw '%s'", serverPtr->relayuser, serverPtr->relaypassword);
                Ns_Log(Notice, "smtpd relayhost: got user and password");
            } else {
                Ns_Log(Notice, "smtpd relayhost: no user and password configured");
            }
        }
    }

    Ns_Log(Notice, "smtpd relayhost: host <%s> port %hu", serverPtr->relayhost, serverPtr->relayport);

    /* SpamAssassin support */
    serverPtr->spamdport = 783;
    if (serverPtr->spamdhost != NULL) {
        char *end;
        Ns_HttpParseHost2(serverPtr->spamdhost, NS_TRUE, &serverPtr->spamdhost, &portString, &end);
        if (portString != NULL) {
            *portString = '\0';
            serverPtr->spamdport = (unsigned short) strtol(portString + 1, NULL, 10);
        }
    }

    /* Register SMTP driver */
#if defined(NS_DRIVER_VERSION_5)
    init.version      = NS_DRIVER_VERSION_5;
#else
    init.version      = NS_DRIVER_VERSION_4;
#endif
    init.name         = "nssmtpd";
    init.listenProc   = SmtpdListenProc;
    init.acceptProc   = SmtpdAcceptProc;
    init.recvProc     = NULL;
    init.sendProc     = NULL;
    init.sendFileProc = NULL;
    init.keepProc     = NULL;
    init.requestProc  = SmtpdRequestProc;
    init.closeProc    = SmtpdCloseProc;
    init.opts         = NS_DRIVER_ASYNC|NS_DRIVER_NOPARSE;
    init.arg          = serverPtr;
    init.path         = path;
    init.protocol     = "smtp";
    init.defaultPort  = DEFAULT_PORT;
#if defined(NS_DRIVER_VERSION_5) && defined(HAVE_OPENSSL_EVP_H)
    init.libraryVersion = ns_strdup(SSLeay_version(SSLEAY_VERSION));
#endif
    if (Ns_DriverInit(server, module, &init) != NS_OK) {
        Ns_Log(Error, "nssmtpd: driver init failed.");
        ns_free(path);
        return NS_ERROR;
    }

    /* Segv/panic handler */
    if ((serverPtr->flags & SMTPD_SEGV) != 0u) {
        if (!Ns_ConfigGetInt(path, "segvtimeout", &segvTimeout)) {
            segvTimeout = -1;
        }
        ns_signal(SIGSEGV, SmtpdSegv);
        Tcl_SetPanicProc(SmtpdPanic);
        Ns_Log(Notice, "nssmtpd: SEGV and Panic trapping is activated for %d seconds", segvTimeout);
    }
#ifdef USE_SAVI
    {
        HRESULT hr;
        CISavi3 *pSAVI;
        U32 version;
        SYSTEMTIME vdlDate;
        U32 detectableViruses;
        OLECHAR versionString[81];
        CISweepClassFactory2 *pFactory;

        // Initialize fake handler to keep all virus data in the memory
        if ((hr = DllGetClassObject((REFIID) & SOPHOS_CLASSID_SAVI, (REFIID) & SOPHOS_IID_CLASSFACTORY2, (void **) &pFactory)) < 0) {
            Ns_Log(Error, "nssmtpd: sophos: Failed to get class factory interface: %x", hr);
            ns_free(path);
            return NS_ERROR;
        }
        if ((hr = pFactory->pVtbl->CreateInstance(pFactory, NULL, (REFIID) & SOPHOS_IID_SAVI3, (void **) &pSAVI)) < 0) {
            pFactory->pVtbl->Release(pFactory);
            Ns_Log(Error, "nssmtpd: sophos: Failed to get a CSAVI3 interface: %x", hr);
            ns_free(path);
            return NS_ERROR;
        }
        pFactory->pVtbl->Release(pFactory);
        if ((hr = pSAVI->pVtbl->InitialiseWithMoniker(pSAVI, "ns_savi")) < 0) {
            Ns_Log(Error, "nssmtpd: sophos: Failed to initialize SAVI: %x", hr);
            pSAVI->pVtbl->Release(pSAVI);
            ns_free(path);
            return NS_ERROR;
        }
        if ((hr = pSAVI->pVtbl->LoadVirusData(pSAVI)) < 0) {
            Ns_Log(Error, "nssmtpd: sophos: Unable to load virus data: %x", hr);
            pSAVI->pVtbl->Terminate(pSAVI);
            pSAVI->pVtbl->Release(pSAVI);
            ns_free(path);
            return NS_ERROR;
        }
        // Engine version
        if (pSAVI->pVtbl->GetVirusEngineVersion(pSAVI,
                                                &version,
                                                versionString,
                                                80,
                                                &vdlDate,
                                                &detectableViruses, NULL, (REFIID) & SOPHOS_IID_ENUM_IDEDETAILS, NULL) >= 0)
            Ns_Log(Notice,
                   "nssmtpd: sophos: Engine version %d.%d %s, Number of detectable viruses: %u, Date of virus data: %d/%d/%d",
                   (int) version >> 16, (int) version & 0x0000FFFF, versionString, (unsigned) detectableViruses,
                   vdlDate.wMonth, vdlDate.wDay, vdlDate.wYear);
    }

#endif

#ifdef USE_CLAMAV
    {
        int rc;
        unsigned int virnum;

        memset(&serverPtr->ClamAvLimits, 0, sizeof(struct cl_limits));
        if (!Ns_ConfigGetInt(path, "clamav_maxfiles", (int*)&serverPtr->ClamAvLimits.maxfiles)) {
            serverPtr->ClamAvLimits.maxfiles = 1000;
        }
        if (!Ns_ConfigGetInt(path, "clamav_maxfilesize", (int*)&serverPtr->ClamAvLimits.maxfilesize)) {
            serverPtr->ClamAvLimits.maxfilesize = 10 * 1048576;
        }
        if (!Ns_ConfigGetInt(path, "clamav_maxreclevel", (int*)&serverPtr->ClamAvLimits.maxreclevel)) {
            serverPtr->ClamAvLimits.maxreclevel = 5;
        }
        if (!Ns_ConfigGetInt(path, "clamav_archivememlim", (int*)&serverPtr->ClamAvLimits.archivememlim)) {
            serverPtr->ClamAvLimits.archivememlim = 0;
        }

        if (!(addr = Ns_ConfigGetValue(path, "clamav_dbdir"))) {
            addr = (char*)cl_retdbdir();
        }
        if ((rc = cl_load(addr, &serverPtr->ClamAvRoot, &virnum, CL_DB_STDOPT)) ||
            (rc = cl_build(serverPtr->ClamAvRoot))) {
            Ns_Log(Error, "nssmtpd: clamav: failed to load db %s: %s", addr, cl_strerror(rc));
        } else {
            Ns_Log(Notice, "nssmtpd: clamav: loaded %u virues", virnum);
        }
    }
#endif

#ifdef USE_DSPAM
    dspam_init_driver();
#endif

    Ns_RegisterAtStartup(SmtpdInit, serverPtr);
    Ns_TclRegisterTrace(server, SmtpdInterpInit, serverPtr, NS_TCL_TRACE_CREATE);
    ns_free(path);

    Ns_Log(Notice, "nssmtpd: version %s loaded", SMTPD_VERSION);

    return NS_OK;
}

static void SmtpdPanic(const char *fmt, ...)
{
    va_list ap;
    time_t now = time(0);

    va_start(ap, fmt);
    Ns_Log(Error, "nssmtpd:[%d]: panic: %s %p %p %p",
           getpid(), fmt, va_arg(ap, void *), va_arg(ap, void *), va_arg(ap, void *));
    va_end(ap);
    while (time(0) - now < segvTimeout) {
        sleep(1);
    }
    kill(getpid(), SIGKILL);
}

static void SmtpdSegv(int UNUSED(sig))
{
    time_t now = time(0);

    Ns_Log(Error, "nssmtpd: SIGSEGV received %d", getpid());
    while (time(0) - now < segvTimeout) {
        sleep(1);
    }
    kill(getpid(), SIGKILL);
}

/*
 *----------------------------------------------------------------------
 *
 * SchedLogRollCallback --
 *
 *      Callback for scheduled procedure to roll the client logfile.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      Rolling the client logfile when configured.
 *
 *----------------------------------------------------------------------
 */

static void

SchedLogRollCallback(void *arg, int UNUSED(id))
{
    smtpdConfig *serverPtr = (smtpdConfig *)arg;

    SendLogRoll(serverPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * SendLogRoll --
 *
 *      Rolling function for the client logfile.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      Rolling the client logfile when configured.
 *
 *----------------------------------------------------------------------
 */
static Ns_ReturnCode
SendLogRoll(void *arg)
{
    Ns_ReturnCode status = NS_OK;
    smtpdConfig *serverPtr = (smtpdConfig *)arg;

    if (serverPtr->sendlog.logging) {
        status = Ns_RollFileCondFmt(SendLogOpen, SendLogClose, serverPtr,
                                    serverPtr->sendlog.logFileName,
                                    serverPtr->sendlog.logRollfmt,
                                    serverPtr->sendlog.logMaxbackup);
    }
    return status;
}

/*
 *----------------------------------------------------------------------
 *
 * SendLogOpen --
 *
 *      Function for opening the send logfile. This function is only called,
 *      when logging is configured.
 *
 * Results:
 *      NS_OK, NS_ERROR
 *
 * Side effects:
 *      Opening the send logfile.
 *
 *----------------------------------------------------------------------
 */
static Ns_ReturnCode
SendLogOpen(void *arg)
{
    Ns_ReturnCode status;
    smtpdConfig *serverPtr = (smtpdConfig *)arg;

    serverPtr->sendlog.fd = ns_open(serverPtr->sendlog.logFileName,
                                     O_APPEND | O_WRONLY | O_CREAT | O_CLOEXEC,
                                     0644);
    if (serverPtr->sendlog.fd == NS_INVALID_FD) {
        Ns_Log(Error, "smtpd:sendlog: error '%s' opening '%s'",
               strerror(errno), serverPtr->sendlog.logFileName);
        status = NS_ERROR;
    } else {
        Ns_Log(Notice, "smtpd:sendlog: logfile '%s' opened",
               serverPtr->sendlog.logFileName);
        status = NS_OK;
    }
    return status;
}

/*
 *----------------------------------------------------------------------
 *
 * SendLogClose --
 *
 *      Function for closing the send logfile when configured.
 *
 * Results:
 *      NS_OK, NS_ERROR
 *
 * Side effects:
 *      Closing the send logfile when configured.
 *
 *----------------------------------------------------------------------
 */
static Ns_ReturnCode
SendLogClose(void *arg)
{
    Ns_ReturnCode status = NS_OK;
    smtpdConfig  *serverPtr = (smtpdConfig *)arg;

    if (serverPtr->sendlog.fd != NS_INVALID_FD) {
        ns_close(serverPtr->sendlog.fd);
        serverPtr->sendlog.fd = NS_INVALID_FD;
        Ns_Log(Notice, "sendfile: logfile '%s' closed",
               serverPtr->sendlog.logFileName);
    }
    return status;
}

/*
 * Add ns_smtpd commands to interp.
 */
static int SmtpdInterpInit(Tcl_Interp *interp, const void *arg)
{
    TCL_CREATEOBJCOMMAND(interp, "ns_smtpd", SmtpdCmd, (ClientData)arg, NULL);
    return TCL_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SmtpdListenProc --
 *
 *      Open a listening TCP socket in nonblocking mode.
 *
 * Results:
 *      The open socket or NS_INVALID_SOCKET on error.
 *
 * Side effects:
 *      Enable TCP_DEFER_ACCEPT if available.
 *
 *----------------------------------------------------------------------
 */

static NS_SOCKET
SmtpdListenProc(Ns_Driver *driver, const char *address, unsigned short port,
                int backlog, bool reuseport)
{
    NS_SOCKET sock;

    sock = Ns_SockListenEx((char*)address, port, backlog, reuseport);
    if (sock != NS_INVALID_SOCKET) {
        smtpdConfig *cfg = driver->arg;

        (void) Ns_SockSetNonBlocking(sock);
        if (cfg->deferaccept != 0) {
#if ((NS_MAJOR_VERSION <= 4) && (NS_MINOR_VERSION <= 99) && (NS_RELEASE_SERIAL <= 19))
            Ns_SockSetDeferAccept(sock, driver->recvwait);
#else
            Ns_SockSetDeferAccept(sock, driver->recvwait.sec);
#endif
        }
    }
    return sock;
}


/*
 *----------------------------------------------------------------------
 *
 * SmtpdCloseProc --
 *
 *      Close the connection socket.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Ignore any errors.
 *
 *----------------------------------------------------------------------
 */

static void
SmtpdCloseProc(Ns_Sock *sock)
{
    NS_NONNULL_ASSERT(sock != NULL);

    if (sock->sock != NS_INVALID_SOCKET) {
        ns_sockclose(sock->sock);
        sock->sock = NS_INVALID_SOCKET;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * SmtpdAcceptProc --
 *
 *      Accept a new socket in nonblocking mode.
 *
 * Results:
 *      possible results:
 *      NS_DRIVER_ACCEPT:       a socket was accepted, poll for data
 *      NS_DRIVER_ACCEPT_DATA:  a socket was accepted, data present, read immediately
 *                      if in async mode, defer reading to connection thread
 *      NS_DRIVER_ACCEPT_QUEUE: a socket was accepted, queue immediately
 *      NS_DRIVER_ACCEPT_ERROR: no socket was accepted
 *
 *     This function returns either NS_DRIVER_ACCEPT_QUEUE or
 *     NS_DRIVER_ACCEPT_ERROR
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static NS_DRIVER_ACCEPT_STATUS
SmtpdAcceptProc(Ns_Sock *sock, NS_SOCKET listensock, struct sockaddr *sockaddrPtr, socklen_t *socklenPtr)
{
    NS_DRIVER_ACCEPT_STATUS status = NS_DRIVER_ACCEPT_ERROR;

    /*
     * This function is essentially copied from nssocket.c but returns
     * on success NS_DRIVER_ACCEPT_QUEUE.
     */

    sock->sock = Ns_SockAccept(listensock, sockaddrPtr, socklenPtr);
    if (sock->sock != NS_INVALID_SOCKET) {

#ifdef __APPLE__
      /*
       * Darwin's poll returns per default writable in situations,
       * where nothing can be written.  Setting the socket option for
       * the send low watermark to 1 fixes this problem.
       */
        int value = 1;
        setsockopt(sock->sock, SOL_SOCKET,SO_SNDLOWAT, &value, sizeof(value));
#endif
        status = NS_DRIVER_ACCEPT_QUEUE;
    }
    return status;
}
/*
 *----------------------------------------------------------------------
 *
 * SmtpdRequestProc --
 *
 *      Process an SMTP request. This proc starts a thread for handling
 *      the request.
 *
 * Results:
 *      NS_OK
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static Ns_ReturnCode SmtpdRequestProc(void *arg, Ns_Conn *conn)
{
  smtpdConfig *server = arg;

  Ns_Log(SmtpdDebug, "SmtpdRequestProc");

  SmtpdThread(SmtpdConnCreate(server, Ns_ConnSockPtr(conn)));
  return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SmtpdInit --
 *
 *      Initialize Smtpd via Tcl script
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */
static void SmtpdInit(void *arg)
{
    smtpdConfig *server = arg;

    Ns_Log(SmtpdDebug,"SmtpdInit");

    if (server->initproc) {
        Ns_TclEval(0, server->server, server->initproc);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * SmtpdThread --
 *
 *      Process an Smtpd connection. This thread implements the main
 *      Smtpd logic.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */
static void SmtpdThread(smtpdConn *conn)
{
    char *data;
    Ns_Conn *nsconn = Ns_GetConn();
    smtpdConfig *config = conn->config;
    Ns_ReturnCode rc = TCL_OK;

    Ns_ThreadSetName("-nssmptd:%ld-", conn->id);
    Ns_Log(SmtpdDebug,"SmtpdThread");

    Ns_GetHostByAddr(&conn->line, Ns_ConnPeerAddr(nsconn));
    if ((conn->line.length) > 0 && (conn->flags & SMTPD_RESOLVE) != 0u) {
        SmtpdPuts(conn, "421 Service not available, could not resolve the hostname");
        SmtpdConnFree(conn);
        return;
    }
    if (!(conn->interp = Ns_GetConnInterp(nsconn))) {
        Ns_Log(Error, "nssmtpd: %ld: Conn/Tcl interp error: %s", conn->id, strerror(errno));
        SmtpdPuts(conn, "421 Service not available, internal error");
        SmtpdConnFree(conn);
        return;
    }

    conn->host = ns_strdup(conn->line.string);
    Ns_MutexLock(&config->locallock);
    if (SmtpdCheckIpaddr(config->local, Ns_ConnPeerAddr(nsconn))) {
        conn->flags |= SMTPD_LOCAL;
    }
    Ns_MutexUnlock(&config->locallock);
    /* Our greeting message */
    Tcl_DStringSetLength(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "220 %s SMTP nssmtpd %s ", Ns_InfoHostname(), SMTPD_VERSION);
    Ns_HttpTime(&conn->line, 0);
    Tcl_DStringAppend(&conn->line, "\r\n", 2);
    if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
        goto error;
    }

    //Ns_Log(SmtpdDebug, "SmtpdThread: %s", conn->line.string);

    while (1) {
        conn->cmd = SMTP_READ;
        if (SmtpdReadLine(conn, &conn->line, &rc) < 0) {
            goto error;
        }
        Tcl_DStringSetLength(&conn->reply, 0);
        Ns_StrToLower(conn->line.string);
        Ns_StrTrim(conn->line.string);
        conn->line.length = (int)strlen(conn->line.string);

        Ns_Log(SmtpdDebug, "SmtpdThread got cmd <%s>", conn->line.string);

        if (!strncasecmp(conn->line.string, "QUIT", 4)) {
            conn->cmd = SMTP_QUIT;
            SmtpdPuts(conn, "221 Bye\r\n");
            break;
        }

        if (!strncasecmp(conn->line.string, "NOOP", 4)) {
            conn->cmd = SMTP_NOOP;
            if (SmtpdPuts(conn, "250 Noop OK\r\n") != NS_OK) {
                goto error;
            }
            continue;
        }

        if (!strncasecmp(conn->line.string, "VRFY", 4)) {
            conn->cmd = SMTP_VRFY;
            if (SmtpdPuts(conn, "252 Cannot VRFY\r\n") != NS_OK) {
                goto error;
            }
            continue;
        }

        if (!strncasecmp(conn->line.string, "HELP", 4)) {
            Tcl_DString ds;

            conn->cmd = SMTP_HELP;
            Tcl_DStringInit(&ds);
            Ns_DStringPrintf(&ds, "214- This is nssmtpd version %s\r\n", SMTPD_VERSION);
            Ns_DStringPrintf(&ds, "214- Supported commands:\r\n");
            Ns_DStringPrintf(&ds, "214-  HELO    EHLO    MAIL    RCPT    DATA\r\n");
            Ns_DStringPrintf(&ds, "214-  RSET    NOOP    QUIT    HELP    VRFY\r\n");
            Ns_DStringPrintf(&ds, "214 End of HELP info\r\n");
            if (SmtpdPuts(conn, ds.string) != NS_OK) {
                goto error;
            }
            Tcl_DStringFree(&ds);
            continue;
        }

        if (!strncasecmp(conn->line.string, "HELO", 4) || !strncasecmp(conn->line.string, "EHLO", 4)) {
            conn->cmd = SMTP_HELO;
            /* Duplicate HELO RFC 1651 4.2 */
            if ((conn->flags & SMTPD_GOTHELO) != 0u) {
                if (SmtpdPuts(conn, "501 Duplicate HELO\r\n") != NS_OK) {
                    goto error;
                }
                continue;
            }
            data = &conn->line.string[5];
            while (*data && isspace(*data))
                data++;
            /* Check for bogus domain name RFC 1123 5.2.5 */
            if (strpbrk(data, " []/@#$%^&*()=+~'{}|<>?\\\",") || strchr("_-.", data[0])) {
                if (SmtpdPuts(conn, "501 Invalid domain\r\n") != NS_OK) {
                    goto error;
                }
                continue;
            }
            /* Call Tcl callback */
            if (SmtpdConnEval(conn, config->heloproc) != TCL_OK) {
                if (SmtpdPuts(conn, "421 Service not available\r\n") != NS_OK) {
                    goto error;
                }
            }
            /* Callback might set its own reply code */
            if (conn->reply.length) {
                if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                    goto error;
                }
            } else {
                if (!strncasecmp(conn->line.string, "HELO", 4)) {
                    if (SmtpdPuts(conn, "250 HELO OK\r\n") != NS_OK) {
                        goto error;
                    }
                } else {
                    Tcl_DStringInit(&conn->line);
                    Ns_DStringPrintf(&conn->line, "250-%s\r\n", Ns_InfoHostname());
                    Ns_DStringPrintf(&conn->line, "250-SIZE %d\r\n", config->maxdata);
#ifdef HAVE_OPENSSL_EVP_H
                    if ((conn->flags & SMTPD_GOTSTARTTLS) == 0u) {
                        Ns_DStringPrintf(&conn->line, "250-STARTTLS\r\n");
                    }
#endif
                    Ns_DStringPrintf(&conn->line, "250-8BITMIME\r\n");
                    Ns_DStringPrintf(&conn->line, "250 HELP\r\n");
                    if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
                        goto error;
                    }
                }
            }
            if ((conn->flags & SMTPD_ABORT) != 0u) {
                break;
            }
            conn->flags |= SMTPD_GOTHELO;
            continue;
        }

#ifdef HAVE_OPENSSL_EVP_H
        if (!strncasecmp(conn->line.string, "STARTTLS", 8)) {
            NS_TLS_SSL_CTX *ctx;
            NS_TLS_SSL *ssl;
            int result;

            conn->cmd = SMTP_STARTTLS;

            if (SmtpdPuts(conn, "220 Go Ahead\r\n") != NS_OK) {
                goto error;
            }

            result = Ns_TLS_CtxServerCreate(
                conn->interp,
                conn->config->certificate,
                conn->config->cafile,
                conn->config->capath,
                0 /*verify*/,
                conn->config->ciphers,
                conn->config->ciphersuites,
                conn->config->protocols,
                &ctx);
            Ns_Log(SmtpdDebug, "STARTTLS-tls-server-create result=%d", result);

            if (likely(result == TCL_OK)) {
                /*
                 * Establish the SSL/TLS connection.
                 */
                result = Ns_TLS_SSLAccept(conn->interp, conn->sock->sock, ctx, &ssl);
                Ns_Log(SmtpdDebug, "STARTTLS-ssl-accept result=%d", result);
                if (result != TCL_OK) {
                    Ns_Log(SmtpdDebug, "STARTTLS-ssl-accept failed");
                    goto error;
                }
                conn->sock->arg = ssl;
            } else {
                goto error;
            }
            Ns_Log(SmtpdDebug, "STARTTLS-ssl-command result=%d", result);

            conn->flags &= ~(SMTPD_GOTHELO);
            conn->flags |= (SMTPD_GOTSTARTTLS);

            continue;
        }
#endif

        if (!strncasecmp(conn->line.string, "RSET", 4)) {
            conn->cmd = SMTP_RSET;
            SmtpdConnReset(conn);
            if (SmtpdPuts(conn, "250 Reset OK\r\n") != NS_OK) {
                goto error;
            }
            continue;
        }

        if (!strncasecmp(conn->line.string, "MAIL FROM:", 10)) {
            conn->cmd = SMTP_MAIL;
            /* Duplicate MAIL */
            if ((conn->flags & SMTPD_GOTMAIL) != 0u) {
                if (SmtpdPuts(conn, "501 Duplicate MAIL\r\n") != NS_OK) {
                    goto error;
                }
                continue;
            }
            /* HELO is required */
            if ((config->flags & SMTPD_NEEDHELO) != 0u
                && (conn->flags & SMTPD_GOTHELO) == 0u
                ) {
                if (SmtpdPuts(conn, "503 Need HELO or EHLO\r\n") != NS_OK) {
                    goto error;
                }
                continue;
            }
            SmtpdConnReset(conn);
            /* Check for optional SIZE parameter */
            if ((data = SmtpdStrPos(&conn->line.string[10], " SIZE="))) {
                if (atoi(data + 6) > config->maxdata) {
                    if (SmtpdPuts(conn, "552 Too much mail data\r\n") != NS_OK) {
                        goto error;
                    }
                    SmtpdConnReset(conn);
                    continue;
                }
                *data = '\0';
            }
            data = Ns_StrTrim(&conn->line.string[10]);
            /* Email address verification */
            if (!strcmp(data, "<>") || !strcasecmp(data, "postmaster"))
                conn->from.addr = ns_strdup(data);
            else {
                smtpdEmail addr;
                /* Prepare error reply because address parser modifies the buffer */
                Ns_DStringPrintf(&conn->reply, "553 %s... Address unrecognized\r\n", data);
                if (parseEmail(&addr, data)) {
                    Tcl_DStringSetLength(&conn->reply, 0);
                    if (SmtpdCheckDomain(conn, addr.domain)) {
                        conn->from.addr = ns_malloc(strlen(addr.mailbox) + strlen(addr.domain) + 2);
                        sprintf(conn->from.addr, "%s@%s", addr.mailbox, addr.domain);
                        Ns_StrToLower(conn->from.addr);
                    }
                }
            }
            if (!conn->from.addr) {
                if (!conn->reply.length) {
                    Ns_DStringPrintf(&conn->reply, "553 %s... Address unrecognized\r\n", data);
                }
                if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                    goto error;
                }
                continue;
            }
            /* Call Tcl callback */
            if (SmtpdConnEval(conn, config->mailproc) != TCL_OK) {
                if (SmtpdPuts(conn, "421 Service not available\r\n") != NS_OK) {
                    goto error;
                }
                break;
            }
            /* Callback might set its own reply code */
            if (!conn->reply.length) {
                Ns_DStringPrintf(&conn->reply, "250 %s... Sender OK\r\n", conn->from.addr);
            }
            if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                goto error;
            }
            if ((conn->flags & SMTPD_ABORT) != 0u) {
                break;
            }
            conn->flags |= SMTPD_GOTMAIL;
            continue;
        }

        if (!strncasecmp(conn->line.string, "RCPT TO:", 8)) {
            char          *host = NULL;
            smtpdRcpt     *rcpt;
            smtpdEmail     addr;
            unsigned short port = 0u;
            unsigned int   flags = 0u;

            conn->cmd = SMTP_RCPT;
            if ((conn->flags & SMTPD_GOTMAIL) == 0u) {
                if (SmtpdPuts(conn, "503 Need MAIL before RCPT\r\n") != NS_OK) {
                    goto error;
                }
                continue;
            }
            if (conn->rcpt.count >= config->maxrcpt) {
                if (SmtpdPuts(conn, "452 Too many recipients\r\n") != NS_OK) {
                    goto error;
                }
                continue;
            }
            data = &conn->line.string[8];
            while (*data && isspace(*data)) {
                data++;
            }
            /* Prepare error reply because address parser modifies the buffer */
            Ns_DStringPrintf(&conn->reply, "553 %s... Address unrecognized\r\n", data);
            /* Email address verification */
            if (parseEmail(&addr, data)) {
                Tcl_DStringSetLength(&conn->reply, 0);
                /* Check for allowed for relaying domains */
                if (SmtpdCheckRelay(conn, &addr, &host, &port)) {
                    flags |= SMTPD_RELAY;

                } else if ((conn->flags & SMTPD_LOCAL) == 0u) {
                    Ns_DStringPrintf(&conn->reply, "550 %s@%s... Relaying denied\r\n", addr.mailbox, addr.domain);
                    Ns_Log(Error, "nssmtpd: %ld: HOST: %s/%s, RCPT: %s@%s, Relaying denied",
                           conn->id, conn->host, Ns_ConnPeerAddr(nsconn), addr.mailbox, addr.domain);
                    if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                        goto error;
                    }
                    continue;
                }
                data = ns_malloc(strlen(addr.mailbox) + strlen(addr.domain) + 2);
                sprintf(data, "%s@%s", addr.mailbox, addr.domain);
                Ns_StrToLower(data);
            } else {
                if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                    goto error;
                }
                continue;
            }
            /* Save address, it might be modified by verification routine */
            rcpt = ns_calloc(1, sizeof(smtpdRcpt));
            rcpt->flags = flags;
            rcpt->addr = data;
            rcpt->relay.host = host;
            rcpt->relay.port = port;
            rcpt->next = conn->rcpt.list;
            conn->rcpt.list = rcpt;
            if (rcpt->next) {
                rcpt->next->prev = rcpt;
            }
            conn->rcpt.count++;
            /* Call Tcl callback */
            if (SmtpdConnEval(conn, config->rcptproc) != TCL_OK) {
                SmtpdPuts(conn, "421 Service not available\r\n");
                break;
            }
            /* Callback might set its own reply code */
            if (!conn->reply.length) {
                Ns_DStringPrintf(&conn->reply, "250 %s... Recipient OK\r\n", data);
            }
            if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                goto error;
            }
            if ((conn->flags & SMTPD_ABORT) != 0u) {
                break;
            }
            continue;
        }

        if (!strncasecmp(conn->line.string, "DATA", 4)) {
            TCL_SIZE_T size = -1;
            smtpdRcpt *rcpt;

            conn->cmd = SMTP_DATA;
            if (!conn->rcpt.list) {
                if (SmtpdPuts(conn, "503 Need RCPT (recipient)\r\n") != NS_OK) {
                    goto error;
                }
                continue;
            }
            /* RelayHost verified recipients to remote SMTPD server and queue others */
            Ns_Log(SmtpdDebug, "DATA relayhost <%s>", config->relayhost);
            if (config->relayhost != NULL) {
                for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
                    Ns_Log(SmtpdDebug, "DATA check rcpt <%s> %s %d -> verified %d", rcpt->addr, rcpt->relay.host, rcpt->relay.port,
                           rcpt->flags & SMTPD_VERIFIED);
                    if ((rcpt->flags & SMTPD_VERIFIED) != 0u) {
                        break;
                    }
                }
                Ns_Log(SmtpdDebug, "DATA rcpt <%p>", (void*)rcpt);

                if (rcpt != NULL
                    && (size = SmtpdRelayData(conn, rcpt->relay.host, rcpt->relay.port)) < 0) {
                    Ns_Log(SmtpdDebug, "SmtpdRelayData failed");
                    goto done;
                }
            }
            // Still data has not been read yet
            if (size == -1) {
                if (SmtpdPuts(conn, "354 Start mail input; end with <CRLF>.<CRLF>\r\n") != NS_OK) {
                    break;
                }
                do {
                    if (SmtpdReadLine(conn, &conn->line, &rc) < 0) {
                        goto error;
                    }
                    /* Remove trailing dot sender the data buffer */
                    if (!strcmp(conn->line.string, ".\r\n")) {
                        Tcl_DStringSetLength(&conn->line, conn->line.length - 3);
                        break;
                    }
                    size += conn->line.length;
                    if (size < config->maxdata) {
                        Tcl_DStringAppend(&conn->body.data, conn->line.string, conn->line.length);
                    }
                } while (conn->line.length > 0);
            }
            /* Maximum data limit reached */
            if (size > config->maxdata) {
                if (SmtpdPuts(conn, "552 Too much mail data\r\n") != NS_OK) {
                    goto error;
                }
                SmtpdConnReset(conn);
                continue;
            }
            /* Quick headers scan */
            SmtpdConnParseData(conn);
            /* SPAM checks */
            SmtpdCheckSpam(conn);
            /* Call Tcl callback */
            if (SmtpdConnEval(conn, config->dataproc) != TCL_OK) {
                SmtpdPuts(conn, "421 Service not available\r\n");
                break;
            }
            /* Callback might set its own reply code */
            if (!conn->reply.length) {
                Tcl_DStringAppend(&conn->reply, "250 Message accepted\r\n", 22);
            }
            /* No reply in relay mode */
            if (config->relayhost) {
                for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
                    if ((rcpt->flags & SMTPD_VERIFIED) == 0u) {
                        break;
                    }
                }
                if (!rcpt) {
                    Tcl_DStringSetLength(&conn->reply, 0);
                }
            }
            if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                goto error;
            }
            if ((conn->flags & SMTPD_ABORT) != 0u) {
                break;
            }
            SmtpdConnPrint(conn);
            SmtpdConnReset(conn);
            continue;
        }
        if (SmtpdPuts(conn, "500 Command unrecognized\r\n") != NS_OK) {
            goto error;
        }
    }
  done:
    SmtpdConnFree(conn);
    return;
  error:
    switch (errno) {
    case EINTR:
    case EAGAIN:
    case 0:
        break;
    default:
        Ns_Log(Error, "nssmtpd: %ld/%d: HOST: %s/%s, I/O error: %d/%d: %s: %s",
               conn->id, getpid(), conn->host, Ns_ConnPeerAddr(nsconn),
               conn->sock->sock, conn->cmd, strerror(errno), conn->line.string);
    }
    SmtpdConnFree(conn);
}

static smtpdConn *SmtpdConnCreate(smtpdConfig *config, Ns_Sock *sock)
{
    smtpdConn     *conn;
    Tcl_HashEntry *rec;
    int            new;

    Ns_Log(SmtpdDebug,"SmtpdConnCreate");

    Ns_MutexLock(&connLock);
    conn = connList;
    if (conn != NULL) {
        connList = connList->next;
    }
    Ns_MutexUnlock(&connLock);

    /* Brand new connection structure */
    if (conn == NULL) {
        conn = ns_calloc(1, sizeof(smtpdConn) + config->bufsize + 1);
        conn->config = config;
        conn->flags = config->flags;
        Tcl_DStringInit(&conn->line);
        Tcl_DStringInit(&conn->reply);
        Tcl_DStringInit(&conn->body.data);
    }
    Ns_CloseOnExec(sock->sock);
    Ns_SockSetNonBlocking(sock->sock);

    conn->sock = sock;
    conn->sock->arg = NULL;
    conn->flags = config->flags;

    Ns_MutexLock(&config->lock);
    conn->id = config->id++;
    rec = Tcl_CreateHashEntry(
                              &config->sessions,
                              (char *) (long)conn->id,
                              &new);
    Tcl_SetHashValue(rec, conn);
    Ns_MutexUnlock(&config->lock);

    return conn;
}

static void
SmtpdConnReset(smtpdConn *conn)
{
    //Ns_Log(SmtpdDebug,"SmtpdConnReset");

    // Default global flags
    conn->flags &= ~(SMTPD_GOTMAIL);
    ns_free(conn->from.addr), conn->from.addr = NULL;
    ns_free((char *)conn->from.data), conn->from.data = NULL;
    Tcl_DStringSetLength(&conn->line, 0);
    Tcl_DStringSetLength(&conn->reply, 0);
    Tcl_DStringSetLength(&conn->body.data, 0);

    while (conn->body.headers) {
        smtpdHdr *next = conn->body.headers->next;
        ns_free(conn->body.headers->name);
        ns_free(conn->body.headers->value);
        ns_free(conn->body.headers);
        conn->body.headers = next;
    }
    conn->body.offset = 0;

    while (conn->rcpt.list) {
        smtpdRcpt *next = conn->rcpt.list->next;
        ns_free((char*)conn->rcpt.list->addr);
        ns_free((char*)conn->rcpt.list->data);
        ns_free((char*)conn->rcpt.list->relay.host);
        ns_free(conn->rcpt.list);
        conn->rcpt.list = next;
    }
    conn->rcpt.count = 0;
}

static void SmtpdConnPrint(smtpdConn *conn)
{
    Ns_Conn *nsconn;
    smtpdRcpt *rcpt;

    Ns_Log(SmtpdDebug,"SmtpdConnPrint");

    if (conn->config->debug < 1) {
        return;
    }
    nsconn = Ns_GetConn();
    Tcl_DStringSetLength(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "nssmtpd: %ld/%d: HOST: %s/%s",
                     conn->id, getpid(), conn->host, Ns_ConnPeerAddr(nsconn));
    Ns_DStringPrintf(&conn->line, ", FLAGS: 0x%X, FROM: %s, RCPT: ", conn->flags, conn->from.addr);
    for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
        Ns_DStringPrintf(&conn->line, "%s(0x%X/%.2f), ", rcpt->addr, rcpt->flags, rcpt->spam_score);
    }
    Ns_DStringPrintf(&conn->line, "SIZE: %lu/%lu", (unsigned long)conn->body.data.length, conn->body.offset);
    Ns_Log(Notice, "%s", conn->line.string);

    /*
     * Update request line for access logging
     */
    Tcl_DStringSetLength(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "SEND /%s SMTP/1.0", conn->from.addr ? conn->from.addr : "Null");
    for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
        Ns_DStringPrintf(&conn->line, "/%s", rcpt->addr);
    }
    ns_free((char *)nsconn->request.line);
    nsconn->request.line = ns_strdup(conn->line.string);
}

static int SmtpdConnEval(smtpdConn *conn, const char *proc)
{
    char name[256];

    Ns_Log(SmtpdDebug, "--- SmtpdConnEval <%s>", proc);
    Tcl_DStringSetLength(&conn->reply, 0);
    if (!proc || !*proc) {
        return TCL_OK;
    }
    snprintf(name, sizeof(name), "%s %lu", proc, conn->id);
    if (Tcl_Eval(conn->interp, name) == TCL_ERROR) {
        (void) Ns_TclLogErrorInfo(conn->interp, "\n(context: smtpd eval)");
        return TCL_ERROR;
    }
    return TCL_OK;
}

static void SmtpdConnFree(smtpdConn *conn)
{
    Tcl_HashEntry *rec;

    //Ns_Log(SmtpdDebug,"SmtpdConnFree");

    if (!conn) {
        return;
    }
    Ns_MutexLock(&conn->config->lock);
    if ((rec = Tcl_FindHashEntry(&conn->config->sessions, (char *)(long) conn->id))) {
        Tcl_DeleteHashEntry(rec);
    }
    Ns_MutexUnlock(&conn->config->lock);
    ns_sockclose(conn->sock->sock);
    conn->sock->sock = -1;
    SmtpdConnReset(conn);
    ns_free((char *)conn->host);
    conn->host = NULL;
    conn->buf.ptr = NULL;
    conn->buf.pos = 0;

    Ns_MutexLock(&connLock);
    conn->next = connList;
    connList = conn;
    Ns_MutexUnlock(&connLock);
}

/*
 *----------------------------------------------------------------------
 *
 * SmtpdEHLOCommand --
 *
 *      Sends an EHLO command over the relay connection and parses the relay's
 *      response to determine the capabilities of the SMTP relay. The function
 *      builds the EHLO command using the local hostname, sends it via the
 *      relay, and reads back the response lines. It scans the response for
 *      the keywords "STARTTLS" and "AUTH" (specifically the "PLAIN"
 *      mechanism) to set corresponding flags in the relay connection.
 *
 * Results:

 *      Returns NS_OK if the EHLO command was successfully processed and the relay's
 *      responses were acceptable. Otherwise, it returns NS_ERROR or NS_FILTER_BREAK
 *      to indicate an unsuccsessful response.
 *
 * Side Effects:
 *      - Modifies the connection's and relay's line buffers.
 *      - Updates the relay's flags (SMTPD_GOTSTARTTLS and SMTPD_GOTAUTHPLAIN)
 *        based on the relay's response vi SmtpdReadMultiLine();
 *
 *----------------------------------------------------------------------
 */
static Ns_ReturnCode
SmtpdEHLOCommand(smtpdConn *conn, smtpdConn *relay) {
    Ns_ReturnCode result = NS_OK;
    /*
     * EHLO command
     */
    Ns_Log(SmtpdDebug,"before sending EHLO, have flags %.8x", relay->flags);

    Tcl_DStringSetLength(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "EHLO %s\r\n", Ns_InfoHostname());
    if (SmtpdWriteDString(relay, &conn->line) != NS_OK
        || SmtpdReadMultiLine(relay, &relay->line, &relay->flags) != NS_OK) {
        result = NS_ERROR;

    } else if (relay->line.string[0] != '2') {
        result =  NS_FILTER_BREAK;

    } else {
        Ns_Log(SmtpdDebug,"after sending EHLO, have flags %.8x", relay->flags);
    }
    return result;
}

/*
 *----------------------------------------------------------------------
 *
 * SmtpdAuthPlainCommand --
 *
 *      This function implements the SMTP AUTH PLAIN command. It constructs a
 *      raw authentication message by concatenating a leading NUL byte, the
 *      username, another NUL byte, and the password base64-encoded.  The
 *      function sends the "AUTH PLAIN <encoded>" command it to the relay
 *      connection, and reads the multi-line response.
 *
 * Results:
 *      Returns NS_OK if the relay returns a successful response (i.e. a response
 *      code starting with '2'). Otherwise, it returns NS_ERROR or NS_FILTER_BREAK
 *      to indicate an authentication failure.
 *
 * Side Effects:
 *      - Modifies the connection's command line buffer to contain the AUTH PLAIN
 *        command.
 *      - Communicates with the relay via SmtpdWriteDString() and SmtpdReadMultiLine().
 *
 *----------------------------------------------------------------------
 */
static Ns_ReturnCode
SmtpdAuthPlainCommand(smtpdConn *conn, smtpdConn *relay, const char *user, const char *password) {
    TCL_SIZE_T  user_len = (TCL_SIZE_T)strlen(user);
    TCL_SIZE_T  password_len = (TCL_SIZE_T)strlen(password);
    Tcl_DString authinfoDS, encodedDs;
    size_t      encoded_len;

    Tcl_DStringInit(&authinfoDS);
    Tcl_DStringInit(&encodedDs);

    /*
     * Construct the raw authentication message consisting of a leading NUL,
     * the username, another NUL, and the password. The message consists of
     * exactly rawlen bytes; no extra null terminator is needed.
     */
    Tcl_DStringAppend(&authinfoDS, "", 1);
    Tcl_DStringAppend(&authinfoDS, user, user_len);
    Tcl_DStringAppend(&authinfoDS, "", 1);
    Tcl_DStringAppend(&authinfoDS, password, password_len);

#if 0
    {
            /* Show the raw identification data as hex for debugging */
            TCL_SIZE_T  rawlen = 1 + user_len + 1 + password_len;
            Tcl_DStringSetLength(&encodedDs, authinfoDS.length*2 + 1);
            Ns_HexString((const unsigned char *)authinfoDS.string, encodedDs.string, authinfoDS.length, NS_FALSE);
            Ns_Log(Notice, "raw_len %d authinfo.len %d hex <%s>", rawlen, authinfoDS.length, encodedDs.string);
    }
#endif

    /*
     * Base64-encode the authentication message.
     */
    Tcl_DStringSetLength(&encodedDs, MAX(4, (authinfoDS.length * 4/3) + 4));
    encoded_len = Ns_Base64Encode((const unsigned char *)authinfoDS.string, (size_t)authinfoDS.length, encodedDs.string, 0, 0);
    Tcl_DStringSetLength(&encodedDs, (TCL_SIZE_T)encoded_len);
    //Ns_Log(Notice, "enc_len %ld encodedDs.len %d base64 <%s>", encoded_len, encodedDs.length, encodedDs.string);

    /*
     * Build the AUTH PLAIN command: "AUTH PLAIN <encoded>\r\n"
     */
    Tcl_DStringSetLength(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "AUTH PLAIN %s\r\n", encodedDs.string);

    Tcl_DStringFree(&authinfoDS);
    Tcl_DStringFree(&encodedDs);

    /* Send the command to the relay */
    if (SmtpdWriteDString(relay, &conn->line) != NS_OK
        || SmtpdReadMultiLine(relay, &relay->line, NULL) != NS_OK) {
        return NS_ERROR;

    } else {
        Ns_Log(SmtpdDebug, "SmtpdAuthPlainCommand response:\n%s", relay->line.string);
        return (relay->line.string[0] != '2' ? NS_FILTER_BREAK : NS_OK);
    }
}

static TCL_SIZE_T
SmtpdRelayData(smtpdConn *conn, const char *host, unsigned short port)
{
    Ns_Sock       sock;
    smtpdRcpt    *rcpt;
    smtpdConn    *relay;
    Ns_Time       timeout = { conn->config->writetimeout, 0 };
    TCL_SIZE_T    size = 0;
    int           vcount = 0;
    Ns_Conn      *nsconn = Ns_GetConn();
    Ns_ReturnCode rc = NS_OK;

    Ns_Log(SmtpdDebug, "SmtpdRelayData");

    /*
     * If we have single recipient, use recipient's relay otherwise for
     * different recipients use default relay.
     */
    for (rcpt = conn->rcpt.list; host != NULL && rcpt != NULL; rcpt = rcpt->next) {
        if ((rcpt->flags & SMTPD_VERIFIED) != 0u
            && rcpt->relay.host != NULL
            && strcmp(rcpt->relay.host, host)
            ) {
            Ns_Log(SmtpdDebug,"SmtpdRelayData set HOST NULL relay.host '%s' provide host '%s'", rcpt->relay.host, host);
            host = NULL;
            break;
        }
    }
    if (!host) {
        host = conn->config->relayhost;
        port = conn->config->relayport;
        Ns_Log(SmtpdDebug,"SmtpdRelayData set host from config %s:%hu", host, port);
    }
    if (!port) {
        port = DEFAULT_PORT;
    }

    Ns_Log(SmtpdDebug,"SmtpdRelayData connect %s:%hu with timeout " NS_TIME_FMT "s",
           host, port, (int64_t)timeout.sec, timeout.usec);

    if ((sock.sock = Ns_SockTimedConnect2(host, port, NULL, 0, &timeout, &rc)) == NS_INVALID_SOCKET) {
        Ns_Log(SmtpdDebug,"SmtpdRelayData connect returns invalid socket (%s)", Ns_ReturnCodeString(rc));
        Ns_Log(Error, "nssmtpd: relay: %lu/%d: Unable to connect to %s:%d: %s",
               conn->id, getpid(), host, port, rc == NS_TIMEOUT ? "timeout" : strerror(errno));
        SmtpdPuts(conn, "421 Service not available\r\n");
        return -1;
    }

    Ns_Log(SmtpdDebug,"SmtpdRelayData connect with timeout %s:%hu " NS_TIME_FMT "s returned %s",
           host, port, (int64_t)timeout.sec, timeout.usec, Ns_ReturnCodeString(rc));

    sock.driver = conn->sock->driver;

    Ns_Log(SmtpdDebug,"SmtpdRelayData create connection");

    /*
     * Allocate relay SMTPD connection
     */
    if (!(relay = SmtpdConnCreate(conn->config, &sock))) {
        ns_sockclose(sock.sock);
        SmtpdPuts(conn, "421 Service not available\r\n");
        return -1;
    }

    /*
     * Read greeting line from the relay
     */
    Ns_Log(SmtpdDebug,"SmtpdRelayData read greeting");

    if (SmtpdReadLine(relay, &relay->line, &rc) < 0) {
        Ns_Log(Error, "nssmtpd: relay: %lu/%d: %s:%d: Greeting read error: %s",
               conn->id, getpid(), host, port, strerror(errno));
        SmtpdConnFree(relay);
        SmtpdPuts(conn, "421 Service not available\r\n");
        return -1;
    }
    Ns_Log(SmtpdDebug,"SmtpdRelayData got greeting, send now EHLO");

    /*
     * EHLO command
     */
    relay->flags |= SMTPD_GOTSTARTTLS;
    rc = SmtpdEHLOCommand(conn, relay);
    if (rc == NS_ERROR) {
        goto error421;
    } else if (rc != NS_OK) {
        goto errorrelay;
    }

    /*
     * If STARTTLS is offered, and OpenSSL is available, attempt TLS
     * connection..
     */
#ifdef HAVE_OPENSSL_EVP_H
    if ((relay->flags & SMTPD_GOTSTARTTLS) != 0) {
        NS_TLS_SSL_CTX *ctx;
        NS_TLS_SSL     *ssl;
        int             result;

        Tcl_DStringSetLength(&conn->line, 0);
        Ns_DStringPrintf(&conn->line, "STARTTLS\r\n");
        if (SmtpdWriteDString(relay, &conn->line) != NS_OK) {
            goto error421;
        }
        if (SmtpdReadLine(relay, &relay->line, &rc) <= 0 || relay->line.string[0] != '2') {
            goto error421;
        }

        if (relay->interp == NULL) {
            relay->interp = conn->interp;
        }

        result = Ns_TLS_CtxClientCreate(
            relay->interp,
            conn->config->certificate,
            conn->config->cafile,
            conn->config->capath,
            0 /*verify*/,
            &ctx);

        if (likely(result == TCL_OK)) {
            /*
             * Make sure, the socket is in a writable state.
             */

            if (Ns_SockTimedWait(relay->sock->sock, NS_SOCK_WRITE|NS_SOCK_READ, &timeout) != NS_OK) {
                goto error421;
            };
            /*
             * Establish the SSL/TLS connection.  The second last argument is
             * the sni_hostname, which might be used via configuration in
             * future versions.
             */
            rc = Ns_TLS_SSLConnect(relay->interp, relay->sock->sock, ctx,
                                   /*sniHostname*/NULL,
#if NS_VERSION_NUM >= 50000
                                   /*caFile*/NULL,
                                   /*caPath*/NULL,
#endif
                                   /*timeoutPtr*/NULL,
                                   &ssl);
            result = (rc == NS_OK ? TCL_OK : TCL_ERROR);
            relay->sock->arg = ssl;
        }
        if (unlikely(result != TCL_OK)) {
            goto error421;
        }

        /*
         * send EHLO command again, options may differ
         */
        Ns_Log(SmtpdDebug,"TLS connection established, send EHLO again");
        rc = SmtpdEHLOCommand(conn, relay);
        if (rc == NS_ERROR) {
            goto error421;
        } else if (rc != NS_OK) {
            goto errorrelay;
        }
    }
#endif

    if ((relay->flags & SMTPD_GOTAUTHPLAIN) != 0) {
        if (conn->config->relayuser != NULL && conn->config->relaypassword != NULL) {
            rc = SmtpdAuthPlainCommand(conn, relay, conn->config->relayuser, conn->config->relaypassword);
            Ns_Log(SmtpdDebug, "Result of Auth %s", Ns_ReturnCodeString(rc));
            if (rc == NS_ERROR) {
                goto error421;
            } else if (rc != NS_OK) {
                goto errorrelay;
            }
        } else {
            //char *p = NULL; *p=0; // debug hook
            Ns_Log(Error, "nssmtpd: AUTH PLAIN was requested, but no user and password was configured");
            goto error421;
        }
    }

    /*
     * MAIL FROM command
     */
    Tcl_DStringSetLength(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "MAIL FROM: <%s>\r\n", !strcmp(conn->from.addr, "<>") ? "" : conn->from.addr);
    if (SmtpdWriteDString(relay, &conn->line) != NS_OK) {
        goto error421;
    }
    if (SmtpdReadLine(relay, &relay->line, &rc) <= 0) {
        goto error421;
    }
    if (relay->line.string[0] != '2') {
        goto errorrelay;
    }

    /*
     * RCPT TO command
     */
    for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
        if ((rcpt->flags & SMTPD_VERIFIED) == 0u) {
            continue;
        }
        Tcl_DStringSetLength(&conn->line, 0);
        Ns_DStringPrintf(&conn->line, "RCPT TO: <%s>\r\n", rcpt->addr);
        if (SmtpdWriteDString(relay, &conn->line) != NS_OK) {
            goto error421;
        }
        if (SmtpdReadLine(relay, &relay->line, &rc) <= 0) {
            goto error421;
        }
        if (relay->line.string[0] != '2') {
            goto errorrelay;
        }
        vcount++;
    }

    /* DATA command */
    if (SmtpdPuts(relay, "DATA\r\n") != NS_OK) {
        goto error421;
    }
    if (SmtpdReadLine(relay, &relay->line, &rc) <= 0) {
        goto error421;
    }
    if (strncmp(relay->line.string, "354", 3)) {
        goto errorrelay;
    }
    if (SmtpdPuts(conn, "354 Start mail input; end with <CRLF>.<CRLF>\r\n") != NS_OK) {
        goto error;
    }
    do {
        if (SmtpdReadLine(conn, &relay->line, &rc) < 0) {
            goto error;
        }
        if (SmtpdWriteDString(relay, &relay->line) != NS_OK) {
            goto error421;
        }
        /* Remove trailing dot from the data buffer */
        if (!strcmp(relay->line.string, ".\r\n")) {
            Tcl_DStringSetLength(&relay->line, relay->line.length - 3);
            break;
        }
        size += relay->line.length;
        if (size < conn->config->maxdata &&
            !(conn->rcpt.count == vcount && (conn->flags & SMTPD_FASTPROXY) != 0u)
            ) {
            Tcl_DStringAppend(&conn->body.data, relay->line.string, relay->line.length);
        }
    } while (relay->line.length > 0);
    if (SmtpdReadLine(relay, &relay->line, &rc) <= 0) {
        goto error421;
    }
    if (relay->line.string[0] != '2') {
        goto errorrelay;
    }
    if (SmtpdWriteDString(conn, &relay->line) != NS_OK) {
        goto error;
    }
    SmtpdConnFree(relay);
    for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
        if ((rcpt->flags & SMTPD_VERIFIED) != 0u) {
            rcpt->flags |= SMTPD_DELIVERED;
        }
    }
    return size;
 error:
    /*
     * Sending mail data failed
     */
    Ns_Log(SmtpdDebug,"SmtpdSend: sending mail data to the relay failed");
    SmtpdConnFree(relay);
    return -1;

 error421:
    /*
     * We have received no proper response from the backend server.
     * Reply 421: Service not available, closing transmission channel.
     */
    Ns_StrTrimRight(conn->line.string);
    Ns_StrTrimRight(relay->line.string);
    Ns_Log(Error, "nssmtpd: relay 421: %lu/%d: HOST: %s/%s, FLAGS: 0x%X, FROM: %s, %s: %s/%s",
           conn->id, getpid(), conn->host, Ns_ConnPeerAddr(nsconn),
           conn->flags, conn->from.addr, conn->line.string, conn->line.string, relay->line.string);
    SmtpdPuts(conn, "421 Service not available\r\n");
    SmtpdConnFree(relay);
    return -1;

  errorrelay:
    /*
     * We received a proper response in the relay buffer, but it is indicating
     * not a success.  Pass the result to the error proc, and when this fails, fall
     * back to the 421 error.
     */
    /*Ns_Log(Notice, "ERROR RELAY: relay string '%s', conn string '%s'",
           relay->line.string,
           conn->line.string);*/
    Ns_StrTrimRight(conn->line.string);
    //conn->line.length = (int)strlen(conn->line.string);
    Ns_StrTrimRight(relay->line.string);
    Tcl_DStringAppend(&conn->line, ": ", 2);
    Tcl_DStringAppend(&conn->line, relay->line.string, relay->line.length);
    Ns_Log(Error, "nssmtpd: relay errorproc: %lu/%d: HOST: %s/%s, FLAGS: 0x%X, FROM: %s, %s/%s",
           conn->id, getpid(), conn->host, Ns_ConnPeerAddr(nsconn), conn->flags, conn->from.addr,
           conn->line.string, relay->line.string);

    SmtpdJoinMultiLine(&relay->line);
    Ns_Log(Error, "nssmtpd: relay errorproc: %lu/%d: HOST: %s/%s, FLAGS: 0x%X, FROM: %s, %s/%s",
           conn->id, getpid(), conn->host, Ns_ConnPeerAddr(nsconn), conn->flags, conn->from.addr,
           conn->line.string, relay->line.string);


    SmtpdConnEval(conn, conn->config->errorproc);
    if (!conn->reply.length) {
        Ns_Log(Warning, "nssmtpd: empty reply, build our own from '%s'", &relay->line.string[4]);
        Ns_DStringPrintf(&conn->reply, "421 Service not available. %s\r\n", &relay->line.string[4]);
    }
    SmtpdWriteDString(conn, &conn->reply);
    SmtpdConnFree(relay);
    return -1;
}

/*
 *----------------------------------------------------------------------
 *
 * SmtpdSendLog --
 *
 *      Write a log message into the SMTP send log file, when logging
 *      is enabled.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Write log file message.
 *
 *----------------------------------------------------------------------
 */


static void
SmtpdSendLog(smtpdConfig *config, Ns_Time *startTimePtr,
             const char *sender, Tcl_Obj *rcptObj,
             const char *host, unsigned short port,
             const char *status, const char *errorCode, size_t bytesSent)
{
    NS_NONNULL_ASSERT(config != NULL);

    if (config->sendlog.logging) {
        Tcl_DString logString;
        Ns_Time     now, diff;
        char        buf[41]; /* Big enough for Ns_LogTime(). */

        Ns_GetTime(&now);
        Ns_DiffTime(&now, startTimePtr, &diff);
        Tcl_DStringInit(&logString);
        Ns_DStringPrintf(&logString, "%s %s %s %s [%s]:%hu " NS_TIME_FMT
                         " %" PRIdz " %s RCPT: %s\n",
                         Ns_LogTime(buf),
                         Ns_ThreadGetName(),
                         status,
                         errorCode,
                         host, port,
                         (int64_t)diff.sec, diff.usec,
                         bytesSent,
                         sender,
                         Tcl_GetString(rcptObj)
                         );

        Ns_MutexLock(&config->sendlog.lock);
        (void)NsAsyncWrite(config->sendlog.fd,
                           logString.string, (size_t)logString.length);
        Ns_MutexUnlock(&config->sendlog.lock);

        Tcl_DStringFree(&logString);
    }
}

static Ns_ReturnCode
SmtpdSend(smtpdConfig *config, Tcl_Interp *interp, const char *sender,
          Tcl_Obj *rcptObj, const char *dataVarName, const char *host,
          unsigned short port)
{
    char         *ptr, *dataString;
    char          finalStatus[4];
    Ns_Sock       sock;
    Tcl_Obj      *data;
    smtpdConn    *conn;
    Ns_Time       timeout = { config->writetimeout, 0 };
    TCL_SIZE_T    dataLength = 0;
    Tcl_DString   dataDString;
    Ns_Time       startTime;
    Ns_ReturnCode rc;
    const char    *errorString = "Unclassified error condition";

    Ns_Log(SmtpdDebug,"SmtpdSend rcpt %s host %s port %hu",
           Tcl_GetString(rcptObj), host, port);
    memcpy(finalStatus, "000", 4);

    if (sender == NULL || rcptObj == NULL || dataVarName == NULL) {
        Tcl_AppendResult(interp, "nssmtpd: send: empty arguments", (char *)0L);
        return NS_ERROR;
    }
    if (!(data = Tcl_GetVar2Ex(interp, dataVarName, 0, TCL_LEAVE_ERR_MSG))) {
        return NS_ERROR;
    }
    if (host == NULL || *host == '\0') {
        host = config->relayhost;
        port = config->relayport;
    }
    if (port == 0) {
        port = DEFAULT_PORT;
    }

    Ns_GetTime(&startTime);

    if ((sock.sock = Ns_SockTimedConnect(host, port, &timeout)) == NS_INVALID_SOCKET) {
        SmtpdSendLog(config, &startTime, sender, rcptObj, host, port, finalStatus, "CONNECT_FAILURE", 0u);
        Tcl_AppendResult(interp, "nssmtpd: send: unable to connect to ", host, ": ",
                         strerror(errno), (char *)0L);
        return NS_ERROR;
    }
    sock.driver = config->driver;
    /*
     * Allocate virtual SMTPD connection
     */
    if (!(conn = SmtpdConnCreate(config, &sock))) {
        Tcl_AppendResult(interp, strerror(errno), (char *)0L);
        ns_sockclose(sock.sock);
        SmtpdSendLog(config, &startTime, sender, rcptObj, host, port, finalStatus, "SETUP_FAILURE", 0u);
        return NS_ERROR;
    }
    /*
     * Read greeting line from the conn
     */
    Ns_Log(SmtpdDebug,"SmtpdSend wait for greeting");

    if (SmtpdReadLine(conn, &conn->line, &rc) < 0) {
        Tcl_AppendResult(interp, "greeting read error: ", strerror(errno), (char *)0L);
        SmtpdConnFree(conn);
        SmtpdSendLog(config, &startTime, sender, rcptObj, host, port, finalStatus, "GREET_FAILURE", 0u);
        return NS_ERROR;
    }
    Ns_Log(SmtpdDebug,"SmtpdSend got greeting");
    Tcl_DStringInit(&dataDString);

    /* HELO command */
    Tcl_DStringSetLength(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "HELO %s\r\n", Ns_InfoHostname());
    if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
        errorString = "send HELO";

        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line, &rc) <= 0) {
        errorString = "read HELO reply";
        goto ioerror;
    }
    if (conn->line.string[0] != '2') {
        memcpy(finalStatus, conn->line.string, 3);
        goto error;
    }

    /* MAIL FROM command */
    Tcl_DStringSetLength(&conn->line, 0);
    Tcl_DStringAppend(&conn->reply, (char *) sender, TCL_INDEX_NONE);
    Ns_DStringPrintf(&conn->line, "MAIL FROM:<%s>\r\n", SmtpdStrTrim(conn->reply.string));
    if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
        errorString = "send MAIL FROM";
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line, &rc) <= 0) {
        errorString = "read MAIL FROM reply";
        goto ioerror;
    }
    if (conn->line.string[0] != '2') {
        memcpy(finalStatus, conn->line.string, 3);
        goto error;
    }

    /*
     * RCPT TO command
     *
     * It is possible to send a mail to multiple recipients, but this requires
     * also multiple "RCPT TO" lines.
     */
    {
        TCL_SIZE_T i, objc;
        Tcl_Obj  **objv;

        if (Tcl_ListObjGetElements(NULL, rcptObj, &objc, &objv) != TCL_OK) {
            goto error;
        }

        for (i = 0; i < objc; i++) {
            TCL_SIZE_T  argLen;
            const char *argString = Tcl_GetStringFromObj(objv[i], &argLen);

            Tcl_DStringSetLength(&conn->line, 0);
            Tcl_DStringSetLength(&conn->reply, 0);
            Tcl_DStringAppend(&conn->reply, (char *)argString, argLen);
            Ns_DStringPrintf(&conn->line, "RCPT TO:<%s>\r\n", SmtpdStrTrim(conn->reply.string));
            if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
                errorString = "send RCPT TO";
                goto ioerror;
            }
            if (SmtpdReadLine(conn, &conn->line, &rc) <= 0) {
                errorString = "read RCPT TO reply";
                goto ioerror;
            }
            if (conn->line.string[0] != '2') {
                memcpy(finalStatus, conn->line.string, 3);
                goto error;
            }
        }
    }

    /*
     * Process data for line starting with a dot and duplicate it.
     * See: rfc5321#section-4.5.2
     */
    dataString = ptr = Tcl_GetStringFromObj(data, &dataLength);

    while ((ptr = strstr(ptr, "\n."))) {
        long offset;

        ptr += 2;
        offset = ptr - dataString;
        /*
         * Copy the data to the Tcl_DString and insert an additional single
         * period ('.').
         */

        Tcl_DStringAppend(&dataDString, dataString, (int)offset);
        Tcl_DStringAppend(&dataDString, ".", 1);
        dataString += offset;
        ptr = dataString;
    }
    if (dataDString.length > 0) {
        /*
         * Only when we have found a line starting with a dot, we are using
         * the Tcl_DString. Append the final chunk in such cases.
         */
        Tcl_DStringAppend(&dataDString, dataString, -1);
        dataString = dataDString.string;
        dataLength = dataDString.length;
    }

    /* DATA command */
    if (SmtpdPuts(conn, "DATA\r\n") != NS_OK) {
        errorString = "send DATA command";
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line, &rc) <= 0) {
        errorString = "read DATA command reply";
        goto ioerror;
    }
    memcpy(finalStatus, conn->line.string, 3);

    if (strncmp(conn->line.string, "354", 3)) {
        goto error;
    }
    if (SmtpdWriteData(conn, dataString, dataLength) != NS_OK) {
        errorString = "send DATA";
        goto ioerror;
    }
    if (SmtpdWriteData(conn, "\r\n.\r\n", 5) != NS_OK) {
        errorString = "send DATA terminate";
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line, &rc) <= 0) {
        errorString = "read DATA terminate reply";
        goto ioerror;
    }
    memcpy(finalStatus, conn->line.string, 3);
    if (conn->line.string[0] != '2') {
        goto error;
    }

    /* QUIT command */
    if (SmtpdPuts(conn, "QUIT\r\n") != NS_OK) {
        errorString = "send QUIT";
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line, &rc) <= 0) {
        errorString = "read QUIT reply";
        goto ioerror;
    }
    Ns_Log(Notice, "nssmtpd: send: from %s to %s via %s:%d %ld bytes",
           sender, Tcl_GetString(rcptObj), host, port, (long)dataLength);
    SmtpdSendLog(config, &startTime, sender, rcptObj, host, port, finalStatus, "SUCCESS", (size_t)dataLength);

    SmtpdConnFree(conn);
    Tcl_DStringFree(&dataDString);
    return NS_OK;

 ioerror:
    if (rc == NS_TIMEOUT) {
        Tcl_AppendResult(interp, "nssmtpd: send: timeout during ", errorString, (char *)0L);

    } else if (errno) {
        Tcl_AppendResult(interp, "nssmtpd: send: I/O error during ", errorString, ": ",
                         conn->line.string, ": ", strerror(errno), (char *)0L);
    }
    SmtpdConnFree(conn);
    SmtpdSendLog(config, &startTime, sender, rcptObj, host, port, finalStatus, "IO_ERROR", 0u);
    Tcl_DStringFree(&dataDString);
    return NS_ERROR;

 error:
    Tcl_AppendResult(interp, "nssmtpd: send: unexpected status from ", host, ": ",
                     conn->line.string, (char *)0L);
    SmtpdConnFree(conn);
    SmtpdSendLog(config, &startTime, sender, rcptObj, host, port, finalStatus, "STATUS_ERROR", 0u);
    Tcl_DStringFree(&dataDString);
    return NS_ERROR;
}

static void
SmtpdRcptFree(smtpdConn *conn, char *addr, int index, unsigned int flags)
{
    int count = -1;
    smtpdRcpt *rcpt, *rcpt2;

    Ns_Log(SmtpdDebug,"SmtpdRcptFree");

    for (rcpt = conn->rcpt.list; rcpt != NULL;) {
        count++;
        if ((flags != 0u && (rcpt->flags & SMTPD_VERIFIED) != 0u)
            || (addr != NULL && !strcmp(rcpt->addr, addr))
            || (index >= 0 && count == index)
            ) {
            if (rcpt->prev != NULL) {
                rcpt->prev->next = rcpt->next;
            } else {
                conn->rcpt.list = rcpt->next;
            }
            if (rcpt->next) {
                rcpt->next->prev = rcpt->prev;
            }
            rcpt2 = rcpt;
            rcpt = rcpt->next;
            ns_free((char*)rcpt2->addr);
            ns_free((char*)rcpt2->data);
            ns_free((char*)rcpt2->relay.host);
            ns_free(rcpt2);
            conn->rcpt.count--;
            continue;
        }
        rcpt = rcpt->next;
    }
}

static ssize_t
SmtpdRecv(Ns_Sock *sock, char *buffer, size_t length, Ns_Time *timeoutPtr, Ns_ReturnCode *rcPtr)
{
    Ns_ReturnCode rc = TCL_OK;
    ssize_t       received;

    NS_NONNULL_ASSERT(sock != NULL);
    NS_NONNULL_ASSERT(buffer != NULL);


again:
    if (sock->arg == NULL) {
        received = ns_recv(sock->sock, buffer, length, 0);

    } else {
#ifdef HAVE_OPENSSL_EVP_H
        SSL *ssl = (SSL *)sock->arg;

        received = 0;
        for (;;) {
            int n = 0, err;

            n = SSL_read(ssl, buffer+received, (int)(length - (size_t)received));
            err = SSL_get_error(ssl, n);

            switch (err) {
            case SSL_ERROR_NONE:
                if (n < 0) {
                    Ns_Log(Error, "SSL_read failed but no error, should not happen");
                    break;
                }
                received += n;
                break;

            case SSL_ERROR_WANT_READ:
                if (n < 0) {
                    continue;
                }
                received += n;
                continue;
            }
            break;
        }
#else
        received = -1;
#endif
    }

    if (received == -1 && errno == EWOULDBLOCK) {
        Ns_Log(SmtpdDebug, "SmtpdRecv: call again after timeout " NS_TIME_FMT "s",
               (int64_t)timeoutPtr->sec, timeoutPtr->usec);
        rc = Ns_SockTimedWait(sock->sock, (unsigned int)NS_SOCK_READ, timeoutPtr);
        Ns_Log(SmtpdDebug, "SmtpdRecv: sock wait returned %s", Ns_ReturnCodeString(rc));
        if (rc == NS_OK) {
            goto again;
        }
    }

    *rcPtr = rc;
    return received;
}

static ssize_t
SmtpdRead(smtpdConn *conn, void *vbuf, ssize_t len, Ns_ReturnCode *rcPtr)
{
    ssize_t nread, n;
    char *buf = (char *) vbuf;
    Ns_Time timeout = { conn->config->readtimeout, 0 };

    Ns_Log(SmtpdDebug,"SmtpdRead");

    nread = len;
    while (len > 0) {
        if (conn->buf.pos > 0) {
            /* Copy bytes already in read-ahead buffer. */
            if (conn->buf.pos > len) {
                n = len;
            } else {
                n = conn->buf.pos;
            }
            memcpy(buf, conn->buf.ptr, (unsigned int) n);
            conn->buf.ptr += n;
            conn->buf.pos -= n;
            len -= n;
            buf += n;
        }
        if (len > 0) {
            /* Attempt to fill the read-ahead buffer. */
            conn->buf.ptr = conn->buf.data;
            conn->buf.pos = SmtpdRecv(conn->sock, conn->buf.data, conn->config->bufsize, &timeout, rcPtr);
            if (conn->buf.pos <= 0) {
                return -1;
            }
        }
    }
    return nread;
}

//static int FID = 0;

static ssize_t SmtpdUnixSend(Ns_Sock *sock, const char *buffer, size_t length)
{
    ssize_t       sent;

    NS_NONNULL_ASSERT(sock != NULL);
    NS_NONNULL_ASSERT(buffer != NULL);

    if (sock->arg == NULL) {
        int         retry_count = 0;
        const char *buf = buffer;
        size_t      tosend = length;

        sent = 0;
        while (tosend > 0) {
            ssize_t n;
            size_t  want_send = MIN(65536, tosend);

            n = ns_send(sock->sock, buf, want_send, 0);

            if (n < 0) {
                int error_code = ns_sockerrno;

                if (Retry(error_code) && retry_count < 10) {
                    Ns_Time timeout = {1, 0};

                    Ns_Log(SmtpdDebug, "nssmtpd retry %d error code %d: %s",
                           retry_count, error_code, strerror(error_code));

                    Ns_SockTimedWait(sock->sock, NS_SOCK_WRITE, &timeout);
                    retry_count++;
                    continue;
                }
                return n;
            } else {
                //if (FID == 0) {
                //    FID = open("/tmp/SEND", O_CREAT|O_WRONLY|O_TRUNC);
                //}
                //write(FID, buf, n);
            }

            retry_count = 0;
            sent += n;
            tosend -= (size_t)n;
            buf += n;
        }

    } else {
#ifdef HAVE_OPENSSL_EVP_H
        struct iovec  iov;
        SSL *ssl = (SSL *)sock->arg;

        (void) Ns_SetVec(&iov, 0, buffer, length);
        sent = 0;
        for (;;) {
            int     err;
            ssize_t n;

            n = SSL_write(ssl, iov.iov_base, (int)iov.iov_len);
            err = SSL_get_error(ssl, (int)n);
            if (err == SSL_ERROR_WANT_WRITE) {
                Ns_Time timeout = { 0, 10000 }; /* 10ms */

                Ns_SockTimedWait(sock->sock, NS_SOCK_WRITE, &timeout);
                continue;
            }
            if (likely(n > -1)) {
                sent += n;

                if (((size_t)n < iov.iov_len)) {
                    Ns_ResetVec(&iov, 1, (size_t)n);
                    continue;
                }
            }
            break;
        }
#else
        sent = -1;
#endif
    }

    Ns_Log(SmtpdDebug, "SmtpdUnixSend sent %ld of %lu bytes", sent, length);
    return sent;
}

static ssize_t SmtpdWrite(smtpdConn *conn, const void *buf, ssize_t len)
{
    return SmtpdUnixSend(conn->sock, buf, (size_t)len);
}


/*
 *----------------------------------------------------------------------
 *
 * SmtpLineTrimCR --
 *
 *      This function trims a trailing carriage return (CR, 0x0d) from a line
 *      stored in a Tcl_DString. If the string length is at least 2, it
 *      examines the character at position (length - 2). If that character is
 *      a CR, the function removes it by replacing it with the final character
 *      and decrementing the string length.
 *
 * Results:
 *      Returns NS_TRUE if the Tcl_DString contained at least 2 characters,
 *      regardless of whether a CR was actually removed. Returns NS_FALSE if
 *      the string is too short to contain a CR.
 *
 * Side Effects:
 *      Modifies the Tcl_DString by potentially removing a trailing CR.
 *
 *----------------------------------------------------------------------
 */
static bool
SmtpLineTrimCR(Tcl_DString *dsPtr)
{
    bool result = NS_TRUE;

    if (dsPtr->length < 2) {
        result = NS_FALSE;
    } else {
        char lastChar = dsPtr->string[dsPtr->length-2];

        if (lastChar == 0x0d) {
            dsPtr->string[dsPtr->length-2] = dsPtr->string[dsPtr->length-1];
            dsPtr->length--;
            dsPtr->string[dsPtr->length] = '\0';
            /*Ns_Log(Notice, "SmtpLineTrimCR returns stripped <%s>", dsPtr->string);*/
        }
    }

    return result;
}

/*
 *----------------------------------------------------------------------
 *
 * SmtpdReadMultiLine --
 *
 *      Reads and concatenates a multi-line SMTP response from the connection.
 *      The function repeatedly reads single lines from the given SMTP
 *      connection using SmtpdReadLine(), trims any trailing carriage return
 *      from each line, and appends the line to the provided Tcl_DString. It
 *      continues this process until it encounters a line whose fourth
 *      character is a space, indicating the end of the multi-line response.
 *
 *      If a non-NULL pointer for EHLO flags is provided (ehloFlagsPtr), the function
 *      also inspects each line for specific EHLO-related messages. If a line contains
 *      "STARTTLS" or "AUTH" (with the "PLAIN" option), it sets the corresponding flags
 *      in *ehloFlagsPtr.
 *
 * Results:
 *      Returns NS_OK if all lines are successfully read and appended to the
 *      Tcl_DString. If a read error occurs or a line is too short (less than
 *      4 characters), the function returns NS_ERROR.
 *
 * Side Effects:
 *      - Modifies the provided Tcl_DString (dsPtr) by appending the text of each line.
 *      - Adjusts each read line by removing a trailing carriage return (0x0d) if present.
 *
 *----------------------------------------------------------------------
 */
static Ns_ReturnCode
SmtpdReadMultiLine(smtpdConn *conn, Tcl_DString *dsPtr, unsigned int *ehloFlagsPtr)
{
    Ns_ReturnCode result = NS_OK;
    Tcl_DString   oneLine;
    char          fourthChar;

    /*
     * Reset the output Tcl_DString and initialize the temporary string for
     * single lines.
     */
    Tcl_DStringSetLength(dsPtr, 0);
    Tcl_DStringInit(&oneLine);

    do {
        ssize_t nread = SmtpdReadLine(conn, &oneLine, &result);

        if (nread <= 0 || oneLine.length < 4) {
            result = NS_ERROR;
            break;
        }
        SmtpLineTrimCR(&oneLine);

        if (ehloFlagsPtr != NULL) {
            Ns_Log(SmtpdDebug, "process EHLO flags in line <%s>", oneLine.string);

            if (!strncasecmp(oneLine.string + 4, "STARTTLS", 8)) {
                *ehloFlagsPtr |= SMTPD_GOTSTARTTLS;

            } else if (!strncasecmp(oneLine.string + 4, "AUTH", 4)) {
                /* Check for a 250 AUTH message containing the PLAIN option */
                if (strstr(oneLine.string, "PLAIN") != NULL) {
                    *ehloFlagsPtr |= SMTPD_GOTAUTHPLAIN;
                } else {
                    Ns_Log(SmtpdDebug,"Warning: unsupported AUTH options: %s", oneLine.string);
                }
            }
        }

        fourthChar = oneLine.string[3];
        Tcl_DStringAppend(dsPtr, oneLine.string, oneLine.length);

    } while (fourthChar != ' ');

    Tcl_DStringFree(&oneLine);
    return result;
}

/*
 *----------------------------------------------------------------------
 *
 * SmtpdJoinMultiLine --
 *
 *      Joins together multi-line SMTP response lines by removing embedded
 *      status codes and enhanced error codes. This function scans through the
 *      provided Tcl_DString for newline characters. For each newline found,
 *      if the following characters represent a 3-digit error code (and
 *      optionally a dot-separated sequence), the function replaces the
 *      newline with a space, removes the error code along with any extra
 *      spacing, and shifts the remaining text accordingly. This process
 *      effectively "joins" the multi-line response into a single continuous
 *      line, suitable for end users.
 *
 * Results:
 *      None. The merged response is stored directly in the provided Tcl_DString.
 *
 * Side Effects:
 *      - Modifies the content and length of the Tcl_DString pointed to by dsPtr.
 *
 *----------------------------------------------------------------------
 */
static void
SmtpdJoinMultiLine(Tcl_DString *dsPtr)
{
    char  *p;

    p = strchr(dsPtr->string, INTCHAR('\n'));
    while (p != NULL) {
        ptrdiff_t offset = p - dsPtr->string;

        //Ns_Log(Notice, "JOIN: '%c' '%c' '%c' '%c'", p[1], p[2], p[3], p[4]);
        if (offset < (dsPtr->length-4)
            && CHARTYPE(digit, p[1]) != 0
            && CHARTYPE(digit, p[2]) != 0
            && CHARTYPE(digit, p[3]) != 0
            ) {
            char *textStart;

            /*Ns_Log(Notice, "... before move len %d shorten by %d to move %ld chars from '%s'",
              dsPtr->length, 4, (dsPtr->length - offset) - 4,  p+5);*/
            *p = ' ';
            memmove(p+1, p+5, (size_t)(dsPtr->length - offset) - 5u);
            Tcl_DStringSetLength(dsPtr, (TCL_SIZE_T)dsPtr->length - 5);
            //Ns_Log(Notice, "... after move len %d line '%s'", dsPtr->length, dsPtr->string);

            /*
             * Skip enhanced error code, e.g., 5.7.8, followed by blanks)
             */
            textStart = p+1;
            while (CHARTYPE(digit, *textStart) != 0 || *textStart == '.') {
                //Ns_Log(Notice, "... skip enhanced digit '%c'", *textStart);
                textStart ++;
            }
            while (*textStart == ' ') {
                textStart ++;
            }
            if (textStart != p+1) {
                ptrdiff_t processed = textStart - dsPtr->string;

                offset = textStart - (p+1);
                memmove(p+1, textStart, (size_t)(dsPtr->length - processed));
                Tcl_DStringSetLength(dsPtr, dsPtr->length - (TCL_SIZE_T)offset);
            }

            //Ns_Log(Notice, "JOIN: -> %d '%s'", dsPtr->length, dsPtr->string);
        }
        p = strchr(dsPtr->string, INTCHAR('\n'));
    }
}

static ssize_t
SmtpdReadLine(smtpdConn *conn, Tcl_DString *dsPtr, Ns_ReturnCode *rcPtr)
{
    char    buf[1];
    ssize_t len = 0, nread;

    Tcl_DStringSetLength(dsPtr, 0);
    do {
        if ((nread = SmtpdRead(conn, buf, 1, rcPtr)) == 1) {
            Tcl_DStringAppend(dsPtr, buf, 1);
            ++len;
            if (buf[0] == '\n') {
                break;
            }
        }
    } while (nread == 1 && dsPtr->length <= conn->config->maxline);

    if (nread > 0 && Ns_LogSeverityEnabled(SmtpdDebug) == NS_TRUE) {
        char *end = &dsPtr->string[dsPtr->length-1], saved = *end;

        *end = '\0';
        Ns_Log(SmtpdDebug, "nssmtpd: %lu: <<< %s", conn->id, dsPtr->string);
        *end = saved;
    }
    return (nread > 0 ? len : nread);
}

static NS_INLINE bool Retry(int errorCode)
{
    return (errorCode == NS_EAGAIN
            || errorCode == NS_EINTR
#if defined(__APPLE__)
            /*
             * Due to a possible kernel bug at least in OS X 10.10 "Yosemite",
             * EPROTOTYPE can be returned while trying to write to a socket
             * that is shutting down. If we retry the write, we should get
             * the expected EPIPE instead.
             */
            || errorCode == EPROTOTYPE
#endif
            || errorCode == NS_EWOULDBLOCK);
}

static Ns_ReturnCode SmtpdWriteData(smtpdConn *conn, const char *buf, ssize_t len)
{
    if (Ns_LogSeverityEnabled(SmtpdDebug) == NS_TRUE) {
        Tcl_DString ds;

        Tcl_DStringInit(&ds);
        Tcl_DStringAppend(&ds, buf, (int)(len-2));
        Ns_Log(SmtpdDebug, "nssmtpd: %lu: >>> %s", conn->id, ds.string);
        Tcl_DStringFree(&ds);
    }

    Ns_Log(SmtpdDebug, "nssmtpd: %lu want to send %ld bytes in total", conn->id, len);

    while (len > 0) {
        ssize_t nwrote = SmtpdWrite(conn, buf, len);

        if (nwrote < 0) {
            return NS_ERROR;
        }
        len -= nwrote;
        buf += nwrote;
    }
    return NS_OK;
}

static Ns_ReturnCode SmtpdWriteDString(smtpdConn *conn, Tcl_DString *dsPtr)
{
    return SmtpdWriteData(conn, dsPtr->string, dsPtr->length);
}

static Ns_ReturnCode SmtpdPuts(smtpdConn *conn, const char *string)
{
    return SmtpdWriteData(conn, string, (int) strlen(string));
}

static char *SmtpdStrPos(char *as1, const char *as2)
{
    register char *s1 = as1, *ptr, c;
    const char    *s2 = as2;

    c = *s2;
    while (*s1)
        if (toupper(*s1++) == toupper(c)) {
            ptr = s1;
            while (toupper(c = *++s2) == toupper(*s1++) && c);
            if (c == 0) {
                return ((char *) ptr - 1);
            }
            s1 = ptr;
            s2 = as2;
            c = *s2;
        }
    return 0;
}

static char *SmtpdStrNPos(char *as1, char *as2, size_t len)
{
    register char *s1 = as1, *s2 = as2, *ptr, *end, c;

    c = *s2;
    end = s1 + len;
    while (*s1 && s1 < end)
        if (toupper(*s1++) == toupper(c)) {
            ptr = s1;
            while (toupper(c = *++s2) == toupper(*s1++) && c && s1 < end);
            if (c == 0) {
                return ((char *) ptr - 1);
            }
            s1 = ptr;
            s2 = as2;
            c = *s2;
        }
    return 0;
}

static char *SmtpdStrTrim(char *str)
{
    size_t len;

    while (*str == '<' || isspace(*str)) {
        str++;
    }
    len = strlen(str);
    while (len-- && (isspace(str[len]) || str[len] == '>')) {
        str[len] = '\0' ;
    }
    return str;
}

static const char *SmtpdGetHeader(smtpdConn *conn, const char *name)
{
    smtpdHdr *hdr;
    for (hdr = conn->body.headers; hdr != NULL; hdr = hdr->next) {
        if (!strcasecmp(name, hdr->name) && hdr->value && *hdr->value) {
            return hdr->value;
        }
    }
    return "";
}

#if defined(USE_DSPAM) || defined (USE_SAVI) || defined(USE_CLAMAV)
static void SmtpdConnAddHeader(smtpdConn *conn, char *name, char *value, int alloc)
{
    smtpdHdr *hdr = ns_calloc(1, sizeof(smtpdHdr));
    hdr->name = ns_strdup(name);
    hdr->value = alloc ? ns_strdup(value) : value;
    hdr->next = conn->body.headers;
    conn->body.headers = hdr;
}
#endif

/*
 *  Find where headers end, if the first line looks like header, find the
 *  first empty line, if not it means we do not have any headers
 */
static void SmtpdConnParseData(smtpdConn *conn)
{
    size_t       size, len;
    smtpdHdr    *header = NULL, *boundary = NULL, *fileHdr;
    char        *body, *end, *line, *hdr, *ptr;
#if defined(USE_CLAMAV) || defined(USE_SAVI)
    unsigned int encodingSize, contentSize;
#endif

    Ns_Log(SmtpdDebug,"SmtpdConnParseData");

    hdr = conn->body.data.string;
    if (!(body = strstr(hdr, "\r\n\r\n")) && !(body = strstr(hdr, "\n\n"))) {
        return;
    }
    while (*body == '\r' || *body == '\n') {
        body++;
    }
    end = strchr(hdr, '\n');
    while (end && end <= body) {
        line = hdr;
        // Check for header continuation
        if (end + 1 < body && (*(end + 1) == ' ' || *(end + 1) == '\t')) {
            end = strchr(end + 1, '\n');
            continue;
        }
        // According to RFC822 only these chars are allowed
        if (*(end - 1) == '\r') {
            end--;
        }
        while (line < end && *line >= 33 && *line <= 126 && *line != ':') {
            line++;
        }
        // Bad header, skip them all, we have only message body
        if (*line != ':')
            break;
        // Create new SMTP header
        header = ns_calloc(1, sizeof(smtpdHdr));
        header->next = conn->body.headers;
        conn->body.headers = header;
        header->name = ns_calloc(1, (unsigned) (line - hdr) + 1);
        memcpy(header->name, hdr, (unsigned) (line - hdr));
        while (line < end && (*line == ':' || *line == ' ' || *line == '\t')) {
            line++;
        }
        if (line < end) {
            size = (unsigned) (end - line);
            header->value = ns_calloc(1, size + 1);
            for (len = 0; len < size; len++) {
                switch (line[len]) {
                case '\r':
                case '\n':
                case '\t':
                    header->value[len] = ' ';
                    break;
                default:
                    header->value[len] = line[len];
                }
            }

            // Check for multipart format
            if (!strcasecmp(header->name, "content-type")) {
                if ((ptr = SmtpdStrPos(header->value, "boundary="))) {
                    for (ptr += 9; *ptr == ' ' || *ptr == '"'; ptr++);
                    for (line = ptr; *line != '\0' && *line != '\n' && *line != '\r' && *line != '"'; line++);
                    header = (smtpdHdr *) ns_calloc(1, sizeof(smtpdHdr));
                    header->name = (char *) ns_calloc(1, (unsigned) (line - ptr) + 3);
                    memcpy(header->name, "--", 2);
                    memcpy(header->name + 2, ptr, (unsigned) (line - ptr));
                    header->next = boundary;
                    boundary = header;
                }

            } else if (!strcasecmp(header->name, "Sender") ||
                    !strcasecmp(header->name, "X-Sender") ||
                    !strcasecmp(header->name, "From") ||
                    !strcasecmp(header->name, "To") || !strcasecmp(header->name, "Reply-To")) {
                smtpdEmail addr;

                Tcl_DStringSetLength(&conn->reply, 0);
                Tcl_DStringAppend(&conn->reply, header->value, TCL_INDEX_NONE);
                if (parseEmail(&addr, conn->reply.string)) {
                    if (size <= (len = strlen(addr.mailbox) + strlen(addr.domain))) {
                        ns_free(header->value);
                        header->value = ns_malloc(len + 1);
                        Ns_Log(Error, "nssmtpd: %lu: header: %s: %ld,%ld", conn->id, header->value, size, len);
                    }
                    sprintf(header->value, "%s@%s", addr.mailbox, addr.domain);
                    Ns_StrToLower(header->value);
                }
            }
        }
        // Reached end of the headers and everything is fine
        while (*end == '\r' || *end == '\n') {
            end++;
        }
        if (end == body) {
            conn->body.offset = (size_t)(end - conn->body.data.string);
            break;
        }
        // Next header
        end = strchr((hdr = end), '\n');
    }
    // MIME parser for multipart messages
    if (!boundary) {
        return;
    }
    // Go from one message part to another and parse headers
    hdr = strstr(body, boundary->name);
    while (hdr) {
        char *encodingType = NULL, *contentType = NULL;
#if defined(USE_CLAMAV) || defined(USE_SAVI)
        char  *filePtr = NULL;
#endif

        fileHdr = 0;
        if (!(hdr = strchr(hdr, '\n'))) {
            break;
        }
        while (*hdr == '\r' || *hdr == '\n') {
            hdr++;
        }
        // Find end of headers
        if (!(body = strstr(hdr, "\r\n\r\n")) && !(body = strstr(hdr, "\n\n"))) {
            break;
        }
        while (*body == '\r' || *body == '\n') {
            body++;
        }
        // Now parse header line
        end = strchr(hdr, '\n');
        while (end && end < body) {
            line = hdr;
            // Check for header continuation
            if (end + 1 < body && (*(end + 1) == ' ' || *(end + 1) == '\t')) {
                end = strchr(end + 1, '\n');
                continue;
            }
            // According to RFC822 only these chars are allowed
            if (*(end - 1) == '\r') {
                end--;
            }
            while (line < end && *line >= 33 && *line <= 126 && *line != ':') {
                line++;
            }
            // Bad header, skip them all, we have only message body
            if (*line != ':') {
                break;
            }
            // Check for specific headers
            if (!strncasecmp(hdr, "Content-Disposition:", 20)) {
                hdr += 20;
                if ((ptr = SmtpdStrNPos(hdr, (char*)"filename=", (size_t)(end - hdr)))) {
                    for (ptr += 9; *ptr == ' ' || *ptr == '"'; ptr++);
                    for (line = ptr; *line != '\0' && *line != '\n' && *line != '\r' && *line != '"'; line++);
                    if (!fileHdr) {
                        fileHdr = (smtpdHdr *) ns_calloc(1, sizeof(smtpdHdr));
                        fileHdr->next = conn->body.headers;
                        conn->body.headers = fileHdr;
                        fileHdr->name = ns_strdup(SMTPD_HDR_FILE);
                    } else {
                        ns_free(fileHdr->value);
                    }
                    fileHdr->value = ns_calloc(1, (unsigned) (line - ptr) + 1);
                    memcpy(fileHdr->value, ptr, (unsigned) (line - ptr));
#if defined(USE_CLAMAV) || defined(USE_SAVI)
                    filePtr = ptr;
#endif
                }

            } else if (!strncasecmp(hdr, "Content-transfer-encoding:", 26)) {
                for (encodingType = hdr + 26; *encodingType && isspace(*encodingType); encodingType++);
#if defined(USE_CLAMAV) || defined(USE_SAVI)
                encodingSize = end - encodingType;
#endif

            } else if (!strncasecmp(hdr, "content-type:", 13)) {
                for (contentType = hdr + 13; *contentType && isspace(*contentType); contentType++);
#if defined(USE_CLAMAV) || defined(USE_SAVI)
                contentSize = end - contentType;
#endif
                if ((ptr = SmtpdStrNPos(contentType, (char*)"boundary=", (size_t)(end - contentType)))) {
                    for (ptr += 9; *ptr == ' ' || *ptr == '"'; ptr++);
                    for (line = ptr; *line != '\0' && *line != '\n' && *line != '\r' && *line != '"'; line++);
                    header = (smtpdHdr *) ns_calloc(1, sizeof(smtpdHdr));
                    header->name = ns_calloc(1, (unsigned) (line - ptr) + 3);
                    memcpy(header->name, "--", 2);
                    memcpy(header->name + 2, ptr, (unsigned) (line - ptr));
                    header->next = boundary;
                    boundary = header;
                }
                if (!fileHdr && (ptr = SmtpdStrNPos(hdr, (char*)"name=", (size_t)(end - hdr)))) {
                    for (ptr += 5; *ptr == ' ' || *ptr == '"'; ptr++);
                    for (line = ptr; *line != '\0' && *line != '\n' && *line != '\r' && *line != '"'; line++);
                    fileHdr = (smtpdHdr *) ns_calloc(1, sizeof(smtpdHdr));
                    fileHdr->next = conn->body.headers;
                    conn->body.headers = fileHdr;
                    fileHdr->name = ns_strdup(SMTPD_HDR_FILE);
                    fileHdr->value = ns_calloc(1, (unsigned) (line - ptr) + 1);
                    memcpy(fileHdr->value, ptr, (unsigned) (line - ptr));
#if defined(USE_CLAMAV) || defined(USE_SAVI)
                    filePtr = ptr;
#endif
                }
            }
            // Reached end of the headers and everything is fine
            while (*end == '\r' || *end == '\n') {
                end++;
            }
            if (end == body) {
                // End of the message part
                if ((hdr = strstr(body, boundary->name))) {
                    size = (size_t)((end = hdr) - body);
                    // Check if this message part ends
                    line = hdr + strlen(boundary->name);
                    if (line[0] == '-' && line[1] == '-') {
                        header = boundary->next;
                        ns_free(boundary->name);
                        ns_free(boundary);
                        boundary = header;
                        // Get next message part
                        hdr = boundary ? strstr(line, boundary->name) : 0;
                    }
                } else {
                    size = strlen(body);
                }
#if defined(USE_CLAMAV) || defined(USE_SAVI)
                // Virus scanning
                if (fileHdr && encodingType && (conn->flags & SMTPD_VIRUSCHECK) != 0u) {
                    // Check attachment for virus, replace infected file with text message
                    if ((!strncasecmp(encodingType, "base64", 6)
                         && (ptr = decode64(body, size, &len))) ||
                        (!strncasecmp(encodingType, "quoted-printable", 16)
                         && (ptr = decodeqp(body, size, &len)))
                        ) {
                        SmtpdCheckVirus(conn, ptr, len, fileHdr->value);
                        ns_free(ptr);
                    }
                    if ((conn->flags & SMTPD_GOTVIRUS) != 0u) {
                        static char *info = "The attachment has been removed due to virus infection";

                        while (body[size - 1] == '\n' || body[size - 1] == '\r') {
                            size--;
                        }
                        memset(body, ' ', size);
                        if (size > strlen(info)) {
                            memcpy(body, info, strlen(info));
                        }
                        if (strlen(fileHdr->value) > 4) {
                            memcpy(filePtr + strlen(fileHdr->value) - 4, ".txt", 4);
                        }
                        memcpy(encodingType, "8bit", 4);
                        memset(encodingType + 4, ' ', encodingSize - 4);
                        memset(contentType, ' ', contentSize);
                        if (contentSize >= 10) {
                            memcpy(contentType, "text/plain", 10);
                        }
                        Ns_Log(Notice, "nssmtpd: %d/%d: virus detected: %s", conn->id, getpid(),
                               SmtpdGetHeader(conn, SMTPD_HDR_VIRUS_STATUS));
                    }
                }
#else
                (void)size; /* silence static checker */
#endif
                break;
            }
            // Next header
            end = strchr((hdr = end), '\n');
        }
    }
}

/* Take length of the longest format (with reserve) for all */
#define FORMAT_SIZE 36

static smtpdIpaddr *SmtpdParseIpaddr(char *str)
{
    struct sockaddr *saPtr, *addr_saPtr;
    smtpdIpaddr     *alist = NULL;
    char             addr[NS_IPADDR_SIZE], mask[NS_IPADDR_SIZE] = "",
                     format1[FORMAT_SIZE], format2[FORMAT_SIZE],
                     format3[FORMAT_SIZE], format4[FORMAT_SIZE];
    bool             have_ipmask = NS_FALSE;
    int              rc;
    unsigned int     maskBits;

    snprintf(format1, sizeof(format1),
             "%%%lu[0123456789.]/%%%lu[0123456789.]",
             (unsigned long)(sizeof(addr)),
             (unsigned long)(sizeof(mask)));
    snprintf(format2, sizeof(format2),
             "%%%lu[0123456789.:]",
             (unsigned long)(sizeof(addr)));
    snprintf(format3, sizeof(format3),
             "%%%lu[^/]/%%%lus",
             (unsigned long)(sizeof(addr)),
             (unsigned long)(sizeof(mask)));
    snprintf(format4, sizeof(format4),
             "%%%lus", (unsigned long)(sizeof(addr)));

    if (sscanf(str, format1, addr, mask) == 2) {
    } else if (sscanf(str, format2, addr) == 1) {
    } else if (sscanf(str, format3, addr, mask) == 2) {
    } else if (sscanf(str, format4, addr) == 1) {
        smtpdIpaddr *arec;
        Tcl_DString  ds, *dsPtr = &ds;
        Tcl_Obj     *listObj, **objv;
        TCL_SIZE_T   objc, i;

        // Obtain all IP addresses for given hostname
        Tcl_DStringInit(dsPtr);
        if (Ns_GetAllAddrByHost(dsPtr, addr) == NS_FALSE) {
            Ns_Log(Error, "could not obtain IP addresses for '%s'", addr);
            return 0;
        }

        listObj = Tcl_NewStringObj(Tcl_DStringValue(dsPtr), Tcl_DStringLength(dsPtr));
        rc = Tcl_ListObjGetElements(NULL, listObj, &objc, &objv);
        if (rc != TCL_OK) {
            Ns_Log(Error, "invalid list of IP addresses '%s'", Tcl_GetString(listObj));
            return 0;
        }

        for (i = 0; i< objc; i++) {
            arec = ns_calloc(1, sizeof(smtpdIpaddr));
            saPtr = (struct sockaddr *)&(arec->addr);
            rc = Ns_GetSockAddr(saPtr, Tcl_GetString(objv[i]), 0);
            if (rc != TCL_OK) {
                Ns_Log(Error, "invalid IP addresses '%s'", Tcl_GetString(objv[i]));
                return 0;
            }
            addr_saPtr = saPtr;
            saPtr = (struct sockaddr *)&(arec->mask);
            saPtr->sa_family = addr_saPtr->sa_family;

            if (addr_saPtr->sa_family == AF_INET) {
                Ns_SockaddrMaskBits(saPtr, 32);
            } else {
                Ns_SockaddrMaskBits(saPtr, 128);
            }
            /*
             * Keep the masked addr in the record.
             */
            Ns_SockaddrMask(addr_saPtr, saPtr, addr_saPtr);

            arec->next = alist;
            alist = arec;
        }

        return alist;
    } else {
        // invalid IP address
        return 0;
    }

    alist = ns_calloc(1, sizeof(smtpdIpaddr));

    saPtr = (struct sockaddr *)&(alist->addr);
    rc = Ns_GetSockAddr(saPtr, addr, 0);
    if (rc != TCL_OK) {
        Ns_Log(Error, "invalid IP addresses '%s'", addr);
        return 0;
    }

    addr_saPtr = saPtr;
    saPtr = (struct sockaddr *)&(alist->mask);
    saPtr->sa_family = addr_saPtr->sa_family;
    maskBits = 0u;

    /* Decode mask */
    if (*mask) {
        if (strchr(mask, '.') || strchr(mask, ':')) {
            (void) Ns_GetSockAddr(saPtr, mask, 0);
            have_ipmask = NS_TRUE;
        } else {
            maskBits = (unsigned int)strtol(mask, NULL, 10);
        }
    }
    if (have_ipmask == NS_FALSE) {
        if (maskBits == 0u) {
            if (addr_saPtr->sa_family == AF_INET6) {
                maskBits = 128u;
            } else {
                maskBits = 32u;
            }
        }
        if ((addr_saPtr->sa_family == AF_INET6) && (maskBits <= 128u)) {
            Ns_SockaddrMaskBits(saPtr, maskBits);
            have_ipmask = NS_TRUE;
        } else if ((addr_saPtr->sa_family == AF_INET) && (maskBits <= 32u)) {
            Ns_SockaddrMaskBits(saPtr, maskBits);
            have_ipmask = NS_TRUE;
        } else {
            Ns_Log(Error, "invalid mask bits %d for IP addresses '%s'", maskBits, addr);
        }
    }
    if (have_ipmask == NS_TRUE) {
        /*
         * Keep the masked addr in the record.
         */
        Ns_SockaddrMask(addr_saPtr, saPtr, addr_saPtr);
    }

#if 0
    /* Guess netmask */
    if (!ipmask) {
        ipmask = ntohl(ipaddr);

        if (!(ipmask & 0xFFFFFFFFul)) {
            ipmask = htonl(0x00000000ul);

        } else if (!(ipmask & 0x00FFFFFF)) {
            ipmask = htonl(0xFF000000ul);

        } else if (!(ipmask & 0x0000FFFF)) {
            ipmask = htonl(0xFFFF0000ul);

        } else if (!(ipmask & 0x000000FF)) {
            ipmask = htonl(0xFFFFFF00ul);

        } else {
            ipmask = htonl(0xFFFFFFFFul);
        }
    }
    /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
#endif

    return alist;
}

static bool SmtpdCheckDomain(smtpdConn *conn, const char *domain)
{
    dnsRecord *rec;
    dnsPacket *reply;

    if (conn != NULL && (conn->flags & SMTPD_NEEDDOMAIN) == 0u) {
        return NS_TRUE;
    }
    if ((reply = dnsLookup(domain, DNS_TYPE_A, 0))) {
        for (rec = reply->anlist; rec != NULL && rec->type != DNS_TYPE_A; rec = rec->next);
        dnsPacketFree(reply, 0);
        if (rec) {
            return NS_TRUE;
        }
        reply = 0;
    }
    if (!reply && (reply = dnsLookup(domain, DNS_TYPE_MX, 0))) {
        for (rec = reply->anlist; rec != NULL && rec->type != DNS_TYPE_MX; rec = rec->next);
        dnsPacketFree(reply, 0);
        if (rec) {
            return NS_TRUE;
        }
    }
    if (!conn) {
        return NS_FALSE;
    }
    Ns_Log(Error, "nssmtpd: checkdomain: %lu: HOST: %s, FLAGS: 0x%X, %s", conn->id, conn->host, conn->flags, domain);
    Ns_DStringPrintf(&conn->reply, "553 %s... Domain unrecognized\r\n", domain);
    return NS_FALSE;
}

static bool SmtpdCheckRelay(smtpdConn *conn, smtpdEmail *addr, char **host, unsigned short *port)
{
    smtpdRelay *relay;

    Ns_MutexLock(&conn->config->relaylock);
    for (relay = conn->config->relaylist; relay != NULL; relay = relay->next) {
        const char *p, *s;

        p = &addr->domain[strlen(addr->domain) - 1];
        s = &relay->name[strlen(relay->name) - 1];
        while (*p == *s) {
            if (s-- == relay->name) {
                /* Full domain match */
                if (p == addr->domain || *(p - 1) == '.') {
                    if (host) {
                        *host = ns_strcopy(relay->host);
                    }
                    if (port) {
                        *port = relay->port;
                    }
                    Ns_MutexUnlock(&conn->config->relaylock);
                    return NS_TRUE;
                }
                break;
            }
            if (p-- == addr->domain) {
                break;
            }
        }
    }
    Ns_MutexUnlock(&conn->config->relaylock);

    return NS_FALSE;
}

/* CHECK command returns just a header (terminated by "\r\n\r\n") with the first
 * line as for PROCESS (i.e. a response code and message), and then a header called
 * "Spam:" with value of either "True" or "False", then a semi-colon, and then the
 * score for this message, " / " then the threshold.  So the entire response looks
 * like either:
 *
 * SPAMD/1.1 0 EX_OK
 * Spam: True ; 15 / 5
 */
#if !defined(USE_SPAMASSASSIN) && !defined(USE_DSPAM)
static int SmtpdCheckSpam(smtpdConn *UNUSED(conn))
{
    return 0;
}

#else
static int SmtpdCheckSpam(smtpdConn *conn)
{
# ifdef USE_SPAMASSASSIN
    int rc;
    char *p;
    float score;
    Ns_Sock sock;
    smtpdRcpt *rcpt;
    smtpdConn *spamd;
    Ns_Time timeout = { conn->config->writetimeout, 0 };

    if (conn->config->spamdhost == NULL) {
        return 0;
    }
    /* Should have at least one unverified recipient */
    for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
        if ((rcpt->flags & SMTPD_DELIVERED) == 0u
            && ((rcpt->flag & SMTPD_SPAMCHECK) != 0u)
            ) {
            break;
        }
    }
    if (!rcpt) {
        return 0;
    }

    /*connect to spamd server */
    if ((sock.sock = Ns_SockTimedConnect(conn->config->spamdhost, conn->config->spamdport, &timeout)) == NS_INVALID_SOCKET) {
        Ns_Log(Error, "nssmtpd: spamd: %d/%d: unable to connect to %s:%d: %s", conn->id, getpid(), conn->config->spamdhost,
               conn->config->spamdport, strerror(errno));
        return -1;
    }
    /* Allocate virtual SMTPD connection */
    if (!(spamd = SmtpdConnCreate(conn->config, &sock))) {
        ns_sockclose(sock.sock);
        return -1;
    }
    Ns_DStringPrintf(&spamd->line, "CHECK SPAMC/1.3\r\n");
    Ns_DStringPrintf(&spamd->line, "content-length: %d\r\n\r\n", conn->body.data.length);
    if (SmtpdWriteDString(spamd, &spamd->line) != NS_OK) {
        goto error;
    }
    if (SmtpdWriteDString(spamd, &conn->body.data) != NS_OK) {
        goto error;
    }
    shutdown(sock.sock, 1);
    if (SmtpdReadLine(spamd, &spamd->line, &rc) < 0) {
        goto error;
    }
    /* We should receive 0 response code */
    if (strncasecmp(spamd->line.string, "SPAMD/", 6) || !strstr(spamd->line.string, "EX_OK")) {
        goto error;
    }
    if (SmtpdReadLine(spamd, &spamd->line, &rc) < 0) {
        goto error;
    }
    /* Validate spam line */
    if (strncmp(spamd->line.string, "Spam:", 5) || !(p = strchr(spamd->line.string + 6, ';'))) {
        goto error;
    }
    rc = strstr(spamd->line.string, "True") ? SMTPD_GOTSPAM : 0;
    score = atof(++p);
    // Update all recipients with spam score/status
    for (; rcpt != NULL; rcpt = rctp->next) {
        if ((rcpt->flags & SMTPD_DELIVERED) != 0u || (rcpt->flag & SMTPD_SPAMCHECK) == 0u) {
            continue;
        }
        rcpt->flags |= rc;
        rcpt->spam_score = score;
    }
    SmtpdConnFree(spamd);
    return 1;
  error:
    Ns_Log(Error, "nssmtpd: spam: %d/%d: %s/%s: %s", conn->id, getpid(), spamd->line.string, spamd->reply.string,
           strerror(errno));
    SmtpdConnFree(spamd);
    return -1;
# endif

# ifdef USE_DSPAM
    char *sig;
    int rc = -1;
    DSPAM_CTX *CTX;
    smtpdRcpt *rcpt;

    /* Check spam for each recipient */
    for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
        if ((rcpt->flags & SMTPD_DELIVERED) != 0u || (rcpt->flags & SMTPD_SPAMCHECK) == 0u) {
            continue;
        }
        if (!(CTX = dspam_init(rcpt->addr, NULL, DSM_PROCESS, DSF_SIGNATURE | DSF_CHAINED | DSF_NOISE))) {
            goto error;
        }
        if ((rc = dspam_process(CTX, conn->body.data.string)) != 0) {
            rcpt->spam_score = 0.01;    // Give small probability to hit the digest at least
            goto error;
        }
        // Save signature in the headers
        if (CTX->signature && (sig = encodehex(CTX->signature->data, CTX->signature->length))) {
            SmtpdConnAddHeader(conn, SMTPD_HDR_SIGNATURE, sig, 0);
        }
        // Update recipient with spam score/status
        rcpt->flags |= CTX->result == DSR_ISSPAM ? SMTPD_GOTSPAM : 0;
        rcpt->spam_score = CTX->probability;
        _ds_destroy_message(CTX->message);
        dspam_destroy(CTX);
    }
    return 1;
  error:
    Ns_Log(Notice, "nssmtpd: spam: %d/%d: rc=%d, result=%d, probability=%.2f",
           conn->id, getpid(), rc, CTX ? CTX->result : 0, CTX ? CTX->probability : 0);
    if (CTX) {
        _ds_destroy_message(CTX->message), dspam_destroy(CTX);
    }
    return -1;
# endif
    return 0;
}
#endif


#if !defined(USE_SAVI) && !defined(USE_CLAMAV)
static int
SmtpdCheckVirus(smtpdConn *UNUSED(conn), char *UNUSED(data),
                TCL_SIZE_T UNUSED(datalen), char *UNUSED(location))
{
    return TCL_OK;
}
#else
static int
SmtpdCheckVirus(smtpdConn *conn, char *data, TCL_SIZE_T datalen, char *location)
{
# ifdef USE_SAVI
    HRESULT hr;
    char buf[81];
    Tcl_DString ds;
    CISavi3 *pSAVI;
    unsigned long virusType;
    unsigned long pcFetched;
    CISweepResults *pResults = NULL;
    unsigned long isDisinfectable;
    CISweepClassFactory2 *pFactory;
    CIEnumSweepResults *pEnumResults;

    if (!location) {
        location = datalen ? "buffer" : data;
    }
    if ((hr = DllGetClassObject((REFIID) & SOPHOS_CLASSID_SAVI, (REFIID)
                                & SOPHOS_IID_CLASSFACTORY2, (void **) &pFactory)) < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Failed to get class factory interface: %s",
                         location, buf, (char *)0L);
        return TCL_ERROR;
    }
    hr = pFactory->pVtbl->CreateInstance(pFactory, NULL, (REFIID) & SOPHOS_IID_SAVI3, (void **) &pSAVI);
    pFactory->pVtbl->Release(pFactory);
    if (hr < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Failed to get a CSAVI3 interface: %s",
                         location, buf, (char *)0L);
        return TCL_ERROR;
    }
    if ((hr = pSAVI->pVtbl->InitialiseWithMoniker(pSAVI, "ns_savi")) < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Failed to initialize SAVI: %s",
                         location, buf, (char *)0L);
        pSAVI->pVtbl->Release(pSAVI);
        return TCL_ERROR;
    }
    if (datalen) {
        hr = pSAVI->pVtbl->SweepBuffer(pSAVI, location, datalen, data,
                                       (REFIID) & SOPHOS_IID_ENUM_SWEEPRESULTS,
                                       (void **) &pEnumResults);
    } else {
        hr = pSAVI->pVtbl->SweepFile(pSAVI, data,
                                     (REFIID) & SOPHOS_IID_ENUM_SWEEPRESULTS,
                                     (void **) &pEnumResults);
    }
    if (hr < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Unable to sweep: %s", location,
                         buf, (char *)0L);
        pSAVI->pVtbl->Terminate(pSAVI);
        pSAVI->pVtbl->Release(pSAVI);
        return TCL_ERROR;
    }
    if ((hr = pEnumResults->pVtbl->Reset(pEnumResults)) < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Failed to reset results enumerator: %s",
                         location, buf, (char *)0L);
        pSAVI->pVtbl->Terminate(pSAVI);
        pSAVI->pVtbl->Release(pSAVI);
        return TCL_ERROR;
    }
    Tcl_DStringInit(&ds);
    while (pEnumResults->pVtbl->Next(pEnumResults, 1, (void **) &pResults, &pcFetched) == SOPHOS_S_OK) {
        if (pResults->pVtbl->GetVirusType(pResults, &virusType) < 0 || virusType == SOPHOS_NO_VIRUS) {
            break;
        }
        switch (virusType) {
        case SOPHOS_VIRUS:
            conn->flags |= SMTPD_GOTVIRUS;
            Tcl_DStringAppend(&ds, "Type=Virus; ", 12);
            break;
        case SOPHOS_VIRUS_IDENTITY:
            conn->flags |= SMTPD_GOTVIRUS;
            Tcl_DStringAppend(&ds, "Type=Identity; ", 15);
            break;
        case SOPHOS_VIRUS_PATTERN:
            conn->flags |= SMTPD_GOTVIRUS;
            Tcl_DStringAppend(&ds, "Type=Pattern; ", 14);
            break;
        }
        if (pResults->pVtbl->GetLocationInformation(pResults, 80, buf, NULL) >= 0) {
            Ns_DStringPrintf(&ds, "Location=%s; ", buf);
        }
        if (pResults->pVtbl->GetVirusName(pResults, 80, buf, NULL) >= 0) {
            Ns_DStringPrintf(&ds, "Name=%s; ", buf);
        }
        if (pResults->pVtbl->IsDisinfectable(pResults, &isDisinfectable) >= 0) {
            Ns_DStringPrintf(&ds, "Repair=%s; ", isDisinfectable ? "Yes" : "No");
        }
        SmtpdConnAddHeader(conn, SMTPD_HDR_VIRUS_STATUS, ds.string, 1);
        pResults->pVtbl->Release(pResults);
        pResults = NULL;
    }
    Tcl_DStringFree(&ds);
    if (pResults) {
        pResults->pVtbl->Release(pResults);
    }
    pEnumResults->pVtbl->Release(pEnumResults);
    pSAVI->pVtbl->Terminate(pSAVI);
    pSAVI->pVtbl->Release(pSAVI);
# endif

# ifdef USE_CLAMAV
    const char   *virname;
    unsigned long size = 0;

    if (datalen) {
        int fd;
        char tmpfile[128];

        tmpnam(tmpfile);
        fd = open(tmpfile, O_CREAT|O_RDWR, 0644);
        if (fd < 0) {
            Tcl_AppendResult(conn->interp, strerror(errno), (char *)0L);
            return TCL_ERROR;
        }
        write(fd, data, datalen);
        unlink(tmpfile);
        if (cl_scandesc(fd, &virname, &size, conn->config->ClamAvRoot,
                        &conn->config->ClamAvLimits, CL_SCAN_STDOPT) == CL_VIRUS) {
            conn->flags |= SMTPD_GOTVIRUS;
            SmtpdConnAddHeader(conn, SMTPD_HDR_VIRUS_STATUS, (char*)virname, 1);
        }
    } else {
        if (cl_scanfile(data, &virname, &size, conn->config->ClamAvRoot,
                        &conn->config->ClamAvLimits, CL_SCAN_STDOPT) == CL_VIRUS) {
            conn->flags |= SMTPD_GOTVIRUS;
            SmtpdConnAddHeader(conn, SMTPD_HDR_VIRUS_STATUS, (char*)virname, 1);
        }
    }
# endif
    return TCL_OK;
}
#endif

static smtpdIpaddr *SmtpdCheckIpaddr(smtpdIpaddr *list, const char *ipString)
{
    struct NS_SOCKADDR_STORAGE sa_ip;
    struct sockaddr *sa_ipPtr = (struct sockaddr *)&sa_ip;
    int    rc;

    rc = ns_inet_pton(sa_ipPtr, ipString);
    if (unlikely(rc <= 0)) {
        Ns_Log(Error, "nssmtpd: invalid incoming IP address '%s'", ipString);
    } else {
        while (list) {
            struct NS_SOCKADDR_STORAGE sa;
            struct sockaddr *maskPtr = (struct sockaddr *)&list->mask, *saPtr = (struct sockaddr *)&sa;

            /*
             * Obtain a copy of the incoming IP address and mask it. Then check
             * the masked result with our entry.
             */
            memcpy(&sa, sa_ipPtr, sizeof (struct NS_SOCKADDR_STORAGE));
            Ns_SockaddrMask(saPtr, maskPtr, saPtr);

            if (Ns_SockaddrSameIP(saPtr, (struct sockaddr *)&list->addr) == NS_TRUE) {
                return list;
            }
            list = list->next;
        }
    }
    return NULL;
}

static unsigned int SmtpdFlags(const char *name)
{
    if (!strcasecmp(name, "verified")) {
        return SMTPD_VERIFIED;
    }
    if (!strcasecmp(name, "local")) {
        return SMTPD_LOCAL;
    }
    if (!strcasecmp(name, "relay")) {
        return SMTPD_RELAY;
    }
    if (!strcasecmp(name, "delivered")) {
        return SMTPD_DELIVERED;
    }
    if (!strcasecmp(name, "abort")) {
        return SMTPD_ABORT;
    }
    if (!strcasecmp(name, "needdomain")) {
        return SMTPD_NEEDDOMAIN;
    }
    if (!strcasecmp(name, "segv")) {
        return SMTPD_SEGV;
    }
    if (!strcasecmp(name, "fastproxy")) {
        return SMTPD_FASTPROXY;
    }
    if (!strcasecmp(name, "resolve")) {
        return SMTPD_RESOLVE;
    }
    if (!strcasecmp(name, "needhelo")) {
        return SMTPD_NEEDHELO;
    }
    if (!strcasecmp(name, "gothelo")) {
        return SMTPD_GOTHELO;
    }
    if (!strcasecmp(name, "gotmail")) {
        return SMTPD_GOTMAIL;
    }
    if (!strcasecmp(name, "spamcheck")) {
        return SMTPD_SPAMCHECK;
    }
    if (!strcasecmp(name, "viruscheck")) {
        return SMTPD_VIRUSCHECK;
    }
    if (!strcasecmp(name, "gotspam")) {
        return SMTPD_GOTSPAM;
    }
    if (!strcasecmp(name, "gotvirus")) {
        return SMTPD_GOTVIRUS;
    }
    return 0u;
}

static int SmtpdCmd(ClientData arg, Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj * const objv[])
{
    char          *name = NULL;
    smtpdRcpt     *rcpt;
    smtpdConn     *conn = NULL;
    Tcl_HashEntry *rec;
    smtpdConfig   *config = arg;
    int            cmd, index = -99;
    TCL_SIZE_T     count = 0;
    unsigned int   id;

    enum {
        cmdInfo,
        cmdFlag,
        cmdSend,
        cmdRelay,
        cmdLocal,
        cmdEncode,
        cmdDecode,
        cmdCheckEmail,
        cmdCheckDomain,
        cmdVirusVersion,
        cmdSpamVersion,
        cmdCheckSpam,
        cmdTrainSpam,
        cmdCheckVirus,
        cmdSessions,
        cmdGetHdr,
        cmdGetHdrs,
        cmdGetBody,
        cmdGetFrom,
        cmdGetFromData,
        cmdSetFrom,
        cmdSetFromData,
        cmdGetRcpt,
        cmdGetRcptData,
        cmdAddRcpt,
        cmdSetRcptData,
        cmdDeleteRcpt,
        cmdSetFlag,
        cmdUnsetFlag,
        cmdGetFlag,
        cmdSetReply,
        cmdGetLine,
        cmdDump
    };

    static const char *sCmd[] = {
        "info",
        "flag",
        "send",
        "relay",
        "local",
        "encode",
        "decode",
        "checkemail",
        "checkdomain",
        "virusversion",
        "spamversion",
        "checkspam",
        "trainspam",
        "checkvirus",
        "sessions",
        "gethdr",
        "gethdrs",
        "getbody",
        "getfrom",
        "getfromdata",
        "setfrom",
        "setfromdata",
        "getrcpt",
        "getrcptdata",
        "addrcpt",
        "setrcptdata",
        "delrcpt",
        "setflag",
        "unsetflag",
        "getflag",
        "setreply",
        "getline",
        "dump",
        0
    };

    if (objc < 2) {
        Tcl_AppendResult(interp, "wrong # args: should be ns_smtpd command ?args ...?",
                         (char *)0L);
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK) {
        return TCL_ERROR;
    }

    if (cmd > cmdSessions) {
        int i;
        if (Tcl_GetIntFromObj(interp, objv[2], &i) != TCL_OK) {
            return TCL_ERROR;
        } else {
            id = (unsigned int)i;
        }
        Ns_MutexLock(&config->lock);
        rec = Tcl_FindHashEntry(&config->sessions, (char *)(long) id);
        Ns_MutexUnlock(&config->lock);
        if (!rec) {
            Tcl_AppendResult(interp, "invalid session id: ",
                             Tcl_GetString(objv[2]), (char *)0L);
            return TCL_ERROR;
        }
        conn = Tcl_GetHashValue(rec);
    }

    switch (cmd) {
    case cmdFlag:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 1, objv, "name");
            return TCL_ERROR;
        }
        id = SmtpdFlags(Tcl_GetString(objv[2]));
        if (id == 0) {
            Tcl_AppendResult(interp, "nssmtpd: invalid flag name ",
                             Tcl_GetString(objv[2]), (char *)0L);
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj((int)id));
        break;

    case cmdEncode:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 1, objv, "type text");
            return TCL_ERROR;
        }

        if (!strcmp(Tcl_GetString(objv[2]), "base64")) {
            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = encode64(name, count))) {
                break;
            }
            Tcl_SetResult(interp, name, (Tcl_FreeProc *) ns_free);

        } else if (!strcmp(Tcl_GetString(objv[2]), "hex")) {
            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            name = encodehex(name, (size_t)count);
            if (name == NULL) {
                break;
            }
            Tcl_SetResult(interp, name, (Tcl_FreeProc *) ns_free);

        } else if (!strcmp(Tcl_GetString(objv[2]), "qprint")) {
            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            name = encodeqp(name, (size_t)count);
            if (name == NULL) {
                break;
            }
            Tcl_SetResult(interp, name, (Tcl_FreeProc *) ns_free);

        } else {
            Tcl_AppendResult(interp, "unknown encode type", (char *)0L);
            return TCL_ERROR;
        }
        break;

    case cmdDecode:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 1, objv, "type text");
            return TCL_ERROR;
        }
        if (!strcmp(Tcl_GetString(objv[2]), "base64")) {
            size_t len;

            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = decode64(name, count, &len))) {
                break;
            }
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *) name, (int)len));
            ns_free(name);

        } else if (!strcmp(Tcl_GetString(objv[2]), "hex")) {
            size_t len;

            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = decodehex(name, &len))) {
                break;
            }
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *) name, (int)len));
            ns_free(name);

        } else if (!strcmp(Tcl_GetString(objv[2]), "qprint")) {
            size_t len;

            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = decodeqp(name, count, &len))) {
                break;
            }
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *) name, (int)len));
            ns_free(name);

        } else {
            Tcl_AppendResult(interp, "unknown decode type", (char *)0L);
            return TCL_ERROR;
        }
        break;

    case cmdInfo:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 1, objv, "address|relay|version|server");
            return TCL_ERROR;
        }
        if (!strcasecmp("server", Tcl_GetString(objv[2]))) {
            Tcl_AppendResult(interp, config->server, (char *)0L);

        } else if (!strcasecmp("version", Tcl_GetString(objv[2]))) {
            Tcl_AppendResult(interp, SMTPD_VERSION, (char *)0L);

        } else if (!strcasecmp("address", Tcl_GetString(objv[2]))) {
            if (config->driver != NULL && config->driver->location != NULL) {
                const char *address = strstr(config->driver->location, "://");

                if (address != NULL) {
                    address += 3;
                } else {
                    address = config->driver->location;
                }
                Tcl_AppendResult(interp, address, (char *)0L);
            }

        } else if (!strcasecmp("relay", Tcl_GetString(objv[2]))) {
            Tcl_Obj *obj = Tcl_NewStringObj(config->relayhost, -1);

            Tcl_AppendToObj(obj, ":", -1);
            Tcl_AppendObjToObj(obj, Tcl_NewIntObj(config->relayport));
            Tcl_SetObjResult(interp, obj);
        }
        break;

    case cmdSessions:{
            Tcl_HashSearch search;
            Tcl_Obj       *list = Tcl_NewListObj(0, 0);

            Ns_MutexLock(&config->lock);
            rec = Tcl_FirstHashEntry(&config->sessions, &search);
            while (rec) {
                conn = Tcl_GetHashValue(rec);
                Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj((int)conn->id));
                Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(conn->from.addr, -1));
                for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
                    Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(rcpt->addr, -1));
                    Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj((int)rcpt->flags));
                }
                rec = Tcl_NextHashEntry(&search);
            }
            Ns_MutexUnlock(&config->lock);
            Tcl_SetObjResult(interp, list);
            break;
        }

    case cmdRelay:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 1, objv, "add|check|clear|del|get|set");
            return TCL_ERROR;
        }
        if (!strcasecmp("add", Tcl_GetString(objv[2]))) {
            if (objc < 5) {
                Tcl_WrongNumArgs(interp, 2, objv, "domain");
                return TCL_ERROR;
            }
            if ((name = Tcl_GetString(objv[3]))) {
                smtpdRelay *relay = ns_calloc(1, sizeof(smtpdRelay));

                relay->name = ns_strdup(name);
                if ((relay->host = strchr(relay->name, ':'))) {
                    char *p;

                    *relay->host++ = 0;
                    if ((p = strchr(relay->host, ':'))) {
                        *p++ = 0;
                        relay->port = (unsigned short) strtol(p, NULL, 10);
                    }
                }
                Ns_MutexLock(&config->relaylock);
                relay->next = config->relaylist;
                config->relaylist = relay;
                Ns_MutexUnlock(&config->relaylock);
            }

        } else if (!strcasecmp("check", Tcl_GetString(objv[2]))) {
            smtpdEmail addr;

            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "address");
                return TCL_ERROR;
            }
            name = ns_strdup(Tcl_GetString(objv[3]));
            if (parseEmail(&addr, name)) {
                unsigned short port;
                smtpdConn      sconn;
                char          *host;

                sconn.config = config;
                if (SmtpdCheckRelay(&sconn, &addr, &host, &port)) {
                    char buf[TCL_INTEGER_SPACE+1];

                    sprintf(buf, ":%d", port ? port : DEFAULT_PORT);
                    Tcl_AppendResult(interp, host, buf, (char *)0L);
                    ns_free(host);
                }
            }
            ns_free(name);

        } else if (!strcasecmp("del", Tcl_GetString(objv[2]))) {
            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "domain");
                return TCL_ERROR;
            }

        } else if (!strcasecmp("get", Tcl_GetString(objv[2]))) {
            smtpdRelay *relay;
            Tcl_Obj *list = Tcl_NewListObj(0, 0);

            Ns_MutexLock(&config->relaylock);
            for (relay = config->relaylist; relay != NULL; relay = relay->next) {
                Tcl_Obj *obj = Tcl_NewStringObj(relay->name, -1);

                if (relay->host) {
                    Tcl_AppendStringsToObj(obj, ":", relay->host, (char *)0L);
                    if (relay->port) {
                        Tcl_AppendObjToObj(obj, Tcl_NewIntObj(relay->port));
                    }
                }
                Tcl_ListObjAppendElement(interp, list, obj);
            }
            Ns_MutexUnlock(&config->relaylock);
            Tcl_SetObjResult(interp, list);

        } else if (!strcasecmp("set", Tcl_GetString(objv[2]))) {
            TCL_SIZE_T  i;
            char       *p;
            smtpdRelay *relay;

            Ns_MutexLock(&config->relaylock);
            while (config->relaylist) {
                relay = config->relaylist->next;
                ns_free((char *)config->relaylist->name);
                ns_free(config->relaylist);
                config->relaylist = relay;
            }
            for (i = 3; i < objc; i++) {
                relay = ns_calloc(1, sizeof(smtpdRelay));
                relay->name = ns_strdup(Tcl_GetString(objv[i]));
                if ((relay->host = strchr(relay->name, ':'))) {
                    *relay->host++ = '\0';
                    if ((p = strchr(relay->host, ':'))) {
                        *p++ = '\0';
                        relay->port =  (unsigned short) strtol(p, NULL, 10);
                    }
                }
                relay->next = config->relaylist;
                config->relaylist = relay;
            }
            Ns_MutexUnlock(&config->relaylock);

        } else if (!strcasecmp("clear", Tcl_GetString(objv[2]))) {
            smtpdRelay *relay;

            Ns_MutexLock(&config->relaylock);
            while (config->relaylist) {
                relay = config->relaylist->next;
                ns_free((char *)config->relaylist->name);
                ns_free(config->relaylist);
                config->relaylist = relay;
            }
            Ns_MutexUnlock(&config->relaylock);
        }
        break;

    case cmdLocal:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 1, objv, "add|del|list|clear|check");
            return TCL_ERROR;
        }
        if (!strcasecmp("add", Tcl_GetString(objv[2]))) {
            smtpdIpaddr *addr, *end;
            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "domain|ipaddr");
                return TCL_ERROR;
            }
            Ns_MutexLock(&config->locallock);
            if ((addr = SmtpdParseIpaddr(Tcl_GetString(objv[3])))) {
                for (end = config->local; end != NULL && end->next; end = end->next);
                if (end) {
                    end->next = addr;
                } else {
                    config->local = addr;
                }
            }
            Ns_MutexUnlock(&config->locallock);

        } else if (!strcasecmp("del", Tcl_GetString(objv[2]))) {
            smtpdIpaddr *addr;

            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "domain|ipaddr");
                return TCL_ERROR;
            }
            Ns_MutexLock(&config->locallock);
            if ((addr = SmtpdCheckIpaddr(config->local, Tcl_GetString(objv[3])))) {
                /*
                 * just clear the bits
                 */
                struct sockaddr *addrPtr = (struct sockaddr *)&(addr->addr);
                struct sockaddr *maskPtr = (struct sockaddr *)&(addr->mask);
                unsigned int maskBits = 32u;

                if (addrPtr->sa_family == AF_INET6) {
                    maskBits = 128;
                }
                Ns_SockaddrMaskBits(addrPtr, maskBits);
                Ns_SockaddrMaskBits(maskPtr, maskBits);
            }
            Ns_MutexUnlock(&config->locallock);

        } else if (!strcasecmp("check", Tcl_GetString(objv[2]))) {
            smtpdIpaddr *addr;

            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "ipaddr");
                return TCL_ERROR;
            }
            Ns_MutexLock(&config->locallock);
            addr = SmtpdCheckIpaddr(config->local, Tcl_GetString(objv[3]));
            Ns_MutexUnlock(&config->locallock);
            Tcl_AppendResult(interp, addr ? "1" : "0", (char *)0L);

        } else if (!strcasecmp("get", Tcl_GetString(objv[2]))) {
            smtpdIpaddr *addr;
            Tcl_Obj     *list = Tcl_NewListObj(0, 0);

            Ns_MutexLock(&config->locallock);
            for (addr = config->local; addr != NULL; addr = addr->next) {
                char     ipString[NS_IPADDR_SIZE];
                Tcl_Obj *obj;
                struct sockaddr *saPtr;

                saPtr = (struct sockaddr *)&(addr->addr);
                obj = Tcl_NewStringObj(ns_inet_ntop(saPtr, ipString, sizeof(ipString)), -1);

                saPtr = (struct sockaddr *)&(addr->mask);
                Tcl_AppendStringsToObj(obj, "/",
                                       ns_inet_ntop(saPtr, ipString, sizeof(ipString)),
                                       (char *)0L);

                Tcl_ListObjAppendElement(interp, list, obj);
            }
            Ns_MutexUnlock(&config->locallock);
            Tcl_SetObjResult(interp, list);

        } else if (!strcasecmp("set", Tcl_GetString(objv[2]))) {
            TCL_SIZE_T i;
            smtpdIpaddr *addr, *end = NULL;

            Ns_MutexLock(&config->locallock);
            while (config->local) {
                addr = config->local->next;
                ns_free(config->local);
                config->local = addr;
            }
            for (i = 3; i < objc; i++) {
                if ((addr = SmtpdParseIpaddr(Tcl_GetString(objv[i])))) {
                    if (end) {
                        end->next = addr;
                    } else {
                        config->local = addr;
                    }
                    for (end = addr; end->next != NULL; end = end->next);
                }
            }
            Ns_MutexUnlock(&config->locallock);

        } else if (!strcasecmp("clear", Tcl_GetString(objv[2]))) {
            smtpdIpaddr *addr;

            Ns_MutexLock(&config->locallock);
            while (config->local) {
                addr = config->local->next;
                ns_free(config->local);
                config->local = addr;
            }
            Ns_MutexUnlock(&config->locallock);
        }
        break;

    case cmdSend:{
            unsigned short port = 0u;
            char          *host = NULL;

            if (objc < 5) {
                Tcl_WrongNumArgs(interp, 1, objv, "sender_email rcpt_email data_varname ?server? ?port?");
                return TCL_ERROR;
            }
            if (objc > 5) {
                host = Tcl_GetString(objv[5]);
            }
            if (objc > 6) {
                port =  (unsigned short) strtol(Tcl_GetString(objv[6]), NULL, 10);
            }
            if (host  == NULL || *host == '\0') {
                smtpdEmail addr;
                smtpdConn  sconn;
                char      *email = ns_strdup(Tcl_GetString(objv[3]));

                sconn.config = config;
                if (parseEmail(&addr, email)) {
                    SmtpdCheckRelay(&sconn, &addr, &host, &port);
                }
                ns_free(email);
            }
            if (SmtpdSend(config, interp, Tcl_GetString(objv[2]), objv[3],
                          Tcl_GetString(objv[4]), host, port) != NS_OK) {
                return TCL_ERROR;
            }
            break;
        }

    case cmdGetHdr:{
            smtpdHdr *hdr;
            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "name");
                return TCL_ERROR;
            }
            name = Tcl_GetString(objv[3]);
            for (hdr = conn->body.headers; hdr != NULL; hdr = hdr->next) {
                if (!strcasecmp(name, hdr->name) && hdr->value && *hdr->value) {
                    Tcl_SetObjResult(interp, Tcl_NewStringObj(hdr->value, -1));
                    break;
                }
            }
            break;
        }

    case cmdGetHdrs:{
            Tcl_Obj *item, *list = Tcl_NewListObj(0, 0);
            smtpdHdr *hdr;
            if (objc > 3) {
                name = Tcl_GetString(objv[3]);
            }
            for (hdr = conn->body.headers; hdr != NULL; hdr = hdr->next) {
                if (objc > 3) {
                    if (!strcasecmp(name, hdr->name) && hdr->value && *hdr->value) {
                        Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(hdr->value, -1));
                    }
                } else {
                    item = Tcl_NewListObj(0, 0);
                    Tcl_ListObjAppendElement(interp, item, Tcl_NewStringObj(hdr->name, -1));
                    Tcl_ListObjAppendElement(interp, item, Tcl_NewStringObj(hdr->value, -1));
                    Tcl_ListObjAppendElement(interp, list, item);
                }
            }
            Tcl_SetObjResult(interp, list);
            break;
        }

    case cmdGetBody:{
            Tcl_Obj *obj = Tcl_NewListObj(0, 0);
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(conn->body.data.string, conn->body.data.length));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj((int)conn->body.offset));
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(conn->body.data.length));
            Tcl_SetObjResult(interp, obj);
            break;
        }

    case cmdDump:{
            FILE *fp;
            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "filename");
                return TCL_ERROR;
            }
            if ((fp = fopen(Tcl_GetString(objv[3]), "a"))) {
                fprintf(fp, "From: %s\n", conn->from.addr);
                for (rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next) {
                    fprintf(fp, "To: %s\n", rcpt->addr);
                }
                fputs("\n", fp);
                fwrite(conn->body.data.string, (size_t)conn->body.data.length, 1, fp);
                fputs("\n\n", fp);
                fclose(fp);
            }
            break;
        }

    case cmdGetLine:
        Tcl_SetObjResult(interp, Tcl_NewStringObj(conn->line.string, conn->line.length));
        break;

    case cmdGetFrom:
        Tcl_SetObjResult(interp, Tcl_NewStringObj(conn->from.addr, -1));
        break;

    case cmdGetFromData:
        Tcl_SetObjResult(interp, Tcl_NewStringObj(conn->from.data, -1));
        break;

    case cmdSetFrom:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "address");
            return TCL_ERROR;
        }
        ns_free((char *)conn->from.addr);
        conn->from.addr = ns_strcopy(Tcl_GetString(objv[3]));
        break;

    case cmdSetFromData:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "data");
            return TCL_ERROR;
        }
        ns_free((char *)conn->from.data);
        conn->from.data = ns_strcopy(Tcl_GetString(objv[3]));
        break;

    case cmdGetRcpt:{
            Tcl_Obj *item, *list = Tcl_NewListObj(0, 0);
            if (objc > 3) {
                if ((name = Tcl_GetString(objv[3]))) {
                    if (parseInt(name) && Tcl_GetIntFromObj(interp, objv[3], &index) != TCL_OK) {
                        Tcl_WrongNumArgs(interp, 2, objv, "?address|index?");
                        return TCL_ERROR;
                    }
                }
            }
            for (count = 0, rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next, count++) {
                if (objc > 3) {
                    if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                        Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(rcpt->addr, -1));
                        Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj((int)rcpt->flags));
                        Tcl_ListObjAppendElement(interp, list, Tcl_NewDoubleObj(rcpt->spam_score));
                        break;
                    }
                } else {
                    item = Tcl_NewListObj(0, 0);
                    Tcl_ListObjAppendElement(interp, item, Tcl_NewStringObj(rcpt->addr, -1));
                    Tcl_ListObjAppendElement(interp, item, Tcl_NewIntObj((int)rcpt->flags));
                    Tcl_ListObjAppendElement(interp, item, Tcl_NewDoubleObj(rcpt->spam_score));
                    Tcl_ListObjAppendElement(interp, list, item);
                }
            }
            Tcl_SetObjResult(interp, list);
            break;
        }

    case cmdGetRcptData:
        if (objc > 3) {
            if ((name = Tcl_GetString(objv[3]))) {
                if (parseInt(name) && Tcl_GetIntFromObj(interp, objv[3], &index) != TCL_OK) {
                    Tcl_WrongNumArgs(interp, 2, objv, "?address|index?");
                    return TCL_ERROR;
                }
            }
        }
        for (count = 0, rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next, count++) {
            if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj(rcpt->data, -1));
                break;
            }
        }
        break;

    case cmdSetRcptData:
        if (objc < 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "address|index data");
            return TCL_ERROR;
        }
        if ((name = Tcl_GetString(objv[3]))) {
            if (parseInt(name) && Tcl_GetIntFromObj(interp, objv[3], &index) != TCL_OK) {
                Tcl_WrongNumArgs(interp, 2, objv, "?address|index?");
                return TCL_ERROR;
            }
        }
        for (count = 0, rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next, count++) {
            if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                ns_free((char *)rcpt->data);
                rcpt->data = ns_strcopy(Tcl_GetString(objv[4]));
                break;
            }
        }
        break;

    case cmdSetFlag:{
            unsigned int flags;
            int          i;

            if (objc < 5) {
                Tcl_WrongNumArgs(interp, 2, objv, "address|index flag");
                return TCL_ERROR;
            }
            if ((name = Tcl_GetString(objv[3]))) {
                if (parseInt(name) && Tcl_GetIntFromObj(interp, objv[3], &index) != TCL_OK) {
                    Tcl_WrongNumArgs(interp, 2, objv, "?address|index?");
                    return TCL_ERROR;
                }
            }
            /* Flag can be name or integer */
            if (Tcl_GetIntFromObj(0, objv[4], &i) != TCL_OK) {
                if (!(flags = SmtpdFlags(Tcl_GetString(objv[4])))) {
                    Tcl_AppendResult(interp, "nssmtpd: invalid flag:",
                                     Tcl_GetString(objv[4]), (char *)0L);
                    return TCL_ERROR;
                }
            } else {
                flags = (unsigned int)i;
            }
            /* Set global connection's flags */
            if (index == -1) {
                if (flags > 0) {
                    conn->flags |= flags;
                } else {
                    conn->flags &= (unsigned int)(~((int)flags * -1));
                }
                Tcl_SetObjResult(interp, Tcl_NewIntObj((int)(conn->flags)));
                break;
            }
            /* Set recipient's flags */
            for (count = 0, rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next, count++) {
                if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                    if (flags > 0) {
                        rcpt->flags |= flags;
                    } else {
                        rcpt->flags &= (unsigned int)(~((int)flags * -1));
                    }
                    Tcl_SetObjResult(interp, Tcl_NewIntObj((int)(rcpt->flags)));
                    break;
                }
            }
            break;
        }

    case cmdUnsetFlag:{
            unsigned int flags;
            int          i;

            if (objc < 5) {
                Tcl_WrongNumArgs(interp, 2, objv, "address|index flag");
                return TCL_ERROR;
            }
            if ((name = Tcl_GetString(objv[3]))) {
                if (parseInt(name) && Tcl_GetIntFromObj(interp, objv[3], &index) != TCL_OK) {
                    Tcl_WrongNumArgs(interp, 2, objv, "?address|index?");
                    return TCL_ERROR;
                }
            }
            /* Flag can be name or integer */
            if (Tcl_GetIntFromObj(0, objv[4], &i) != TCL_OK) {
                if (!(flags = SmtpdFlags(Tcl_GetString(objv[4])))) {
                    Tcl_AppendResult(interp, "nssmtpd: invalid flag:",
                                     Tcl_GetString(objv[4]), (char *)0L);
                    return TCL_ERROR;
                }
            } else {
                flags = (unsigned int)i;
            }
            /* Set global connection's flags */
            if (index == -1) {
                conn->flags &= ~flags;
                Tcl_SetObjResult(interp, Tcl_NewIntObj((int)(conn->flags)));
                break;
            }
            /* Set recipient's flags */
            for (count = 0, rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next, count++) {
                if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                    rcpt->flags &= ~flags;
                    Tcl_SetObjResult(interp, Tcl_NewIntObj((int)(rcpt->flags)));
                    break;
                }
            }
            break;
        }

    case cmdGetFlag:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "?address|index?");
            return TCL_ERROR;
        }
        if ((name = Tcl_GetString(objv[3]))) {
            if (parseInt(name) && Tcl_GetIntFromObj(interp, objv[3], &index) != TCL_OK) {
                Tcl_WrongNumArgs(interp, 2, objv, "?address|index?");
                return TCL_ERROR;
            }
        }
        /* Global connection's flags */
        if (index == -1) {
            Tcl_SetObjResult(interp, Tcl_NewIntObj((int)(conn->flags)));
            return TCL_OK;
        }
        /* Recipient's flags */
        for (count = 0, rcpt = conn->rcpt.list; rcpt != NULL; rcpt = rcpt->next, count++) {
            if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                Tcl_SetObjResult(interp, Tcl_NewIntObj((int)rcpt->flags));
                return TCL_OK;
            }
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
        break;

    case cmdAddRcpt:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "address ?flags? ?data?");
            return TCL_ERROR;
        }
        rcpt = ns_calloc(1, sizeof(smtpdRcpt));
        rcpt->addr = ns_strdup(Tcl_GetString(objv[3]));
        { int flags = 0;
            if ((objc > 4 && Tcl_GetIntFromObj(interp, objv[4], &flags) != TCL_OK) || (flags < 0)) {
            return TCL_ERROR;
          }
          rcpt->flags = (unsigned int)flags;
        }
        if (objc > 5) {
            rcpt->data = ns_strcopy(Tcl_GetString(objv[5]));
        }
        rcpt->next = conn->rcpt.list;
        conn->rcpt.list = rcpt;
        conn->rcpt.count++;
        break;

    case cmdDeleteRcpt:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "address|index");
            return TCL_ERROR;
        }
        if ((name = Tcl_GetString(objv[3]))) {
            if (parseInt(name) && Tcl_GetIntFromObj(interp, objv[3], &index) != TCL_OK) {
                Tcl_WrongNumArgs(interp, 2, objv, "?address|index?");
                return TCL_ERROR;
            }
        }
        SmtpdRcptFree(conn, name, index, 0);
        break;

    case cmdSetReply:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "reply");
            return TCL_ERROR;
        }
        Tcl_DStringSetLength(&conn->reply, 0);
        Tcl_DStringAppend(&conn->reply, Tcl_GetString(objv[3]), TCL_INDEX_NONE);
        break;

    case cmdCheckDomain:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "domain");
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj(SmtpdCheckDomain(0, Tcl_GetString(objv[2]))));
        break;

    case cmdCheckEmail:{
            smtpdEmail addr;
            if (objc < 3) {
                Tcl_WrongNumArgs(interp, 1, objv, "email");
                return TCL_ERROR;
            }
            if (parseEmail(&addr, Tcl_GetString(objv[2])))
                Tcl_AppendResult(interp, addr.mailbox, "@", addr.domain, (char *)0L);
            break;
        }

    case cmdSpamVersion:
#ifdef USE_DSPAM
        Tcl_AppendResult(interp, "DSPAM", (char *)0L);
#endif

#ifdef USE_SPAMASSASSIN
        Tcl_AppendResult(interp, "SpamAssassin", (char *)0L);
#endif
        break;

    case cmdCheckSpam:{
            Ns_Sock sock;
            char score[12];
            smtpdConn *sconn;

            if (objc < 3) {
                Tcl_WrongNumArgs(interp, 2, objv, "message ?email?");
                return TCL_ERROR;
            }
            sock.sock = -1;
            sconn = SmtpdConnCreate(config, &sock);
            Tcl_DStringAppend(&sconn->body.data, Tcl_GetString(objv[2]), TCL_INDEX_NONE);
            sconn->rcpt.list = ns_calloc(1, sizeof(smtpdRcpt));
            sconn->rcpt.list->flags |= SMTPD_SPAMCHECK;
            sconn->rcpt.list->addr = ns_strdup(objc > 3 ? Tcl_GetString(objv[3]) : "smtpd");
            SmtpdCheckSpam(sconn);
            sprintf(score, "%.2f", sconn->rcpt.list->spam_score);
            Tcl_AppendResult(interp,
                             ((sconn->rcpt.list->flags & SMTPD_GOTSPAM) != 0u) ? "Spam" : "Innocent",
                             " ", score, " ",
                             SmtpdGetHeader(sconn, SMTPD_HDR_SIGNATURE), (char *)0L);
            SmtpdConnFree(sconn);
            break;
        }

    case cmdTrainSpam:{
#ifdef USE_DSPAM
            Tcl_DString ds;
            DSPAM_CTX *CTX;
            struct _ds_spam_signature SIG;
            unsigned int flags = DSF_CHAINED | DSF_NOISE;

            if (objc < 5) {
                Tcl_WrongNumArgs(interp, 2, objv, "1|0 email message ?signature? ?mode? ?source?");
                return TCL_ERROR;
            }
            if (objc > 5) {
                if ((SIG.data = decodehex(Tcl_GetString(objv[5]), &SIG.length))) {
                    flags |= DSF_SIGNATURE;
                }
            }
            if (!(CTX = dspam_init(Tcl_GetString(objv[3]), NULL, DSM_PROCESS, flags)))
                break;
            CTX->source = DSS_ERROR;
            CTX->classification = atoi(Tcl_GetString(objv[2])) ? DSR_ISSPAM : DSR_ISINNOCENT;
            if (objc > 6) {
                if (!strcmp(Tcl_GetString(objv[6]), "teft"))
                    CTX->training_mode = DST_TEFT;
                else if (!strcmp(Tcl_GetString(objv[6]), "toe"))
                    CTX->training_mode = DST_TOE;
                else if (!strcmp(Tcl_GetString(objv[6]), "tum"))
                    CTX->training_mode = DST_TUM;
            }
            if (objc > 7) {
                if (!strcmp(Tcl_GetString(objv[7]), "error"))
                    CTX->source = DSS_ERROR;
                else if (!strcmp(Tcl_GetString(objv[7]), "corpus"))
                    CTX->source = DSS_CORPUS;
                else if (!strcmp(Tcl_GetString(objv[7]), "inoculation"))
                    CTX->source = DSS_INOCULATION;
                else if (!strcmp(Tcl_GetString(objv[7]), "none"))
                    CTX->source = DSS_NONE;
            }
            if ((flags & DSF_SIGNATURE) != 0u)
                CTX->signature = &SIG;
            dspam_process(CTX, Tcl_GetString(objv[4]));
            if ((flags & DSF_SIGNATURE) != 0u)
                ns_free(SIG.data);
            Tcl_DStringInit(&ds);
            Ns_DStringPrintf(&ds, "Flags: 0x%X, Source: 0x%X, Mode: 0x%X, Probability: %2.4f, Confidence: %2.4f, Result: %s",
                             flags,
                             CTX->source,
                             CTX->training_mode,
                             CTX->probability,
                             CTX->confidence,
                             CTX->result == DSR_ISSPAM ? "Spam" :
                             CTX->result == DSR_ISINNOCENT ? "Innocent" :
                             CTX->result == DSR_ISWHITELISTED ? "Whitelisted" : "Error");
            Tcl_AppendResult(interp, ds.string, (char *)0L);
            Tcl_DStringFree(&ds);
            _ds_destroy_message(CTX->message);
            dspam_destroy(CTX);
#endif
            break;
        }

    case cmdVirusVersion:
#ifdef USE_SAVI
        Tcl_AppendResult(interp, "Sophos", (char *)0L);
#endif
#ifdef USE_CLAMAV
        Tcl_AppendResult(interp, "ClamAV", (char *)0L);
#endif
        break;

    case cmdCheckVirus:{
            Ns_Sock sock;
            smtpdConn *sconn;

            if (objc < 3) {
                Tcl_WrongNumArgs(interp, 2, objv, "data");
                return TCL_ERROR;
            }
            sock.sock = -1;
            sconn = SmtpdConnCreate(config, &sock);
            sconn->interp = interp;
            if (Tcl_GetString(objv[2])[0] == '/') {
                SmtpdCheckVirus(sconn, Tcl_GetString(objv[2]), 0, 0);
            } else {
                SmtpdCheckVirus(sconn, Tcl_GetString(objv[2]), Tcl_GetCharLength(objv[2]), 0);
            }
            if ((sconn->flags & SMTPD_GOTVIRUS) != 0u) {
                Tcl_AppendResult(interp, SmtpdGetHeader(sconn, SMTPD_HDR_VIRUS_STATUS), (char *)0L);
            }
            SmtpdConnFree(conn);
            break;
        }
    }

    return TCL_OK;
}

static bool parseEmail(smtpdEmail *addr, char *str)
{
    int tok = ' ', ingroup = 0;
    char *phrase, *mailbox, *domain, *comment;

    while (tok) {
        tok = parsePhrase(&str, &phrase, ingroup ? ",%@<;" : ",%@<:");
        switch (tok) {
        case ',':
        case '\0':
        case ';':
            if (tok == ';') {
                ingroup = 0;
            }
            break;

        case ':':
            ingroup++;
            break;

        case '%':
        case '@':
            (void) parseDomain(&str, &domain, &comment);
            if (!*phrase || !*domain) {
                return NS_FALSE;
            }
            addr->name = comment;
            addr->mailbox = phrase;
            addr->domain = domain;
            return NS_TRUE;

        case '<':
            tok = parsePhrase(&str, &mailbox, "%@>");
            switch (tok) {
            case '%':
            case '@':
                if (!*mailbox) {
                    *--str = '@';
                    tok = parseRoute(&str, &comment);
                    if (tok != ':') {
                        while (tok && tok != '>') {
                            tok = *str++;
                        }
                        continue;
                    }
                    tok = parsePhrase(&str, &mailbox, "%@>");
                    if (tok != '@' && tok != '%') {
                        continue;
                    }
                }
                (void) parseDomain(&str, &domain, 0);
                if (!*mailbox || !*domain) {
                    return NS_FALSE;
                }
                addr->name = phrase;
                addr->mailbox = mailbox;
                addr->domain = domain;
                return NS_TRUE;
            }
        }
    }
    return NS_FALSE;
}

/*
 * Parse an RFC 822 "phrase",stopping at 'specials'
 */
static int parsePhrase(char **inp, char **phrasep, const char *specials)
{
    char *src = *inp, *dst;

    src = parseSpace(src);
    *phrasep = dst = src;
    for (;;) {
        char c = *src++;

        if (c == '\"') {
            while ((c = *src)) {
                src++;
                if (c == '\"') {
                    break;
                }
                if (c == '\\') {
                    if (!(c = *src)) {
                        break;
                    }
                    src++;
                }
                *dst++ = c;
            }

        } else if (isspace(c) || c == '(') {
            src--;
            src = parseSpace(src);
            *dst++ = ' ';

        } else if (!c || strchr(specials, c)) {
            if (dst > *phrasep && dst[-1] == ' ') {
                dst--;
            }
            *dst = '\0';
            *inp = src;
            return c;

        } else {
            *dst++ = c;
        }
    }
}

/*
 * Parse a domain.  If 'commentp' is non-nil,parses any trailing comment
 */
static int parseDomain(char **inp, char **domainp, char **commentp)
{
    int comment;
    char *src = *inp, *dst, *cdst;

    if (commentp) {
        *commentp = NULL;
    }
    src = parseSpace(src);
    *domainp = dst = src;
    for (;;) {
        char c = *src++;

        if (isalnum(c) || c == '-' || c == '[' || c == ']') {
            *dst++ = c;
            if (commentp) {
                *commentp = NULL;
            }

        } else if (c == '.') {
            if (dst > *domainp && dst[-1] != '.') {
                *dst++ = c;
            }
            if (commentp) {
                *commentp = NULL;
            }

        } else if (c == '(') {
            if (commentp) {
                *commentp = cdst = src;
                comment = 1;
                while (comment && (c = *src)) {
                    src++;
                    if (c == '(') {
                        comment++;
                    } else if (c == ')') {
                        comment--;
                    } else if (c == '\\' && (c = *src)) {
                        src++;
                    }
                    if (comment) {
                        *cdst++ = c;
                    }
                }
                *cdst = '\0';
            } else {
                src--;
                src = parseSpace(src);
            }

        } else if (!isspace(c)) {
            if (dst > *domainp && dst[-1] == '.') {
                dst--;
            }
            *dst = '\0';
            *inp = src;
            return c;
        }
    }
}

/*
 * Parse a source route (at-domain-list)
 */
static int parseRoute(char **inp, char **routep)
{
    char *src = *inp, *dst;

    src = parseSpace(src);
    *routep = dst = src;
    for (;;) {
        char c = *src++;
        if (isalnum(c) || c == '-' || c == '[' || c == ']' || c == ',' || c == '@') {
            *dst++ = c;
        } else if (c == '.') {
            if (dst > *routep && dst[-1] != '.') {
                *dst++ = c;
            }
        } else if (isspace(c) || c == '(') {
            src--;
            src = parseSpace(src);
        } else {
            while (dst > *routep && (dst[-1] == '.' || dst[-1] == ',' || dst[-1] == '@')) {
                dst--;
            }
            *dst = '\0';
            *inp = src;
            return c;
        }
    }
}

/*
 * Parse comments and whitespaces
 */
static char *parseSpace(char *s)
{
    int c, comment;

    while ((c = *s)) {
        if (c == '(') {
            comment = 1;
            s++;
            while ((comment && (c = *s))) {
                s++;
                if (c == '\\' && *s) {
                    s++;
                } else if (c == '(') {
                    comment++;
                } else if (c == ')') {
                    comment--;
                }
            }
            s--;
        } else if (!isspace(c)) {
            break;
        }
        s++;
    }
    return s;
}

static int parseInt(char *val)
{
    if (val == NULL || *val == 0) {
        return 0;
    }
    // Skip leading spaces
    while (isspace(*val)) {
        val++;
    }
    // Check for minus sign
    if (!isdigit(*val)) {
        if (*val != '-') {
            return 0;
        }
        val++;
    }
    while (*val) {
        if (!isdigit(*val)) {
            return 0;
        }
        val++;
    }
    return 1;
}

static char *encodehex(const char *buf, size_t len)
{
    char *s;

    if (!buf || !*buf || !len) {
        s = NULL;
    } else {
        size_t i, j;

        s = ns_calloc(2, len + 1);
        for (j = 0, i = 0; i < len; i++) {
            s[j++] = hex[(buf[i] >> 4) & 0x0F];
            s[j++] = hex[buf[i] & 0x0F];
        }
    }
    return s;
}

static char *decodehex(const char *str, size_t *len)
{
    size_t count = 0u;
    char *p, *t, *s, code[] = "00";

    if (!str || !*str || !len) {
        return 0;
    }
    *len = strlen(str) / 2;

    t = p = ns_calloc(1, *len);
    for (s = (char *) str; *s != '\0' && count < *len; count++) {
        if (!isxdigit(*s) || !isxdigit(*(s + 1))) {
            ns_free(p);
            return 0;
        }
        code[0] = *s++;
        code[1] = *s++;
        *t++ = (char) strtol(code, NULL, 16);
    }
    return p;
}

static char *encode64(const char *in, TCL_SIZE_T len)
{
    static unsigned char basis_64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????";
    unsigned char *out, *buf;

    buf = out = ns_malloc((unsigned) (len + 2) / 3 * 4 + 1);

    while (len >= 3) {
        *out++ = basis_64[in[0] >> 2];
        *out++ = basis_64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
        *out++ = basis_64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
        *out++ = basis_64[in[2] & 0x3f];
        in += 3;
        len -= 3;
    }
    if (len > 0) {
        unsigned char oval;

        *out++ = basis_64[in[0] >> 2];
        oval = (in[0] << 4) & 0x30;
        if (len > 1) {
            oval |= (unsigned char)(in[1] >> 4);
        }
        *out++ = basis_64[oval];
        *out++ = (len < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }
    *out = '\0';
    return (char *) buf;
}

static char *decode64(const char *in, TCL_SIZE_T len, size_t *outlen)
{
    char *out, *buf;
    int   i, d = 0, dlast = 0, phase = 0;
    static int table[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 00-0F */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 10-1F */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 20-2F */
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 30-3F */
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,   /* 40-4F */
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 50-5F */
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 60-6F */
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 70-7F */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 80-8F */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 90-9F */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* A0-AF */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* B0-BF */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* C0-CF */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* D0-DF */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* E0-EF */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /* F0-FF */
    };

    out = buf = ns_malloc((unsigned) len + 1);
    *outlen = 0;

    for (i = 0; i < len; ++i) {
        if (in[i] == '\n' || in[i] == '\r') {
            continue;
        }
        d = table[(unsigned char) in[i]];
        if (d != -1) {
            switch (phase) {
            case 0:
                ++phase;
                break;
            case 1:
                *out++ = (char)((dlast << 2) | ((d & 0x30) >> 4));
                ++phase;
                break;
            case 2:
                *out++ = (char)(((dlast & 0xf) << 4) | ((d & 0x3c) >> 2));
                ++phase;
                break;
            case 3:
                *out++ = (char)(((dlast & 0x03) << 6) | d);
                phase = 0;
                break;
            }
            dlast = d;
        }
    }
    *out = 0;
    *outlen = (size_t)(out - buf);
    return buf;
}

static char *encodeqp(const char *in, size_t len)
{
    int   i = 0;
    char *buf, *out;

    buf = out = ns_malloc((unsigned) (3 * len + (6 * len) / 75 + 3));
    while (len--) {
        char c;

        if ((c = *in++) == '\r' && *in == '\n' && len) {
            *out++ = '\r';
            *out++ = *in++;
            len--;
            i = 0;
        } else {
            if (iscntrl(c) || c == 0x7f || c & 0x80 || c == '=' || (c == ' ' && *in == '\r')) {
                if ((i += 3) > 75) {
                    *out++ = '=';
                    *out++ = '\r';
                    *out++ = '\n';
                    i = 3;
                }
                *out++ = '=';
                *out++ = hex[c >> 4];
                *out++ = hex[c & 0xf];
            } else {
                if ((++i) > 75) {
                    *out++ = '=';
                    *out++ = '\r';
                    *out++ = '\n';
                    i = 1;
                }
                *out++ = c;
            }
        }
    }
    *out = '\0';
    return buf;
}

static char *decodeqp(const char *in, TCL_SIZE_T len, size_t *outlen)
{
    char c2, *out, *buf, *ptr, *s;

    s = (char *) in;
    ptr = buf = out = ns_malloc((unsigned) len + 1);

    while (s - in < len) {
        char c;

        switch (c = *s++) {
        case '=':
            if (s - in < len)
                switch (c = *s++) {
                case 0:
                    s--;
                    break;
                case '\r':
                    if (s - in < len && *s == '\n') {
                        s++;
                    }
                    NS_FALL_THROUGH;
                case '\n':
                    ptr = out;
                    break;
                default:
                    if (!(isxdigit(c) && s - in < len && (c2 = *s++) && isxdigit(c2))) {
                        ns_free(buf);
                        return 0;
                    }
                    if (isdigit(c)) {
                        c = (char)(c - '0');
                    } else {
                        c = (char) (c - (isupper(c) ? 'A' - 10 : 'a' - 10));
                    }
                    if (isdigit(c2)) {
                        c2 = (char)(c2 - '0');
                    } else {
                        c2 = (char)(c2 - (isupper(c2) ? 'A' - 10 : 'a' - 10));
                    }
                    *out++ = (char)(c2 + (c << 4));
                    ptr = out;
                    break;
                }
            break;
        case ' ':
            *out++ = c;
            break;
        case '\r': NS_FALL_THROUGH;
        case '\n':
            out = ptr;
            NS_FALL_THROUGH;
        default:
            *out++ = c;
            ptr = out;
        }
    }
    *out = 0;
    *outlen = (size_t)(out - buf);
    return buf;
}

static void dnsInit(const char *name, ...)
{
    va_list ap;

    Ns_MutexLock(&dnsMutex);
    va_start(ap, name);

    if (!strcmp(name, "nameserver")) {
        char      *s, *n;
        dnsServer *server, *next;

        while ((s = va_arg(ap, char *))) {
            while (s) {
                if ((n = strchr(s, ','))) {
                    *n++ = '\0' ;
                }
                server = ns_calloc(1, sizeof(dnsServer));
                server->name = ns_strdup(s);
                //server->ipaddr = inet_addr(s);
                for (next = dnsServers; next != NULL && next->next != NULL; next = next->next);
                if (!next) {
                    dnsServers = server;
                } else {
                    next->next = server;
                }
                s = n;
            }
        }
    } else if (!strcmp(name, "debug")) {
        dnsDebug = va_arg(ap, int);
    } else if (!strcmp(name, "retry")) {
        dnsResolverRetries = va_arg(ap, int);
    } else if (!strcmp(name, "timeout")) {
        dnsResolverTimeout = va_arg(ap, int);
    } else if (!strcmp(name, "failuretimeout")) {
        dnsFailureTimeout = va_arg(ap, int);
    } else if (!strcmp(name, "ttl")) {
         dnsTTL = va_arg(ap, unsigned long);
    }
    va_end(ap);
    Ns_MutexUnlock(&dnsMutex);
}

static dnsPacket *dnsLookup(const char *name, unsigned short type, int *errcode)
{
    char       buf[DNS_BUFSIZE];
    dnsServer *server = NULL;
    dnsPacket *req, *reply;
    int        sock = NS_INVALID_SOCKET;
    socklen_t  socklen;

    if (name == NULL) {
        return NULL;
    }

    // Prepare DNS request packet
    req = ns_calloc(1, sizeof(dnsPacket));
    req->id = (unsigned short)((unsigned long) req % (unsigned long) name);
    DNS_SET_RD(req->u, 1);
    req->buf.allocated = DNS_REPLY_SIZE;
    req->buf.data = ns_calloc(1, req->buf.allocated);
    {
        dnsRecord *rec = ns_calloc(1, sizeof(dnsRecord));

        rec->name = ns_strcopy(name);
        rec->type = type;
        rec->class = DNS_CLASS_INET;
        rec->len = 4;
        rec->ttl = dnsTTL;
        dnsRecordAppend(&req->qdlist, rec);
        req->qdcount++;
    }
    dnsEncodePacket(req);

    while (1) {
        int    retries, rc;
        time_t now;
        struct NS_SOCKADDR_STORAGE sa;
        struct sockaddr           *saPtr = (struct sockaddr *)&sa;

        now = time(0);
        Ns_MutexLock(&dnsMutex);
        retries = dnsResolverRetries;
        if (server) {
            /* Disable only if we have more than one server */
            if (++server->fail_count > 2 && dnsServers->next) {
                server->fail_time = now;
                Ns_Log(Error, "dnsLookup: %s: nameserver disabled", server->name);
            }
            server = server->next;
        } else {
            server = dnsServers;
        }
        while (server) {
            if (server->fail_time != 0 && ((int)(now - server->fail_time) > dnsFailureTimeout)) {
                server->fail_count = 0;
                server->fail_time = 0;
                Ns_Log(Error, "dnsLookup: %s: nameserver re-enabled", server->name);
            }
            if (server->fail_time == 0) {
                break;
            }
            server = server->next;
        }
        Ns_MutexUnlock(&dnsMutex);
        if (!server) {
            break;
        }
        if (dnsDebug > 5) {
            Ns_Log(Error, "dnsLookup: %s: resolving %s...", server->name, name);
        }

        // todo: don't hard-code port 53 (DNS port)
        rc = Ns_GetSockAddr(saPtr, server->name, 53);
        if (rc != TCL_OK) {
            Ns_Log(Error, "dnsLookup: invalid server name '%s'", server->name);
            return 0;
        }

        if (sock == NS_INVALID_SOCKET) {
            if ((sock = socket(saPtr->sa_family, SOCK_DGRAM, 0)) < 0) {
                if (errcode) {
                    *errcode = errno;
                }
                return 0;
            }
        }

        while (retries--) {
            ssize_t       size;
            struct pollfd pfds[1];
            int           n;

            socklen = sizeof(struct sockaddr_in);
            if (sendto(sock, req->buf.data + 2, req->buf.size, 0, saPtr, socklen) < 0) {
                if (dnsDebug > 3) {
                    Ns_Log(Error, "dnsLookup: %s: sendto: %s", server->name, strerror(errno));
                }
                continue;
            }

            pfds[0].fd = sock;
            pfds[0].events = (short)POLLIN;
            pfds[0].revents = 0;

            do {
                n = ns_poll(pfds, 1, dnsResolverTimeout*1000);
            } while (n < 0  && errno == NS_EINTR);

            if (n < 0) {
                if (dnsDebug > 3 && errno) {
                    Ns_Log(Error, "dnsLookup: %s: select: %s", server->name,
                           ns_sockstrerror(errno));
                }
                continue;
            }

            if ((size = recv(sock, buf, DNS_BUFSIZE, 0)) <= 0) {
                if (dnsDebug > 3) {
                    Ns_Log(Error, "dnsLookup: %s: recvfrom: %s", server->name, strerror(errno));
                }
                continue;
            }
            if (!(reply = dnsParsePacket((unsigned char *) buf, (size_t)size))) {
                continue;
            }
            // DNS packet id should be the same
            if (reply->id == req->id) {
                ns_sockclose(sock);
                dnsPacketFree(req, 0);
                Ns_MutexLock(&dnsMutex);
                server->fail_count = 0;
                server->fail_time = 0;
                Ns_MutexUnlock(&dnsMutex);
                return reply;
            }
            dnsPacketFree(reply, 0);
        }
    }
    dnsPacketFree(req, 0);
    ns_sockclose(sock);
    if (errcode) {
        *errcode = ENOENT;
    }
    return 0;
}

static void dnsRecordFree(dnsRecord *pkt)
{
    if (pkt != NULL) {
        return;
    }
    ns_free((char *)pkt->name);
    switch (pkt->type) {
    case DNS_TYPE_MX:
        if (!pkt->data.mx) {
            break;
        }
        ns_free((char *)pkt->data.mx->name);
        ns_free(pkt->data.mx);
        break;
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        ns_free((char*)pkt->data.name);
        break;
    case DNS_TYPE_SOA:
        if (!pkt->data.soa) {
            break;
        }
        ns_free((char*)pkt->data.soa->mname);
        ns_free((char*)pkt->data.soa->rname);
        ns_free(pkt->data.soa);
        break;
    }
    ns_free(pkt);
}

static void dnsRecordDestroy(dnsRecord **pkt)
{
    if (!pkt) {
        return;
    }
    while (*pkt) {
        dnsRecord *next = (*pkt)->next;
        dnsRecordFree(*pkt);
        *pkt = next;
    }
}

static dnsRecord *dnsRecordAppend(dnsRecord ** list, dnsRecord *pkt)
{
    if (list == NULL || pkt == NULL) {
        return NULL;
    }
    for (; *list != NULL; list = &(*list)->next);
    *list = pkt;
    return *list;
}

static int dnsParseName(dnsPacket *pkt, char **ptr, char *buf, int buflen, int pos, int level)
{
    unsigned short i, len, offset;
    char          *p;

    if (level > 15) {
        Ns_Log(Error, "nsdns: infinite loop %ld: %d", (*ptr - pkt->buf.data) - 2, level);
        return -9;
    }
    while ((len = (unsigned short)*((*ptr)++)) != 0) {
        switch (len & 0xC0) {
        case 0xC0:
            offset = (unsigned short)(((len & ~0xC0) << 8) + (u_char) **ptr);
            if (offset >= pkt->buf.size) {
                return -1;
            }
            (*ptr)++;
            p = &pkt->buf.data[offset + 2];
            return dnsParseName(pkt, &p, buf, buflen, pos, level + 1);
        case 0x80:
        case 0x40:
            return -2;
        }
        if (len > buflen) {
            return -3;
        }
        for (i = 0; i < len; i++) {
            if (--buflen <= 0) {
                return -4;
            }
            buf[pos++] = **ptr;
            (*ptr)++;
        }
        if (--buflen <= 0) {
            return -5;
        }
        buf[pos++] = '.';
    }
    buf[pos] = '\0';
    // Remove last . in the name
    if (buf[pos - 1] == '.') {
        buf[pos - 1] = '\0' ;
    }
    return pos;
}

static dnsPacket *dnsParseHeader(void *buf, size_t size)
{
    unsigned short *p;
    dnsPacket *pkt;

    pkt = ns_calloc(1, sizeof(dnsPacket));
    p = (unsigned short *) buf;
    pkt->id = ntohs(p[0]);
    pkt->u = ntohs(p[1]);
    pkt->qdcount = ntohs(p[2]);
    pkt->ancount = ntohs(p[3]);
    pkt->nscount = ntohs(p[4]);
    pkt->arcount = ntohs(p[5]);
    /* First two bytes are reserved for packet length
       in TCP mode plus some overhead in case we compress worse
       than it was */
    pkt->buf.allocated = (unsigned short)(size + 128u);
    pkt->buf.data = ns_malloc(pkt->buf.allocated);
    pkt->buf.size = (unsigned short)size;
    memcpy(pkt->buf.data + 2, buf, (unsigned) size);
    pkt->buf.ptr = &pkt->buf.data[DNS_HEADER_LEN + 2];
    return pkt;
}

static dnsRecord *dnsParseRecord(dnsPacket *pkt, int query)
{
    int rc;
    //int offset;
    char name[256] = {'\0'};
    dnsRecord *y;

    Ns_Log(SmtpdDebug, "dnsParseRecord");

    y = ns_calloc(1, sizeof(dnsRecord));
    //offset = (pkt->buf.ptr - pkt->buf.data) - 2;
    // The name of the resource
    if ((rc = dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0)) < 0) {
        snprintf(name, 255, "invalid name: %d %s: ", rc, pkt->buf.ptr);
        goto err;
    }
    y->name = ns_strdup(name);
    // The type of data
    if (pkt->buf.ptr + 2 > pkt->buf.data + pkt->buf.allocated) {
        strcpy(name, "invalid type position");
        goto err;
    }
    y->type = ntohs(*((unsigned short *) pkt->buf.ptr));
    pkt->buf.ptr += 2;
    // The class type
    if (pkt->buf.ptr + 2 > pkt->buf.data + pkt->buf.allocated) {
        strcpy(name, "invalid class position");
        goto err;
    }
    y->class = ntohs(*((unsigned short *) pkt->buf.ptr));
    pkt->buf.ptr += 2;
    // Query block stops here
    if (query) {
        goto rec;
    }
    // Answer blocks carry a TTL and the actual data.
    if (pkt->buf.ptr + 4 > pkt->buf.data + pkt->buf.allocated) {
        strcpy(name, "invalid TTL position");
        goto err;
    }
    y->ttl = ntohl(*((unsigned *) pkt->buf.ptr));
    pkt->buf.ptr += 4;
    // Fetch the resource data.
    if (pkt->buf.ptr + 2 > pkt->buf.data + pkt->buf.allocated) {
        strcpy(name, "invalid data position");
        goto err;
    }
    if (!(y->len = (short)ntohs(*((unsigned short *) pkt->buf.ptr)))) {
        strcpy(name, "empty data len");
        goto err;
    }
    pkt->buf.ptr += 2;
    if (pkt->buf.ptr + y->len > pkt->buf.data + pkt->buf.allocated) {
        strcpy(name, "invalid data len");
        goto err;
    }
    switch (y->type) {
    case DNS_TYPE_AAAA:
        Ns_Log(Notice, "AAAA records are not implemented yet");
        break;
    case DNS_TYPE_A:
        memcpy(&y->data.ipaddr, pkt->buf.ptr, 4);
        pkt->buf.ptr += 4;
        break;
    case DNS_TYPE_MX:
        y->data.soa = ns_calloc(1, sizeof(dnsSOA));
        y->data.mx->preference = ntohs(*((unsigned short *) pkt->buf.ptr));
        pkt->buf.ptr += 2;
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0) {
            goto err;
        }
        y->data.mx->name = ns_strcopy(name);
        break;
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        //offset = (pkt->buf.ptr - pkt->buf.data) - 2;
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0) {
            goto err;
        }
        y->data.name = ns_strdup(name);
        break;
    case DNS_TYPE_SOA:
        y->data.soa = ns_calloc(1, sizeof(dnsSOA));
        /* MNAME */
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0)
            goto err;
        y->data.soa->mname = ns_strdup(name);
        /* RNAME */
        if (dnsParseName(pkt, &pkt->buf.ptr, name, 255, 0, 0) < 0) {
            goto err;
        }
        y->data.soa->rname = ns_strdup(name);
        if (pkt->buf.ptr + 20 > pkt->buf.data + pkt->buf.allocated) {
            strcpy(name, "invalid SOA data len");
            goto err;
        }
        y->data.soa->serial = ntohl(*((unsigned *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
        y->data.soa->refresh = ntohl(*((unsigned *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
        y->data.soa->retry = ntohl(*((unsigned *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
        y->data.soa->expire = ntohl(*((unsigned *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
        y->data.soa->ttl = ntohl(*((unsigned *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
    }
rec:
    return y;
err:
    dnsRecordFree(y);
    return 0;

}

static dnsPacket *dnsParsePacket(unsigned char *packet, size_t size)
{
    int i;
    dnsPacket *pkt;
    dnsRecord *rec;

    pkt = dnsParseHeader(packet, size);
    for (i = 0; i < pkt->qdcount; i++) {
        if (!(rec = dnsParseRecord(pkt, 1))) {
            goto err;
        }
        dnsRecordAppend(&pkt->qdlist, rec);
    }
    if (!pkt->qdlist) {
        goto err;
    }
    for (i = 0; i < pkt->ancount; i++) {
        if (!(rec = dnsParseRecord(pkt, 0))) {
            goto err;
        }
        dnsRecordAppend(&pkt->anlist, rec);
    }
    for (i = 0; i < pkt->nscount; i++) {
        if (!(rec = dnsParseRecord(pkt, 0))) {
            goto err;
        }
        dnsRecordAppend(&pkt->nslist, rec);
    }
    for (i = 0; i < pkt->arcount; i++) {
        if (!(rec = dnsParseRecord(pkt, 0))) {
            goto err;
        }
        dnsRecordAppend(&pkt->arlist, rec);
    }
    return pkt;
  err:
    dnsPacketFree(pkt, 2);
    return 0;

}

static void dnsEncodeName(dnsPacket *pkt, const char *name)
{
    dnsName *nm;

    dnsEncodeGrow(pkt, (name ? strlen(name) + 1 : 1), "name");
    if (name) {
        int k = 0, len;

        while (name[k]) {
            int i;
            char c;

            for (len = 0; (c = name[k + len]) != 0 && c != '.'; len++);
            if (!len || len > 63) {
                break;
            }
            // Find already saved domain name
            for (nm = pkt->nmlist; nm != NULL; nm = nm->next) {
                if (!strcasecmp(nm->name, &name[k])) {
                    dnsEncodePtr(pkt, nm->offset);
                    return;
                }
            }
            // Save name part for future reference
            nm = (dnsName *) ns_calloc(1, sizeof(dnsName));
            nm->next = pkt->nmlist;
            pkt->nmlist = nm;
            nm->name = ns_strdup(&name[k]);
            nm->offset = (short)((pkt->buf.ptr - pkt->buf.data) - 2);
            // Encode name part inline
            *pkt->buf.ptr++ = (char) (len & 0x3F);
            for (i = 0; i < len; i++) {
                *pkt->buf.ptr++ = name[k++];
            }
            if (name[k] == '.') {
                k++;
            }
        }
    }
    *pkt->buf.ptr++ = '\0';
}

static void dnsEncodeHeader(dnsPacket *pkt)
{
    unsigned short *p = (unsigned short *) pkt->buf.data;

    pkt->buf.size = (unsigned short)((pkt->buf.ptr - pkt->buf.data) - 2u);
    p[0] = htons(pkt->buf.size);
    p[1] = htons(pkt->id);
    p[2] = htons(pkt->u);
    p[3] = htons(pkt->qdcount);
    p[4] = htons(pkt->ancount);
    p[5] = htons(pkt->nscount);
    p[6] = htons(pkt->arcount);
}

static void dnsEncodePtr(dnsPacket *pkt, int offset)
{
    *pkt->buf.ptr++ = (char)(0xC0 | (offset >> 8));
    *pkt->buf.ptr++ = (char)(offset & 0xFF);
}

static void dnsEncodeShort(dnsPacket *pkt, int num)
{
    *((unsigned short *) pkt->buf.ptr) = htons((unsigned short) num);
    pkt->buf.ptr += 2;
}

static void dnsEncodeLong(dnsPacket *pkt, unsigned long num)
{
    *((unsigned long *) pkt->buf.ptr) = htonl((unsigned) num);
    pkt->buf.ptr += 4;
}

static void dnsEncodeData(dnsPacket *pkt, void *ptr, int len)
{
    memcpy(pkt->buf.ptr, ptr, (unsigned) len);
    pkt->buf.ptr += len;
}

static void dnsEncodeBegin(dnsPacket *pkt)
{
    // Mark offset where the record begins
    pkt->buf.rec = pkt->buf.ptr;
    dnsEncodeShort(pkt, 0);
}

static void dnsEncodeEnd(dnsPacket *pkt)
{
    unsigned short len = (unsigned short)(pkt->buf.ptr - pkt->buf.rec);
    *((unsigned short *) pkt->buf.rec) = htons((unsigned short)(len - 2));
}

static void dnsEncodeRecord(dnsPacket *pkt, dnsRecord *list)
{
    Ns_Log(SmtpdDebug, "dnsEncodeRecord");
    dnsEncodeGrow(pkt, 12, "pkt:hdr");
    for (; list != NULL; list = list->next) {
        dnsEncodeName(pkt, list->name);
        dnsEncodeGrow(pkt, 16, "pkt:data");
        dnsEncodeShort(pkt, list->type);
        dnsEncodeShort(pkt, list->class);
        dnsEncodeLong(pkt, list->ttl);
        dnsEncodeBegin(pkt);
        switch (list->type) {
        case DNS_TYPE_A:
            dnsEncodeData(pkt, &list->data.ipaddr, 4);
            break;
        case DNS_TYPE_AAAA:
            Ns_Log(Notice, "AAAA records are not implemented yet");
            break;
        case DNS_TYPE_MX:
            dnsEncodeShort(pkt, list->data.mx->preference);
            dnsEncodeName(pkt, list->data.mx->name);
            break;
        case DNS_TYPE_SOA:
            dnsEncodeName(pkt, list->data.soa->mname);
            dnsEncodeName(pkt, list->data.soa->rname);
            dnsEncodeGrow(pkt, 20, "pkt:soa");
            dnsEncodeLong(pkt, list->data.soa->serial);
            dnsEncodeLong(pkt, list->data.soa->refresh);
            dnsEncodeLong(pkt, list->data.soa->retry);
            dnsEncodeLong(pkt, list->data.soa->expire);
            dnsEncodeLong(pkt, list->data.soa->ttl);
            break;
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR:
            dnsEncodeName(pkt, list->data.name);
            break;
        }
        dnsEncodeEnd(pkt);
    }
}

static void dnsEncodePacket(dnsPacket *pkt)
{
    pkt->buf.ptr = &pkt->buf.data[DNS_HEADER_LEN + 2];
    /* Encode query part */
    dnsEncodeName(pkt, pkt->qdlist->name);
    dnsEncodeShort(pkt, pkt->qdlist->type);
    dnsEncodeShort(pkt, pkt->qdlist->class);
    /* Encode answer records */
    dnsEncodeRecord(pkt, pkt->anlist);
    dnsEncodeRecord(pkt, pkt->nslist);
    dnsEncodeRecord(pkt, pkt->arlist);
    dnsEncodeHeader(pkt);
}

static void dnsEncodeGrow(dnsPacket *pkt, size_t size, const char *UNUSED(proc))
{
    size_t offset = (size_t)pkt->buf.ptr - (size_t)pkt->buf.data;
    long roffset = pkt->buf.rec - pkt->buf.data;
    if (offset + size >= pkt->buf.allocated) {
        pkt->buf.allocated = (unsigned short)(pkt->buf.allocated + 256u);
        pkt->buf.data = ns_realloc(pkt->buf.data, pkt->buf.allocated);
        pkt->buf.ptr = &pkt->buf.data[offset];
        if (pkt->buf.rec)
            pkt->buf.rec = &pkt->buf.data[roffset];
    }
}

static void dnsPacketFree(dnsPacket *pkt, int UNUSED(type))
{
    if (!pkt)
        return;
    dnsRecordDestroy(&pkt->qdlist);
    dnsRecordDestroy(&pkt->nslist);
    dnsRecordDestroy(&pkt->arlist);
    dnsRecordDestroy(&pkt->anlist);
    while (pkt->nmlist) {
        dnsName *next = pkt->nmlist->next;
        ns_free((char *)pkt->nmlist->name);
        ns_free(pkt->nmlist);
        pkt->nmlist = next;
    }
    ns_free((char*)pkt->buf.data);
    ns_free(pkt);
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
