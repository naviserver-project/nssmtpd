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
 *   Naviserver SMTP server/proxy
 *
 *   Author Vlad Seryakov vlad@crystalballinc.com
 *
 */

#include "ns.h"
#include "nssock.h"
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
#define SMTPD_VERIFIED       0x0000001
#define SMTPD_LOCAL          0x0000002
#define SMTPD_RELAY          0x0000004
#define SMTPD_DELIVERED      0x0000008
#define SMTPD_ABORT          0x0000010
#define SMTPD_VIRUSCHECK     0x0000020
#define SMTPD_SPAMCHECK      0x0000040
#define SMTPD_NEEDDOMAIN     0x0000100
#define SMTPD_SEGV           0x0001000
#define SMTPD_FASTPROXY      0x0004000
#define SMTPD_RESOLVE        0x0008000
#define SMTPD_NEEDHELO       0x0010000
#define SMTPD_GOTHELO        0x0020000
#define SMTPD_GOTMAIL        0x0040000
#define SMTPD_GOTSPAM        0x0080000
#define SMTPD_GOTVIRUS       0x0100000
#define SMTPD_GOTSTARTTLS    0x0200000

#define SMTPD_VERSION              "2.1"
#define SMTPD_HDR_FILE             "X-Smtpd-File"
#define SMTPD_HDR_VIRUS_STATUS     "X-Smtpd-Virus-Status"
#define SMTPD_HDR_SIGNATURE        "X-Smtpd-Signature"

// Email address
typedef struct _smtpdEmail {
    char *name;
    char *domain;
    char *mailbox;
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
    char *name;
    char *host;
    int port;
} smtpdRelay;

// Recipient list
typedef struct _smtpdRcpt {
    struct _smtpdRcpt *next, *prev;
    char *addr;
    unsigned int flags;
    char *data;
    struct {
        int port;
        char *host;
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
    int bufsize;
    int maxline;
    int maxdata;
    int maxrcpt;
    int readtimeout;
    int writetimeout;
    char *relayhost;
    int relayport;
    char *address;
    int port;
    char *spamdhost;
    int spamdport;
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
} smtpdConfig;

typedef struct _smtpdConn {
    struct _smtpdConn *next;
    unsigned int id;
    int cmd;
    unsigned int flags;
    char *host;
    Ns_Sock *sock;
    Ns_DString line;
    Ns_DString reply;
    Tcl_Interp *interp;
    smtpdConfig *config;
    struct {
        char *addr;
        char *data;
    } from;
    struct {
        int count;
        smtpdRcpt *list;
    } rcpt;
    struct {
        int offset;
        Ns_DString data;
        smtpdHdr *headers;
    } body;
    struct {
        int pos;
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
    char *name;
    //unsigned long ipaddr;
    unsigned long fail_time;
    unsigned long fail_count;
} dnsServer;

typedef struct _dnsSOA {
    char *mname;
    char *rname;
    unsigned long serial;
    unsigned long refresh;
    unsigned long retry;
    unsigned long expire;
    unsigned long ttl;
} dnsSOA;

typedef struct _dnsMX {
    char *name;
    unsigned short preference;
} dnsMX;

typedef struct _dnsName {
    struct _dnsName *next;
    char *name;
    short offset;
} dnsName;

typedef struct _dnsRecord {
    struct _dnsRecord *next, *prev;
    char *name;
    unsigned short type;
    unsigned short class;
    unsigned long ttl;
    short len;
    union {
        char *name;
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
    short qdcount;
    short ancount;
    short nscount;
    short arcount;
    dnsName *nmlist;
    dnsRecord *qdlist;
    dnsRecord *anlist;
    dnsRecord *nslist;
    dnsRecord *arlist;
    struct {
        unsigned short allocated;
        unsigned short size;
        char *rec;
        char *ptr;
        char *data;
    } buf;
} dnsPacket;

#ifdef HAVE_OPENSSL_EVP_H
typedef struct {
    SSL_CTX     *ctx;
    Ns_Mutex     lock;
    int          verify;
    int          deferaccept;  /* Enable the TCP_DEFER_ACCEPT optimization. */
    DH          *dhKey512;     /* Fallback Diffie Hellman keys of length 512 */
    DH          *dhKey1024;    /* Fallback Diffie Hellman keys of length 1024 */
} SSLDriver;

typedef struct {
    SSL         *ssl;
    int          verified;
} SSLContext;
#endif

static int parseEmail(smtpdEmail *addr, char *str);
static char *encode64(const char *in, int len);
static char *decode64(const char *in, int len, int *outlen);
static char *encodeqp(const char *in, int len);
static char *decodeqp(const char *in, int len, int *outlen);
static char *encodehex(const char *buf, int len);
static char *decodehex(const char *str, int *len);
static int parsePhrase(char **inp, char **phrasep, char *specials);
static int parseDomain(char **inp, char **domainp, char **commmentp);
static int parseRoute(char **inp, char **routep);
static char *parseSpace(char *s);
static int parseInt(char *val);

static void dnsInit(char *name, ...);
static void dnsRecordFree(dnsRecord *pkt);
static void dnsRecordDestroy(dnsRecord **pkt);
static dnsRecord *dnsRecordAppend(dnsRecord **list, dnsRecord *pkt);
static dnsPacket *dnsParseHeader(void *packet, int size);
static dnsRecord *dnsParseRecord(dnsPacket *pkt, int query);
static dnsPacket *dnsParsePacket(unsigned char *packet, int size);
static int dnsParseName(dnsPacket *pkt, char **ptr, char *buf, int len, int pos, int level);
static void dnsEncodeName(dnsPacket *pkt, char *name);
static void dnsEncodeGrow(dnsPacket *pkt, unsigned int size, char *proc);
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
static dnsPacket *dnsLookup(char *name, int type, int *errcode);

static Ns_DriverAcceptProc SmtpdAcceptProc;
static Ns_DriverRequestProc SmtpdRequestProc;

static void SmtpdInit(void *arg);
static int SmtpdRequestProc(void *arg, Ns_Conn *conn);
static Ns_TclTraceProc SmtpdInterpInit;
static Tcl_ObjCmdProc SmtpdCmd;
static void SmtpdThread(smtpdConn *conn);
static int SmtpdRelayData(smtpdConn *conn, char *host, int port);
static int SmtpdSend(smtpdConfig *server, Tcl_Interp *interp, const char *sender, const char *rcpt, char *data, char *host, int port);
static smtpdConn *SmtpdConnCreate(smtpdConfig *server, Ns_Sock *sock);
static void SmtpdConnReset(smtpdConn *conn);
static void SmtpdConnFree(smtpdConn *conn);
static void SmtpdConnPrint(smtpdConn *conn);
static void SmtpdRcptFree(smtpdConn *conn, char *addr, int index, unsigned int flags);
static int SmtpdConnEval(smtpdConn *conn, const char *proc);
static void SmtpdConnParseData(smtpdConn *conn);
static char *SmtpdGetHeader(smtpdConn *conn, char *name);
#if defined(USE_DSPAM) || defined (USE_SAVI) || defined(USE_CLAMAV)
static void SmtpdConnAddHeader(smtpdConn *conn, char *name, char *value, int alloc);
#endif
static int SmtpdRead(smtpdConn *conn, void *vbuf, int len);
static int SmtpdWrite(smtpdConn *conn, void *vbuf, int len);
static int SmtpdWriteDString(smtpdConn *conn, Ns_DString *dsPtr);
static int SmtpdPuts(smtpdConn *conn, char *string);
static int SmtpdWriteData(smtpdConn *conn, char *buf, int len);
static int SmtpdReadLine(smtpdConn *conn, Ns_DString *dsPtr);
static char *SmtpdStrPos(char *as1, char *as2);
static char *SmtpdStrNPos(char *as1, char *as2, int len);
static char *SmtpdStrTrim(char *str);
static smtpdIpaddr *SmtpdParseIpaddr(char *str);
static smtpdIpaddr *SmtpdCheckIpaddr(smtpdIpaddr *list, const char *ipString);
static int SmtpdCheckDomain(smtpdConn *conn, char *domain);
static int SmtpdCheckRelay(smtpdConn *conn, smtpdEmail *addr, char **host, int *port);
static int SmtpdCheckSpam(smtpdConn *conn);
static int SmtpdCheckVirus(smtpdConn *conn, char *data, int datalen, char *location);
static void SmtpdPanic(const char *fmt, ...);
static void SmtpdSegv(int sig);
static int SmtpdFlags(const char *name);

static int Ns_TLS_CtxServerCreate(Tcl_Interp *interp, const char *cert,
                                  const char *caFile, const char *caPath,
                                  int verify, NS_TLS_SSL_CTX **ctxPtr);
static int Ns_TLS_SSLAccept(Tcl_Interp *interp, NS_SOCKET sock,
                            NS_TLS_SSL_CTX *ctx, NS_TLS_SSL **sslPtr);
static ssize_t TlsRecv(Ns_Sock *sock, struct iovec *bufs, int nbufs,
                       Ns_Time *timeoutPtr, unsigned int flags);
static ssize_t TlsSend(Ns_Sock *sock, const struct iovec *bufs, int nbufs,
                       const Ns_Time *timeoutPtr, unsigned int flags);
static void TlsClose(Ns_Sock *sock);

NS_EXPORT int Ns_ModuleVersion = 1;
NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;

// Free list of connection structures
static smtpdConn *connList = 0;
static Ns_Mutex connLock;
static int segvTimeout;
static char hex[] = "0123456789ABCDEF";

// Static DNS stuff
int dnsDebug = 0;
int dnsTTL = 86400;

static Ns_Mutex dnsMutex;
static dnsServer *dnsServers = 0;
static int dnsResolverRetries = 3;
static int dnsResolverTimeout = 5;
static int dnsFailureTimeout = 300;

// Default port
const static int DEFAULT_PORT = 25;

static Ns_LogSeverity SmtpdDebug;    /* Severity at which to log verbose debugging. */

NS_EXPORT int Ns_ModuleInit(const char *server, const char *module)
{
    char *path, *addr2, *portString;
    const char *addr;
    smtpdRelay *relay;
    Ns_DriverInitData init = {0};
    smtpdConfig *serverPtr;

    SmtpdDebug = Ns_CreateLogSeverity("Debug(smtpd)");
    path = ns_strdup(Ns_ConfigGetPath(server, module, (char *)0));
    
    serverPtr = ns_calloc(1, sizeof(smtpdConfig));
    serverPtr->deferaccept = Ns_ConfigBool(path, "deferaccept", NS_FALSE);
    serverPtr->nodelay = Ns_ConfigBool(path, "nodelay", NS_FALSE);
    serverPtr->server = server;
    Tcl_InitHashTable(&serverPtr->sessions, TCL_ONE_WORD_KEYS);
    serverPtr->address = ns_strcopy(Ns_ConfigGetValue(path, "address"));
    
    if (!Ns_ConfigGetInt(path, "port", &serverPtr->port)) {
        serverPtr->port = DEFAULT_PORT;
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
    if (!Ns_ConfigGetInt(path, "bufsize", &serverPtr->bufsize)) {
        serverPtr->bufsize = 1024 * 4;
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
    serverPtr->initproc = Ns_ConfigGetValue(path, "initproc");
    serverPtr->heloproc = Ns_ConfigGetValue(path, "heloproc");
    serverPtr->mailproc = Ns_ConfigGetValue(path, "mailproc");
    serverPtr->rcptproc = Ns_ConfigGetValue(path, "rcptproc");
    serverPtr->dataproc = Ns_ConfigGetValue(path, "dataproc");
    serverPtr->errorproc = Ns_ConfigGetValue(path, "errorproc");
    dnsInit("nameserver", Ns_ConfigGetValue(path, "nameserver"), 0);

    /* Parse flags */
    if ((addr = Ns_ConfigGetValue(path, "flags"))) {
        char *n;
        while (addr) {
            if ((n = strchr(addr, ','))) {
                *n++ = 0;
            }
            serverPtr->flags |= SmtpdFlags(addr);
            addr = n;
        }
        Ns_Log(Notice, "ns_smtpd: flags = 0x%x", serverPtr->flags);
    }

    /* Add local domains to relay table */
    serverPtr->relaylist = ns_calloc(1, sizeof(smtpdRelay));
    serverPtr->relaylist->name = ns_strdup("localhost");

    path = Ns_InfoHostname();
    while (path != NULL) {
        addr2 = strchr(path, '.');
        if (addr2 != NULL) {
            relay = ns_calloc(1, sizeof(smtpdRelay));
            relay->name = ns_strdup(path);
            relay->next = serverPtr->relaylist;
            serverPtr->relaylist = relay;
            Ns_Log(Notice, "ns_smtpd: adding local relay domain: %s", path);
            addr2++;
        }
        path = addr2;
    }

    /* SMTP relay support */
    serverPtr->relayport = DEFAULT_PORT;
    if (serverPtr->relayhost != NULL) {
        Ns_HttpParseHost(serverPtr->relayhost, &serverPtr->relayhost, &portString);
        if (portString != NULL) {
            *portString = '\0';
            serverPtr->relayport = (int) strtol(portString + 1, NULL, 10);
        }
    }

    /* SpamAssassin support */
    serverPtr->spamdport = 783;
    if (serverPtr->spamdhost != NULL) {
        Ns_HttpParseHost(serverPtr->spamdhost, &serverPtr->spamdhost, &portString);
        if (portString != NULL) {
            *portString = '\0';
            serverPtr->spamdport = (int) strtol(portString + 1, NULL, 10);
        }
    }
    Ns_MutexSetName2(&serverPtr->lock, "nssmtpd", "smtpd");

    /* Register SMTP driver */
    init.version = NS_DRIVER_VERSION_4;
    init.name = "nssmtpd";
    init.listenProc = Ns_DriverSockListen; //SmtpdListenProc;
    init.acceptProc = SmtpdAcceptProc;
    init.recvProc = Ns_DriverSockRecv; //SmtpdRecvProc;
    init.sendProc = Ns_DriverSockSend; // SmtpdSendProc;
    init.sendFileProc = NULL; // SmtpdSendFileProc;
    init.keepProc = NULL; // SmtpdKeepProc;
    init.requestProc = SmtpdRequestProc;
    init.closeProc = Ns_DriverSockClose;
    init.opts = NS_DRIVER_ASYNC|NS_DRIVER_NOPARSE;
    init.arg = serverPtr;
    init.path = path;
    init.protocol = "smtp";
    init.defaultPort = DEFAULT_PORT;
    if (Ns_DriverInit(server, module, &init) != NS_OK) {
        Ns_Log(Error, "nssmtpd: driver init failed.");
	ns_free(path);
        return NS_ERROR;
    }

    /* Segv/panic handler */
    if (serverPtr->flags & SMTPD_SEGV) {
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
            Ns_Log(Error, "nssmtpd: sophos: Failed to initialise SAVI: %x", hr);
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
    unsigned int now = time(0);

    va_start(ap, fmt);
    Ns_Log(Error, "nssmtpd:[%d]: panic: %s %p %p %p",
           getpid(), fmt, va_arg(ap, void *), va_arg(ap, void *), va_arg(ap, void *));
    va_end(ap);
    while (time(0) - now < segvTimeout) {
        sleep(1);
    }
    kill(getpid(), SIGKILL);
}

static void SmtpdSegv(int sig)
{
    unsigned int now = time(0);

    Ns_Log(Error, "nssmtpd: SIGSEGV received %d", getpid());
    while (time(0) - now < segvTimeout) {
        sleep(1);
    }
    kill(getpid(), SIGKILL);
}

/*
 * Add ns_smtpd commands to interp.
 */
static int SmtpdInterpInit(Tcl_Interp *interp, const void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_smtpd", SmtpdCmd, (ClientData)arg, NULL);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SmtpdAcceptProc --
 *
 *      Accept a new socket in non-blocking mode.
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
    int     status = NS_DRIVER_ACCEPT_ERROR;

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
 *      Process an smtp request. This proc start a thread for handling
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

static int SmtpdRequestProc(void *arg, Ns_Conn *conn)
{
  smtpdConfig *server = arg;

  Ns_Log(SmtpdDebug, "======================= SmtpdRequestProc");
  
  SmtpdThread(SmtpdConnCreate(server, Ns_ConnSockPtr(conn)));
  return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * SmtpdInit --
 *
 *      Initialize Smtpd via tcl script
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

    Ns_Log(SmtpdDebug,"SmtpdThread");

    Ns_GetHostByAddr(&conn->line, Ns_ConnPeer(nsconn));
    if (!conn->line.length && conn->flags & SMTPD_RESOLVE) {
        SmtpdPuts(conn, "421 Service not available, could not resolve the hostname");
        SmtpdConnFree(conn);
        return;
    }
    if (!(conn->interp = Ns_GetConnInterp(nsconn))) {
        Ns_Log(Error, "nssmtpd: %d: Conn/Tcl interp error: %s", conn->id, strerror(errno));
        SmtpdPuts(conn, "421 Service not available, internal error");
        SmtpdConnFree(conn);
        return;
    }

    conn->host = ns_strdup(conn->line.string);
    Ns_MutexLock(&config->locallock);
    if (SmtpdCheckIpaddr(config->local, Ns_ConnPeer(nsconn))) {
        conn->flags |= SMTPD_LOCAL;
    }
    Ns_MutexUnlock(&config->locallock);
    /* Our greeting message */
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "220 %s SMTP nssmtpd %s ", Ns_InfoHostname(), SMTPD_VERSION);
    Ns_HttpTime(&conn->line, 0);
    Ns_DStringAppend(&conn->line, "\r\n");
    if (SmtpdWriteDString(conn, &conn->line)) {
        goto error;
    }

    //Ns_Log(SmtpdDebug, "SmtpdThread: %s", conn->line.string);

    while (1) {
        conn->cmd = SMTP_READ;
        fprintf(stderr, "SmptdThread: %p \n", conn->sock->arg);
        if (SmtpdReadLine(conn, &conn->line) < 0) {
            goto error;
        }
        Ns_DStringTrunc(&conn->reply, 0);
        Ns_StrToLower(conn->line.string);
        Ns_StrTrim(conn->line.string);
        conn->line.length = strlen(conn->line.string);
        
        //Ns_Log(SmtpdDebug, "=== SmtpdThread: %s", conn->line.string);

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
            Ns_DString ds;
            conn->cmd = SMTP_HELP;
            Ns_DStringInit(&ds);
            Ns_DStringPrintf(&ds, "214- This is nssmtpd version %s\r\n", SMTPD_VERSION);
            Ns_DStringPrintf(&ds, "214- Supported commands:\r\n");
            Ns_DStringPrintf(&ds, "214-  HELO    EHLO    MAIL    RCPT    DATA\r\n");
            Ns_DStringPrintf(&ds, "214-  RSET    NOOP    QUIT    HELP    VRFY\r\n");
            Ns_DStringPrintf(&ds, "214 End of HELP info\r\n");
            if (SmtpdPuts(conn, ds.string) != NS_OK) {
                goto error;
            }
            Ns_DStringFree(&ds);
            continue;
        }

        if (!strncasecmp(conn->line.string, "HELO", 4) || !strncasecmp(conn->line.string, "EHLO", 4)) {
            conn->cmd = SMTP_HELO;
            /* Duplicate HELO RFC 1651 4.2 */
            if (conn->flags & SMTPD_GOTHELO) {
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
                    Ns_DStringInit(&conn->line);
                    Ns_DStringPrintf(&conn->line, "250-%s\r\n", Ns_InfoHostname());
                    Ns_DStringPrintf(&conn->line, "250-SIZE %d\r\n", config->maxdata);
//#ifdef HAVE_OPENSSL_EVP_H
                    if (!(conn->flags & SMTPD_GOTSTARTTLS)) {
                        Ns_DStringPrintf(&conn->line, "250-STARTTLS\r\n");
                    }
//#endif
                    Ns_DStringPrintf(&conn->line, "250-8BITMIME\r\n");
                    Ns_DStringPrintf(&conn->line, "250 HELP\r\n");
                    if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
                        goto error;
                    }
                }
            }
            if (conn->flags & SMTPD_ABORT) {
                break;
            }
            conn->flags |= SMTPD_GOTHELO;
            continue;
        }

//#ifdef HAVE_OPENSSL_EVP_H
        if (!strncasecmp(conn->line.string, "STARTTLS", 8)) {
            conn->cmd = SMTP_STARTTLS;
            NS_TLS_SSL_CTX *ctx;
            NS_TLS_SSL *ssl;

            if (SmtpdPuts(conn, "220 Go Ahead\r\n") != NS_OK) {
                goto error;
            }

            int result = Ns_TLS_CtxServerCreate(conn->interp,
                "/home/costash/server.pem" /*cert*/,
                NULL /*caFile*/,
                NULL /*caPath*/,
                0 /*verify*/,
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
                SSLContext *sslPtr = ns_calloc(1, sizeof(SSLContext));
                if (sslPtr == NULL) {
                    Ns_Log(SmtpdDebug, "STARTTLS-ssl-accept failed. Could not allocate SSLContext.");
                    goto error;
                }
                sslPtr->ssl = ssl;
                fprintf(stderr, "STARTTLS--setting ssl %p->%p\n", conn->sock, ssl);
                conn->sock->arg = ssl;
            } else {
                goto error;
            }
            Ns_Log(SmtpdDebug, "STARTTLS-ssl-command result=%d", result);
            fprintf(stderr, "SmptdThread: end of STARTTLS %p \n", conn->sock->arg);

            conn->flags &= ~(SMTPD_GOTHELO);
            conn->flags |= (SMTPD_GOTSTARTTLS);

            continue;
        }
//#endif

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
            if (conn->flags & SMTPD_GOTMAIL) {
                if (SmtpdPuts(conn, "501 Duplicate MAIL\r\n") != NS_OK) {
                    goto error;
                }
                continue;
            }
            /* HELO is required */
            if ((config->flags & SMTPD_NEEDHELO) && !(conn->flags & SMTPD_GOTHELO)) {
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
                *data = 0;
            }
            data = Ns_StrTrim(&conn->line.string[10]);
            /* Email address verification */
            if (!strcmp(data, "<>") || !strcasecmp(data, "postmaster"))
                conn->from.addr = ns_strdup(data);
            else {
                smtpdEmail addr;
                /* Prepare error reply because address parser modifies the buffer */
                Ns_DStringPrintf(&conn->reply, "553 %s... Address unrecognised\r\n", data);
                if (parseEmail(&addr, data)) {
                    Ns_DStringTrunc(&conn->reply, 0);
                    if (SmtpdCheckDomain(conn, addr.domain)) {
                        conn->from.addr = ns_malloc(strlen(addr.mailbox) + strlen(addr.domain) + 2);
                        sprintf(conn->from.addr, "%s@%s", addr.mailbox, addr.domain);
                        Ns_StrToLower(conn->from.addr);
                    }
                }
            }
            if (!conn->from.addr) {
                if (!conn->reply.length) {
                    Ns_DStringPrintf(&conn->reply, "553 %s... Address unrecognised\r\n", data);
                }
                if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                    goto error;
                }
                continue;
            }
            /* Call Tcl callback */
            if (SmtpdConnEval(conn, config->mailproc) != TCL_OK) {
                if (SmtpdPuts(conn, "421 Service not available\r\n")) {
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
            if (conn->flags & SMTPD_ABORT) {
                break;
            }
            conn->flags |= SMTPD_GOTMAIL;
            continue;
        }

        if (!strncasecmp(conn->line.string, "RCPT TO:", 8)) {
            char *host = 0;
            smtpdRcpt *rcpt;
            smtpdEmail addr;
            int port = 0, flags = 0;

            conn->cmd = SMTP_RCPT;
            if (!(conn->flags & SMTPD_GOTMAIL)) {
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
            Ns_DStringPrintf(&conn->reply, "553 %s... Address unrecognised\r\n", data);
            /* Email address verification */
            if (parseEmail(&addr, data)) {
                Ns_DStringTrunc(&conn->reply, 0);
                /* Check for allowed for relaying domains */
                if (SmtpdCheckRelay(conn, &addr, &host, &port)) {
                    flags |= SMTPD_RELAY;
                } else
                if (!(conn->flags & SMTPD_LOCAL)) {
                    Ns_DStringPrintf(&conn->reply, "550 %s@%s... Relaying denied\r\n", addr.mailbox, addr.domain);
                    Ns_Log(Error, "nssmtpd: %d: HOST: %s/%s, RCPT: %s@%s, Relaying denied",
                           conn->id, conn->host, Ns_ConnPeer(nsconn), addr.mailbox, addr.domain);
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
            if (conn->flags & SMTPD_ABORT) {
                break;
            }
            continue;
        }

        if (!strncasecmp(conn->line.string, "DATA", 4)) {
            int size = -1;
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
                    Ns_Log(SmtpdDebug, "DATA check rcpt <%s> %s %d -> verfied %d", rcpt->addr, rcpt->relay.host, rcpt->relay.port,
                           rcpt->flags & SMTPD_VERIFIED);
                    if (rcpt->flags & SMTPD_VERIFIED) {
                        break;
                    }
                }
                Ns_Log(SmtpdDebug, "DATA rcpt <%p>", (void*)rcpt);

                if (rcpt != NULL
                    && (size = SmtpdRelayData(conn, rcpt->relay.host, rcpt->relay.port)) < 0) {
                    goto done;
                }
            }
            // Still data has not been read yet
            if (size == -1) {
                if (SmtpdPuts(conn, "354 Start mail input; end with <CRLF>.<CRLF>\r\n") != NS_OK) {
                    break;
                }
                do {
                    if (SmtpdReadLine(conn, &conn->line) < 0) {
                        goto error;
                    }
                    /* Remove trailing dot sender the data buffer */
                    if (!strcmp(conn->line.string, ".\r\n")) {
                        Ns_DStringTrunc(&conn->line, conn->line.length - 3);
                        break;
                    }
                    size += conn->line.length;
                    if (size < config->maxdata) {
                        Ns_DStringNAppend(&conn->body.data, conn->line.string, conn->line.length);
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
                Ns_DStringAppend(&conn->reply, "250 Message accepted\r\n");
            }
            /* No reply in relay mode */
            if (config->relayhost) {
                for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
                    if (!(rcpt->flags & SMTPD_VERIFIED)) {
                        break;
                    }
                }
                if (!rcpt) {
                    Ns_DStringTrunc(&conn->reply, 0);
                }
            }
            if (SmtpdWriteDString(conn, &conn->reply) != NS_OK) {
                goto error;
            }
            if (conn->flags & SMTPD_ABORT) {
                break;
            }
            SmtpdConnPrint(conn);
            SmtpdConnReset(conn);
            continue;
        }
        if (SmtpdPuts(conn, "500 Command unrecognised\r\n") != NS_OK) {
            Ns_Log(SmtpdDebug, "Unrecognized command: %s", conn->line.string);
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
        Ns_Log(Error, "nssmtpd: %d/%d: HOST: %s/%s, I/O error: %d/%d: %s: %s",
               conn->id, getpid(), conn->host, Ns_ConnPeer(nsconn),
               conn->sock->sock, conn->cmd, strerror(errno), conn->line.string);
    }
    SmtpdConnFree(conn);
}

static smtpdConn *SmtpdConnCreate(smtpdConfig *config, Ns_Sock *sock)
{
    smtpdConn *conn;
    Tcl_HashEntry *rec;
    int new;

    Ns_Log(SmtpdDebug,"SmtpdConnCreate");

    Ns_MutexLock(&connLock);
    if ((conn = connList)) {
        connList = connList->next;
    }
    Ns_MutexUnlock(&connLock);

    /* Brand new connection structure */
    if (!conn) {
        conn = ns_calloc(1, sizeof(smtpdConn) + config->bufsize + 1);
        conn->config = config;
        conn->flags = config->flags;
        Ns_DStringInit(&conn->line);
        Ns_DStringInit(&conn->reply);
        Ns_DStringInit(&conn->body.data);
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

static void SmtpdConnReset(smtpdConn *conn)
{
    //Ns_Log(SmtpdDebug,"SmtpdConnReset");

    // Default global flags
    conn->flags &= ~(SMTPD_GOTMAIL);
    ns_free(conn->from.addr), conn->from.addr = 0;
    ns_free(conn->from.data), conn->from.data = 0;
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringTrunc(&conn->reply, 0);
    Ns_DStringTrunc(&conn->body.data, 0);

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
        ns_free(conn->rcpt.list->addr);
        ns_free(conn->rcpt.list->data);
        ns_free(conn->rcpt.list->relay.host);
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
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "nssmtpd: %d/%d: HOST: %s/%s", conn->id, getpid(), conn->host, Ns_ConnPeer(nsconn));
    Ns_DStringPrintf(&conn->line, ", FLAGS: 0x%X, FROM: %s, RCPT: ", conn->flags, conn->from.addr);
    for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
        Ns_DStringPrintf(&conn->line, "%s(0x%X/%.2f), ", rcpt->addr, rcpt->flags, rcpt->spam_score);
    }
    Ns_DStringPrintf(&conn->line, "SIZE: %d/%d", conn->body.data.length, conn->body.offset);
    Ns_Log(Notice, "%s", conn->line.string);

    /*
     * Update request line for access logging
     */
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "SEND /%s SMTP/1.0", conn->from.addr ? conn->from.addr : "Null");
    for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
        Ns_DStringPrintf(&conn->line, "/%s", rcpt->addr);
    }
    ns_free((char *)nsconn->request.line);
    nsconn->request.line = ns_strdup(conn->line.string);
}

static int SmtpdConnEval(smtpdConn *conn, const char *proc)
{
    char name[256];

    Ns_Log(SmtpdDebug, "--- SmtpdConnEval <%s>", proc);
    Ns_DStringTrunc(&conn->reply, 0);
    if (!proc || !*proc) {
        return TCL_OK;
    }
    snprintf(name, sizeof(name), "%s %u", proc, conn->id);
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
    ns_free(conn->host);
    conn->host = 0;
    conn->buf.ptr = 0;
    conn->buf.pos = 0;

    Ns_MutexLock(&connLock);
    conn->next = connList;
    connList = conn;
    Ns_MutexUnlock(&connLock);
}

static int SmtpdRelayData(smtpdConn *conn, char *host, int port)
{
    Ns_Sock sock;
    smtpdRcpt *rcpt;
    smtpdConn *relay;
    Ns_Time timeout = { conn->config->writetimeout, 0 };
    int size = 0, vcount = 0;
    Ns_Conn *nsconn = Ns_GetConn();

    Ns_Log(SmtpdDebug,"====== SmtpdRelayData");

    /* if we have single recipient use recipient's relay
       otherwise for different recipients use default relay */
    for (rcpt = conn->rcpt.list; host && rcpt; rcpt = rcpt->next) {
        if (rcpt->flags & SMTPD_VERIFIED && rcpt->relay.host && strcmp(rcpt->relay.host, host)) {
            host = 0;
            break;
        }
    }
    if (!host) {
        host = conn->config->relayhost;
        port = conn->config->relayport;
    }
    if (!port) {
        port = DEFAULT_PORT;
    }
    if ((sock.sock = Ns_SockTimedConnect(host, port, &timeout)) == NS_INVALID_SOCKET) {
        Ns_Log(Error, "nssmtpd: relay: %d/%d: Unable to connect to %s:%d: %s",
               conn->id, getpid(), host, port, strerror(errno));
        SmtpdPuts(conn, "421 Service not available\r\n");
        return -1;
    }
    sock.driver = conn->sock->driver;
    /* Allocate relay SMTPD connection */
    if (!(relay = SmtpdConnCreate(conn->config, &sock))) {
        ns_sockclose(sock.sock);
        SmtpdPuts(conn, "421 Service not available\r\n");
        return -1;
    }
    /* Read greeting line from the relay */
    if (SmtpdReadLine(relay, &relay->line) < 0) {
        Ns_Log(Error, "nssmtpd: relay: %d/%d: %s:%d: Greeting read error: %s",
               conn->id, getpid(), host, port, strerror(errno));
        SmtpdConnFree(relay);
        SmtpdPuts(conn, "421 Service not available\r\n");
        return -1;
    }

    /* HELO command */
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "HELO %s\r\n", Ns_InfoHostname());
    if (SmtpdWriteDString(relay, &conn->line) != NS_OK) {
        goto error421;
    }
    if (SmtpdReadLine(relay, &relay->line) <= 0) {
        goto error421;
    }
    if (relay->line.string[0] != '2') {
        goto errorrelay;
    }

    /* MAIL FROM command */
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "MAIL FROM: <%s>\r\n", !strcmp(conn->from.addr, "<>") ? "" : conn->from.addr);
    if (SmtpdWriteDString(relay, &conn->line) != NS_OK) {
        goto error421;
    }
    if (SmtpdReadLine(relay, &relay->line) <= 0) {
        goto error421;
    }
    if (relay->line.string[0] != '2') {
        goto errorrelay;
    }

    /* RCPT TO command */
    for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
        if (!(rcpt->flags & SMTPD_VERIFIED)) {
            continue;
        }
        Ns_DStringTrunc(&conn->line, 0);
        Ns_DStringPrintf(&conn->line, "RCPT TO: <%s>\r\n", rcpt->addr);
        if (SmtpdWriteDString(relay, &conn->line) != NS_OK) {
            goto error421;
        }
        if (SmtpdReadLine(relay, &relay->line) <= 0) {
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
    if (SmtpdReadLine(relay, &relay->line) <= 0) {
        goto error421;
    }
    if (strncmp(relay->line.string, "354", 3)) {
        goto errorrelay;
    }
    if (SmtpdPuts(conn, "354 Start mail input; end with <CRLF>.<CRLF>\r\n") != NS_OK) {
        goto error;
    }
    do {
        if (SmtpdReadLine(conn, &relay->line) < 0) {
            goto error;
        }
        if (SmtpdWriteDString(relay, &relay->line) != NS_OK) {
            goto error421;
        }
        /* Remove trailing dot from the data buffer */
        if (!strcmp(relay->line.string, ".\r\n")) {
            Ns_DStringTrunc(&relay->line, relay->line.length - 3);
            break;
        }
        size += relay->line.length;
        if (size < conn->config->maxdata && !(conn->rcpt.count == vcount && conn->flags & SMTPD_FASTPROXY)) {
            Ns_DStringNAppend(&conn->body.data, relay->line.string, relay->line.length);
        }
    } while (relay->line.length > 0);
    if (SmtpdReadLine(relay, &relay->line) <= 0) {
        goto error421;
    }
    if (relay->line.string[0] != '2') {
        goto errorrelay;
    }
    if (SmtpdWriteDString(conn, &relay->line) != NS_OK) {
        goto error;
    }
    SmtpdConnFree(relay);
    for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
        if (rcpt->flags & SMTPD_VERIFIED) {
            rcpt->flags |= SMTPD_DELIVERED;
        }
    }
    return size;

  error:
    SmtpdConnFree(relay);
    return -1;

  error421:
    Ns_StrTrimRight(conn->line.string);
    Ns_StrTrimRight(relay->line.string);
    Ns_Log(Error, "nssmtpd: relay: %d/%d: HOST: %s/%s, FLAGS: 0x%X, FROM: %s, %s: %s/%s",
           conn->id, getpid(), conn->host, Ns_ConnPeer(nsconn),
           conn->flags, conn->from.addr, conn->line.string, conn->line.string, relay->line.string);
    SmtpdPuts(conn, "421 Service not available\r\n");
    SmtpdConnFree(relay);
    return -1;

  errorrelay:
    Ns_StrTrimRight(conn->line.string);
    conn->line.length = strlen(conn->line.string);
    Ns_StrTrimRight(relay->line.string);
    Ns_DStringAppend(&conn->line, ": ");
    Ns_DStringAppend(&conn->line, relay->line.string);
    Ns_Log(Error, "nssmtpd: relay: %d/%d: HOST: %s/%s, FLAGS: 0x%X, FROM: %s, %s/%s",
           conn->id, getpid(), conn->host, Ns_ConnPeer(nsconn), conn->flags, conn->from.addr,
           conn->line.string, relay->line.string);
    SmtpdConnEval(conn, conn->config->errorproc);
    if (!conn->reply.length) {
        Ns_DStringPrintf(&conn->reply, "421 Service not available. %s\r\n", &relay->line.string[4]);
    }
    SmtpdWriteDString(conn, &conn->reply);
    SmtpdConnFree(relay);
    return -1;
}

static int SmtpdSend(smtpdConfig *config, Tcl_Interp *interp, const char *sender, const char *rcpt, char *dname, char *host, int port)
{
    char *ptr;
    Ns_Sock sock;
    Tcl_Obj *data;
    smtpdConn *conn;
    Ns_Time timeout = { config->writetimeout, 0 };
    int duplicated = 0;

    Ns_Log(SmtpdDebug,"SmtpdSend");

    if (!sender || !rcpt || !dname) {
        Tcl_AppendResult(interp, "nssmtpd: send: empty arguments", 0);
        return -1;
    }
    if (!(data = Tcl_GetVar2Ex(interp, dname, 0, TCL_LEAVE_ERR_MSG))) {
        return -1;
    }
    if (!host || !*host) {
        host = config->relayhost;
        port = config->relayport;
    }
    if (!port) {
        port = DEFAULT_PORT;
    }

    if ((sock.sock = Ns_SockTimedConnect(host, port, &timeout)) == NS_INVALID_SOCKET) {
        Tcl_AppendResult(interp, "nssmtpd: send: unable to connect to ", host, ": ", strerror(errno), 0);
        return -1;
    }
    sock.driver = config->driver;
    /* Allocate virtual SMTPD connection */
    if (!(conn = SmtpdConnCreate(config, &sock))) {
        Tcl_AppendResult(interp, strerror(errno), 0);
        ns_sockclose(sock.sock);
        return -1;
    }
    /* Read greeting line from the conn */
    if (SmtpdReadLine(conn, &conn->line) < 0) {
        Tcl_AppendResult(interp, "greeting read error: ", strerror(errno), 0);
        SmtpdConnFree(conn);
        return -1;
    }

    /* HELO command */
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringPrintf(&conn->line, "HELO %s\r\n", Ns_InfoHostname());
    if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line) <= 0) {
        goto ioerror;
    }
    if (conn->line.string[0] != '2') {
        goto error;
    }

    /* MAIL FROM command */
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringAppend(&conn->reply, (char *) sender);
    Ns_DStringPrintf(&conn->line, "MAIL FROM:<%s>\r\n", SmtpdStrTrim(conn->reply.string));
    if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line) <= 0) {
        goto ioerror;
    }
    if (conn->line.string[0] != '2') {
        goto error;
    }

    /* RCPT TO command */
    Ns_DStringTrunc(&conn->line, 0);
    Ns_DStringTrunc(&conn->reply, 0);
    Ns_DStringAppend(&conn->reply, (char *) rcpt);
    Ns_DStringPrintf(&conn->line, "RCPT TO:<%s>\r\n", SmtpdStrTrim(conn->reply.string));
    if (SmtpdWriteDString(conn, &conn->line) != NS_OK) {
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line) <= 0) {
        goto ioerror;
    }
    if (conn->line.string[0] != '2') {
        goto error;
    }

    /* Process data for line with single dot */
    ptr = Tcl_GetString(data);
    while ((ptr = strstr(ptr, "\n."))) {
        ptr += 2;
        if (*ptr == '\r' || *ptr == '\n') {
            int offset = ptr - Tcl_GetString(data);
            /* Copy the object only if we have single line with dot
               and the object is shared */
            if (Tcl_IsShared(data) && !duplicated) {
                data = Tcl_DuplicateObj(data);
                duplicated = 1;
            }
            Tcl_SetObjLength(data, Tcl_GetCharLength(data) + 1);
            ptr = Tcl_GetString(data) + offset;
            memmove(ptr + 1, ptr, (unsigned) Tcl_GetCharLength(data) - offset);
            *(ptr++) = '.';
        }
    }

    /* DATA command */
    if (SmtpdPuts(conn, "DATA\r\n") != NS_OK) {
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line) <= 0) {
        goto ioerror;
    }
    if (strncmp(conn->line.string, "354", 3)) {
        goto error;
    }
    if (SmtpdWriteData(conn, Tcl_GetString(data), (int) Tcl_GetCharLength(data)) != NS_OK) {
        goto ioerror;
    }
    if (SmtpdWriteData(conn, "\r\n.\r\n", 5) != NS_OK) {
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line) <= 0) {
        goto ioerror;
    }
    if (conn->line.string[0] != '2') {
        goto error;
    }

    /* QUIT command */
    if (SmtpdPuts(conn, "QUIT\r\n") != NS_OK) {
        goto ioerror;
    }
    if (SmtpdReadLine(conn, &conn->line) <= 0) {
        goto ioerror;
    }
    SmtpdConnFree(conn);
    Ns_Log(Notice, "nssmtpd: send: from %s to %s via %s:%d %d bytes", sender, rcpt, host, port, Tcl_GetCharLength(data));
    if (duplicated) {
        Tcl_DecrRefCount(data);
    }
    return 0;

  ioerror:
    if (errno) {
        Tcl_AppendResult(interp, "nssmtpd: send: I/O error: ", conn->line.string, ": ", strerror(errno), 0);
    }
    SmtpdConnFree(conn);
    if (duplicated) {
        Tcl_DecrRefCount(data);
    }
    return -1;

  error:
    Tcl_AppendResult(interp, "nssmtpd: send: unexpected status from ", host, ": ", conn->line.string, 0);
    SmtpdConnFree(conn);
    if (duplicated) {
        Tcl_DecrRefCount(data);
    }
    return -1;
}

static void SmtpdRcptFree(smtpdConn *conn, char *addr, int index, unsigned int flags)
{
    int count = -1;
    smtpdRcpt *rcpt, *rcpt2;

    Ns_Log(SmtpdDebug,"SmtpdRcptFree");

    for (rcpt = conn->rcpt.list; rcpt;) {
        count++;
        if ((flags && rcpt->flags & SMTPD_VERIFIED) || (addr && !strcmp(rcpt->addr, addr)) || (index >= 0 && count == index)) {
            if (rcpt->prev) {
                rcpt->prev->next = rcpt->next;
            } else {
                conn->rcpt.list = rcpt->next;
            }
            if (rcpt->next) {
                rcpt->next->prev = rcpt->prev;
            }
            rcpt2 = rcpt;
            rcpt = rcpt->next;
            ns_free(rcpt2->addr);
            ns_free(rcpt2->data);
            ns_free(rcpt2->relay.host);
            ns_free(rcpt2);
            conn->rcpt.count--;
            continue;
        }
        rcpt = rcpt->next;
    }
}

static ssize_t
        SmtpdRecv(Ns_Sock *sock, char *buffer, size_t length, Ns_Time *timeoutPtr)
{
    ssize_t       received;
    int n = 0;

    NS_NONNULL_ASSERT(sock != NULL);
    NS_NONNULL_ASSERT(buffer != NULL);
again:
    fprintf(stderr, "Receive: want receive %lu bytes {from ssl %d %p->%p}\n", length, sock->arg!=NULL, sock, sock->arg);
    if (sock->arg == NULL) {
        received = ns_recv(sock->sock, buffer, length, 0);
    } else {
//#ifdef HAVE_OPENSSL_EVP_H
        SSL *ssl = (SSL *)sock->arg;
        fprintf(stderr, "### SSL_read want %lu\n", length);

        received = 0;
        for (;;) {
            int n = 0, err;

            n = SSL_read(ssl, buffer+received, (int)(length - (size_t)received));
            err = SSL_get_error(ssl, n);
            fprintf(stderr, "### SSL_read n %d got %lu err %d\n", n, received, err);
            switch (err) {
            case SSL_ERROR_NONE:
                if (n < 0) {
                    Ns_Log(Error, "SSL_read failed but no error, should not happen");
                    fprintf(stderr, "### SSL_read failed but no error, should not happen");
                    break;
                }
                received += n;
                break;

            case SSL_ERROR_WANT_READ:
                fprintf(stderr, "### partial read, n %d\n", (int)n);
                if (n < 0) {
                    continue;
                }
                received += n;
                continue;
            }
            break;
        }
//#else
#if 0
        received = -1;
#endif
    }

    fprintf(stderr, "Receive: received %ld bytes from {%s} %d \n", received, buffer, errno);
    if (received == -1 && errno == EWOULDBLOCK) {
        if (Ns_SockTimedWait(sock->sock, (unsigned int)NS_SOCK_READ, timeoutPtr) == NS_OK) {
            goto again;
        }
    }

    Ns_Log(Ns_LogTaskDebug, "HttpTaskRecv received %ld bytes (from %lu)", received, length);
    return received;
}








static int SmtpdRead(smtpdConn *conn, void *vbuf, int len)
{
    int nread, n;
    char *buf = (char *) vbuf;
    Ns_Time timeout = { conn->config->readtimeout, 0 };

    //Ns_Log(SmtpdDebug,"SmtpdRead");

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

            conn->buf.pos = SmtpdRecv(conn->sock, conn->buf.data, conn->config->bufsize, &timeout);
            /*if (conn->sock->arg != NULL) {
#ifdef HAVE_OPENSSL_EVP_H
                //TODO: figure out how to call this
                conn->buf.pos = TlsRecv(conn->sock, conn->buf.data, conn->config->bufsize, &timeout, 0);
#endif
            } else {
                conn->buf.pos = Ns_SockRecv(conn->sock->sock, conn->buf.data, conn->config->bufsize, &timeout);
            }
*/
            if (conn->buf.pos <= 0) {
                return -1;
            }
        }
    }
    return nread;
}



static ssize_t
MySmtpdSend(Ns_Sock *sock, char *buffer, size_t length)
{
    ssize_t       sent;

    NS_NONNULL_ASSERT(sock != NULL);
    NS_NONNULL_ASSERT(buffer != NULL);

    if (sock->arg == NULL) {
        sent = ns_send(sock->sock, buffer, length, 0);
    } else {
//#ifdef HAVE_OPENSSL_EVP_H
        struct iovec  iov;
        (void) Ns_SetVec(&iov, 0, buffer, length);

        SSL *ssl = (SSL *)sock->arg;
        sent = 0;
        for (;;) {
            int     err;
            ssize_t n;

            n = SSL_write(ssl, iov.iov_base, (int)iov.iov_len);
            err = SSL_get_error(ssl, n);
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
//#else
#if 0
        sent = -1;
#endif
    }

    Ns_Log(Ns_LogTaskDebug, "HttpTaskSend sent %ld bytes (from %lu)", sent, length);
    return sent;
}








static int SmtpdWrite(smtpdConn *conn, void *vbuf, int len)
{
    int nwrote;
    char *buf;
    Ns_Time timeout = { conn->config->writetimeout, 0 };

    nwrote = len;
    buf = vbuf;
    while (len > 0) {
        int n;
        /*if (conn->sock->arg != NULL) {
#ifdef HAVE_OPENSSL_EVP_H
            n = TlsSend(conn->sock, conn->buf.data, conn->config->bufsize, &timeout, 0);
#endif
        } else {
            n = Ns_SockSend(conn->sock->sock, buf, len, &timeout);
        }*/
        n = MySmtpdSend(conn->sock, buf, len);

        if (n < 0) {
            return -1;
        }
        len -= n;
        buf += n;
    }
    return nwrote;
}

static int SmtpdReadLine(smtpdConn *conn, Ns_DString *dsPtr)
{
    char buf[1];
    int len = 0, nread;

    Ns_DStringTrunc(dsPtr, 0);
    do {
        if ((nread = SmtpdRead(conn, buf, 1)) == 1) {
            Ns_DStringNAppend(dsPtr, buf, 1);
            ++len;
            if (buf[0] == '\n') {
                break;
            }
        }
    } while (nread == 1 && dsPtr->length <= conn->config->maxline);
    
    if (nread > 0 && Ns_LogSeverityEnabled(SmtpdDebug) == NS_TRUE) {
        char *end = &dsPtr->string[dsPtr->length-1], saved = *end;
        
        *end = '\0';
        Ns_Log(SmtpdDebug, "nssmtpd: %d: <<< %s", conn->id, dsPtr->string);
        *end = saved;
    }
    return (nread > 0 ? len : nread);
}

static int SmtpdWriteData(smtpdConn *conn, char *buf, int len)
{
    if (Ns_LogSeverityEnabled(SmtpdDebug) == NS_TRUE) {
        Tcl_DString ds;

        Tcl_DStringInit(&ds);
        Tcl_DStringAppend(&ds, buf, len-2);
        Ns_Log(SmtpdDebug, "nssmtpd: %d: >>> %s", conn->id, ds.string);
        Tcl_DStringFree(&ds);
    }

    while (len > 0) {
        int nwrote = SmtpdWrite(conn, buf, len);
	
        if (nwrote < 0) {
            return NS_ERROR;
        }
        len -= nwrote;
        buf += nwrote;
    }
    return NS_OK;
}

static int SmtpdWriteDString(smtpdConn *conn, Ns_DString *dsPtr)
{
    return SmtpdWriteData(conn, dsPtr->string, dsPtr->length);
}

static int SmtpdPuts(smtpdConn *conn, char *string)
{
    return SmtpdWriteData(conn, string, (int) strlen(string));
}

static char *SmtpdStrPos(char *as1, char *as2)
{
    register char *s1 = as1, *s2 = as2, *ptr, c;

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

static char *SmtpdStrNPos(char *as1, char *as2, int len)
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
    int len;

    while (*str == '<' || isspace(*str)) {
        str++;
    }
    len = strlen(str);
    while (len-- && (isspace(str[len]) || str[len] == '>')) {
        str[len] = 0;
    }
    return str;
}

static char *SmtpdGetHeader(smtpdConn *conn, char *name)
{
    smtpdHdr *hdr;
    for (hdr = conn->body.headers; hdr; hdr = hdr->next) {
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
    unsigned int len, size;
    smtpdHdr    *header = 0, *boundary = 0, *fileHdr;
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
            if (!strcasecmp(header->name, "Content-Type")) {
                if ((ptr = SmtpdStrPos(header->value, "boundary="))) {
                    for (ptr += 9; *ptr == ' ' || *ptr == '"'; ptr++);
                    for (line = ptr; *line && *line != '\n' && *line != '\r' && *line != '"'; line++);
                    header = (smtpdHdr *) ns_calloc(1, sizeof(smtpdHdr));
                    header->name = (char *) ns_calloc(1, (unsigned) (line - ptr) + 3);
                    memcpy(header->name, "--", 2);
                    memcpy(header->name + 2, ptr, (unsigned) (line - ptr));
                    header->next = boundary;
                    boundary = header;
                }
            } else
                // Parse all email headers
            if (!strcasecmp(header->name, "Sender") ||
                    !strcasecmp(header->name, "X-Sender") ||
                    !strcasecmp(header->name, "From") ||
                    !strcasecmp(header->name, "To") || !strcasecmp(header->name, "Reply-To")) {
                smtpdEmail addr;
                Ns_DStringTrunc(&conn->reply, 0);
                Ns_DStringAppend(&conn->reply, header->value);
                if (parseEmail(&addr, conn->reply.string)) {
                    if (size <= (len = strlen(addr.mailbox) + strlen(addr.domain))) {
                        ns_free(header->value);
                        header->value = ns_malloc(len + 1);
                        Ns_Log(Error, "nssmtpd: %d: header: %s: %d,%d", conn->id, header->value, size, len);
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
            conn->body.offset = end - conn->body.data.string;
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
                if ((ptr = SmtpdStrNPos(hdr, "filename=", end - hdr))) {
                    for (ptr += 9; *ptr == ' ' || *ptr == '"'; ptr++);
                    for (line = ptr; *line && *line != '\n' && *line != '\r' && *line != '"'; line++);
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
            } else
            if (!strncasecmp(hdr, "Content-Transfer-Encoding:", 26)) {
                for (encodingType = hdr + 26; *encodingType && isspace(*encodingType); encodingType++);
#if defined(USE_CLAMAV) || defined(USE_SAVI)
                encodingSize = end - encodingType;
#endif
            } else
            if (!strncasecmp(hdr, "Content-Type:", 13)) {
                for (contentType = hdr + 13; *contentType && isspace(*contentType); contentType++);
#if defined(USE_CLAMAV) || defined(USE_SAVI)
                contentSize = end - contentType;
#endif
                if ((ptr = SmtpdStrNPos(contentType, "boundary=", end - contentType))) {
                    for (ptr += 9; *ptr == ' ' || *ptr == '"'; ptr++);
                    for (line = ptr; *line && *line != '\n' && *line != '\r' && *line != '"'; line++);
                    header = (smtpdHdr *) ns_calloc(1, sizeof(smtpdHdr));
                    header->name = ns_calloc(1, (unsigned) (line - ptr) + 3);
                    memcpy(header->name, "--", 2);
                    memcpy(header->name + 2, ptr, (unsigned) (line - ptr));
                    header->next = boundary;
                    boundary = header;
                }
                if (!fileHdr && (ptr = SmtpdStrNPos(hdr, "name=", end - hdr))) {
                    for (ptr += 5; *ptr == ' ' || *ptr == '"'; ptr++);
                    for (line = ptr; *line && *line != '\n' && *line != '\r' && *line != '"'; line++);
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
                    size = (end = hdr) - body;
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
                if (fileHdr && encodingType && (conn->flags & SMTPD_VIRUSCHECK)) {
                    // Check attachement for virus, replace infected file with text message
                    if ((!strncasecmp(encodingType, "base64", 6) && (ptr = decode64(body, size, (int*)&len))) ||
                        (!strncasecmp(encodingType, "quoted-printable", 16) && (ptr = decodeqp(body, size, (int*)&len)))) {
                        SmtpdCheckVirus(conn, ptr, len, fileHdr->value);
                        ns_free(ptr);
                    }
                    if (conn->flags & SMTPD_GOTVIRUS) {
                        static char *info = "The attachement has been removed due to virus infection";
                        
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
#endif
                break;
            }
            // Next header
            end = strchr((hdr = end), '\n');
        }
    }
}

static smtpdIpaddr *SmtpdParseIpaddr(char *str)
{
    struct sockaddr *saPtr, *addr_saPtr;
    smtpdIpaddr     *alist = NULL;
    char             addr[NS_IPADDR_SIZE], mask[NS_IPADDR_SIZE] = "", format[16];
    bool             have_ipmask = NS_FALSE;
    int              rc, maskBits;

    snprintf(format, sizeof(format), "%%%lus", sizeof(addr));

    if (sscanf(str, "%[0123456789.]/%[0123456789.]", addr, mask) == 2);
    else
    if (sscanf(str, "%[0123456789.:]", addr) == 1);
    else
    if (sscanf(str, "%[^/]/%17s", addr, mask) == 2);
    else
    if (sscanf(str, format, addr) == 1) {
        smtpdIpaddr *arec;
        Tcl_DString  ds, *dsPtr = &ds;
        Tcl_Obj     *listObj, **objv;
        int          objc, i;

        // Obtain all IP addresses for given hostname
        Tcl_DStringInit(dsPtr);
        if (Ns_GetAllAddrByHost(dsPtr, addr) == NS_FALSE) {
            Ns_Log(Error, "could not obtain IP addresses for '%s'", addr);
            return 0;
        }

        listObj = Tcl_NewStringObj(Tcl_DStringValue(dsPtr), Tcl_DStringLength(dsPtr));
        rc = Tcl_ListObjGetElements(NULL, listObj, &objc, &objv);
        if (rc != TCL_OK) {
            Ns_Log(Error, "invalid list of ip adresses '%s'", Tcl_GetString(listObj));
            return 0;
        }

        for (i = 0; i< objc; i++) {
            arec = ns_calloc(1, sizeof(smtpdIpaddr));
            saPtr = (struct sockaddr *)&(arec->addr);
            rc = Ns_GetSockAddr(saPtr, Tcl_GetString(objv[i]), 0);
            if (rc != TCL_OK) {
                Ns_Log(Error, "invalid ip adresses '%s'", Tcl_GetString(objv[i]));
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
        Ns_Log(Error, "invalid ip adresses '%s'", addr);
        return 0;
    }

    addr_saPtr = saPtr;
    saPtr = (struct sockaddr *)&(alist->mask);
    saPtr->sa_family = addr_saPtr->sa_family;
    maskBits = 0;
    
    /* Decode mask */
    if (*mask) {
        if (strchr(mask, '.') || strchr(mask, ':')) {
            (void) Ns_GetSockAddr(saPtr, mask, 0);
            have_ipmask = NS_TRUE;
        } else {
            maskBits = strtol(mask, NULL, 10);
        }
    }
    if (have_ipmask == NS_FALSE) {
        if (maskBits == 0) {
            if (addr_saPtr->sa_family == AF_INET6) {
                maskBits = 128;
            } else {
                maskBits = 32;
            }
        }
        if ((addr_saPtr->sa_family == AF_INET6) && (maskBits <= 128)) {
            Ns_SockaddrMaskBits(saPtr, maskBits);
            have_ipmask = NS_TRUE;
        } else if ((addr_saPtr->sa_family == AF_INET) && (maskBits <= 32)) {
            Ns_SockaddrMaskBits(saPtr, maskBits);
            have_ipmask = NS_TRUE;
        } else {
            Ns_Log(Error, "invalid mask bits %d for ip adresses '%s'", maskBits, addr);
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
        } else
        if (!(ipmask & 0x00FFFFFF)) {
            ipmask = htonl(0xFF000000ul);
        } else
        if (!(ipmask & 0x0000FFFF)) {
            ipmask = htonl(0xFFFF0000ul);
        } else
        if (!(ipmask & 0x000000FF)) {
            ipmask = htonl(0xFFFFFF00ul);
        } else {
            ipmask = htonl(0xFFFFFFFFul);
        }
    }
    /* 1.2.3.4/255.255.255.0  --> 1.2.3.0 */
#endif    

    return alist;
}

static int SmtpdCheckDomain(smtpdConn *conn, char *domain)
{
    dnsRecord *rec;
    dnsPacket *reply;

    if (conn && !(conn->flags & SMTPD_NEEDDOMAIN)) {
        return 1;
    }
    if ((reply = dnsLookup(domain, DNS_TYPE_A, 0))) {
        for (rec = reply->anlist; rec && rec->type != DNS_TYPE_A; rec = rec->next);
        dnsPacketFree(reply, 0);
        if (rec) {
            return 1;
        }
        reply = 0;
    }
    if (!reply && (reply = dnsLookup(domain, DNS_TYPE_MX, 0))) {
        for (rec = reply->anlist; rec && rec->type != DNS_TYPE_MX; rec = rec->next);
        dnsPacketFree(reply, 0);
        if (rec) {
            return 1;
        }
    }
    if (!conn) {
        return 0;
    }
    Ns_Log(Error, "nssmtpd: checkdomain: %d: HOST: %s, FLAGS: 0x%X, %s", conn->id, conn->host, conn->flags, domain);
    Ns_DStringPrintf(&conn->reply, "553 %s... Domain unrecognised\r\n", domain);
    return 0;
}

static int SmtpdCheckRelay(smtpdConn *conn, smtpdEmail *addr, char **host, int *port)
{
    smtpdRelay *relay;

    Ns_MutexLock(&conn->config->relaylock);
    for (relay = conn->config->relaylist; relay; relay = relay->next) {
        char *p, *s;

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
                    return 1;
                }
                break;
            }
            if (p-- == addr->domain) {
                break;
            }
        }
    }
    Ns_MutexUnlock(&conn->config->relaylock);
    
    return 0;
}

/* CHECK command returns just a header (terminated by "\r\n\r\n") with the first
 * line as for PROCESS (ie a response code and message), and then a header called
 * "Spam:" with value of either "True" or "False", then a semi-colon, and then the
 * score for this message, " / " then the threshold.  So the entire response looks
 * like either:
 *
 * SPAMD/1.1 0 EX_OK
 * Spam: True ; 15 / 5
 */
static int SmtpdCheckSpam(smtpdConn *conn)
{
#ifdef USE_SPAMASSASSIN
    int rc;
    char *p;
    float score;
    Ns_Sock sock;
    smtpdRcpt *rcpt;
    smtpdConn *spamd;
    Ns_Time timeout = { conn->config->writetimeout, 0 };

    if (!conn->config->spamdhost)
        return 0;
    /* Should have at least one unverified recipient */
    for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
        if (!(rcpt->flags & SMTPD_DELIVERED) && (rcpt->flag & SMTPD_SPAMCHECK)) {
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
    Ns_DStringPrintf(&spamd->line, "Content-Length: %d\r\n\r\n", conn->body.data.length);
    if (SmtpdWriteDString(spamd, &spamd->line) != NS_OK) {
        goto error;
    }
    if (SmtpdWriteDString(spamd, &conn->body.data) != NS_OK) {
        goto error;
    }
    shutdown(sock.sock, 1);
    if (SmtpdReadLine(spamd, &spamd->line) < 0) {
        goto error;
    }
    /* We should receive 0 response code */
    if (strncasecmp(spamd->line.string, "SPAMD/", 6) || !strstr(spamd->line.string, "EX_OK")) {
        goto error;
    }
    if (SmtpdReadLine(spamd, &spamd->line) < 0) {
        goto error;
    }
    /* Validate spam line */
    if (strncmp(spamd->line.string, "Spam:", 5) || !(p = strchr(spamd->line.string + 6, ';'))) {
        goto error;
    }
    rc = strstr(spamd->line.string, "True") ? SMTPD_GOTSPAM : 0;
    score = atof(++p);
    // Update all recipients with spam score/status
    for (; rcpt; rcpt = rctp->next) {
        if (rcpt->flags & SMTPD_DELIVERED || !(rcpt->flag & SMTPD_SPAMCHECK)) {
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
#endif

#ifdef USE_DSPAM
    char *sig;
    int rc = -1;
    DSPAM_CTX *CTX;
    smtpdRcpt *rcpt;

    /* Check spam for each recipient */
    for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
        if (rcpt->flags & SMTPD_DELIVERED || !(rcpt->flags & SMTPD_SPAMCHECK)) {
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
#endif
    return 0;
}

static int SmtpdCheckVirus(smtpdConn *conn, char *data, int datalen, char *location)
{
#ifdef USE_SAVI
    HRESULT hr;
    char buf[81];
    Ns_DString ds;
    CISavi3 *pSAVI;
    unsigned long virusType;
    unsigned long pcFetched;
    CISweepResults *pResults = 0;
    unsigned long isDisinfectable;
    CISweepClassFactory2 *pFactory;
    CIEnumSweepResults *pEnumResults;

    if (!location) {
        location = datalen ? "buffer" : data;
    }
    if ((hr = DllGetClassObject((REFIID) & SOPHOS_CLASSID_SAVI, (REFIID) & SOPHOS_IID_CLASSFACTORY2, (void **) &pFactory)) < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Failed to get class factory interface: %s", location, buf, 0);
        return TCL_ERROR;
    }
    hr = pFactory->pVtbl->CreateInstance(pFactory, NULL, (REFIID) & SOPHOS_IID_SAVI3, (void **) &pSAVI);
    pFactory->pVtbl->Release(pFactory);
    if (hr < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Failed to get a CSAVI3 interface: %s", location, buf, 0);
        return TCL_ERROR;
    }
    if ((hr = pSAVI->pVtbl->InitialiseWithMoniker(pSAVI, "ns_savi")) < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Failed to initialize SAVI: %s", location, buf, 0);
        pSAVI->pVtbl->Release(pSAVI);
        return TCL_ERROR;
    }
    if (datalen) {
        hr = pSAVI->pVtbl->SweepBuffer(pSAVI, location, datalen, data, (REFIID) & SOPHOS_IID_ENUM_SWEEPRESULTS, (void **) &pEnumResults);
    } else {
        hr = pSAVI->pVtbl->SweepFile(pSAVI, data, (REFIID) & SOPHOS_IID_ENUM_SWEEPRESULTS, (void **) &pEnumResults);
    }
    if (hr < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Unable to sweep: %s", location, buf, 0);
        pSAVI->pVtbl->Terminate(pSAVI);
        pSAVI->pVtbl->Release(pSAVI);
        return TCL_ERROR;
    }
    if ((hr = pEnumResults->pVtbl->Reset(pEnumResults)) < 0) {
        sprintf(buf, "%lx", hr);
        Tcl_AppendResult(conn->interp, "nssavi: %s: Failed to reset results enumerator: %s", location, buf, 0);
        pSAVI->pVtbl->Terminate(pSAVI);
        pSAVI->pVtbl->Release(pSAVI);
        return TCL_ERROR;
    }
    Ns_DStringInit(&ds);
    while (pEnumResults->pVtbl->Next(pEnumResults, 1, (void **) &pResults, &pcFetched) == SOPHOS_S_OK) {
        if (pResults->pVtbl->GetVirusType(pResults, &virusType) < 0 || virusType == SOPHOS_NO_VIRUS) {
            break;
        }
        switch (virusType) {
        case SOPHOS_VIRUS:
            conn->flags |= SMTPD_GOTVIRUS;
            Ns_DStringAppend(&ds, "Type=Virus; ");
            break;
        case SOPHOS_VIRUS_IDENTITY:
            conn->flags |= SMTPD_GOTVIRUS;
            Ns_DStringAppend(&ds, "Type=Identity; ");
            break;
        case SOPHOS_VIRUS_PATTERN:
            conn->flags |= SMTPD_GOTVIRUS;
            Ns_DStringAppend(&ds, "Type=Pattern; ");
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
        pResults = 0;
    }
    Ns_DStringFree(&ds);
    if (pResults) {
        pResults->pVtbl->Release(pResults);
    }
    pEnumResults->pVtbl->Release(pEnumResults);
    pSAVI->pVtbl->Terminate(pSAVI);
    pSAVI->pVtbl->Release(pSAVI);
#endif

#ifdef USE_CLAMAV
    const char *virname;
    unsigned long size = 0;

    if (datalen) {
        int fd;
        char tmpfile[128];
        
        tmpnam(tmpfile);
        fd = open(tmpfile, O_CREAT|O_RDWR, 0644);
        if (fd < 0) {
            Tcl_AppendResult(conn->interp, strerror(errno), 0);
            return TCL_ERROR;
        }
        write(fd, data, datalen);
        unlink(tmpfile);
        if (cl_scandesc(fd, &virname, &size, conn->config->ClamAvRoot, &conn->config->ClamAvLimits, CL_SCAN_STDOPT) == CL_VIRUS) {
            conn->flags |= SMTPD_GOTVIRUS;
            SmtpdConnAddHeader(conn, SMTPD_HDR_VIRUS_STATUS, (char*)virname, 1);
        }
    } else {
        if (cl_scanfile(data, &virname, &size, conn->config->ClamAvRoot, &conn->config->ClamAvLimits, CL_SCAN_STDOPT) == CL_VIRUS) {
            conn->flags |= SMTPD_GOTVIRUS;
            SmtpdConnAddHeader(conn, SMTPD_HDR_VIRUS_STATUS, (char*)virname, 1);
        }
    }
#endif
    return TCL_OK;
}

static smtpdIpaddr *SmtpdCheckIpaddr(smtpdIpaddr *list, const char *ipString)
{
    struct NS_SOCKADDR_STORAGE sa_ip;
    struct sockaddr *sa_ipPtr = (struct sockaddr *)&sa_ip;
    int    rc;

    rc = ns_inet_pton(sa_ipPtr, ipString);
    if (unlikely(rc <= 0)) {
        Ns_Log(Error, "nssmtpd: invalid incoming ip address '%s'", ipString);
    } else {
        while (list) {
            struct NS_SOCKADDR_STORAGE sa;
            struct sockaddr *maskPtr = (struct sockaddr *)&list->mask, *saPtr = (struct sockaddr *)&sa;

            /*
             * Obtain a copy of the incoming ip address and mask it. Then check
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

static int SmtpdFlags(const char *name)
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
    return 0;
}

static int SmtpdCmd(ClientData arg, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[])
{
    char *name = 0;
    smtpdRcpt *rcpt;
    smtpdConn *conn = 0;
    Tcl_HashEntry *rec;
    smtpdConfig *config = arg;
    int cmd, id, index = -99, count = 0;

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
        Tcl_AppendResult(interp, "wrong # args: should be ns_smtpd command ?args ...?", 0);
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], sCmd, "command", TCL_EXACT, (int *) &cmd) != TCL_OK) {
        return TCL_ERROR;
    }
    if (cmd > cmdSessions) {
        if (Tcl_GetIntFromObj(interp, objv[2], &id) != TCL_OK) {
            return TCL_ERROR;
        }
        Ns_MutexLock(&config->lock);
        rec = Tcl_FindHashEntry(&config->sessions, (char *)(long) id);
        Ns_MutexUnlock(&config->lock);
        if (!rec) {
            Tcl_AppendResult(interp, "invalid session id: ", Tcl_GetStringFromObj(objv[2], 0), 0);
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
        if (!(id = SmtpdFlags(Tcl_GetString(objv[2])))) {
            Tcl_AppendResult(interp, "nssmtpd: invalid flag name ", Tcl_GetString(objv[2]), 0);
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj(id));
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
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "hex")) {
            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = encodehex(name, count))) {
                break;
            }
            Tcl_SetResult(interp, name, (Tcl_FreeProc *) ns_free);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "qprint")) {
            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = encodeqp(name, count))) {
                break;
            }
            Tcl_SetResult(interp, name, (Tcl_FreeProc *) ns_free);
        } else {
            Tcl_AppendResult(interp, "unknown encode type", 0);
            return TCL_ERROR;
        }
        break;

    case cmdDecode:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 1, objv, "type text");
            return TCL_ERROR;
        }
        if (!strcmp(Tcl_GetString(objv[2]), "base64")) {
            int len;
            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = decode64(name, count, &len))) {
                break;
            }
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *) name, len));
            ns_free(name);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "hex")) {
            int len;
            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = decodehex(name, &len))) {
                break;
            }
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *) name, len));
            ns_free(name);
        } else
        if (!strcmp(Tcl_GetString(objv[2]), "qprint")) {
            int len;
            name = (char *) Tcl_GetByteArrayFromObj(objv[3], &count);
            if (!(name = decodeqp(name, count, &len))) {
                break;
            }
            Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((unsigned char *) name, len));
            ns_free(name);
        } else {
            Tcl_AppendResult(interp, "unknown decode type", 0);
            return TCL_ERROR;
        }
        break;

    case cmdInfo:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 1, objv, "address|relay|version|server");
            return TCL_ERROR;
        }
        if (!strcasecmp("server", Tcl_GetString(objv[2]))) {
            Tcl_AppendResult(interp, config->server, 0);
        } else
        if (!strcasecmp("version", Tcl_GetString(objv[2]))) {
            Tcl_AppendResult(interp, SMTPD_VERSION, 0);
        } else
        if (!strcasecmp("address", Tcl_GetString(objv[2]))) {
            if (config->driver && config->driver->location) {
                const char *address = strstr(config->driver->location, "://");
                if (address) {
                    address += 3;
                } else {
                    address = config->driver->location;
                }
                Tcl_AppendResult(interp, address, 0);
            }
        } else
        if (!strcasecmp("relay", Tcl_GetString(objv[2]))) {
            Tcl_Obj *obj = Tcl_NewStringObj(config->relayhost, -1);
            Tcl_AppendToObj(obj, ":", -1);
            Tcl_AppendObjToObj(obj, Tcl_NewIntObj(config->relayport));
            Tcl_SetObjResult(interp, obj);
        }
        break;

    case cmdSessions:{
            Tcl_HashSearch search;
            Tcl_Obj *list = Tcl_NewListObj(0, 0);
            Ns_MutexLock(&config->lock);
            rec = Tcl_FirstHashEntry(&config->sessions, &search);
            while (rec) {
                conn = Tcl_GetHashValue(rec);
                Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(conn->id));
                Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(conn->from.addr, -1));
                for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
                    Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(rcpt->addr, -1));
                    Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(rcpt->flags));
                }
                rec = Tcl_NextHashEntry(&search);
            }
            Ns_MutexUnlock(&config->lock);
            Tcl_SetObjResult(interp, list);
            break;
        }

    case cmdRelay:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 1, objv, "add|del|get|set");
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
                        relay->port = atoi(p);
                    }
                }
                Ns_MutexLock(&config->relaylock);
                relay->next = config->relaylist;
                config->relaylist = relay;
                Ns_MutexUnlock(&config->relaylock);
            }
        } else
        if (!strcasecmp("check", Tcl_GetString(objv[2]))) {
            smtpdEmail addr;
            
            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "address");
                return TCL_ERROR;
            }
            name = ns_strdup(Tcl_GetString(objv[3]));
            if (parseEmail(&addr, name)) {
                int port;
                smtpdConn conn;
                char *host;
                
                conn.config = config;
                if (SmtpdCheckRelay(&conn, &addr, &host, &port)) {
                    char buf[10];
                    
                    sprintf(buf, ":%d", port ? port : DEFAULT_PORT);
                    Tcl_AppendResult(interp, host, buf, 0);
                    ns_free(host);
                }
            }
            ns_free(name);
        } else
        if (!strcasecmp("del", Tcl_GetString(objv[2]))) {
            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "domain");
                return TCL_ERROR;
            }
        } else
        if (!strcasecmp("get", Tcl_GetString(objv[2]))) {
            smtpdRelay *relay;
            Tcl_Obj *list = Tcl_NewListObj(0, 0);
            
            Ns_MutexLock(&config->relaylock);
            for (relay = config->relaylist; relay; relay = relay->next) {
                Tcl_Obj *obj = Tcl_NewStringObj(relay->name, -1);
                
                if (relay->host) {
                    Tcl_AppendStringsToObj(obj, ":", relay->host, 0);
                    if (relay->port) {
                        Tcl_AppendObjToObj(obj, Tcl_NewIntObj(relay->port));
                    }
                }
                Tcl_ListObjAppendElement(interp, list, obj);
            }
            Ns_MutexUnlock(&config->relaylock);
            Tcl_SetObjResult(interp, list);
        } else
        if (!strcasecmp("set", Tcl_GetString(objv[2]))) {
            int i;
            char *p;
            smtpdRelay *relay;
            Ns_MutexLock(&config->relaylock);
            while (config->relaylist) {
                relay = config->relaylist->next;
                ns_free(config->relaylist->name);
                ns_free(config->relaylist);
                config->relaylist = relay;
            }
            for (i = 3; i < objc; i++) {
                relay = ns_calloc(1, sizeof(smtpdRelay));
                relay->name = ns_strdup(Tcl_GetString(objv[i]));
                if ((relay->host = strchr(relay->name, ':'))) {
                    *relay->host++ = 0;
                    if ((p = strchr(relay->host, ':'))) {
                        *p++ = 0;
                        relay->port = atoi(p);
                    }
                }
                relay->next = config->relaylist;
                config->relaylist = relay;
            }
            Ns_MutexUnlock(&config->relaylock);
        } else
        if (!strcasecmp("clear", Tcl_GetString(objv[2]))) {
            smtpdRelay *relay;
            Ns_MutexLock(&config->relaylock);
            while (config->relaylist) {
                relay = config->relaylist->next;
                ns_free(config->relaylist->name);
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
                for (end = config->local; end && end->next; end = end->next);
                if (end)
                    end->next = addr;
                else
                    config->local = addr;
            }
            Ns_MutexUnlock(&config->locallock);
        } else
        if (!strcasecmp("del", Tcl_GetString(objv[2]))) {
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
                int maskBits = 32;
                if (addrPtr->sa_family == AF_INET6) {
                    maskBits = 128;
                }
                Ns_SockaddrMaskBits(addrPtr, maskBits);
                Ns_SockaddrMaskBits(maskPtr, maskBits);
            }
            Ns_MutexUnlock(&config->locallock);
        } else
        if (!strcasecmp("check", Tcl_GetString(objv[2]))) {
            smtpdIpaddr *addr;
            
            if (objc < 4) {
                Tcl_WrongNumArgs(interp, 2, objv, "ipaddr");
                return TCL_ERROR;
            }
            Ns_MutexLock(&config->locallock);
            addr = SmtpdCheckIpaddr(config->local, Tcl_GetString(objv[3]));
            Ns_MutexUnlock(&config->locallock);
            Tcl_AppendResult(interp, addr ? "1" : "0", 0);
        } else
        if (!strcasecmp("get", Tcl_GetString(objv[2]))) {
            smtpdIpaddr *addr;
            Tcl_Obj     *list = Tcl_NewListObj(0, 0);
            
            Ns_MutexLock(&config->locallock);
            for (addr = config->local; addr; addr = addr->next) {
                char     ipString[NS_IPADDR_SIZE];
                Tcl_Obj *obj;
                struct sockaddr *saPtr;
                
                saPtr = (struct sockaddr *)&(addr->addr);
                obj = Tcl_NewStringObj(ns_inet_ntop(saPtr, ipString, sizeof(ipString)), -1);

                saPtr = (struct sockaddr *)&(addr->mask);
                Tcl_AppendStringsToObj(obj, "/",
                                       ns_inet_ntop(saPtr, ipString, sizeof(ipString)),
                                       NULL);
                
                Tcl_ListObjAppendElement(interp, list, obj);
            }
            Ns_MutexUnlock(&config->locallock);
            Tcl_SetObjResult(interp, list);
        } else
        if (!strcasecmp("set", Tcl_GetString(objv[2]))) {
            int i;
            smtpdIpaddr *addr, *end = 0;
            
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
                    for (end = addr; end->next; end = end->next);
                }
            }
            Ns_MutexUnlock(&config->locallock);
        } else
        if (!strcasecmp("clear", Tcl_GetString(objv[2]))) {
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
            int port = 0;
            char *host = NULL;

            if (objc < 5) {
                Tcl_WrongNumArgs(interp, 1, objv, "sender_email rcpt_email data_varname ?server? ?port?");
                return TCL_ERROR;
            }
            if (objc > 5) {
                host = Tcl_GetString(objv[5]);
            }
            if (objc > 6) {
                port = atoi(Tcl_GetString(objv[6]));
            }
            if (!host || !*host) {
                smtpdEmail addr;
                smtpdConn conn;
                char *email = ns_strdup(Tcl_GetString(objv[3]));
                conn.config = config;
                if (parseEmail(&addr, email)) {
                    SmtpdCheckRelay(&conn, &addr, &host, &port);
                }
                ns_free(email);
            }
            if (SmtpdSend(config, interp, Tcl_GetString(objv[2]), Tcl_GetString(objv[3]), Tcl_GetString(objv[4]), host, port)) {
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
            for (hdr = conn->body.headers; hdr; hdr = hdr->next) {
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
            for (hdr = conn->body.headers; hdr; hdr = hdr->next) {
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
            Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(conn->body.offset));
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
                for (rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next) {
                    fprintf(fp, "To: %s\n", rcpt->addr);
                }
                fputs("\n", fp);
                fwrite(conn->body.data.string, conn->body.data.length, 1, fp);
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
        ns_free(conn->from.addr);
        conn->from.addr = ns_strcopy(Tcl_GetString(objv[3]));
        break;

    case cmdSetFromData:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "data");
            return TCL_ERROR;
        }
        ns_free(conn->from.data);
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
            for (count = 0, rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next, count++) {
                if (objc > 3) {
                    if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                        Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(rcpt->addr, -1));
                        Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(rcpt->flags));
                        Tcl_ListObjAppendElement(interp, list, Tcl_NewDoubleObj(rcpt->spam_score));
                        break;
                    }
                } else {
                    item = Tcl_NewListObj(0, 0);
                    Tcl_ListObjAppendElement(interp, item, Tcl_NewStringObj(rcpt->addr, -1));
                    Tcl_ListObjAppendElement(interp, item, Tcl_NewIntObj(rcpt->flags));
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
        for (count = 0, rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next, count++) {
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
        for (count = 0, rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next, count++) {
            if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                ns_free(rcpt->data);
                rcpt->data = ns_strcopy(Tcl_GetString(objv[4]));
                break;
            }
        }
        break;

    case cmdSetFlag:{
            int flags;
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
            if (Tcl_GetIntFromObj(0, objv[4], &flags) != TCL_OK) {
                if (!(flags = SmtpdFlags(Tcl_GetString(objv[4])))) {
                    Tcl_AppendResult(interp, "nssmtpd: invalid flag:", Tcl_GetString(objv[4]), 0);
                    return TCL_ERROR;
                }
            }
            /* Set global connection's flags */
            if (index == -1) {
                if (flags > 0) {
                    conn->flags |= flags;
                } else {
                    conn->flags &= ~(flags * -1);
                }
                Tcl_SetObjResult(interp, Tcl_NewIntObj(conn->flags));
                break;
            }
            /* Set recipient's flags */
            for (count = 0, rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next, count++) {
                if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                    if (flags > 0) {
                        rcpt->flags |= flags;
                    } else {
                        rcpt->flags &= ~(flags * -1);
                    }
                    Tcl_SetObjResult(interp, Tcl_NewIntObj(rcpt->flags));
                    break;
                }
            }
            break;
        }

    case cmdUnsetFlag:{
            int flags;
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
            if (Tcl_GetIntFromObj(0, objv[4], &flags) != TCL_OK) {
                if (!(flags = SmtpdFlags(Tcl_GetString(objv[4])))) {
                    Tcl_AppendResult(interp, "nssmtpd: invalid flag:", Tcl_GetString(objv[4]), 0);
                    return TCL_ERROR;
                }
            }
            /* Set global connection's flags */
            if (index == -1) {
                conn->flags &= ~flags;
                Tcl_SetObjResult(interp, Tcl_NewIntObj(conn->flags));
                break;
            }
            /* Set recipient's flags */
            for (count = 0, rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next, count++) {
                if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                    rcpt->flags &= ~flags;
                    Tcl_SetObjResult(interp, Tcl_NewIntObj(rcpt->flags));
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
            Tcl_SetObjResult(interp, Tcl_NewIntObj(conn->flags));
            return TCL_OK;
        }
        /* Recipient's flags */
        for (count = 0, rcpt = conn->rcpt.list; rcpt; rcpt = rcpt->next, count++) {
            if ((index >= 0 && index == count) || (name && !strcmp(name, rcpt->addr))) {
                Tcl_SetObjResult(interp, Tcl_NewIntObj(rcpt->flags));
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
	  if (objc > 4 && Tcl_GetIntFromObj(interp, objv[4], &flags) != TCL_OK) {
            return TCL_ERROR;
	  }
	  rcpt->flags = flags;
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
        Ns_DStringTrunc(&conn->reply, 0);
        Ns_DStringAppend(&conn->reply, Tcl_GetString(objv[3]));
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
                Tcl_AppendResult(interp, addr.mailbox, "@", addr.domain, 0);
            break;
        }

    case cmdSpamVersion:
#ifdef USE_DSPAM
        Tcl_AppendResult(interp, "DSPAM", 0);
#endif

#ifdef USE_SPAMASSASSIN
        Tcl_AppendResult(interp, "SpamAssassin", 0);
#endif
        break;

    case cmdCheckSpam:{
            Ns_Sock sock;
            char score[12];
            smtpdConn *conn;

            if (objc < 3) {
                Tcl_WrongNumArgs(interp, 2, objv, "message ?email?");
                return TCL_ERROR;
            }
            sock.sock = -1;
            conn = SmtpdConnCreate(config, &sock);
            Ns_DStringAppend(&conn->body.data, Tcl_GetString(objv[2]));
            conn->rcpt.list = ns_calloc(1, sizeof(smtpdRcpt));
            conn->rcpt.list->flags |= SMTPD_SPAMCHECK;
            conn->rcpt.list->addr = ns_strdup(objc > 3 ? Tcl_GetString(objv[3]) : "smtpd");
            SmtpdCheckSpam(conn);
            sprintf(score, "%.2f", conn->rcpt.list->spam_score);
            Tcl_AppendResult(interp,
                             ((conn->rcpt.list->flags & SMTPD_GOTSPAM) != 0) ? "Spam" : "Innocent",
                             " ", score, " ",
                             SmtpdGetHeader(conn, SMTPD_HDR_SIGNATURE), 0);
            SmtpdConnFree(conn);
            break;
        }

    case cmdTrainSpam:{
#ifdef USE_DSPAM
            Ns_DString ds;
            DSPAM_CTX *CTX;
            struct _ds_spam_signature SIG;
            unsigned int flags = DSF_CHAINED | DSF_NOISE;

            if (objc < 5) {
                Tcl_WrongNumArgs(interp, 2, objv, "1|0 email message ?signature? ?mode? ?source?");
                return TCL_ERROR;
            }
            if (objc > 5) {
                if ((SIG.data = decodehex(Tcl_GetString(objv[5]), &SIG.length)))
                    flags |= DSF_SIGNATURE;
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
            if (flags & DSF_SIGNATURE)
                CTX->signature = &SIG;
            dspam_process(CTX, Tcl_GetString(objv[4]));
            if (flags & DSF_SIGNATURE)
                ns_free(SIG.data);
            Ns_DStringInit(&ds);
            Ns_DStringPrintf(&ds, "Flags: 0x%X, Source: 0x%X, Mode: 0x%X, Probability: %2.4f, Confidence: %2.4f, Result: %s",
                             flags,
                             CTX->source,
                             CTX->training_mode,
                             CTX->probability,
                             CTX->confidence,
                             CTX->result == DSR_ISSPAM ? "Spam" :
                             CTX->result == DSR_ISINNOCENT ? "Innocent" :
                             CTX->result == DSR_ISWHITELISTED ? "Whitelisted" : "Error");
            Tcl_AppendResult(interp, ds.string, 0);
            Ns_DStringFree(&ds);
            _ds_destroy_message(CTX->message);
            dspam_destroy(CTX);
#endif
            break;
        }

    case cmdVirusVersion:
#ifdef USE_SAVI
        Tcl_AppendResult(interp, "Sophos", 0);
#endif
#ifdef USE_CLAMAV
        Tcl_AppendResult(interp, "ClamAV", 0);
#endif
        break;

    case cmdCheckVirus:{
            Ns_Sock sock;
            smtpdConn *conn;

            if (objc < 3) {
                Tcl_WrongNumArgs(interp, 2, objv, "data");
                return TCL_ERROR;
            }
            sock.sock = -1;
            conn = SmtpdConnCreate(config, &sock);
            conn->interp = interp;
            if (Tcl_GetString(objv[2])[0] == '/') {
                SmtpdCheckVirus(conn, Tcl_GetString(objv[2]), 0, 0);
            } else {
                SmtpdCheckVirus(conn, Tcl_GetString(objv[2]), Tcl_GetCharLength(objv[2]), 0);
            }
            if (conn->flags & SMTPD_GOTVIRUS) {
                Tcl_AppendResult(interp, SmtpdGetHeader(conn, SMTPD_HDR_VIRUS_STATUS), 0);
            }
            SmtpdConnFree(conn);
            break;
        }
    }
    return TCL_OK;
}

static int parseEmail(smtpdEmail *addr, char *str)
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
            tok = parseDomain(&str, &domain, &comment);
            if (!*phrase || !*domain) {
                return 0;
            }
            addr->name = comment;
            addr->mailbox = phrase;
            addr->domain = domain;
            return 1;

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
                tok = parseDomain(&str, &domain, 0);
                if (!*mailbox || !*domain) {
                    return 0;
                }
                addr->name = phrase;
                addr->mailbox = mailbox;
                addr->domain = domain;
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Parse an RFC 822 "phrase",stopping at 'specials'
 */
static int parsePhrase(char **inp, char **phrasep, char *specials)
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
        } else
        if (isspace(c) || c == '(') {
            src--;
            src = parseSpace(src);
            *dst++ = ' ';
        } else
        if (!c || strchr(specials, c)) {
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
        *commentp = 0;
    }
    src = parseSpace(src);
    *domainp = dst = src;
    for (;;) {
        char c = *src++;
        
        if (isalnum(c) || c == '-' || c == '[' || c == ']') {
            *dst++ = c;
            if (commentp) {
                *commentp = 0;
            }
        } else
        if (c == '.') {
            if (dst > *domainp && dst[-1] != '.') {
                *dst++ = c;
            }
            if (commentp) {
                *commentp = 0;
            }
        } else
        if (c == '(') {
            if (commentp) {
                *commentp = cdst = src;
                comment = 1;
                while (comment && (c = *src)) {
                    src++;
                    if (c == '(') {
                        comment++;
                    } else
                    if (c == ')') {
                        comment--;
                    } else
                    if (c == '\\' && (c = *src)) {
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
        } else
        if (!isspace(c)) {
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
        } else
        if (c == '.') {
            if (dst > *routep && dst[-1] != '.') {
                *dst++ = c;
            }
        } else
        if (isspace(c) || c == '(') {
            src--;
            src = parseSpace(src);
        } else {
            while (dst > *routep && (dst[-1] == '.' || dst[-1] == ',' || dst[-1] == '@')) {
                dst--;
            }
            *dst = 0;
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
    int c, comment = 0;
    while ((c = *s)) {
        if (c == '(') {
            comment = 1;
            s++;
            while ((comment && (c = *s))) {
                s++;
                if (c == '\\' && *s) {
                    s++;
                } else
                if (c == '(') {
                    comment++;
                } else
                if (c == ')') {
                    comment--;
                }
            }
            s--;
        } else
        if (!isspace(c)) {
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

static char *encodehex(const char *buf, int len)
{
    char *s;
    int i, j;

    if (!buf || !*buf || !len) {
        return 0;
    }
    s = ns_calloc(2, len + 1);
    for (j = 0, i = 0; i < len; i++) {
        s[j++] = hex[(buf[i] >> 4) & 0x0F];
        s[j++] = hex[buf[i] & 0x0F];
    }
    return s;
}

static char *decodehex(const char *str, int *len)
{
    int c = 0;
    char *p, *t, *s, code[] = "00";

    if (!str || !*str || !len) {
        return 0;
    }
    *len = strlen(str) / 2;

    t = p = ns_calloc(1, *len);
    for (s = (char *) str; *s && c < *len; c++) {
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

static char *encode64(const char *in, int len)
{
    static char basis_64[] =
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
            oval |= in[1] >> 4;
        }
        *out++ = basis_64[oval];
        *out++ = (len < 2) ? '=' : basis_64[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }
    *out = '\0';
    return (char *) buf;
}

static char *decode64(const char *in, int len, int *outlen)
{
    char *out, *buf;
    int i, d = 0, dlast = 0, phase = 0;
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
                *out++ = ((dlast << 2) | ((d & 0x30) >> 4));
                ++phase;
                break;
            case 2:
                *out++ = (((dlast & 0xf) << 4) | ((d & 0x3c) >> 2));
                ++phase;
                break;
            case 3:
                *out++ = (((dlast & 0x03) << 6) | d);
                phase = 0;
                break;
            }
            dlast = d;
        }
    }
    *out = 0;
    *outlen = out - buf;
    return buf;
}

static char *encodeqp(const char *in, int len)
{
    int i = 0;
    char *buf, *out;
    static char *hex = "0123456789ABCDEF";

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

static char *decodeqp(const char *in, int len, int *outlen)
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
                case '\n':
                    ptr = out;
                    break;
                default:
                    if (!(isxdigit(c) && s - in < len && (c2 = *s++) && isxdigit(c2))) {
                        ns_free(buf);
                        return 0;
                    }
                    if (isdigit(c)) {
                        c -= '0';
                    } else {
                        c -= (isupper(c) ? 'A' - 10 : 'a' - 10);
                    }
                    if (isdigit(c2)) {
                        c2 -= '0';
                    } else {
                        c2 -= (isupper(c2) ? 'A' - 10 : 'a' - 10);
                    }
                    *out++ = c2 + (c << 4);
                    ptr = out;
                    break;
                }
            break;
        case ' ':
            *out++ = c;
            break;
        case '\r':
        case '\n':
            out = ptr;
        default:
            *out++ = c;
            ptr = out;
        }
    }
    *out = 0;
    *outlen = out - buf;
    return buf;
}

static void dnsInit(char *name, ...)
{
    va_list ap;

    Ns_MutexLock(&dnsMutex);
    va_start(ap, name);

    if (!strcmp(name, "nameserver")) {
        char *s, *n;
        dnsServer *server, *next;
        while ((s = va_arg(ap, char *))) {
            while (s) {
                if ((n = strchr(s, ','))) {
                    *n++ = 0;
                }
                server = ns_calloc(1, sizeof(dnsServer));
                server->name = ns_strdup(s);
                //server->ipaddr = inet_addr(s);
                for (next = dnsServers; next && next->next; next = next->next);
                if (!next) {
                    dnsServers = server;
                } else {
                    next->next = server;
                }
                s = n;
            }
        }
    } else
     if (!strcmp(name, "debug")) {
        dnsDebug = va_arg(ap, int);
    } else
     if (!strcmp(name, "retry")) {
        dnsResolverRetries = va_arg(ap, int);
    } else
     if (!strcmp(name, "timeout")) {
        dnsResolverTimeout = va_arg(ap, int);
    } else
     if (!strcmp(name, "failuretimeout")) {
        dnsFailureTimeout = va_arg(ap, int);
    } else
     if (!strcmp(name, "ttl")) {
        dnsTTL = va_arg(ap, int);
    }
    va_end(ap);
    Ns_MutexUnlock(&dnsMutex);
}

static dnsPacket *dnsLookup(char *name, int type, int *errcode)
{
    fd_set fds;
    char buf[DNS_BUFSIZE];
    struct timeval tv;
    dnsServer *server = 0;
    dnsPacket *req, *reply;
    int sock = NS_INVALID_SOCKET, len;

    if (!name) {
        return 0;
    }

    // Prepare DNS request packet
    req = ns_calloc(1, sizeof(dnsPacket));
    req->id = (unsigned long) req % (unsigned long) name;
    DNS_SET_RD(req->u, 1);
    req->buf.allocated = DNS_REPLY_SIZE;
    req->buf.data = ns_calloc(1, req->buf.allocated);
    if (name) {
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
        int timeout, retries, now, rc;
        struct NS_SOCKADDR_STORAGE sa;
        struct sockaddr           *saPtr = (struct sockaddr *)&sa;

        now = time(0);
        Ns_MutexLock(&dnsMutex);
        retries = dnsResolverRetries;
        timeout = dnsResolverTimeout;
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
            if (server->fail_time && now - server->fail_time > dnsFailureTimeout) {
                server->fail_count = server->fail_time = 0;
                Ns_Log(Error, "dnsLookup: %s: nameserver re-enabled", server->name);
            }
            if (!server->fail_time) {
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
            len = sizeof(struct sockaddr_in);
            if (sendto(sock, req->buf.data + 2, req->buf.size, 0, saPtr, len) < 0) {
                if (dnsDebug > 3) {
                    Ns_Log(Error, "dnsLookup: %s: sendto: %s", server->name, strerror(errno));
                }
                continue;
            }
            tv.tv_usec = 0;
            tv.tv_sec = timeout;
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            if (select(sock + 1, &fds, 0, 0, &tv) <= 0 || !FD_ISSET(sock, &fds)) {
                if (dnsDebug > 3 && errno) {
                    Ns_Log(Error, "dnsLookup: %s: select: %s", server->name, strerror(errno));
                }
                continue;
            }
            if ((len = recv(sock, buf, DNS_BUFSIZE, 0)) <= 0) {
                if (dnsDebug > 3) {
                    Ns_Log(Error, "dnsLookup: %s: recvfrom: %s", server->name, strerror(errno));
                }
                continue;
            }
            if (!(reply = dnsParsePacket((unsigned char *) buf, len))) {
                continue;
            }
            // DNS packet id should be the same
            if (reply->id == req->id) {
                ns_sockclose(sock);
                dnsPacketFree(req, 0);
                Ns_MutexLock(&dnsMutex);
                server->fail_count = server->fail_time = 0;
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
    if (!pkt) {
        return;
    }
    ns_free(pkt->name);
    switch (pkt->type) {
    case DNS_TYPE_MX:
        if (!pkt->data.mx) {
            break;
        }
        ns_free(pkt->data.mx->name);
        ns_free(pkt->data.mx);
        break;
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
        ns_free(pkt->data.name);
        break;
    case DNS_TYPE_SOA:
        if (!pkt->data.soa) {
            break;
        }
        ns_free(pkt->data.soa->mname);
        ns_free(pkt->data.soa->rname);
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
    if (!list || !pkt) {
        return 0;
    }
    for (; *list; list = &(*list)->next);
    *list = pkt;
    return *list;
}

static int dnsParseName(dnsPacket *pkt, char **ptr, char *buf, int buflen, int pos, int level)
{
    unsigned short i, len, offset;
    char *p;

    if (level > 15) {
        Ns_Log(Error, "nsdns: infinite loop %ld: %d", (*ptr - pkt->buf.data) - 2, level);
        return -9;
    }
    while ((len = *((*ptr)++)) != 0) {
        switch (len & 0xC0) {
        case 0xC0:
            if ((offset = ((len & ~0xC0) << 8) + (u_char) ** ptr) >= pkt->buf.size) {
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
    buf[pos] = 0;
    // Remove last . in the name
    if (buf[pos - 1] == '.') {
        buf[pos - 1] = 0;
    }
    return pos;
}

static dnsPacket *dnsParseHeader(void *buf, int size)
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
    pkt->buf.allocated = size + 128;
    pkt->buf.data = ns_malloc(pkt->buf.allocated);
    pkt->buf.size = size;
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
    y->ttl = ntohl(*((unsigned long *) pkt->buf.ptr));
    pkt->buf.ptr += 4;
    // Fetch the resource data.
    if (pkt->buf.ptr + 2 > pkt->buf.data + pkt->buf.allocated) {
        strcpy(name, "invalid data position");
        goto err;
    }
    if (!(y->len = ntohs(*((unsigned short *) pkt->buf.ptr)))) {
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
        y->data.soa->serial = ntohl(*((unsigned long *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
        y->data.soa->refresh = ntohl(*((unsigned long *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
        y->data.soa->retry = ntohl(*((unsigned long *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
        y->data.soa->expire = ntohl(*((unsigned long *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
        y->data.soa->ttl = ntohl(*((unsigned long *) pkt->buf.ptr));
        pkt->buf.ptr += 4;
    }
rec:
    return y;
err:
    dnsRecordFree(y);
    return 0;

}

static dnsPacket *dnsParsePacket(unsigned char *packet, int size)
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

static void dnsEncodeName(dnsPacket *pkt, char *name)
{
    dnsName *nm;

    dnsEncodeGrow(pkt, (name ? strlen(name) + 1 : 1), "name");
    if (name) {
        int k = 0, len;

        while (name[k]) {
            int i;
            unsigned int c;
            
            for (len = 0; (c = name[k + len]) != 0 && c != '.'; len++);
            if (!len || len > 63) {
                break;
            }
            // Find already saved domain name
            for (nm = pkt->nmlist; nm; nm = nm->next) {
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
            nm->offset = (pkt->buf.ptr - pkt->buf.data) - 2;
            // Encode name part inline
            *pkt->buf.ptr++ = (u_char) (len & 0x3F);
            for (i = 0; i < len; i++) {
                *pkt->buf.ptr++ = name[k++];
            }
            if (name[k] == '.') {
                k++;
            }
        }
    }
    *pkt->buf.ptr++ = 0;
}

static void dnsEncodeHeader(dnsPacket *pkt)
{
    unsigned short *p = (unsigned short *) pkt->buf.data;

    pkt->buf.size = (pkt->buf.ptr - pkt->buf.data) - 2;
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
    *pkt->buf.ptr++ = 0xC0 | (offset >> 8);
    *pkt->buf.ptr++ = (offset & 0xFF);
}

static void dnsEncodeShort(dnsPacket *pkt, int num)
{
    *((unsigned short *) pkt->buf.ptr) = htons((unsigned short) num);
    pkt->buf.ptr += 2;
}

static void dnsEncodeLong(dnsPacket *pkt, unsigned long num)
{
    *((unsigned long *) pkt->buf.ptr) = htonl((unsigned long) num);
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
    unsigned short len = pkt->buf.ptr - pkt->buf.rec;
    *((unsigned short *) pkt->buf.rec) = htons(len - 2);
}

static void dnsEncodeRecord(dnsPacket *pkt, dnsRecord *list)
{
    Ns_Log(SmtpdDebug, "dnsEncodeRecord");
    dnsEncodeGrow(pkt, 12, "pkt:hdr");
    for (; list; list = list->next) {
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

static void dnsEncodeGrow(dnsPacket *pkt, unsigned int size, char *proc)
{
    int offset = pkt->buf.ptr - pkt->buf.data;
    int roffset = pkt->buf.rec - pkt->buf.data;
    if (offset + size >= pkt->buf.allocated) {
        pkt->buf.allocated += 256;
        pkt->buf.data = ns_realloc(pkt->buf.data, pkt->buf.allocated);
        pkt->buf.ptr = &pkt->buf.data[offset];
        if (pkt->buf.rec)
            pkt->buf.rec = &pkt->buf.data[roffset];
    }
}

static void dnsPacketFree(dnsPacket *pkt, int type)
{
    if (!pkt)
        return;
    dnsRecordDestroy(&pkt->qdlist);
    dnsRecordDestroy(&pkt->nslist);
    dnsRecordDestroy(&pkt->arlist);
    dnsRecordDestroy(&pkt->anlist);
    while (pkt->nmlist) {
        dnsName *next = pkt->nmlist->next;
        ns_free(pkt->nmlist->name);
        ns_free(pkt->nmlist);
        pkt->nmlist = next;
    }
    ns_free(pkt->buf.data);
    ns_free(pkt);
}

//#ifdef HAVE_OPENSSL_EVP_H


/*
 *----------------------------------------------------------------------
 *
 * Ns_TLS_CtxServerCreate --
 *
 *   Create and Initialize OpenSSL context
 *
 * Results:
 *   Result code.
 *
 * Side effects:
 *  None
 *
 *----------------------------------------------------------------------
 */

static int
Ns_TLS_CtxServerCreate(Tcl_Interp *interp,
                       const char *cert, const char *caFile, const char *caPath, int verify,
                       NS_TLS_SSL_CTX **ctxPtr)
{
    NS_TLS_SSL_CTX *ctx;

    NS_NONNULL_ASSERT(interp != NULL);
    NS_NONNULL_ASSERT(ctxPtr != NULL);

    ctx = SSL_CTX_new(SSLv23_server_method());
    *ctxPtr = ctx;
    if (ctx == NULL) {
        Ns_TclPrintfResult(interp, "ctx init failed: %s", ERR_error_string(ERR_get_error(), NULL));
        return TCL_ERROR;
    }

    int rc = SSL_CTX_set_cipher_list(ctx, "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!RC4");

    SSL_CTX_set_default_verify_paths(ctx);
    SSL_CTX_load_verify_locations(ctx, caFile, caPath);
    SSL_CTX_set_verify(ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    if (cert != NULL) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
            Ns_TclPrintfResult(interp, "certificate load error: %s", ERR_error_string(ERR_get_error(), NULL));
            return TCL_ERROR;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
            Ns_TclPrintfResult(interp, "private key load error: %s", ERR_error_string(ERR_get_error(), NULL));
            return TCL_ERROR;
        }
    }

    return TCL_OK;
}



/*
 *----------------------------------------------------------------------
 *
 * Ns_TLS_SSLAccept --
 *
 *   Initialize a socket as ssl socket and wait until the socket is usable (is
 *   accepted, handshake performed)
 *
 * Results:
 *   Result code.
 *
 * Side effects:
 *   None
 *
 *----------------------------------------------------------------------
 */

static int
Ns_TLS_SSLAccept(Tcl_Interp *interp, NS_SOCKET sock, NS_TLS_SSL_CTX *ctx,
                  NS_TLS_SSL **sslPtr)
{
    NS_TLS_SSL     *ssl;

    NS_NONNULL_ASSERT(interp != NULL);
    NS_NONNULL_ASSERT(ctx != NULL);
    NS_NONNULL_ASSERT(sslPtr != NULL);

    Ns_Log(SmtpdDebug, "SSLAccept: before new.");
    ssl = SSL_new(ctx);
    *sslPtr = ssl;
    if (ssl == NULL) {
        Ns_TclPrintfResult(interp, "SSLAccept failed: %s", ERR_error_string(ERR_get_error(), NULL));
        Ns_Log(SmtpdDebug, "SSLAccept failed: %s", ERR_error_string(ERR_get_error(), NULL));
        return TCL_ERROR;
    }

    SSL_set_fd(ssl, sock);
    SSL_set_accept_state(ssl);

    while (1) {
        int rc, sslerr;

        Ns_Log(SmtpdDebug, "ssl accept");
        //rc  = SSL_accept(ssl);
        rc = SSL_do_handshake(ssl);
        Ns_Log(SmtpdDebug, "ssl accept rc=%d", rc);
        sslerr = SSL_get_error(ssl, rc);
        Ns_Log(SmtpdDebug, "ssl accept sslerr=%d", sslerr);

        if (sslerr == SSL_ERROR_WANT_WRITE || sslerr == SSL_ERROR_WANT_READ) {
            Ns_Time timeout = { 0, 10000 }; /* 10ms */
            Ns_SockTimedWait(sock, NS_SOCK_WRITE|NS_SOCK_READ, &timeout);
            continue;
        }
        break;
    }

    Ns_Log(SmtpdDebug, "SSLAccept state: %d",  SSL_get_state(ssl));
    if (!SSL_is_init_finished(ssl)) {
        Ns_TclPrintfResult(interp, "ssl accept failed: %s", ERR_error_string(ERR_get_error(), NULL));
        Ns_Log(SmtpdDebug, "ssl accept failed: %s", ERR_error_string(ERR_get_error(), NULL));
        free(ssl);
        ssl = NULL;
        return TCL_ERROR;
    }

    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * TlsRecv --
 *
 *      Receive data into given buffers.
 *
 * Results:
 *      Total number of bytes received or -1 on error or timeout.
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static ssize_t
TlsRecv(Ns_Sock *sock, struct iovec *bufs, int nbufs, Ns_Time *timeoutPtr, unsigned int flags)
{
    SSLDriver *drvPtr = sock->driver->arg;
    SSLContext *sslPtr = sock->arg;
    int got = 0;
    char *p = (char *)bufs->iov_base;

    /*
     * Verify client certificate, driver may require valid cert
     */

    if (drvPtr->verify && sslPtr->verified == 0) {
        X509 *peer;
        if ((peer = SSL_get_peer_certificate(sslPtr->ssl))) {
             X509_free(peer);
             if (SSL_get_verify_result(sslPtr->ssl) != X509_V_OK) {
                 char ipString[NS_IPADDR_SIZE];
                 Ns_Log(Error, "nsssl: client certificate not valid by %s",
                        ns_inet_ntop((struct sockaddr *)&(sock->sa), ipString, sizeof(ipString)));
                 return NS_ERROR;
             }
        } else {
            char ipString[NS_IPADDR_SIZE];
            Ns_Log(Error, "nsssl: no client certificate provided by %s",
                   ns_inet_ntop((struct sockaddr *)&(sock->sa), ipString, sizeof(ipString)));
            return NS_ERROR;
        }
        sslPtr->verified = 1;
    }

    while (1) {
        int err, n;

        ERR_clear_error();
        n = SSL_read(sslPtr->ssl, p + got, bufs->iov_len - got);
        err = SSL_get_error(sslPtr->ssl, n);

        switch (err) {
        case SSL_ERROR_NONE:
            if (n < 0) {
                fprintf(stderr, "### SSL_read should not happen\n");
                return n;
            }
            /*fprintf(stderr, "### SSL_read %d pending %d\n", n, SSL_pending(sslPtr->ssl));*/
            got += n;
            if (n == 1 && got < bufs->iov_len) {
                /*fprintf(stderr, "### SSL retry after read of %d bytes\n", n);*/
                continue;
            }
            /*Ns_Log(Notice, "### SSL_read %d got <%s>", got, p);*/
            return got;

        case SSL_ERROR_WANT_READ:
            /*fprintf(stderr, "### SSL_read WANT_READ returns %d\n", got);*/
            return got;

        default:
            /*fprintf(stderr, "### SSL_read error\n");*/
            SSL_set_shutdown(sslPtr->ssl, SSL_RECEIVED_SHUTDOWN);
            return -1;
        }
    }

    return -1;
}


/*
 *----------------------------------------------------------------------
 *
 * TlsSend --
 *
 *      Send data from given buffers.
 *
 * Results:
 *      Total number of bytes sent or -1 on error or timeout.
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static ssize_t
TlsSend(Ns_Sock *sock, const struct iovec *bufs, int nbufs,
     const Ns_Time *timeoutPtr, unsigned int flags)
{
    SSLContext *sslPtr = sock->arg;
    int         rc, size;
    bool        decork;

    size = 0;
    decork = Ns_SockCork(sock, NS_TRUE);
    while (nbufs > 0) {
        if (bufs->iov_len > 0) {
            ERR_clear_error();
            rc = SSL_write(sslPtr->ssl, bufs->iov_base, bufs->iov_len);

            if (rc < 0) {
                if (SSL_get_error(sslPtr->ssl, rc) == SSL_ERROR_WANT_WRITE) {
                    Ns_Time timeout = { sock->driver->sendwait, 0 };
                    if (Ns_SockTimedWait(sock->sock, NS_SOCK_WRITE, &timeout) == NS_OK) {
                    continue;
                    }
                }
                if (decork == NS_TRUE) {
                    Ns_SockCork(sock, NS_FALSE);
                }
                SSL_set_shutdown(sslPtr->ssl, SSL_RECEIVED_SHUTDOWN);
                return -1;
            }
            size += rc;
            if (rc < bufs->iov_len) {
                Ns_Log(Debug, "SSL: partial write, wanted %ld wrote %d", bufs->iov_len, rc);
            break;
            }
        }
        nbufs--;
        bufs++;
    }

    if (decork == NS_TRUE) {
        Ns_SockCork(sock, NS_FALSE);
    }
    return size;
}


/*
 *----------------------------------------------------------------------
 *
 * TlsClose --
 *
 *      Close the connection socket.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Does not close UDP socket
 *
 *----------------------------------------------------------------------
 */

static void
TlsClose(Ns_Sock *sock)
{
    SSLContext *sslPtr = sock->arg;

    if (sslPtr != NULL) {
        int i;
        for (i = 0; i < 4 && !SSL_shutdown(sslPtr->ssl); i++) {
            ;
        }
        SSL_free(sslPtr->ssl);
        ns_free(sslPtr);
    }
    if (sock->sock > -1) {
        ns_sockclose(sock->sock);
        sock->sock = -1;
    }
    sock->arg = NULL;
}

//#else
#if 0

static int
Ns_TLS_CtxServerCreate(Tcl_Interp *interp,
                       const char *cert, const char *caFile, const char *caPath, int verify,
                       NS_TLS_SSL_CTX **ctxPtr)
{
    Ns_TclPrintfResult(interp, "CtxCreate failed: no support for OpenSSL built in");
    return TCL_ERROR;
}


static int
Ns_TLS_SSLAccept(Tcl_Interp *interp, NS_SOCKET UNUSED(sock), NS_TLS_SSL_CTX *UNUSED(ctx),
                  NS_TLS_SSL **UNUSED(sslPtr))
{
    Ns_TclPrintfResult(interp, "SSLAccept failed: no support for OpenSSL built in");
    return TCL_ERROR;
}

static ssize_t
TlsRecv(Ns_Sock *sock, struct iovec *bufs, int nbufs, Ns_Time *timeoutPtr, unsigned int flags)
{
    Ns_TclPrintfResult(interp, "TlsRecv failed: no support for OpenSSL built in");
    return TCL_ERROR;
}

static ssize_t
TlsSend(Ns_Sock *sock, const struct iovec *bufs, int nbufs,
        const Ns_Time *timeoutPtr, unsigned int flags)
{
    Ns_TclPrintfResult(interp, "TlsSend failed: no support for OpenSSL built in");
    return TCL_ERROR;
}

static void TlsClose(Ns_Sock *sock)
{
    Ns_TclPrintfResult(interp, "TlsClose failed: no support for OpenSSL built in");
    return TCL_ERROR;
}

#endif

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
