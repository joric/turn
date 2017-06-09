// (c) joric 2010, public domain

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include "md5.h"
#include "hmac.h"
#define THREAD DWORD
#else
#include <sys/time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#define SOCKET int
#define THREAD pthread_t
#endif

#include <stdio.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <memory.h>

SOCKET turnSocket;

int turnPort = 3478;
char *turnHost = "0.0.0.0";
char *turnUser = "toto";
char *turnRealm = "domain.org";
int turnMagicCookie = 0x2112A442;
char turnKey[16];
char turnError[256] = { 0 };
char turnNonce[256] = { 0 };

#define turnBufferSize 512
#define turnBuffers 8

typedef struct
{
    int family;
    unsigned int port;
    unsigned char ip[4];
    char host[64];
    char str[64];
    struct sockaddr_in addr;
    SOCKET sock;
    int server;
    THREAD thread;
} turnAddress;

turnAddress turnServer;
turnAddress turnClient;
turnAddress turnPeer;
turnAddress turnRelay;

int turnCount = 0;
int turnHeaderSize = 20;
int turnDebug = 1;

typedef struct
{
    int type;
    int length;
    int magic;
    char *tsx_id;
    char *nonce;
    int errorcode;
    char *errormsg;
    char data[turnBufferSize];
    int ofs;
} turnMessage;

turnMessage turnMessages[turnBuffers];

int turnChannel = 0x40020000;

#define TN(id) {static char buf[16]; sprintf(buf, "0x%04x", id); return buf; }
#define T(id) if (type == id) return #id; else

enum turnActionType
{
    turnActionNone,
    turnActionBind,
    turnActionHandshake,
    turnActionAllocate,
    turnActionRefresh,
    turnActionRemoveAllocation,
    turnActionPermission,
    turnActionBindChannel,
    turnActionSend
};

enum turnMethodType
{
    turnMethodBinding = 0x0001,
    turnMethodSharedSecret = 0x0002,
    turnMethodAllocate = 0x0003,
    turnMethodRefresh = 0x0004,
    turnMethodSend = 0x0006,
    turnMethodData = 0x0006,
    turnMethodCreatePermission = 0x0008,
    turnMethodChannelBind = 0x0009,
};

enum turnMessageCode
{
    turnCodeRequest = 0x0000,
    turnCodeIndication = 0x010,
    turnCodeSuccessResp = 0x0100,
    turnCodeErrorResp = 0x0110
};

char *turnMessageCodeName(int type)
{
    T(turnCodeRequest);
    T(turnCodeIndication);
    T(turnCodeSuccessResp);
    T(turnCodeErrorResp);
    TN(type);
}

char *turnMethodName(int type)
{
    T(turnMethodBinding);
    T(turnMethodAllocate);
    T(turnMethodRefresh);
    T(turnMethodSharedSecret);
    T(turnMethodSend);
    T(turnMethodCreatePermission);
    T(turnMethodChannelBind);
    TN(type);
}

enum turnAttributeType
{
    turnAttrMappedAddress = 0x0001,
    turnAttrResponseAddress = 0x0002,
    turnAttrChangeRequest = 0x0003,
    turnAttrSourceAddress = 0x0004,
    turnAttrChangedAddress = 0x0005,
    turnAttrUsername = 0x0006,
    turnAttrPassword = 0x0007,
    turnAttrMessageIntegrity = 0x0008,
    turnAttrErrorCode = 0x0009,
    turnAttrUnknownAttribute = 0x000A,
    turnAttrReflectedFrom = 0x000B,
    turnAttrRealm = 0x0014,
    turnAttrNonce = 0x0015,
    turnAttrRequestedTransport = 0x0019,
    turnAttrXorMappedAddress = 0x0020,
    turnAttrXorOnly = 0x0021,
    turnAttrXorMappedAddressX = 0x8020,
    turnAttrSoftware = 0x8022,
    turnAttrFingerprint = 0x8028,
    turnAttrUnknownAddress2 = 0x802b,
    turnAttrUnknownAddress3 = 0x802c,
    turnAttrLifetime = 0x000D,
    turnAttrBandwidth = 0x0010,
    turnAttrXorRelayedAddress = 0x0016,
    turnAttrXorPeerAddress = 0x0012,
    turnAttrData = 0x0013,
    turnAttrDontFragment = 0x001A,
    turnAttrChannel = 0x000C,
};

char *turnAttributeName(int type)
{
    T(turnAttrMappedAddress);
    T(turnAttrResponseAddress);
    T(turnAttrChangeRequest);
    T(turnAttrSourceAddress);
    T(turnAttrChangedAddress);
    T(turnAttrUsername);
    T(turnAttrPassword);
    T(turnAttrMessageIntegrity);
    T(turnAttrErrorCode);
    T(turnAttrUnknownAttribute);
    T(turnAttrReflectedFrom);
    T(turnAttrRealm);
    T(turnAttrNonce);
    T(turnAttrRequestedTransport);
    T(turnAttrXorMappedAddress);
    T(turnAttrXorOnly);
    T(turnAttrXorMappedAddressX);
    T(turnAttrSoftware);
    T(turnAttrFingerprint);
    T(turnAttrUnknownAddress2);
    T(turnAttrUnknownAddress3);
    T(turnAttrLifetime);
    T(turnAttrBandwidth);
    T(turnAttrXorRelayedAddress);
    T(turnAttrXorPeerAddress);
    T(turnAttrData);
    T(turnAttrDontFragment);
    T(turnAttrChannel);
    TN(type);
};

#ifdef WIN32
int turnMillis()
{
    FILETIME ft;
    LARGE_INTEGER li;
    GetSystemTimeAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    unsigned long int ret = li.QuadPart;
    ret -= 116444736000000000LL;
    ret /= 10000;
    return ret;
}

void turnSleep(int t)
{
    Sleep(t);
}
#else
int turnMillis()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long int ret = tv.tv_usec;
    ret /= 1000;
    ret += (tv.tv_sec * 1000);
    return ret;
}

void turnSleep(int t)
{
    usleep(t * 1000);
}
#endif

int turnWrite(turnMessage * m, int v)
{
    return (m && m->ofs < turnBufferSize - 1) ? m->data[m->ofs++] = v & 0xff : 0;
}

int turnRead(turnMessage * m)
{
    return (m && m->ofs < turnBufferSize - 1) ? m->data[m->ofs++] & 0xff : 0;
}

#define w8(m, v) turnWrite(m, v & 0xff)
#define w16(m, v) w8(m, v >> 8) + w8(m, v)
#define w32(m, v) w16(m, v >> 16) + w16(m, v)
#define wData(m, buf, len) {int k = 0, i = 0; for (i = 0; i < len; i++) k += w8(m, buf[i]);}
#define r8(m) turnRead(m)
#define r16(m) (((r8(m) << 8) | r8(m)) & 0xffff)
#define r32(m) ((r16(m) << 16) | r16(m))
#define rData(m, buf, len) {int i= 0; for (i = 0; i < len; i++) buf[i] = r8(m);}

void turnHexDump(char *buf, int len)
{
    int i;
    printf("\"");
    for (i = 0; i < len; i++)
        printf("%02x", buf[i] & 0xff);
//              printf("%d ", buf[i] & 0xff);
    printf("\"");
}

void turnStrDump(char *buf, int len)
{
    int i;
    printf("\"");
    for (i = 0; i < len; i++)
        if (buf[i] != 0)
            printf("%c", buf[i]);
    printf("\"");
}

void turnXorAddr(turnAddress * a, int cookie)
{
    int i;

    cookie = htonl(cookie);
    char *p = (char *) &cookie;
    int msb_cookie = ((char *) &cookie)[0] << 8 | ((char *) &cookie)[1];
    a->port ^= msb_cookie;

    for (i = 0; i < 4; i++)
        a->ip[i] ^= p[i];
}

void turnReadAddr(turnMessage * m, turnAddress * a, int cookie)
{
    a->sock = 0;
    a->server = 0;

    a->family = r16(m);
    a->port = r16(m);
    rData(m, a->ip, 4);

    if (cookie)
        turnXorAddr(a, cookie);

    sprintf(a->host, "%d.%d.%d.%d", a->ip[0], a->ip[1], a->ip[2], a->ip[3]);
    sprintf(a->str, "%s:%d", a->host, a->port);
}

void turnWriteAddr(turnMessage * m, int type, turnAddress * a, int cookie)
{
    w16(m, type);
    w16(m, 8);
    w16(m, a->family);
    turnXorAddr(a, cookie);
    w16(m, a->port);
    wData(m, a->ip, 4);
    turnXorAddr(a, cookie);
}

void turnRandomKey(char *buf, int from, int to, int len)
{
    int i;
    for (i = 0; i < len; i++)
        buf[i] = from + (rand() % (to - from));
}

int turnRoundTo(int offset, int align)
{
    return offset + ((align - (offset % align)) % align);
}

void turnPushMessage(turnMessage * m)
{
    turnCount++;
    if (turnCount >= turnBuffers)
        turnCount = 0;
}

void turnWriteAttr(turnMessage * m, int attr, char *buf, int len)
{
    int pad = turnRoundTo(len, 4) - len;
    w16(m, attr);
    w16(m, len);
    wData(m, buf, len);
    m->ofs += pad;
}

#define turnWriteAttrStr(m,attr,str) turnWriteAttr(m, attr, str, strlen(str));
#define turnWriteAttrInt(m,attr,value) w16(m, attr); w16(m, 4); w32(m, value);

void turnWriteHeader(turnMessage * m, int type)
{
    char tsx[12];

    turnRandomKey(tsx, 0, 0xff, 12);

    m->ofs = 0;
    m->type = type;
    m->magic = turnMagicCookie;

    w16(m, m->type);
    w16(m, m->length);
    w32(m, m->magic);

    m->tsx_id = m->data + m->ofs;
    wData(m, tsx, 12);
}

void turnWriteCredentials(turnMessage * m)
{
    turnWriteAttrStr(m, turnAttrUsername, turnUser);
    turnWriteAttrStr(m, turnAttrRealm, turnRealm);
    m->nonce = m->data + m->ofs;
    turnWriteAttrStr(m, turnAttrNonce, turnNonce);
}

void turnWriteFooter(turnMessage * m, int write_integrity)
{
    m->length = m->ofs;

    if (write_integrity)
        m->length += 24;

    m->ofs = 2;
    w16(m, m->length - turnHeaderSize);

    if (write_integrity)
    {
        int len = 20;
        unsigned char hash[20];
        HMAC(EVP_sha1(), turnKey, 16, (unsigned char *) m->data, m->length - 24, hash, &len);
        m->ofs = m->length - 24;
        w16(m, turnAttrMessageIntegrity);
        w16(m, len);
        wData(m, hash, len);
    }
}

void turnWriteMessage(turnMessage * m, int action)
{
    switch (action)
    {
        case turnActionBind:
            turnWriteHeader(m, turnMethodBinding);
            turnWriteFooter(m, 0);
            break;

        case turnActionAllocate:
            turnWriteHeader(m, turnMethodAllocate);
            turnWriteAttrInt(m, turnAttrRequestedTransport, 0x11000000);
            turnWriteCredentials(m);
            turnWriteFooter(m, 1);
            break;

        case turnActionRefresh:
            turnWriteHeader(m, turnMethodRefresh);
            turnWriteCredentials(m);
            turnWriteFooter(m, 1);
            break;

        case turnActionRemoveAllocation:
            turnWriteHeader(m, turnMethodRefresh);
            turnWriteAttrInt(m, turnAttrLifetime, 0);
            turnWriteCredentials(m);
            turnWriteFooter(m, 1);
            break;

        case turnActionPermission:
            turnWriteHeader(m, turnMethodCreatePermission);
            turnWriteAddr(m, turnAttrXorPeerAddress, &turnRelay, turnMagicCookie);
            turnWriteCredentials(m);
            turnWriteFooter(m, 1);
            break;

        case turnActionSend:
            m->ofs = 0;
            w16(m, turnChannel >> 16);
            w16(m, 5);
            wData(m, "hello", 5);
            m->length = m->ofs;
            break;

        case turnActionBindChannel:
            turnWriteHeader(m, turnMethodChannelBind);
            turnWriteAttrInt(m, turnAttrChannel, turnChannel);
            turnWriteAddr(m, turnAttrXorPeerAddress, &turnRelay, turnMagicCookie);
            turnWriteCredentials(m);
            turnWriteFooter(m, 1);
            break;
    }
}

void turnParseMessage(turnMessage * m)
{
    m->ofs = 0;
    m->type = r16(m);
    m->length = r16(m);
    m->magic = r32(m);

    if (m->magic != turnMagicCookie)
        return;

    m->tsx_id = m->data + m->ofs;
    m->ofs += 12;

    if (turnDebug)
    {
        int msg = m->type & 0x00F;
        int code = m->type & 0x110;

        printf("Message: %s (%s)\n", turnMethodName(msg), turnMessageCodeName(code));
        printf(" hdr: length=%d, magic=0x%x, tsx_id=", m->length, m->magic);
        turnHexDump(m->tsx_id, 12);
        printf("\n");
        printf(" Attributes:\n");
    }

    int offset = m->ofs;

    strcpy(turnError, "NULL");

    while ((offset - turnHeaderSize) < m->length)
    {
        turnAddress static_a;
        turnAddress *a = &static_a;
        int attr = r16(m);
        int len = r16(m);

        if (turnDebug)
            printf(" %s length=%d, ", turnAttributeName(attr), len);

        int cookie = (attr == turnAttrXorMappedAddress || attr == turnAttrXorRelayedAddress || attr == turnAttrXorMappedAddressX || attr == turnAttrXorPeerAddress) ? turnMagicCookie : 0;

        switch (attr)
        {
            case turnAttrMappedAddress:
            case turnAttrResponseAddress:
            case turnAttrSourceAddress:
            case turnAttrChangedAddress:
            case turnAttrXorMappedAddress:
            case turnAttrXorPeerAddress:
            case turnAttrXorRelayedAddress:
            case turnAttrXorMappedAddressX:
            case turnAttrUnknownAddress2:
            case turnAttrUnknownAddress3:

                turnReadAddr(m, a, cookie);

                if (attr == turnAttrXorRelayedAddress)
                    memcpy(&turnRelay, a, sizeof(turnAddress));

                if (attr == turnAttrMappedAddress || attr == turnAttrXorMappedAddress)
                    memcpy(&turnPeer, a, sizeof(turnAddress));

                if (turnDebug)
                    printf("%s, addr=%s", a->family == 1 ? "IPv4" : "IPv6", a->str);

                break;

            case turnAttrErrorCode:
                r16(m);
                m->errorcode = (r8(m) & 0x7) * 100 + r8(m);
                m->errormsg = m->data + m->ofs;
                sprintf(turnError, "%d [%s]", m->errorcode, m->errormsg);

                if (turnDebug)
                    printf(turnError);

                break;

            case turnAttrSoftware:
            case turnAttrUsername:
            case turnAttrRealm:
            case turnAttrNonce:

                if (turnDebug)
                    turnStrDump(m->data + m->ofs, len);

                if (attr == turnAttrNonce)
                    memcpy(turnNonce, m->data + m->ofs, len);

                break;

            default:
                if (turnDebug)
                    turnHexDump(m->data + m->ofs, len);
                break;
        }

        if (turnDebug)
            printf("\n");

        len = turnRoundTo(len, 4);
        offset += len + 4;
        m->ofs = offset;
    }

    m->length = m->length + turnHeaderSize;

    if (turnDebug)
        printf("End of message\n");
}

void turnSend(turnAddress * a, char *data, int datalen)
{
    printf("[send %d bytes]\n", datalen);
    send(turnServer.sock, data, datalen, 0);
}

void turnRecv(turnAddress * a, char *data, int datalen)
{
    turnSleep(100);

    printf("[recv %d bytes]\n", datalen);

    if (datalen < 0)
        return;

    if (datalen < turnBufferSize)
    {
        turnMessage m;
        memcpy(m.data, data, datalen);
        turnParseMessage(&m);
        turnPushMessage(&m);
    }
}

int turnOpenNetwork()
{
#ifdef WIN32
    WSADATA wsa;
    int res;
    if ((res = WSAStartup(MAKEWORD(2, 0), &wsa)) < 0)
        return -1;
#endif
}

int turnCloseNetwork()
{
#ifdef WIN32
    WSACleanup();
#endif
}

static void *turnThread(void *param)
{
    turnAddress *a = (turnAddress *) param;

    char buffer[turnBufferSize];
    long res = 0;
    struct sockaddr_in addr;

    if ((a->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        return;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(a->port);
    struct hostent *hp = (struct hostent *) gethostbyname(a->host);
    memcpy(&addr.sin_addr.s_addr, hp->h_addr_list[0], hp->h_length);

    if ((res = connect(a->sock, (struct sockaddr *) &addr, sizeof(struct sockaddr))) == -1)
        return;

    while (res != -1)
    {
        res = recv(a->sock, buffer, turnBufferSize, 0);
        turnRecv(a, buffer, res);
    }

error:

#ifdef WIN32
    closesocket(a->sock);
#else
    close(a->sock);
#endif

}

turnStatus()
{
    printf("+====================================================================+\n");
    printf("|             CLIENT                |             PEER               |\n");
    printf("|                                   |                                |\n");
    printf("| Relay addr: %-21s | Address: %-21s |\n", turnRelay.str, turnPeer.str);
    printf("|                                   |                                |\n");
    printf("| a      Allocate relay             | 0  Send data to relay address  |\n");
    printf("| b      BindChannel to peer        |                                |\n");
    printf("| s      Send data to peer          |                                |\n");
    printf("| r      Refresh allocation         |                                |\n");
    printf("| x      Delete allocation          |                                |\n");
    printf("+-----------------------------------+                                |\n");
    printf("| q  Quit                  d  Dump  |                                |\n");
    printf("+-----------------------------------+--------------------------------+\n");
    printf("| Error: %-60s|\n", turnError);
    printf("+-----------------------------------+--------------------------------+\n");

    printf("turn>");
}

void turnMakeMD5Key(char *key, char *user, char *realm, char *pass)
{
    char buf[256] = { 0 };
    sprintf(buf, "%s:%s:%s", user, realm, pass);

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, buf, strlen(buf));
    MD5_Final(key, &ctx);
}

void turnCreateThread(turnAddress * a)
{
#ifdef _WIN32
    CreateThread((LPSECURITY_ATTRIBUTES) NULL, 0, (LPTHREAD_START_ROUTINE) turnThread, a, 0, &a->thread);
#else
    pthread_create(&a->thread, NULL, turnThread, a);
#endif
}

int main(int argc, char **argv)
{
    int timeout = 1000;
    char input[turnBufferSize];

    srand(time(0));

#if 0
    turnHost = "stun.xten.com";
    turnUser = "toto";
    turnRealm = "domain.org";
#endif

#if 1
    turnHost = "numb.viagenie.ca";
    turnUser = "viagenie.ca@gmail.com";
    turnRealm = "viagenie.ca";
#endif

#if 0
    turnHost = "10.1.1.1";
    turnUser = "toto";
    turnRealm = "domain.org";
#endif

    turnOpenNetwork();

    turnReadAddr(0, &turnRelay, 0);
    turnReadAddr(0, &turnPeer, 0);

    turnReadAddr(0, &turnServer, 0);
    turnReadAddr(0, &turnClient, 0);

    turnAddress *a = &turnServer;

    turnAddress *b = &turnClient;

    strcpy(a->host, turnHost);
    a->port = turnPort;
    a->server = 0;
    turnCreateThread(a);

    char *password = "password";

    //client may use precalculated turnKey (you may get rid of md5 code as well)
    turnMakeMD5Key(turnKey, turnUser, turnRealm, password);

    int action = 0;

    while (1)
    {
        turnStatus();

        fgets(input, turnBufferSize, stdin);

        switch (input[0])
        {
            case 'a':
                action = turnActionAllocate;
                break;

            case 'b':
                action = turnActionBindChannel;
                break;

            case 's':
                action = turnActionSend;
                break;

            case 'c':
                action = turnActionBindChannel;
                break;

            case 'r':
                action = turnActionRefresh;
                break;

            case 'x':
                action = turnActionRemoveAllocation;
                break;

            case 'q':
                exit(0);
                break;

            default:
                action = turnActionBind;
                break;
        }

        while (action != 0)
        {
            turnMessage *m = &turnMessages[turnCount];

            turnWriteMessage(m, action);

            turnSend(a, m->data, m->length);

            turnParseMessage(m);
            turnPushMessage(m);

            int time = turnMillis();
            int count = turnCount;

            while (turnMillis() < time + timeout && count == turnCount)
                turnSleep(1);

            if (count == turnCount)
                printf("[timeout]\n");

            action = 0;
        }
    }

    turnCloseNetwork();

    return 0;
}
