#include <stdio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include "CoAPPlatform.h"
#include "CoAPExport.h"
#include "CoAPObserve.h"
#include "CoAPMessage.h"
#include "CoAPResource.h"

int g_status = 0;
int g_msg_id = 0;

#define COAP_CLIENT_PORT    (5684)
#define COAP_MULTICAST_GROUP "224.0.1.187"
#define COAP_INIT_TOKEN     (0x01020304)
#define COAP_SERV_MAX_PATH_LEN ((COAP_MSG_MAX_PATH_LEN + 1) * COAP_RESOURCE_MAX_DEPTH + 6)

#define DEVINFO_NOTIFY_URI  "/sys/awss/device/info/notify"
#if 1
#define DEVICE_INFO         "{\"awssVer\":{\"smartconfig\":\"2.0\",\"zconfig\":\"2.0\",\"router\":\"2.0\",\"ap\":\"2.0\"},\"productKey\":\"p1lfqbgUBmD\",\"deviceName\":\"rFxQZUvlQQtjdfXiXVQA\",\"mac\":\"94:28:2E:AB:A0:E6\",\"ip\":\"192.168.124.2\",\"security\":3,\"random\":\"82ADEF2CB435717A2AA34F317B61B2B2\",\"sign\":\"1c77ae02579426106408bf4c77846599\"}"
#else

#endif

#define EXAMPLE_TRACE(fmt, ...)  \
    do { \
        HAL_Printf("%s|%03d :: ", __func__, __LINE__); \
        HAL_Printf(fmt, ##__VA_ARGS__); \
        HAL_Printf("%s", "\r\n"); \
    } while(0)

static unsigned int CoAPServerToken_get(unsigned char *p_encoded_data)
{
    static unsigned int value = COAP_INIT_TOKEN;
    p_encoded_data[0] = (unsigned char)((value & 0x00FF) >> 0);
    p_encoded_data[1] = (unsigned char)((value & 0xFF00) >> 8);
    p_encoded_data[2] = (unsigned char)((value & 0xFF0000) >> 16);
    p_encoded_data[3] = (unsigned char)((value & 0xFF000000) >> 24);
    value++;
    return sizeof(unsigned int);
}


static int CoAPServerPath_2_option(char *uri, CoAPMessage *message)
{
    char *ptr     = NULL;
    char *pstr    = NULL;
    char  path[COAP_MSG_MAX_PATH_LEN]  = {0};

    if (NULL == uri || NULL == message) {
        EXAMPLE_TRACE("Invalid paramter p_path %p, p_message %p", uri, message);
        return COAP_ERROR_INVALID_PARAM;
    }
    if (COAP_SERV_MAX_PATH_LEN < strlen(uri)) {
        EXAMPLE_TRACE("The uri length is too loog,len = %d", (int)strlen(uri));
        return COAP_ERROR_INVALID_LENGTH;
    }
    EXAMPLE_TRACE("The uri is %s", uri);
    ptr = pstr = uri;
    while ('\0' != *ptr) {
        if ('/' == *ptr) {
            if (ptr != pstr) {
                memset(path, 0x00, sizeof(path));
                strncpy(path, pstr, ptr - pstr);
                EXAMPLE_TRACE("path: %s,len=%d", path, (int)(ptr - pstr));
                CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                                  (unsigned char *)path, (int)strlen(path));
            }
            pstr = ptr + 1;

        }
        if ('\0' == *(ptr + 1) && '\0' != *pstr) {
            memset(path, 0x00, sizeof(path));
            strncpy(path, pstr, sizeof(path) - 1);
            EXAMPLE_TRACE("path: %s,len=%d", path, (int)strlen(path));
            CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                              (unsigned char *)path, (int)strlen(path));
        }
        ptr ++;
    }
    return COAP_SUCCESS;
}


void  sendRespCallback(CoAPContext *context, CoAPReqResult result, void *userdata, NetworkAddr *remote, CoAPMessage *message)
{
   if(COAP_RECV_RESP_TIMEOUT == result){
        EXAMPLE_TRACE("\r\nsend message timeout, resend it\r\n");
       //CoAPObsServer_notify(context, "/status", (unsigned char *)"{\"status\":\"1\"}", strlen("{\"status\":\"1\"}"), NULL);
   }
   else{
       EXAMPLE_TRACE("\r\nreceive response message from %s:%d, payload: %s\r\n", remote->addr, remote->port, message->payload);
   }
}


static int requestRemoteService(CoAPContext *context, NetworkAddr *remote,char *uri, unsigned char *payload,
                            unsigned short length, int msg_code, CoAPSendMsgHandler resp_cb, void *user_data)
{
    int ret = COAP_SUCCESS;
    CoAPMessage message;
    unsigned char tokenlen;
    unsigned char token[COAP_MSG_MAX_TOKEN_LEN] = {0};

    CoAPMessage_init(&message);
    CoAPMessageType_set(&message, COAP_MESSAGE_TYPE_NON);
    CoAPMessageCode_set(&message, msg_code);
    CoAPMessageId_set(&message, CoAPMessageId_gen(context));
    tokenlen = CoAPServerToken_get(token);
    CoAPMessageToken_set(&message, token, tokenlen);
    CoAPMessageHandler_set(&message, resp_cb);
    CoAPMessageUserData_set(&message, user_data);

    CoAPServerPath_2_option((char *)uri, &message);
    CoAPUintOption_add(&message, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);
    CoAPMessagePayload_set(&message, payload, length);

    ret = CoAPMessage_send(context, remote, &message);
    CoAPMessage_destory(&message);

    return ret;
}


static void usage(void)
{
    printf("\ncoap_client -d ip -p port -u uri -m message -c codetype\n");
    printf("\t -d destination ip address, default:224.0.1.187\n");
    printf("\t -p destination port, default:5683\n");
    printf("\t -u uri path\n");
    printf("\t -m send of message\n");
    printf("\t -c get/put/post, default:get\n");
    printf("\t -h show help text\n");
}

static char ip[20] = "224.0.1.187";
static short port = 5683;
static char msg[1500] = {0};
static char uri[256] = {0};
static char code_type = COAP_MSG_CODE_GET;
extern char *optarg;

void parse_opt(int argc, char *argv[])
{
    int ch;
    while ((ch = getopt(argc, argv, "d:p:u:m:c:")) != -1) {
        switch ((char)ch) {
        case 'd':
            //addr = inet_addr(optarg);
            strncpy(ip, optarg, sizeof(ip) - 1);
            if (inet_addr(optarg) == -1 && strcmp(ip, "255.255.255.255") != 0){
                printf("invalid ip address: %s\n", optarg);
                return;
            }

            break;
        case 'p':
            port = (short)atoi(optarg);
            if (port == 0) {
                printf("invalid port: %s\n", optarg);
                return;
            }
            break;
        case 'u':
            strncpy(uri, optarg, sizeof(uri) - 1);
            if (strlen(uri) == 0){
                printf("invalid uri: %s\n", optarg);
                return;
            }
            break;
        case 'm':
            strncpy(msg, optarg, sizeof(msg) - 1);
            if (strlen(msg) == 0){
                printf("invalid msg: %s\n", optarg);
                return;
            }
            break;
        case 'c':
            if (strcmp(optarg, "get") == 0)
                code_type = COAP_MSG_CODE_GET;
            else if(strcmp(optarg, "put") == 0)
                code_type = COAP_MSG_CODE_PUT;
            else if(strcmp(optarg, "post") == 0)
                code_type = COAP_MSG_CODE_POST;
            else{
                printf("invalid code type: %s\n", optarg);
                return;
            }
            break;
        case 'h':
        default:
            usage();
            exit(0);
        }
    }
}

static CoAPContext *coapContextInit()
{
    CoAPInitParam param;
    CoAPContext * context = NULL;

    param.appdata = NULL;
    param.group = COAP_MULTICAST_GROUP;
    param.notifier = NULL;
    param.obs_maxcount = 16;
    param.res_maxcount = 32;
    param.port = COAP_CLIENT_PORT;
    param.send_maxcount = 16;
    param.waittime = 2000;

    context = CoAPContext_create(&param);

    return (CoAPContext *)context;
}


int main(int argc, char *argv[])
{
    NetworkAddr addr;
    if(argc < 3){
        usage();
        return -1;
    }

    parse_opt(argc, argv);
    if(0 == ip || 0 == port || strlen(msg) == 0)
    {
        usage();
        return -1;
    }

    LITE_openlog("CoAPClient");
    LITE_set_loglevel(5);

    printf("addr: %s, port: %d, msg: %s, codetype: %d\n",
            ip, port, msg, code_type);

    CoAPContext * context = coapContextInit();
    if (NULL == context)
    {
        printf("coap context init fail\n");
        return -1;
    }

    addr.port = port;
    strcpy(addr.addr, ip);
    printf("send msg: %s\n", msg);
    if (0 != requestRemoteService(context, &addr, uri, msg, strlen(msg), code_type, sendRespCallback, NULL)){
        printf("send msg fail\n");
    }

    printf("wait response msg\n");
    sleep(3);

    return 0;
}

