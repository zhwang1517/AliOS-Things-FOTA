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

static char ip[20] = "224.0.1.187";
static char version[128] = "{\"smartconfig\":\"2.0\",\"zconfig\":\"2.0\",\"router\":\"2.0\",\"ap\":\"2.0\"}";
static char random_str[33] = {0};
static char sign[33] = {0};
static char productkey[33] = {0};
static char devicename[33] = {0};
static char mac[18] = "94:28:2E:AB:A0:E6";
extern char *optarg;


#define COAP_SERVER_PORT    (5683)
#define COAP_MULTICAST_GROUP "224.0.1.187"

#define COAP_INIT_TOKEN     (0x01020304)
#define COAP_SERV_MAX_PATH_LEN ((COAP_MSG_MAX_PATH_LEN + 1) * COAP_RESOURCE_MAX_DEPTH + 6)

#define DEVINFO_NOTIFY_URI  "/sys/awss/device/info/notify"
#define DEVICE_INFO_FMT     "{\"awssVer\":%s,\"productKey\":\"%s\",\"deviceName\":\"%s\",\"mac\":\"%s\",\"ip\":\"%s\",\"security\":3,\"random\":\"%s\",\"sign\":\"%s\"}"

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


void  sendNotifyCallback(CoAPContext *context, CoAPReqResult result, void *userdata, NetworkAddr *remote, CoAPMessage *message)
{
   if(COAP_RECV_RESP_TIMEOUT == result){
        EXAMPLE_TRACE("\r\nsend message timeout, resend it\r\n");
       //CoAPObsServer_notify(context, "/status", (unsigned char *)"{\"status\":\"1\"}", strlen("{\"status\":\"1\"}"), NULL);
   }
   else{
       EXAMPLE_TRACE("\r\nreceive response message from %s:%d, payload: %s\r\n", remote->addr, remote->port, message->payload);
   }
}


void getDeviceInfoCallback(CoAPContext *context, const char *paths, NetworkAddr *remote, CoAPMessage *request)
{
    unsigned char payload[1024] = {0};
    CoAPMessage response;

    EXAMPLE_TRACE("=====================receive request msg: uri paths: %s, payload: %s", paths, request->payload);

    CoAPMessage_init(&response);
    CoAPMessageType_set(&response, COAP_MESSAGE_TYPE_CON);
    CoAPMessageCode_set(&response, COAP_MSG_CODE_205_CONTENT);
    CoAPMessageId_set(&response, request->header.msgid);

    if(COAP_SUCCESS == CoAPOption_present(request, COAP_OPTION_OBSERVE)){
        CoAPObsServer_add(context, paths, remote, request);
        CoAPUintOption_add(&response, COAP_OPTION_OBSERVE, 0);
    }

    CoAPUintOption_add(&response, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);
    char devinfo_str[256] = {0};
    snprintf(devinfo_str, sizeof(devinfo_str) - 1, DEVICE_INFO_FMT, version, productkey, devicename, mac, ip, random_str, sign);
    snprintf((char *)payload, sizeof(payload), "{\"id\":\"%d\",\"code\":200,\"data\":%s}", request->header.msgid, devinfo_str);
    CoAPMessagePayload_set(&response, payload, strlen((char *)payload));

    CoAPMessage_send(context, remote, &response);
    CoAPMessage_destory(&response);
    EXAMPLE_TRACE("=====================send response msg: %s", payload);
}


void switchapCallback(CoAPContext *context, const char *paths, NetworkAddr *remote, CoAPMessage *request)
{
    unsigned char payload[1024] = {0};
    CoAPMessage response;

    EXAMPLE_TRACE("=====================receive request msg: uri paths: %s, payload: %s", paths, request->payload);

    CoAPMessage_init(&response);
    CoAPMessageType_set(&response, COAP_MESSAGE_TYPE_CON);
    CoAPMessageCode_set(&response, COAP_MSG_CODE_205_CONTENT);
    CoAPMessageId_set(&response, request->header.msgid);

    CoAPUintOption_add(&response, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);
    snprintf((char *)payload, sizeof(payload), "{\"id\":\"%d\",\"code\":200,\"data\":%s}",  request->header.msgid, "{}");
    CoAPMessagePayload_set(&response, payload, strlen((char *)payload));

    CoAPMessage_send(context, remote, &response);
    CoAPMessage_destory(&response);


    EXAMPLE_TRACE("=====================send response msg: %s", payload);
}



int CoAPMessageSendMultiCast(CoAPContext * context, NetworkAddr * remote)
{
    CoAPMessage message;
    CoAPMessage_init(&message);
    CoAPMessageType_set(&message, COAP_MESSAGE_TYPE_NON);
    CoAPMessageCode_set(&message, COAP_MSG_CODE_GET);
    CoAPMessageId_set(&message, CoAPMessageId_gen(context));
    CoAPMessageHandler_set(&message, sendNotifyCallback);

    CoAPStrOption_add(&message, COAP_OPTION_URI_PATH,
                      (unsigned char *)"hello", (int)strlen("hello"));

    CoAPUintOption_add(&message, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);

    CoAPMessage_send(context, remote, &message);

    CoAPMessage_destory(&message);
    return COAP_SUCCESS;
}


int subscribeEvent(CoAPContext * context, NetworkAddr * remote, char *uri)
{
    CoAPMessage message;
    CoAPMessage_init(&message);
    CoAPMessageType_set(&message, COAP_MESSAGE_TYPE_CON);
    CoAPMessageCode_set(&message, COAP_MSG_CODE_GET);
    CoAPMessageId_set(&message, CoAPMessageId_gen(context));
    CoAPMessageHandler_set(&message, sendNotifyCallback);

    CoAPUintOption_add(&message, COAP_OPTION_OBSERVE, 0);
    CoAPServerPath_2_option((char *)uri, &message);
    //CoAPStrOption_add(&message, COAP_OPTION_URI_PATH,
    //                  (unsigned char *)uri, (int)strlen(uri));

    CoAPUintOption_add(&message, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);
    CoAPMessagePayload_set(&message, "{\"id\":1111,\"method\":"",\"params\":{}}", strlen((char *)"{\"id\":1111,\"method\":"",\"params\":{}}"));

    CoAPMessage_send(context, remote, &message);

    CoAPMessage_destory(&message);
    return COAP_SUCCESS;
}


int notifyDeviceInfo(CoAPContext *context)
{
    NetworkAddr addr;
    int msg_id = 0;
    char payload[2048] = {0};
    char devinfo_str[256] = {0};
    snprintf(devinfo_str, sizeof(devinfo_str) - 1, DEVICE_INFO_FMT, version, productkey, devicename, mac, ip, random_str, sign);

    sprintf(payload, "{\"id\":%d, \"method\":\"awss.device.info.notify\", \"params\":%s}",
        g_msg_id++, devinfo_str);

    addr.port = COAP_SERVER_PORT;
    memset(addr.addr, 0x00, sizeof(addr.addr));
    strcpy(addr.addr, COAP_MULTICAST_GROUP);

    EXAMPLE_TRACE("send notify device info msg: %s", payload);
    CoAPServerMultiCast_send(context, &addr, (const char *)DEVINFO_NOTIFY_URI, (unsigned char *)payload, strlen(payload), sendNotifyCallback, &msg_id);

    return 0;
}

int registerServiceCallback(CoAPContext *context, const char *path,
                    unsigned short permission, CoAPRecvMsgHandler callback)
{
    return CoAPResource_register(context, path, permission, COAP_CT_APP_JSON, 60, callback);
}


static void usage(void)
{
    printf("\ndevice_server -p productkey -d devicename -r random -s sign -i ipaddr\n");
    printf("\t -v awssVer, default: %s\n", "{\"smartconfig\":\"2.0\",\"zconfig\":\"2.0\",\"router\":\"2.0\",\"ap\":\"2.0\"}");
    printf("\t -p product key\n");
    printf("\t -d device name\n");
    printf("\t -r random hexstring\n");
    printf("\t -s sign hexstring\n");
    printf("\t -i ip address\n");
    printf("\t -m mac address\n");
    printf("\t -h show help text\n");
}


void parse_opt(int argc, char *argv[])
{
    int ch;
    while ((ch = getopt(argc, argv, "v:p:d:r:s:i:m:")) != -1) {
        switch ((char)ch) {
        case 'v':
            strncpy(version, optarg, sizeof(version) - 1);
            break;
        case 'p':
            strncpy(productkey, optarg, sizeof(productkey) - 1);
            break;
        case 'd':
            strncpy(devicename, optarg, sizeof(devicename) - 1);
            break;
        case 'r':
            strncpy(random_str, optarg, sizeof(random_str) - 1);
            break;
        case 's':
            strncpy(sign, optarg, sizeof(sign) - 1);
            break;
        case 'i':
            strncpy(ip, optarg, sizeof(ip) - 1);
            if (inet_addr(optarg) == -1 && strcmp(ip, "255.255.255.255") != 0){
                printf("invalid ip address: %s\n", optarg);
                return;
            }
            break;
        case 'm':
            strncpy(mac, optarg, sizeof(mac) - 1);
            break;
        case 'h':
        default:
            usage();
            exit(0);
        }
    }
}


#define AWSS_APP_URI_ENABLE_STATE_NOTIFY         "/sys/awss/router/enable/event"
#define AWSS_APP_URI_GETCIPHER_STATE_NOTIFY      "/sys/awss/router/getcipher/event"
#define AWSS_APP_URI_JOINEDDEVICE_NOTIFY         "/sys/awss/router/joineddevice/event"
#define AWSS_APP_URI_SWITCHAP_RESULT_NOTIFY      "/sys/awss/router/switchap/result/event"
#define AWSS_APP_URI_AUTHEDDEVICE_NOTIFY         "/sys/awss/router/autheddevice/event"
#define AWSS_APP_URI_DEVICE_INFO_GET             "/sys/awss/device/info/get"
#define AWSS_APP_URI_DEVICE_SWITCHAP_FMT         "/sys/%s/%s/awss/device/switchap"


static CoAPContext *coapContextInit()
{
    CoAPInitParam param;
    CoAPContext * context = NULL;

    param.appdata = NULL;
    param.group = COAP_MULTICAST_GROUP;
    param.notifier = NULL;
    param.obs_maxcount = 16;
    param.res_maxcount = 32;
    param.port = COAP_SERVER_PORT;
    param.send_maxcount = 16;
    param.waittime = 2000;

    context = CoAPContext_create(&param);

    return (CoAPContext *)context;
}


static int deviceServiceInit(CoAPContext * context)
{
    NetworkAddr addr;
    char path[256] = {0};

    EXAMPLE_TRACE("start coap device server");

    registerServiceCallback(context, AWSS_APP_URI_DEVICE_INFO_GET, COAP_PERM_GET, getDeviceInfoCallback);
    snprintf(path, sizeof(path) - 1, AWSS_APP_URI_DEVICE_SWITCHAP_FMT, productkey, devicename);
    registerServiceCallback(context, path, COAP_PERM_GET, switchapCallback);

    addr.port = COAP_SERVER_PORT;
    memset(addr.addr, 0x00, sizeof(addr.addr));
    strcpy(addr.addr, COAP_MULTICAST_GROUP);
    subscribeEvent(context, &addr, AWSS_APP_URI_ENABLE_STATE_NOTIFY);
    subscribeEvent(context, &addr, AWSS_APP_URI_GETCIPHER_STATE_NOTIFY);
    subscribeEvent(context, &addr, AWSS_APP_URI_JOINEDDEVICE_NOTIFY);
    subscribeEvent(context, &addr, AWSS_APP_URI_SWITCHAP_RESULT_NOTIFY);

    CoAPServer_loop(context);

    return 0;
}


int main(int argc, char *argv[])
{
    if(argc < 6){
        usage();
        return -1;
    }

    LITE_openlog("DeviceServer");
    LITE_set_loglevel(5);

    parse_opt(argc, argv);
    if('\0' == random_str[0] || '\0' == sign || '\0' == productkey || '\0' == devicename)
    {
        usage();
        return -1;
    }

    printf("version: %s, productkey: %s, devicename: %s, \n\trandom: %s, sign: %s, ip: %s, mac: %s\n",
            version, productkey, devicename, random_str, sign, ip, mac);

    CoAPContext * context = coapContextInit();
    if (NULL == context)
    {
        printf("coap context init fail\n");
        return -1;
    }
    deviceServiceInit(context);

    while(1){
        sleep(5);
        notifyDeviceInfo(context);
    }
}

