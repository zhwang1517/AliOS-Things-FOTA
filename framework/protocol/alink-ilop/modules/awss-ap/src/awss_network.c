/*
 * Copyright (c) 2014-2016 Alibaba Group. All rights reserved.
 *
 * Alibaba Group retains all right, title and interest (including all
 * intellectual property rights) in and to this computer program, which is
 * protected by applicable intellectual property laws.  Unless you have
 * obtained a separate written license from Alibaba Group., you are not
 * authorized to utilize all or a part of this computer program for any
 * purpose (including reproduction, distribution, modification, and
 * compilation into object code), and you must immediately destroy or
 * return to Alibaba Group all copies of this computer program.  If you
 * are licensed by Alibaba Group, your rights to utilize this computer
 * program are limited by the terms of that license.  To obtain a license,
 * please contact Alibaba Group.
 *
 * This computer program contains trade secrets owned by Alibaba Group.
 * and, unless unauthorized by Alibaba Group in writing, you agree to
 * maintain the confidentiality of this computer program and related
 * information and to not disclose this computer program and related
 * information to any other person or entity.
 *
 * THIS COMPUTER PROGRAM IS PROVIDED AS IS WITHOUT ANY WARRANTIES, AND
 * Alibaba Group EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED,
 * INCLUDING THE WARRANTIES OF MERCHANTIBILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, TITLE, AND NONINFRINGEMENT.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include "lite-log.h"
#include "stdbool.h"
#include "awss_ap.h"
#include "awss_network.h"
#include "awss_coap.h"
#include "awss_cmp.h"
#include "json_parser.h"
#include "iot_export.h"
#include "iot_import_awss_ap.h"
#include "awss_devlist.h"
#include "iot_export_cmp.h"

#define __AWSS_AP_UT__  1
#define PLATFORM_WAIT_INFINITE			(~0)
#define AWSS_NETWORK_CODE_SUCCESS       200


awss_request_queue_t *g_awss_request_queue;

static void *msg_id_lock = NULL;
static uint32_t g_msg_id = 0;

//#ifndef __AWSS_AP_UT__

#define HWADDR_BYTES        6
#define BSSID_STR_FMT       "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_STR_FMT    "%02x:%02x:%02x:%02x:%02x:%02x"

static int get_netif_hwaddr(const char *ifname, unsigned char hw_addr[HWADDR_BYTES])
{
    struct ifreq ifreq;
    int sock = -1;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return AWSS_ERROR;
    }
    strcpy(ifreq.ifr_name, ifname);

    if (ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0) {
        close(sock);
        perror("ioctl");
        return AWSS_ERROR;
    }

    memcpy((char *)hw_addr, ifreq.ifr_hwaddr.sa_data, HWADDR_BYTES);

    close(sock);

    return AWSS_SUCCESS;
}


static char *get_ap_bssid(const char *ifname, char bssid_str[PRODUCT_MAC_LEN + 1])
{
    unsigned char hw_addr[HWADDR_BYTES] = {0};
    int len = 0;

    int ret = get_netif_hwaddr(ifname, hw_addr);
    if (ret != AWSS_SUCCESS)
        return NULL;

    snprintf(bssid_str, PRODUCT_MAC_LEN + 1, BSSID_STR_FMT,
             (unsigned char)hw_addr[0],
             (unsigned char)hw_addr[1],
             (unsigned char)hw_addr[2],
             (unsigned char)hw_addr[3],
             (unsigned char)hw_addr[4],
             (unsigned char)hw_addr[5]);

    return bssid_str;
}


static char *get_netif_macaddr(const char *ifname, char mac_str[PRODUCT_MAC_LEN + 1])
{
    unsigned char hw_addr[HWADDR_BYTES] = {0};
    int len = 0;

    int ret = get_netif_hwaddr(ifname, hw_addr);
    if (ret != AWSS_SUCCESS)
        return NULL;

    snprintf(mac_str, PRODUCT_MAC_LEN + 1, MAC_ADDR_STR_FMT,
             (unsigned char)hw_addr[0],
             (unsigned char)hw_addr[1],
             (unsigned char)hw_addr[2],
             (unsigned char)hw_addr[3],
             (unsigned char)hw_addr[4],
             (unsigned char)hw_addr[5]);

    return mac_str;
}

static char *get_netif_ipaddr(const char *ifname, char ip_str[AWSS_DEVICE_IP_LEN + 1])
{
    struct ifreq ifreq;
    int sock = -1;
    char ifname_buff[IFNAMSIZ] = {0};

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return NULL;
    }

    ifreq.ifr_addr.sa_family = AF_INET; //ipv4 address
    strncpy(ifreq.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifreq) < 0) {
        close(sock);
        perror("ioctl");
        return NULL;
    }

    close(sock);
    strncpy(ip_str,
            inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr),
            AWSS_DEVICE_IP_LEN);

    return ip_str;
}
//#endif


static int get_brif_portid(const char *br_name, const char *if_name)
{
    FILE *fp = NULL;
    char line[128] = {0};
    int port_id = -1;
    char brname_str[32] = {0};
    char cmd[32] = {0};
    bool matched = false;

    snprintf(cmd, sizeof(cmd) - 1, "brctl show");
    //log_debug("cmd: %s", cmd);
    if((fp = popen(cmd, "r")) == NULL) {
        log_err("popen error");
        return port_id;
    }

    char name_str[32] = {0};//br_name or if_name
    char brid_str[32] = {0};
    char stp_str[8] = {0};
    char ifname_str[32] = {0};
    while ( (fgets(line, sizeof(line), fp)) != NULL) {
        //log_debug("gets: %s", line);
        int arg_cnt = sscanf(line, "%s %s %s %s", name_str, brid_str, stp_str, ifname_str);
        if (arg_cnt == 4) {
            //log_debug("bridge name: %s, bridge id: %s, stp enable: %s, interface: %s",
            //    name_str, brid_str, stp_str, ifname_str);
            if (strcmp(br_name, name_str) == 0) {
                strcpy(brname_str, name_str);
                port_id = 1;
                if (strcmp(if_name, ifname_str) == 0) {
                    matched = true;
                    break;
                }
            }
            else {
                brname_str[0] = '\0';
                continue;
            }
        }
        else if (arg_cnt == 1) {
            //log_debug("interface: %s", name_str);
            if (strcmp(br_name, brname_str) != 0) {
                continue;
            }

            port_id++;
            if (strcmp(if_name, name_str) == 0) {
                matched = true;
                break;
            }
            continue;
        }
        else {
            continue;
        }
    }

    pclose(fp);
    if (!matched)
        port_id = -1;
    //log_debug("bridge interface %s portid: %d", if_name, port_id);

    return port_id;
}


static int get_fdb_portid(const char *br_name, const char *mac)
{
    FILE *fp = NULL;
    char line[128] = {0};
    char cmd[128] = {0};
    int port_id = -1;
    int i = 0;

    char mac_low_str[PRODUCT_MAC_LEN + 1] = {0};
    while (i < strlen(mac)) {
        mac_low_str[i] = tolower(mac[i]);
        i++;
    }

    snprintf(cmd, sizeof(cmd) - 1,
        "brctl showmacs %s |grep %s", br_name, mac_low_str);
    //log_debug("cmd: %s", cmd);
    if((fp = popen(cmd, "r")) == NULL) {
        log_err("popen error");
        return port_id;
    }

    if (NULL != fgets(line, sizeof(line), fp)) {
        //log_debug("gets: %s", line);
        if (sscanf(line, "%d", &port_id) != 1) {
            log_err("fdb format error");
        }
        log_debug("fdb port_id: %d, mac: %s", port_id, mac_low_str);
    }

    pclose(fp);

    return port_id;
}


static int response_msg_code_parse(const char *payload, int payload_len, int *code)
{
    int ret = AWSS_ERROR;

    if (NULL == payload || 0 == payload_len)
        return ret;

    char code_str[16] = {0};
    int length = 0;
    char *data = json_get_value_by_name((char *)payload, payload_len, "code", &length, NULL);
    if (NULL == data){
        log_err("get code fail");
        return ret;
    }

    strncpy(code_str, data, sizeof(code_str) > length?length:sizeof(code_str) - 1);
    if (1 == sscanf(code_str, "%d", code))
        ret =  AWSS_SUCCESS;

    return ret;
}

static int32_t __parse_device_info_callback(char *p_cName, int iNameLen, char *p_cValue, int iValueLen, int iValueType, void *p_CBData) {
    int copy_len = 0;
    dev_info_t *dev_info = (dev_info_t*)p_CBData;

    if(!strncmp(p_cName, "awssVer", iNameLen)){
        copy_len = (iValueLen >= sizeof(dev_info->version))?sizeof(dev_info->version) - 1:iValueLen;
        strncpy(dev_info->version, p_cValue, copy_len);
    }else if(!strncmp(p_cName, "productKey", iNameLen)){
        copy_len = iValueLen >= sizeof(dev_info->product_key)?sizeof(dev_info->product_key) - 1:iValueLen;
        strncpy(dev_info->product_key, p_cValue, copy_len);
    }else if(!strncmp(p_cName, "deviceName", iNameLen)){
        copy_len = iValueLen >= sizeof(dev_info->device_name)?sizeof(dev_info->device_name) - 1:iValueLen;
        strncpy(dev_info->device_name, p_cValue, copy_len);
    }else if(!strncmp(p_cName, "ip", iNameLen)){
        copy_len = iValueLen >= sizeof(dev_info->ip)?sizeof(dev_info->ip) - 1:iValueLen;
        strncpy(dev_info->ip, p_cValue, copy_len);
    }else if(!strncmp(p_cName, "mac", iNameLen)){
        copy_len = iValueLen >= sizeof(dev_info->mac)?sizeof(dev_info->mac) - 1:iValueLen;
        strncpy(dev_info->mac, p_cValue, copy_len);
    }else if(!strncmp(p_cName, "random", iNameLen)){
        copy_len = iValueLen >= sizeof(dev_info->random)?sizeof(dev_info->random) - 1:iValueLen;
        strncpy(dev_info->random, p_cValue, copy_len);
    }else if(!strncmp(p_cName, "sign", iNameLen)){
        copy_len = iValueLen >= sizeof(dev_info->sign)?sizeof(dev_info->sign) - 1:iValueLen;
        strncpy(dev_info->sign, p_cValue, copy_len);
    }else if(!strncmp(p_cName, "security", iNameLen)){
        char security[16] = {0};
        strncpy(security, p_cValue, iValueLen);
        dev_info->security = (uint8_t)atoi(security);
    }

    return JSON_PARSE_OK;
}


static dev_info_t * devinfo_get_response_msg_parse(const char *payload, int payload_len)
{
    int length = 0;
    int code = 0;
    if (response_msg_code_parse(payload, payload_len, &code) != AWSS_SUCCESS
        || code != AWSS_NETWORK_CODE_SUCCESS){
        log_warning("parse code fail, code: %d", code);
        return NULL;
    }

    char *data = json_get_value_by_name((char *)payload, payload_len, "data", &length, NULL);
    if (NULL == data)
        return NULL;

    //TODO: parse device info
    dev_info_t *dev_info = LITE_malloc(sizeof(dev_info_t));
    memset(dev_info, 0, sizeof(dev_info_t));
    //json_parse_name_value(data, length, __parse_device_info_callback, dev_info);
    if (JSON_RESULT_OK != json_parse_name_value(data, length, __parse_device_info_callback, dev_info)) {
        LITE_free(dev_info);
        dev_info = NULL;
        log_err("parse device info fail, data: %s", data);
    }

    return dev_info;
}


static dev_info_t * devinfo_notify_msg_parse(const char *payload, int payload_len)
{
    int length = 0;
    char *params = json_get_value_by_name((char *)payload, payload_len, "params", &length, NULL);
    if (NULL == params)
        return NULL;

    //log_debug("device info notify, params: %s", params);

    dev_info_t *dev_info = LITE_malloc(sizeof(dev_info_t));
    memset(dev_info, 0, sizeof(dev_info_t));
    if (JSON_RESULT_OK != json_parse_name_value(params, length, __parse_device_info_callback, dev_info)) {
        LITE_free(dev_info);
        dev_info = NULL;
        log_err("parse device info fail, parmas: %s", params);
    }
    else
        __dump_devinfo(dev_info);

    return dev_info;
}


static int awss_msg_id_get(void) {
    int ret;
    HAL_MutexLock(msg_id_lock);
    ret = g_msg_id++;
    HAL_MutexUnlock(msg_id_lock);

    return ret;
}


void awss_msg_session_init(awss_msg_session_t *session) {
    session->psem = HAL_SemaphoreCreate();
    session->request = NULL;
    session->response = NULL;
}


void awss_msg_session_destroy(awss_msg_session_t *session) {
    HAL_SemaphoreDestroy(session->psem);
    session->request = NULL;
    session->response = NULL;
}


void awss_msg_session_wait(awss_msg_session_t *session) {
    HAL_SemaphoreWait(session->psem, PLATFORM_WAIT_INFINITE);
}


int awss_msg_session_timewait(awss_msg_session_t *session, int timeout_ms) {
    return HAL_SemaphoreWait(session->psem, timeout_ms);
}


void awss_msg_session_signal(awss_msg_session_t *session) {
    HAL_SemaphorePost(session->psem);
}


bool awss_net_device_established(char *mac, char *ip)
{
    char lan_ifname[PRODUCT_IFNAME_LEN + 1] = {0};
    char aha_ifname[PRODUCT_IFNAME_LEN + 1] = {0};
    char adha_ifname[PRODUCT_IFNAME_LEN + 1] = {0};
    char aha_brname[PRODUCT_IFNAME_LEN + 1] = {0};

    int aha_portid = get_brif_portid(product_get_aha_bridge_ifname(aha_brname),
        product_get_aha_port_ifname(aha_ifname));
    int adha_portid = get_brif_portid(product_get_aha_bridge_ifname(aha_brname),
        product_get_aha_port_ifname(adha_ifname));

    //TODO: br_ifname = "br-lan"
    int fdb_portid = get_fdb_portid(product_get_lan_ifname(lan_ifname), mac);

    log_debug("aha_brname: %s, aha_portid: %d, adha_portid: %d, lan_ifname: %s, fdb_portid: %d",
        aha_brname, aha_portid, adha_portid, lan_ifname, fdb_portid);

    if (((strcmp(lan_ifname, aha_brname) == 0) && aha_portid != fdb_portid
        && adha_portid != fdb_portid && -1 != fdb_portid) ||
        ((strcmp(lan_ifname, aha_brname) != 0) && -1 != fdb_portid))
        return true;

    return false;
}



char *awss_net_method_to_path_convert(const char *method, const char *path_prefix, char *path_buf, uint32_t buf_sz)
{
    const char *method_delimiters = ".";
    const char *path_delimiters = "/";
    int len = 0;
    char method_buf[AWSS_METHOD_STR_MAX_LENGTH] = {0};

    //log_debug("path prefix: %s, method: %s", path_prefix, method);
    strncpy(method_buf, method, sizeof(method_buf) - 1);
    if (strlen(method_buf) + strlen((char *)path_prefix) >=  buf_sz) {
        log_err("buffer size error");
        return NULL;
    }

    len = snprintf(path_buf, buf_sz, "%s", path_prefix);
    char *temp = strtok(method_buf, method_delimiters);
    while(temp){
        len += snprintf(path_buf + len, buf_sz - len, "%s", temp);
        temp = strtok(NULL, method_delimiters);

        if (temp) {
            len += snprintf(path_buf + len, buf_sz - len, "%s", path_delimiters);
        }
    }
    if (len == buf_sz) {
        log_err("buffer size error");
        return NULL;
    }
    path_buf[len] = '\0';

    return path_buf;
}


int awss_net_service_enable_notify(const char *product_key, const char *device_name,
                                int8_t code, const char *info)
{
    int ret = AWSS_ERROR;
    char *payload_buf = LITE_malloc(AWSS_NETWORK_MAX_MSG_SIZE);

    int len = snprintf(payload_buf, AWSS_NETWORK_MAX_MSG_SIZE - 1,
        AWSS_NOTIFY_ENABLE_STATE_MSG_FMT, awss_msg_id_get(), AWSS_APP_METHOD_ENABLE_STATE_NOTIFY,
        code, info, product_key, device_name);
    if (len == AWSS_NETWORK_MAX_MSG_SIZE - 1) {
        goto end;
    }

    ret = AWSS_SUCCESS;
    payload_buf[len] = '\0';

    log_debug("payload_buf: %s", payload_buf);

    char uri[AWSS_URI_STR_MAX_LENGTH] = {0};
    awss_net_method_to_path_convert(AWSS_APP_METHOD_ENABLE_STATE_NOTIFY, AWSS_APP_SRV_URI_PREFIX, uri, sizeof(uri));

    log_debug("notify msg, uri: %s, payload: %s", uri, payload_buf);

    awss_coap_event_notify(uri, (unsigned char *)payload_buf, len);

end:
    if (payload_buf)
        LITE_free(payload_buf);

    return ret;
}


int awss_net_getting_cipher_notify(dev_info_t *dev_info, int8_t code, const char *info)
{
    int ret = AWSS_ERROR;
    char *payload_buf = LITE_malloc(AWSS_NETWORK_MAX_MSG_SIZE);

    int len = snprintf(payload_buf, AWSS_NETWORK_MAX_MSG_SIZE - 1,
        AWSS_NOTIFY_GETCIPHER_STATE_MSG_FMT, awss_msg_id_get(), AWSS_APP_METHOD_GETCIPHER_STATE_NOTIFY,
        code, info, dev_info->product_key, dev_info->device_name);
    if (len == AWSS_NETWORK_MAX_MSG_SIZE - 1) {
        goto end;
    }

    ret = AWSS_SUCCESS;
    payload_buf[len] = '\0';
    char uri[AWSS_URI_STR_MAX_LENGTH] = {0};
    awss_net_method_to_path_convert(AWSS_APP_METHOD_GETCIPHER_STATE_NOTIFY, AWSS_APP_SRV_URI_PREFIX, uri, sizeof(uri));

    log_debug("notify msg, uri: %s, payload: %s", uri, payload_buf);

    awss_coap_event_notify(uri, (unsigned char *)payload_buf, len);

end:
    if (payload_buf)
        LITE_free(payload_buf);

    return ret;
}


int awss_net_joined_device_notify(dev_info_t *dev_info)
{
    int ret = AWSS_ERROR;
    char *payload_buf = LITE_malloc(AWSS_NETWORK_MAX_MSG_SIZE);

    int len = snprintf(payload_buf, AWSS_NETWORK_MAX_MSG_SIZE - 1,
        AWSS_NOTIFY_JOINEDDEVICE_MSG_FMT, awss_msg_id_get(), AWSS_APP_METHOD_JOINEDDEVICE_NOTIFY,
        dev_info->product_key, dev_info->device_name);
    if (len == AWSS_NETWORK_MAX_MSG_SIZE - 1) {
        goto end;
    }

    ret = AWSS_SUCCESS;
    payload_buf[len] = '\0';
    char uri[AWSS_URI_STR_MAX_LENGTH] = {0};
    awss_net_method_to_path_convert(AWSS_APP_METHOD_JOINEDDEVICE_NOTIFY, AWSS_APP_SRV_URI_PREFIX, uri, sizeof(uri));

    log_debug("notify msg, uri: %s, payload: %s", uri, payload_buf);

    awss_coap_event_notify(uri, (unsigned char *)payload_buf, len);

end:
    if (payload_buf)
        LITE_free(payload_buf);

    return ret;
}


int awss_net_authed_device_notify(dev_info_t *dev_info)
{
    printf("authed device, product key: %s, device name: %s", dev_info->product_key, dev_info->device_name);
    return 0;
}


int awss_net_device_switchap_result_notify(dev_info_t *dev_info, int8_t code, const char *info)
{
    int ret = AWSS_ERROR;
    char *payload_buf = LITE_malloc(AWSS_NETWORK_MAX_MSG_SIZE);

    int len = snprintf(payload_buf, AWSS_NETWORK_MAX_MSG_SIZE - 1,
        AWSS_NOTIFY_SWITCHAP_RESULT_MSG_FMT, awss_msg_id_get(), AWSS_APP_METHOD_SWITCHAP_RESULT_NOTIFY,
        code, info, dev_info->product_key, dev_info->device_name);
    if (len == AWSS_NETWORK_MAX_MSG_SIZE - 1) {
        goto end;
    }

    ret = AWSS_SUCCESS;
    payload_buf[len] = '\0';
    char uri[AWSS_URI_STR_MAX_LENGTH] = {0};
    awss_net_method_to_path_convert(AWSS_APP_METHOD_SWITCHAP_RESULT_NOTIFY, AWSS_APP_SRV_URI_PREFIX, uri, sizeof(uri));

    log_debug("notify msg, uri: %s, payload: %s", uri, payload_buf);
    awss_coap_event_notify(uri, (unsigned char *)payload_buf, len);
    log_debug("");
end:
    if (payload_buf)
        LITE_free(payload_buf);

    return ret;
}


awss_msg_t *awss_net_accs_service_invoke(awss_msg_t *req_msg)
{
    awss_msg_t *resp = NULL;
    iotx_cmp_send_peer_t cloud_peer;

#if 0//__AWSS_AP_UT__
    log_debug("invoke accs service UT: uri path: %s, payload: %s", req_msg->uri, req_msg->payload);
    return NULL;
#endif

    memset(&cloud_peer, 0, sizeof(cloud_peer));
    log_debug("invoke accs service: uri path: %s, payload: %s", req_msg->uri, req_msg->payload);
    resp = awss_cmp_service_invoke(req_msg, &cloud_peer);
    if (NULL == resp) {
        log_err("invoke accs service fail, uri path: %s, payload: %s", req_msg->uri, req_msg->payload);
        return resp;
    }

    log_debug("response msg: %s", resp->payload);
    return resp;
}



awss_msg_t *awss_net_alcs_service_invoke(const char *ip, awss_msg_t *req_msg)
{
    awss_msg_t *resp = NULL;
    NetworkAddr remote;

    strncpy((char *)remote.addr, ip, sizeof(remote.addr));
    remote.port = AWSS_ALCS_PORT;
    log_debug("invoke alcs service: ip: %s, uri path: %s, payload: %s", ip, req_msg->uri, req_msg->payload);
    resp = awss_coap_service_invoke(req_msg, &remote);
    if (NULL == resp) {
        log_err("invoke alcs service fail, ip: %s, uri path: %s, payload: %s", ip, req_msg->uri, req_msg->payload);
        return resp;
    }

    log_debug("response msg: %s", resp->payload);
    return resp;
}

//#ifndef __AWSS_AP_UT__
/*
* device info payload format: ["hex","hex","hex"]
* hexstring original data format:
* deviceName_len: 1 bytes, 0-255
* deviceName£ºhexString(deviceName_len bytes)
* productKey_len : 1 bytes, 0-255
* productKey£ºhexString(productKey_len bytes)
* random£ºhexString(32 bytes)
* sign : hexString(32 bytes)
*/
static char *__calc_device_hexstr(dev_info_t dev_info[], uint8_t dev_cnt)
{
    char hexstr_buf[256] = {0};
    int buf_size = dev_cnt * 256;
    int index = 0;
    int payload_len = 0;
    char *payload_buf = LITE_malloc(buf_size);
    payload_buf[payload_len++] = '[';


    while(index < dev_cnt) {
        int len = 0;
        char char_buf[PRODUCT_KEY_LEN + DEVICE_NAME_LEN + 3] = {0};
        char_buf[len++] = (uint8_t)strlen(dev_info[index].device_name);

        len += snprintf(char_buf + len, sizeof(char_buf) - len, "%s", dev_info[index].device_name);

        char_buf[len++] = (uint8_t)strlen(dev_info[index].product_key);
        len += snprintf(char_buf + len, sizeof(char_buf) - len, "%s", dev_info[index].product_key);

        LITE_hexbuf_convert(char_buf, hexstr_buf, len, 0);
        //utils_hex_to_str((uint8_t *)char_buf, len, hexstr_buf, sizeof(hexstr_buf));
        len *= 2;
        len += snprintf(hexstr_buf + len, sizeof(hexstr_buf) - len, "%s", dev_info[index].random);
#ifdef __AWSS_AP_UT__
        len += snprintf(hexstr_buf + len, sizeof(hexstr_buf) - len, "%s", "1c77ae02579426106408bf4c77846599");
#else
        len += snprintf(hexstr_buf + len, sizeof(hexstr_buf) - len, "%s", dev_info[index].sign);
#endif
        if (len >= sizeof(hexstr_buf)){
            log_err("Buffer overflow");
            break;
        }
        hexstr_buf[len] = '\0';

        log_debug("device hexstr: %s", hexstr_buf);
        if (index > 0)
            payload_len += snprintf(payload_buf + payload_len, buf_size - payload_len, ",\"%s\"", hexstr_buf);
        else
            payload_len += snprintf(payload_buf + payload_len, buf_size - payload_len, "\"%s\"", hexstr_buf);

        index++;
    }

    payload_buf[payload_len++] = ']';
    payload_buf[payload_len] = '\0';

    return payload_buf;
}



/*json array: [{"productKey":"","deviceName":"","period":60}]*/
static int __parse_devid_array(const char *json_array, int length, dev_id_t devid[], uint8_t *devid_cnt)
{
    int ret = AWSS_SUCCESS;
    int actual_cnt = 0;
    char *json_buf = NULL;

    json_buf = LITE_malloc(length + 1);
    strncpy(json_buf, json_array, length);
    json_buf[length] = '\0';

    log_debug("devid array: %s", json_buf);

    char *pos, *entry, *value = NULL;
    int len, type, dest_size, value_len = 0;
    json_array_for_each_entry(json_buf, length, pos, entry, len, type) {
        if (actual_cnt >= *devid_cnt) {
            log_err("devid array size error");
            ret = AWSS_ERROR;
            break;
        }

        //parse productKey
        value = json_get_value_by_name(entry, len, "productKey", &value_len, NULL);
        if (value == NULL){
            log_err("parse device productKey fail");
            ret = AWSS_ERROR;
            break;
        }
        dest_size = sizeof(devid[actual_cnt].product_key);
        dest_size = dest_size > value_len?value_len:dest_size;
        strncpy(devid[actual_cnt].product_key, value, dest_size);
        devid[actual_cnt].product_key[dest_size - 1] = '\0';

        //parse deviceName
        value = json_get_value_by_name(entry, len, "deviceName", &value_len, NULL);
        if (value == NULL){
            log_err("parse device deviceName fail");
            ret = AWSS_ERROR;
            break;
        }
        dest_size = sizeof(devid[actual_cnt].device_name);
        dest_size = dest_size > value_len?value_len:dest_size;
        strncpy(devid[actual_cnt].device_name, value, value_len);
        devid[actual_cnt].device_name[dest_size - 1] = '\0';

        //parse period
        value = json_get_value_by_name(entry, len, "timeout", &value_len, NULL);
        if (value == NULL || 1 != sscanf(value, "%u", &(devid[actual_cnt].period))){
            log_err("parse device period fail");
            ret = AWSS_ERROR;
            break;
        }

        log_debug("device id, productkey: %s, devicename: %s, timeout: %u",
            devid[actual_cnt].product_key, devid[actual_cnt].device_name, devid[actual_cnt].period);

        actual_cnt++;
    }
    *devid_cnt = actual_cnt;

    if (json_buf)
        LITE_free(json_buf);

    return ret;
}
//#endif

/*
* --> "params":{"type":"ROUTER","ssid":"","bssid":"xxx","rssi":"xxx""payload":["hex","hex","hex"]}
* <-- "data":[{"productKey":"","deviceName":"","period":60}]
*/
int awss_net_device_sign_verify(dev_info_t dev_info[], uint8_t devinfo_cnt,
                                dev_id_t devid[], uint8_t *devid_cnt)
{
    int ret = AWSS_ERROR;

#if 0//__AWSS_AP_UT__
    strcpy(devid[0].product_key, dev_info[0].product_key);
    strcpy(devid[0].device_name, dev_info[0].device_name);
    devid[0].period = 60;

    log_debug("device sign verify success!!!");
    *devid_cnt = 1;
    ret = AWSS_SUCCESS;
#else
    char ssid [ PRODUCT_SSID_LEN + 1 ] = {0};
    char passwd [ PRODUCT_PWD_LEN + 1 ] = {0};
    char ifname [ PRODUCT_IFNAME_LEN + 1 ] = {0};
    char bssid [ PRODUCT_MAC_LEN + 1 ] = {0};
    char *payload_hexstr = NULL;

    awss_msg_t *resp_msg = NULL;
    awss_msg_t *req_msg = NULL;

    //TODO: call cloud mthod:awss.enrollee.found
    product_get_extranet_ap_info(ssid, passwd, ifname);
    //product_get_extranet_ap_port_ifname(ifname);
    if (NULL == get_ap_bssid(ifname, bssid)) {
        log_err("get bssid fail, ifname: %s", ifname);
#ifdef __AWSS_AP_UT__
        strcpy(bssid, "010101010101");
#else
        goto end;
#endif
    }

    log_debug("extranet ssid: %s, bssid: %s", ssid, bssid);

    int payload_sz = AWSS_NETWORK_MAX_MSG_SIZE;
    req_msg = LITE_malloc(sizeof(awss_msg_t) + payload_sz);
    memset(req_msg, 0, sizeof(awss_msg_t) + payload_sz);

    if (NULL == awss_net_method_to_path_convert(AWSS_CLOUD_METHOD_DEVICE_FUND,
            AWSS_CLOUD_URI_PREFIX_FMT, req_msg->uri, sizeof(req_msg->uri))) {
        log_err("convert method to uri fail, method: %s", AWSS_CLOUD_METHOD_DEVICE_FUND);
        goto end;
    }

    log_debug("uri path: %s", req_msg->uri);
    payload_hexstr = __calc_device_hexstr(dev_info, devinfo_cnt);

    req_msg->msg_id = awss_msg_id_get();
    strncpy(req_msg->method, AWSS_CLOUD_METHOD_DEVICE_FUND, sizeof(req_msg->method) - 1);
    req_msg->payload_length = snprintf((char *)req_msg->payload, payload_sz - 1,
        AWSS_REQUEST_VERIFY_DEVICE_PARAMS_FMT, ssid, bssid, payload_hexstr);
    if (req_msg->payload_length >= payload_sz - 1){
        log_err("The message is too long");
        goto end;
    }
    req_msg->payload[req_msg->payload_length] = '\0';

    log_debug("request msg: uri: %s, payload: %s", req_msg->uri, req_msg->payload);
    resp_msg = awss_net_accs_service_invoke(req_msg);
    if (NULL == resp_msg) {
        log_err("invoke accs service fail, uri: %s, payload: %s", req_msg->uri, req_msg->payload);
        goto end;
    }

    log_debug("response msg payload: %s, length: %d", resp_msg->payload, resp_msg->payload_length);
    int data_len = 0;
    data_len = resp_msg->payload_length;
    char *data = resp_msg->payload;

    //TODO: parse deviceid, data:[{"productKey":"","deviceName":"","period":60}]
    ret = __parse_devid_array(data, data_len, devid, devid_cnt);
    RET_GOTO(ret, end, "parse device id fail, data: %s", data);

end:
    if(req_msg)
        LITE_free(req_msg);
    if(resp_msg)
        LITE_free(resp_msg);
    if(payload_hexstr)
        LITE_free(payload_hexstr);
#endif

#if __AWSS_AP_UT__
    strcpy(devid[0].product_key, dev_info[0].product_key);
    strcpy(devid[0].device_name, dev_info[0].device_name);
    devid[0].period = 60;

    log_debug("device sign verify success!!!");
    *devid_cnt = 1;
    ret = AWSS_SUCCESS;
#endif

    return ret;
}


/*
* --> "params":{"awss_ver":{},"deviceName":"TestDeviceName","productKey":"TestProductKey","productId":"TestId","cipherType":6,"random":"xxx"}
* <-- "data":"secret"
*/
int awss_net_encrypt_cipher_get(dev_info_t *dev_info, char *cipher_buf, int buf_sz)
{
    int ret = AWSS_ERROR;

#if 0//__AWSS_AP_UT__
    strcpy(cipher_buf, "82ADEF2CB435717A2AA34F317B61B2B2");
    log_debug("get cipher success, cipher: %s", cipher_buf);

    ret = AWSS_SUCCESS;
#endif
    awss_msg_t *resp_msg = NULL;
    awss_msg_t *req_msg = NULL;

    int payload_sz = AWSS_NETWORK_MAX_MSG_SIZE;
    req_msg = LITE_malloc(sizeof(awss_msg_t) + payload_sz);
    memset(req_msg, 0, sizeof(awss_msg_t) + payload_sz);

    if (NULL == awss_net_method_to_path_convert(AWSS_CLOUD_METHOD_CIPHER_GET,
            "", req_msg->uri, sizeof(req_msg->uri))) {
        log_err("convert method to uri fail, method: %s", AWSS_CLOUD_METHOD_CIPHER_GET);
        goto end;
    }

    log_debug("uri path: %s", req_msg->uri);

    req_msg->msg_id = awss_msg_id_get();
    strncpy(req_msg->method, AWSS_CLOUD_METHOD_CIPHER_GET, sizeof(req_msg->method) - 1);
    req_msg->payload_length= snprintf((char *)req_msg->payload, payload_sz - 1,
        AWSS_REQUEST_GET_CIPHER_PARAMS_FMT, dev_info->version, dev_info->device_name, dev_info->product_key,
        AWSS_CLOUD_URI_PREFIX_FMT, dev_info->security, dev_info->random);

    if (req_msg->payload_length >= payload_sz - 1){
        log_err("The message is too long");
        goto end;
    }

    log_debug("request msg: uri: %s, payload: %s", req_msg->uri, req_msg->payload);
    resp_msg = awss_net_accs_service_invoke(req_msg);
    if (NULL == resp_msg) {
        log_err("invoke accs service fail, uri: %s, payload: %s", req_msg->uri, req_msg->payload);
        goto end;
    }

    log_debug("response data: %s", resp_msg->payload);

    //TODO: parse deviceid, data:"secret"
#if 0
    int code = 0;
    if (response_msg_code_parse((char *)resp_msg->payload, resp_msg->payload_length, &code) == AWSS_SUCCESS
        && code == AWSS_NETWORK_CODE_SUCCESS){
#else
    if (resp_msg->code == AWSS_NETWORK_CODE_SUCCESS){
#endif
        int data_len = 0;
        char *data = json_get_value_by_name((char *)resp_msg->payload, resp_msg->payload_length, "secret", &data_len, NULL);
        if (NULL == data){
            log_err("get secret fail");
            goto end;
        }

        int cp_len = data_len > buf_sz - 1?(buf_sz - 1):data_len;
        strncpy(cipher_buf, data, cp_len);
        cipher_buf[cp_len] = '\0';

        ret = AWSS_SUCCESS;
        log_debug("get cipher success, cipher: %s", cipher_buf);
    }
    else
        log_debug("get cipher failue");

end:
    if(req_msg)
        LITE_free(req_msg);
    if(resp_msg)
        LITE_free(resp_msg);

#ifdef __AWSS_AP_UT__
    if (cipher_buf[0] != '\0') {
        strcpy(cipher_buf, "82ADEF2CB435717A2AA34F317B61B2B2");
        log_debug("get cipher success, cipher: %s", cipher_buf);
    }
    ret = AWSS_SUCCESS;
#endif

    return ret;
}


dev_info_t *awss_net_device_info_get(const char *ip_addr)
{
    awss_msg_t *resp_msg = NULL;
    dev_info_t *dev_info = NULL;

    int payload_sz = AWSS_NETWORK_MAX_MSG_SIZE;
    awss_msg_t *req_msg = LITE_malloc(sizeof(awss_msg_t) + payload_sz);
    memset(req_msg, 0, sizeof(awss_msg_t) + payload_sz);

    if (NULL == awss_net_method_to_path_convert(AWSS_DEVICE_METHOD_DEVICE_INFO_GET,
            AWSS_DEVICE_URI_PREFIX, req_msg->uri, sizeof(req_msg->uri))) {
        log_err("convert method to uri fail, method: %s", AWSS_DEVICE_METHOD_DEVICE_INFO_GET);
        goto end;
    }

    log_debug("uri path: %s", req_msg->uri);

    req_msg->msg_id = awss_msg_id_get();
    strncpy(req_msg->method, AWSS_DEVICE_METHOD_DEVICE_INFO_GET, sizeof(req_msg->method) - 1);
    req_msg->payload_length= snprintf((char *)req_msg->payload, payload_sz - 1,
        AWSS_REQUEST_GET_DEVINFO_MSG_FMT,
        req_msg->msg_id, AWSS_DEVICE_METHOD_DEVICE_INFO_GET);
    if (req_msg->payload_length >= payload_sz - 1){
        log_err("The message is too long");
        goto end;
    }

    log_debug("request msg: uri: %s, payload: %s", req_msg->uri, req_msg->payload);
    resp_msg = awss_net_alcs_service_invoke(ip_addr, req_msg);
    if (NULL == resp_msg) {
        log_err("alcs service invoke fail, uri: %s, payload: %s", req_msg->uri, req_msg->payload);
        goto end;
    }

    log_debug("response data: %s", resp_msg->payload);
    if (NULL != (dev_info = devinfo_get_response_msg_parse((char *)resp_msg->payload, resp_msg->payload_length))){
        log_debug("parse device info resp msg success");
        __dump_devinfo(dev_info);
    }
    else
        log_debug("parse device info resp msg fail, payload: %s", resp_msg->payload);

end:
    if (req_msg)
        LITE_free(req_msg);

    if (resp_msg)
        LITE_free(resp_msg);

    return dev_info;
}


int awss_net_device_switchap(dev_info_t *dev_info, const char *ssid_str, const char *pwd_str)
{
    int ret = AWSS_ERROR;
    char uri_prefix[AWSS_URI_STR_MAX_LENGTH] = {0};
    awss_msg_t *resp_msg = NULL;

    int payload_sz = AWSS_NETWORK_MAX_MSG_SIZE;
    awss_msg_t *req_msg = LITE_malloc(sizeof(awss_msg_t) + payload_sz);
    memset(req_msg, 0, sizeof(awss_msg_t) + payload_sz);

    snprintf(uri_prefix, sizeof(uri_prefix) - 1, AWSS_DEVICE_URI_PREFIX"%s/%s/",
        dev_info->product_key, dev_info->device_name);
    if (NULL == awss_net_method_to_path_convert(AWSS_DEVICE_METHOD_SWITCHAP, uri_prefix,
        req_msg->uri, sizeof(req_msg->uri))) {
        log_err("convert method to uri fail, method: %s", AWSS_DEVICE_METHOD_SWITCHAP);
        goto end;
    }
    log_debug("uri path: %s", req_msg->uri);

    req_msg->msg_id = awss_msg_id_get();
    strncpy(req_msg->method, AWSS_DEVICE_METHOD_SWITCHAP, sizeof(req_msg->method) - 1);
    req_msg->payload_length= snprintf((char *)req_msg->payload, payload_sz - 1,
        AWSS_REQUEST_SWITCHAP_MSG_FMT,
        req_msg->msg_id, AWSS_DEVICE_METHOD_SWITCHAP,
        ssid_str, pwd_str, (int)dev_info->security);
    if (req_msg->payload_length >= payload_sz - 1){
        log_err("The message is too long");
        goto end;
    }

    log_debug("request msg: uri: %s, payload: %s", req_msg->uri, req_msg->payload);

    resp_msg = awss_net_alcs_service_invoke(dev_info->ip, req_msg);
    if (NULL == resp_msg) {
        log_err("alcs service invoke fail, uri: %s, payload: %s", req_msg->uri, req_msg->payload);
        goto end;
    }

    log_debug("response data: %s", resp_msg->payload);

    int code = 0;
    if (response_msg_code_parse((char *)resp_msg->payload, resp_msg->payload_length, &code) == AWSS_SUCCESS
        && code == AWSS_NETWORK_CODE_SUCCESS){
        ret = AWSS_SUCCESS;

        log_debug("switchap success");
    }
    else
        log_debug("switchap failue");

end:
    if (req_msg)
        LITE_free(req_msg);

    if (resp_msg)
        LITE_free(resp_msg);

    return ret;
}


dev_info_t *awss_net_search_device(void)
{
    dev_info_t *dev_info = NULL;
    //const char *ip_addr = "192.168.124.1";
    const char *ip_addr = AWSS_ALCS_MC_ADDR;;

    dev_info = awss_net_device_info_get(ip_addr);
    if (NULL == dev_info) {
        goto end;
    }

    log_debug("search device success:");
    __dump_devinfo(dev_info);

end:
    return dev_info;
}


int awss_net_device_info_notification_handle(const char *msg, int req_len)
{
    int ret = AWSS_ERROR;

    //log_debug("device info notification msg: %s", msg);
    dev_info_t * dev_info = devinfo_notify_msg_parse(msg, req_len);
    if (NULL == dev_info) {
        log_err("malloc error!");
        return ret;
    }

    awss_attach_device(dev_info);
    if (dev_info)
        LITE_free(dev_info);

    return AWSS_SUCCESS;
}

/*
 *data:{
    "awss_ver": {},
    "dev_type": 2,
    "product_key": "%s",
    "device_name": "%s",
    "mac": "%s",
    "ip": "%s",
    "token": "%s"
  }
*/
int awss_net_ap_devinfo_getting_handle(const char *req_msg, int req_len, char **resp_msg, int *resp_len)
{
    int ret = AWSS_ERROR;
    int length = 0;
    char product_key[PRODUCT_KEY_MAXLEN + 1] = {0};
    char device_name[DEVICE_NAME_MAXLEN + 1] = {0};
    uint32_t msg_id = 0;
    int temp_len;
    char *temp;

    temp = json_get_value_by_name((char *)req_msg, req_len, "id", &temp_len, NULL);
    if (NULL == temp){
        log_err("message format error, msg: %s", req_msg);
        return ret;
    }
    sscanf(temp, "%u", &msg_id);

    HAL_GetProductKey(product_key);
    HAL_GetDeviceName(device_name);

    *resp_msg = LITE_malloc(AWSS_NETWORK_MAX_MSG_SIZE);
    memset(*resp_msg, 0, AWSS_NETWORK_MAX_MSG_SIZE);

    char token[] = "93DAB75D142D15DF020C51B7670CB927";
#ifdef __AWSS_AP_UT__
    length = snprintf(*resp_msg, AWSS_NETWORK_MAX_MSG_SIZE - 1,
        AWSS_RESPONSE_DEVINFO_MSG_FTM, msg_id, AWSS_NETWORK_CODE_SUCCESS,
        product_key, device_name, "01:01:01:01:01:01", "192.168.0.1", token);
#else
    char ifname[PRODUCT_IFNAME_LEN + 1] = {0};
    char mac_str [ PRODUCT_MAC_LEN + 1 ] = {0};
    char ip_str [ AWSS_DEVICE_IP_LEN + 1 ] = {0};

    product_get_lan_ifname(ifname);
    if (NULL == get_netif_macaddr(ifname, mac_str)){
        log_err("get macaddr fail, ifname: %s", ifname);
        goto err;
    }
    if (NULL == get_netif_ipaddr((char *)ifname, ip_str)){
        log_err("get ipaddr fail, ifname: %s", ifname);
        goto err;
    }

    length = snprintf(*resp_msg, AWSS_NETWORK_MAX_MSG_SIZE - 1,
        AWSS_RESPONSE_DEVINFO_MSG_FTM, msg_id, AWSS_NETWORK_CODE_SUCCESS,
        product_key, device_name, mac_str, ip_str, token);
#endif
    *resp_len = length;

    log_debug("device info getting response msg: %s", *resp_msg);
    ret = AWSS_SUCCESS;

    return ret;

#ifndef __AWSS_AP_UT__
err:
#endif
    if (NULL != *resp_msg) {
        LITE_free(*resp_msg);
        *resp_msg = NULL;
    }

    return ret;
}


int awss_net_device_checkin_handle_for_alcs(const char *req_msg, int req_len, char **resp_msg, int *resp_len)
{
    //get product key & device name
    char *params = NULL;
    int params_len = 0;
    int temp_len;
    char *temp;
    char product_key[PRODUCT_KEY_MAXLEN + 1] = {0};
    char device_name[DEVICE_NAME_MAXLEN + 1] = {0};
    uint32_t period = 0;
#if 1
    uint32_t msg_id = 0;
    temp = json_get_value_by_name((char *)req_msg, req_len, "id", &temp_len, NULL);
    if (NULL == temp){
        log_err("message format error, msg: %s", req_msg);
        return AWSS_ERROR;
    }
    sscanf(temp, "%d", &msg_id);

    params = json_get_value_by_name((char *)req_msg, req_len, "params", &params_len, NULL);
    if (NULL == params){
        log_err("message format error, msg: %s", req_msg);
        return AWSS_ERROR;
    }
    log_debug("params: %s", params);
#else
    params = req_msg;
    params_len = req_len;
#endif
    temp = json_get_value_by_name(params, params_len, "productKey", &temp_len, NULL);
    strncpy(product_key, temp, temp_len);

    temp = json_get_value_by_name(params, params_len, "deviceName", &temp_len, NULL);
    strncpy(device_name, temp, temp_len);

    temp = json_get_value_by_name(params, params_len, "period", &temp_len, NULL);
    sscanf(temp, "%d", &period);

    int ret = awss_checkin_device(product_key, device_name, period);
    if (resp_msg != NULL) {
        int buf_size = 128;
        *resp_msg = LITE_malloc(128);
#if 1
        temp_len = snprintf(*resp_msg, buf_size - 1, AWSS_RESPONSE_CHECKIN_MSG_FMT, msg_id, ret);
#else
        temp_len = snprintf(*resp_msg, buf_size - 1, AWSS_RESPONSE_CHECKIN_DATA_FMT);
#endif
        (*resp_msg)[temp_len] = '\0';
        *resp_len = temp_len;
    }

    return ret;
}



int awss_net_device_checkin_handle(const char *req_msg, int req_len, char **resp_msg, int *resp_len)
{
    //get product key & device name
    char *params = NULL;
    int params_len = 0;
    int temp_len;
    char *temp;
    char product_key[PRODUCT_KEY_MAXLEN + 1] = {0};
    char device_name[DEVICE_NAME_MAXLEN + 1] = {0};
    uint32_t period = 0;
    int ret = AWSS_ERROR;

#if 0
    char *json_array = LITE_malloc(req_len);
    if (NULL == json_array)
        return ret;

    temp = json_get_value_by_name((char *)req_msg, req_len, "dev_list", &temp_len, NULL);
    if (NULL == temp){
        log_err("get dev_list fail");
        goto end;
    }
    strncpy(json_array, temp, temp_len);
    json_array[temp_len] = '\0';

    char *pos, *entry;
    int len, type;
    json_array_for_each_entry(json_array, temp_len, pos, entry, len, type) {
        params = (char *)entry;
        params_len = len;

        temp = json_get_value_by_name(params, params_len, "productKey", &temp_len, NULL);
        strncpy(product_key, temp, temp_len);

        temp = json_get_value_by_name(params, params_len, "deviceName", &temp_len, NULL);
        strncpy(device_name, temp, temp_len);

        temp = json_get_value_by_name(params, params_len, "timeout", &temp_len, NULL);
        sscanf(temp, "%d", &period);

        int ret = awss_device_checkin(product_key, device_name, period);
        if (resp_msg != NULL) {
            int buf_size = 128;
            *resp_msg = LITE_malloc(128);

            temp_len = snprintf(*resp_msg, buf_size - 1, AWSS_RESPONSE_CHECKIN_DATA_FMT);
            *resp_msg[temp_len] = '\0';
            *resp_len = temp_len;
        }

        //TODO: support dev_list
        break;
    }

end:
    if (json_array)
        LITE_free(json_array);
#else
    params = (char *)req_msg;
    params_len = req_len;

    temp = json_get_value_by_name(params, params_len, "productKey", &temp_len, NULL);
    strncpy(product_key, temp, temp_len);

    temp = json_get_value_by_name(params, params_len, "deviceName", &temp_len, NULL);
    strncpy(device_name, temp, temp_len);

    temp = json_get_value_by_name(params, params_len, "timeout", &temp_len, NULL);
    sscanf(temp, "%d", &period);

    ret = awss_checkin_device(product_key, device_name, period);
    if (resp_msg != NULL) {
        int buf_size = 128;
        *resp_msg = LITE_malloc(128);

        temp_len = snprintf(*resp_msg, buf_size - 1, AWSS_RESPONSE_CHECKIN_DATA_FMT);
        *resp_msg[temp_len] = '\0';
        *resp_len = temp_len;
    }
#endif

    return ret;
}


int awss_net_whitelist_push_handle(const char *payload, int payload_length, char **resp_msg, int *resp_len)
{
    log_debug("TODO: push device whitelist");
    return AWSS_SUCCESS;
}


int awss_net_init(void)
{
    int ret = AWSS_ERROR;
    msg_id_lock = HAL_MutexCreate();

    log_debug("awss net init");
    //request queue init
    awss_msg_queue_init(&g_awss_request_queue);

    //coap context init
    ret = awss_coap_init();
    if (ret != AWSS_SUCCESS){
        log_err("awss coap init fail");
        goto err;
    }

    ret = awss_cmp_init();
    if (ret != AWSS_SUCCESS){
        log_err("awss cmp init fail");
        goto err;
    }

    return  AWSS_SUCCESS;

err:
    if(msg_id_lock){
        HAL_MutexDestroy(msg_id_lock);
        msg_id_lock = NULL;
    }

    return ret;
}

void awss_net_deinit(void)
{
    awss_cmp_deinit();
    awss_coap_deinit();
    awss_msg_queue_destroy(g_awss_request_queue);
    g_awss_request_queue = NULL;

    HAL_MutexDestroy(msg_id_lock);
    msg_id_lock = NULL;

    return;
}

