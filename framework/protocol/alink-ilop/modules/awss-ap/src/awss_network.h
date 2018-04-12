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

#ifndef __AWSS_NETWORK__H__
#define __AWSS_NETWORK__H__

#include <unistd.h>
#include <stdbool.h>
#include "awss_msg_queue.h"
#include "awss_devlist.h"


#ifdef __cplusplus
extern "C" {
#endif
//#define AWSS_CLOUD_URI_PREFIX_FMT       "/sys/%s/%s/thing/"
#define AWSS_CLOUD_URI_PREFIX_FMT       ""
#define AWSS_RT_SRV_URI_PREFIX          "/sys/"
#define AWSS_APP_SRV_URI_PREFIX         AWSS_RT_SRV_URI_PREFIX
#define AWSS_DEVICE_URI_PREFIX          "/sys/"


//payload format

#define AWSS_REQUEST_MSG_COMMON_FMT             "{\"id\":%d,\"version\":\"1.0\",\"method\":\"%s\",\"params\":%s}"
#define AWSS_RESPONSE_MSG_COMMON_FMT            "{\"id\":%d,\"code\":%d,\"data\":%s}"
#define AWSS_NOTIFY_MSG_COMMON_FMT              AWSS_REQUEST_MSG_COMMON_FMT

#define AWSS_RESPPONSE_DEVINFO_DATA_FTM         "{\"productKey\":\"%s\",\"deviceName\":\"%s\"}"
#define AWSS_RESPONSE_CHECKIN_DATA_FMT          "{}"

#define AWSS_REQUEST_DEVINFO_PARAMS_FMT         "{}"
#define AWSS_REQUEST_SWITCHAP_PARAMS_FMT        "{\"ssid\":\"%s\",\"passwd\":\"%s\",\"encrypted\":\"%d\"}}"
#define AWSS_REQUEST_GET_CIPHER_PARAMS_FMT      "{\"awssVer\":%s,\"deviceName\":\"%s\",\"productKey\":\"%s\",\"productId\":\"%s\",\"cipherType\":%d,\"random\":\"%s\"}"
#define AWSS_REQUEST_VERIFY_DEVICE_PARAMS_FMT   "{\"type\":1,\"ssid\":\"%s\",\"bssid\":\"%s\",\"rssi\":-1,\"payload\":%s}"

#define AWSS_NOTIFY_ENABLE_STATE_PARAMS_FMT     "{\"code\":%d,\"msg\":\"%s\",\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}"
#define AWSS_NOTIFY_GETCIPHER_STATE_PARAMS_FMT  "{\"code\":%d,\"msg\":\"%s\",\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}"
#define AWSS_NOTIFY_JOINEDDEVICE_PARAMS_FMT     "{\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\",}}}"
#define AWSS_NOTIFY_SWITCHAP_RESULT_PARAMS_FMT  "{\"code\":%d,\"msg\":\"%s\",\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}"
#define AWSS_NOTIFY_AUTHEDDEVICE_PARAMS_FMT     "{\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}"




//dev_type:0: wifi device, 1: ethernet device, 2: awss ap...
#define AWSS_RESPONSE_DEVINFO_MSG_FTM       "{\"id\":%d,\"code\":%d,\"data\":{\"awssVer\":{},\"type\":2,\"productKey\":\"%s\",\"deviceName\":\"%s\",\"mac\":\"%s\",\"ip\":\"%s\",\"token\":\"%s\"}}"
#define AWSS_RESPONSE_CHECKIN_MSG_FMT       "{\"id\":%d,\"code\":%d,\"data\":{}}"

#define AWSS_REQUEST_GET_DEVINFO_MSG_FMT    "{\"id\":%d,\"version\":\"1.0\",\"method\":\"%s\",\"params\":{}}"
#define AWSS_REQUEST_SWITCHAP_MSG_FMT       "{\"id\":%d,\"version\":\"1.0\",\"method\":\"%s\",\"params\":{\"ssid\":\"%s\",\"passwd\":\"%s\",\"encrypted\":\"%d\"}}"
#define AWSS_REQUEST_GET_CIPHER_MSG_FMT     "{\"id\":%d,\"version\":\"1.0\",\"method\":\"%s\"\"params\":{\"awssVer\":%s,\"deviceName\":\"%s\",\"productKey\":\"%s\",\"productId\":\"%s\",\"cipherType\":%d,\"random\":\"%s\"}}"
#define AWSS_REQUEST_VERIFY_DEVICE_MSG_FMT  "{\"id\":%d,\"version\":\"1.0\",\"method\":\"%s\"\"params\":{\"type\":\"ROUTER\",\"ssid\":\"%s\",\"bssid\":\"%s\",\"rssi\":-1,\"payload\":%s}}"

#define AWSS_NOTIFY_ENABLE_STATE_MSG_FMT    "{\"id\":%d,\"method\":\"%s\",\"data\":{\"code\":%d,\"msg\":\"%s\",\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}}"
#define AWSS_NOTIFY_GETCIPHER_STATE_MSG_FMT "{\"id\":%d,\"method\":\"%s\",\"data\":{\"code\":%d,\"msg\":\"%s\",\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}}"
#define AWSS_NOTIFY_JOINEDDEVICE_MSG_FMT    "{\"id\":%d,\"method\":\"%s\",\"data\":{\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}}"
#define AWSS_NOTIFY_SWITCHAP_RESULT_MSG_FMT "{\"id\":%d,\"method\":\"%s\",\"data\":{\"code\":%d,\"msg\":\"%s\",\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}}"
#define AWSS_NOTIFY_AUTHEDDEVICE_MSG_FMT    "{\"id\":%d,\"method\":\"%s\",\"data\":{\"deviceinfo\":{\"productKey\":\"%s\",\"deviceName\":\"%s\"}}}"


//router->app
#define AWSS_APP_METHOD_ENABLE_STATE_NOTIFY         "awss.router.enable.event"
#define AWSS_APP_METHOD_GETCIPHER_STATE_NOTIFY      "awss.router.getcipher.event"
#define AWSS_APP_METHOD_JOINEDDEVICE_NOTIFY         "awss.router.joineddevice.event"
#define AWSS_APP_METHOD_SWITCHAP_RESULT_NOTIFY      "awss.router.switchap.result.event"
#define AWSS_APP_METHOD_AUTHEDDEVICE_NOTIFY         "awss.router.autheddevice.event"

//app->router
#define AWSS_RT_METHOD_DEVICEINFO_GET               "device.info.get"
#define AWSS_RT_METHOD_DEVICE_CHECKIN               "awss.router.device.checkin"
//device->router
#define AWSS_RT_METHOD_DEVICE_INFO_NOTIFY           "awss.device.info.notify"
//cloud->router
#define AWSS_RT_METHOD_ENROLLEE_CHECKIN             "thing.awss.enrollee.checkin"
#define AWSS_RT_METHOD_WHITELIST_PUSH               "thing.awss.router.whitelist.push"
#define AWSS_RT_METHOD_ENROLLEE_CHECKIN_REPLY       "thing.awss.enrollee.checkin_reply"
#define AWSS_RT_METHOD_WHITELIST_PUSH_REPLY         "thing.awss.router.whitelist.push_reply"

//router->cloud
#define AWSS_CLOUD_METHOD_DEVICE_FUND               "thing.awss.enrollee.found"
#define AWSS_CLOUD_METHOD_CIPHER_GET                "thing.cipher.get"
#define AWSS_CLOUD_METHOD_DEVICE_FUND_REPLY         "thing.awss.enrollee.found_reply"
#define AWSS_CLOUD_METHOD_CIPHER_GET_REPLY          "thing.cipher.get_reply"


//router->device
#define AWSS_DEVICE_METHOD_DEVICE_INFO_GET          "awss.device.info.get"
#define AWSS_DEVICE_METHOD_SWITCHAP                 "awss.device.switchap"

#define AWSS_NETWORK_MAX_MSG_SIZE       (1400)



extern awss_request_queue_t *g_awss_request_queue;

bool awss_net_device_established(char *mac, char *ip);

void awss_msg_session_init(awss_msg_session_t *session);

void awss_msg_session_destroy(awss_msg_session_t *session);

void awss_msg_session_wait(awss_msg_session_t *session);

int awss_msg_session_timewait(awss_msg_session_t *session, int timeout_ms);

void awss_msg_session_signal(awss_msg_session_t *session);

char *awss_net_method_to_path_convert(const char *method, const char *path_prefix, char *path_buf, uint32_t buf_sz);

int awss_net_service_enable_notify(const char *product_key, const char *device_name,
                                int8_t code, const char *info);

int awss_net_getting_cipher_notify(dev_info_t *dev_info, int8_t code, const char *info);

int awss_net_joined_device_notify(dev_info_t *dev_info);

int awss_net_authed_device_notify(dev_info_t *dev_info);

int awss_net_device_switchap_result_notify(dev_info_t *dev_info, int8_t code, const char *info);

int awss_net_device_sign_verify(dev_info_t dev_info[], uint8_t devinfo_cnt,
                                dev_id_t devid[], uint8_t *devid_cnt);
dev_info_t *awss_net_device_info_get(const char *ip_addr);

dev_info_t *awss_net_search_device(void);

int awss_net_encrypt_cipher_get(dev_info_t *dev_info, char *cipher_buf, int buf_sz);

int awss_net_device_switchap(dev_info_t *dev_info, const char *ssid_str, const char *pwd_str);

int awss_net_device_info_notification_handle(const char *req_msg, int req_len);

int awss_net_ap_devinfo_getting_handle(const char *req_msg, int req_len, char **resp_msg, int *resp_len);

int awss_net_device_checkin_handle_for_alcs(const char *req_msg, int req_len, char **resp_msg, int *resp_len);

int awss_net_device_checkin_handle(const char *req_msg, int req_len, char **resp_msg, int *resp_len);

int awss_net_whitelist_push_handle(const char *payload, int payload_length, char **resp_msg, int *resp_len);

int awss_net_init();

void awss_net_deinit();

#ifdef __cplusplus
}
#endif
#endif

