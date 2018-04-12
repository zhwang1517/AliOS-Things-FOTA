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
#include <string.h>
#include "lite-log.h"
#include "stdbool.h"
#include "json_parser.h"
#include "awss_ap.h"
#include "awss_coap.h"
#include "awss_network.h"
#include "CoAPExport.h"
#include "CoAPObserve.h"
#include "CoAPMessage.h"
#include "CoAPResource.h"

#define __AWSS_AP_UT__  1


#define AWSS_ALCS_REQUEST_TIMEROUT      (3*1000)
#define COAP_INIT_TOKEN                 (0x01020304)
#define COAP_SERV_MAX_PATH_LEN ((COAP_MSG_MAX_PATH_LEN + 1) * COAP_RESOURCE_MAX_DEPTH + 6)

static CoAPContext *g_alcs_context = NULL;
static uint32_t g_alcs_running = 0;
static void *g_coap_thread = NULL;

static unsigned int coap_server_token_get(unsigned char *p_encoded_data)
{
    static unsigned int value = COAP_INIT_TOKEN;
    p_encoded_data[0] = (unsigned char)((value & 0x00FF) >> 0);
    p_encoded_data[1] = (unsigned char)((value & 0xFF00) >> 8);
    p_encoded_data[2] = (unsigned char)((value & 0xFF0000) >> 16);
    p_encoded_data[3] = (unsigned char)((value & 0xFF000000) >> 24);
    value++;
    return sizeof(unsigned int);
}

static int coap_server_path_2_option(char *uri, CoAPMessage *message)
{
    char *ptr     = NULL;
    char *pstr    = NULL;
    char  path[COAP_MSG_MAX_PATH_LEN + 1]  = {0};

    if (NULL == uri || NULL == message) {
        log_err("Invalid paramter p_path %p, p_message %p", uri, message);
        return COAP_ERROR_INVALID_PARAM;
    }
    if (COAP_SERV_MAX_PATH_LEN < strlen(uri)) {
        log_err("The uri length is too loog,len = %d", (int)strlen(uri));
        return COAP_ERROR_INVALID_LENGTH;
    }
    log_debug("The uri is %s", uri);
    ptr = pstr = uri;
    while ('\0' != *ptr) {
        if ('/' == *ptr) {
            if (ptr != pstr) {
                memset(path, 0x00, sizeof(path));
                strncpy(path, pstr, ptr - pstr);
                log_debug("path: %s,len=%d", path, (int)(ptr - pstr));
                CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                                  (unsigned char *)path, (int)strlen(path));
            }
            pstr = ptr + 1;

        }
        if ('\0' == *(ptr + 1) && '\0' != *pstr) {
            memset(path, 0x00, sizeof(path));
            strncpy(path, pstr, sizeof(path) - 1);
            log_debug("path: %s,len=%d", path, (int)strlen(path));
            CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                              (unsigned char *)path, (int)strlen(path));
        }
        ptr ++;
    }
    return COAP_SUCCESS;
}


static CoAPContext *coap_server_init()
{
    CoAPInitParam param;
    CoAPContext * context = NULL;

    param.appdata = NULL;
    param.group = "224.0.1.187";
    param.notifier = NULL;
    param.obs_maxcount = 16;
    param.res_maxcount = 32;
    param.port = AWSS_ALCS_PORT;
    param.send_maxcount = 16;
    param.waittime = 2000;

    context = CoAPContext_create(&param);

    return (CoAPContext *)context;
}

void *coap_server_yield(void *param)
{
    CoAPContext *context = (CoAPContext *)param;
    log_debug("Enter to coap server yield");
    while(g_alcs_running){
        CoAPMessage_cycle(context);
    }

    return NULL;
}

static int awss_coap_service_register(CoAPContext *context, const char *uri,
    unsigned short permission, CoAPRecvMsgHandler callback)
{
    return CoAPResource_register(context, uri, permission, COAP_CT_APP_JSON, 60, callback);
}


static void awss_coap_server_loop(CoAPContext *context)
{
    int stack_used;
    HAL_ThreadCreate(&g_coap_thread, coap_server_yield, (void *)context, NULL, &stack_used);
}


static int coap_request_msg_send(CoAPContext *context, NetworkAddr *remote,char *uri, unsigned char *payload,
                            unsigned short length, CoAPSendMsgHandler resp_cb, void *user_data)
{
    int ret = COAP_SUCCESS;
    CoAPMessage message;
    unsigned char tokenlen;
    unsigned char token[COAP_MSG_MAX_TOKEN_LEN] = {0};

    CoAPMessage_init(&message);
    CoAPMessageType_set(&message, COAP_MESSAGE_TYPE_CON);
    CoAPMessageCode_set(&message, COAP_MSG_CODE_GET);
    CoAPMessageId_set(&message, CoAPMessageId_gen(context));
    tokenlen = coap_server_token_get(token);
    CoAPMessageToken_set(&message, token, tokenlen);
    CoAPMessageHandler_set(&message, resp_cb);
    CoAPMessageUserData_set(&message, user_data);

    coap_server_path_2_option((char *)uri, &message);
    CoAPUintOption_add(&message, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);
    CoAPMessagePayload_set(&message, payload, length);

    ret = CoAPMessage_send(context, remote, &message);
    CoAPMessage_destory(&message);

    return ret;
}


static int coap_reply_msg_send(CoAPContext *context, NetworkAddr *remote, CoAPMessage *request,
                        unsigned char *payload, unsigned short length)
{
    CoAPMessage response;

    CoAPMessage_init(&response);
    CoAPMessageType_set(&response, COAP_MESSAGE_TYPE_NON);
    CoAPMessageCode_set(&response, COAP_MSG_CODE_205_CONTENT);
    CoAPMessageId_set(&response, request->header.msgid);

    CoAPUintOption_add(&response, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);
    CoAPMessagePayload_set(&response, payload, length);


    int ret = CoAPMessage_send(context, remote, &response);
    CoAPMessage_destory(&response);

    return ret;
}

static void coap_send_msg_callback(CoAPContext *context, CoAPReqResult result, void *userdata, NetworkAddr *remote, CoAPMessage *message)
{
    log_debug("======================send msg callback, id=%d, timestamp: %lld", (uint32_t)userdata, HAL_UptimeMs());
    if (COAP_RECV_RESP_TIMEOUT == result){
        log_err("coap request timeout!");
        return;
    }

    if (NULL == message->payload) {
        log_err("===================payload is NULL!");
        return;
    }

    int buf_sz = sizeof(awss_msg_t) + message->payloadlen + 1;

    log_debug("receive response, payload len: %d, payload: %s, ", message->payloadlen, message->payload);
    awss_msg_t *resp_msg = LITE_malloc(buf_sz);
    if (resp_msg) {
        memset(resp_msg, 0, buf_sz);
        resp_msg->msg_id = (uint32_t)userdata;
        if (message->payload) {
            memcpy(resp_msg->payload, message->payload, message->payloadlen);
            resp_msg->payload_length = message->payloadlen;
        }

        awss_request_node_t *node = awss_request_queue_trigger(g_awss_request_queue, resp_msg);
        if (node) {
            log_debug("process_msg_response, send signal");
            awss_msg_session_signal(&node->session);
        } else {
            log_warning("unknown response msg");
            LITE_free(resp_msg);
        }
    } else {
        log_err("failed to malloc memory");
    }

    return;
}


static void coap_request_callback(CoAPContext *context, const char *paths,
                        NetworkAddr *remote, CoAPMessage *request)
{
    int ret = -1;
    char method[AWSS_METHOD_STR_MAX_LENGTH] = {0};
    int length = 0;
    int resp_len = 0;
    char *resp_msg = NULL;

    log_debug("Receive form: %s:%d, path: %s, payload: %s, length: %d",
        remote->addr, remote->port, paths, request->payload, request->payloadlen);
    char *temp = json_get_value_by_name((char *)request->payload, request->payloadlen, "method", &length, NULL);
    if (NULL == temp) {
        log_err("Invalid pyaload: %s", request->payload);
        return ;
    }
    strncpy(method, temp, length);

    log_debug("method: %s", method);
    if (strncmp(method, AWSS_RT_METHOD_DEVICE_INFO_NOTIFY,
        strlen(AWSS_RT_METHOD_DEVICE_INFO_NOTIFY)) == 0) {
        ret = awss_net_device_info_notification_handle((char *)request->payload, request->payloadlen);
        if (AWSS_SUCCESS != ret) {
            log_err("handle device info notification msg fail");
        }
    }
    else if (strncmp(method, AWSS_RT_METHOD_DEVICEINFO_GET,
        strlen(AWSS_RT_METHOD_DEVICEINFO_GET)) == 0) {
        ret = awss_net_ap_devinfo_getting_handle((char *)request->payload, request->payloadlen, &resp_msg, &resp_len);
        if (ret != AWSS_SUCCESS)
            log_err("handle getting router device info fail");
    }
    else if (strncmp(method, AWSS_RT_METHOD_DEVICE_CHECKIN,
        strlen(AWSS_RT_METHOD_DEVICE_CHECKIN)) == 0) {
        ret = awss_net_device_checkin_handle_for_alcs((char *)request->payload, request->payloadlen,  &resp_msg, &resp_len);
        if (AWSS_SUCCESS != ret) {
            log_err("handle checkin device fail");
        }
    }

    log_debug("resp_msg: %s, length: %d", resp_msg, resp_len);

    //send response msg
    if (resp_msg) {
        ret = coap_reply_msg_send(context, remote, request, (unsigned char *)resp_msg, (unsigned short)resp_len);
        if (ret != AWSS_SUCCESS)
            log_err("send response msg fail, msg: %s", resp_msg);

        LITE_free(resp_msg);
        resp_msg = NULL;
    }

    return;
}


static void coap_subscribe_callback(CoAPContext *context, const char *paths, NetworkAddr *remote, CoAPMessage *request)
{
    unsigned char payload[256] = {0};
    CoAPMessage response;

    CoAPMessage_init(&response);
    CoAPMessageType_set(&response, COAP_MESSAGE_TYPE_CON);
    CoAPMessageCode_set(&response, COAP_MSG_CODE_205_CONTENT);
    CoAPMessageId_set(&response, request->header.msgid);

    log_debug("The message type %d", request->header.type);
    if(COAP_SUCCESS == CoAPOption_present(request, COAP_OPTION_OBSERVE)){
        CoAPObsServer_add(context, paths, remote, request);
        CoAPUintOption_add(&response, COAP_OPTION_OBSERVE, 0);

        log_debug("Accept subcribe, payload: %s", request->payload);
    }

    CoAPUintOption_add(&response, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);
    snprintf((char *)payload, sizeof(payload), "{}");
    CoAPMessagePayload_set(&response, payload, strlen((char *)payload));

    CoAPMessage_send(context, remote, &response);
    CoAPMessage_destory(&response);
}


static int coap_service_register(CoAPContext * context)
{
    int ret = AWSS_ERROR;
    char uri[AWSS_URI_STR_MAX_LENGTH] = {0};

    log_debug("register coap service");

    //notify device info
    if (NULL != awss_net_method_to_path_convert(AWSS_RT_METHOD_DEVICE_INFO_NOTIFY,
            AWSS_RT_SRV_URI_PREFIX, uri, sizeof(uri))) {
        log_debug("register uri: %s", uri);
        awss_coap_service_register(context, uri, COAP_PERM_POST, coap_request_callback);
    }
    //get device info
    if (NULL != awss_net_method_to_path_convert(AWSS_RT_METHOD_DEVICEINFO_GET,
            AWSS_RT_SRV_URI_PREFIX, uri, sizeof(uri))) {
        log_debug("register uri: %s", uri);
        awss_coap_service_register(context, uri, COAP_PERM_GET, coap_request_callback);
    }
    //checkin device
    if (NULL != awss_net_method_to_path_convert(AWSS_RT_METHOD_DEVICE_CHECKIN,
            AWSS_RT_SRV_URI_PREFIX, uri, sizeof(uri))) {
        log_debug("register uri: %s", uri);
        awss_coap_service_register(context, uri, COAP_PERM_PUT, coap_request_callback);
    }

    //register event callback
    if (NULL != awss_net_method_to_path_convert(AWSS_APP_METHOD_ENABLE_STATE_NOTIFY,
            AWSS_RT_SRV_URI_PREFIX, uri, sizeof(uri))) {
        log_debug("register uri: %s", uri);
        awss_coap_service_register(context, uri, COAP_PERM_GET, coap_subscribe_callback);
    }

    if (NULL != awss_net_method_to_path_convert(AWSS_APP_METHOD_GETCIPHER_STATE_NOTIFY,
            AWSS_RT_SRV_URI_PREFIX, uri, sizeof(uri))) {
        log_debug("register uri: %s", uri);
        awss_coap_service_register(context, uri, COAP_PERM_GET, coap_subscribe_callback);
    }

    if (NULL != awss_net_method_to_path_convert(AWSS_APP_METHOD_JOINEDDEVICE_NOTIFY,
            AWSS_RT_SRV_URI_PREFIX, uri, sizeof(uri))) {
        log_debug("register uri: %s", uri);
        awss_coap_service_register(context, uri, COAP_PERM_GET, coap_subscribe_callback);
    }
    if (NULL != awss_net_method_to_path_convert(AWSS_APP_METHOD_SWITCHAP_RESULT_NOTIFY,
            AWSS_RT_SRV_URI_PREFIX, uri, sizeof(uri))) {
        log_debug("register uri: %s", uri);
        awss_coap_service_register(context, uri, COAP_PERM_GET, coap_subscribe_callback);
    }

    log_debug("register coap service success");

    ret = AWSS_SUCCESS;

    return ret;
}


int awss_coap_event_notify(const char *uri, unsigned char *payload, unsigned short length)
{
    log_debug("uri: %s, payload: %s, length: %d", uri, payload, length);
    return CoAPObsServer_notify(g_alcs_context, uri, payload, length, NULL);
}


awss_msg_t *awss_coap_service_invoke(awss_msg_t *req, NetworkAddr *remote)
{
    awss_msg_t *p_rsp = NULL;

    if (!req)
        return NULL;

    unsigned msg_id = req->msg_id;
    awss_request_node_t *node = (awss_request_node_t *) LITE_malloc(sizeof(awss_request_node_t));
    awss_msg_session_init(&node->session);
    node->session.id = msg_id;
    //node->session.request_msg = req;

    if (!awss_request_queue_push(g_awss_request_queue, node)) {
        log_debug("coap msg send, id=%d, timestamp: %lld", msg_id, HAL_UptimeMs());
        int ret = coap_request_msg_send(g_alcs_context, remote,
            req->uri, (unsigned char *)req->payload, req->payload_length,
            coap_send_msg_callback, (void *)(msg_id));
        if (ret == AWSS_SUCCESS) {
            log_debug("waiting for response, id=%d, timestamp: %lld", msg_id, HAL_UptimeMs());
            if (!awss_msg_session_timewait(&node->session, AWSS_ALCS_REQUEST_TIMEROUT)) {
                log_debug("get reponse, id=%d", msg_id);
                p_rsp = node->session.response;
            } else {
                log_warning("waiting response id=%d timeout, timestamp: %lld", msg_id, HAL_UptimeMs());
            }
        } else {
            log_err("failed to send message(len=%d).", req->payload_length);
        }
        awss_request_queue_pop(g_awss_request_queue, node);
    }

    awss_msg_session_destroy(&node->session);
    LITE_free(node);

    //check session id
    if (p_rsp) {
        if (p_rsp->msg_id != req->msg_id) {
            log_err("The response message id matching error, req_id: %d, resp_id: %d",
                req->msg_id, p_rsp->msg_id);

            LITE_free(p_rsp);
            p_rsp = NULL;
        }
    }
    else
        log_err("service invoke timeout!");

    return p_rsp;
}


int awss_coap_init(void)
{
    int ret = AWSS_ERROR;
    g_alcs_running = 1;
    log_debug("awss coap init");

    CoAPContext *context = coap_server_init();
    if (NULL == context){
        log_err("coap context init fail");
        return ret;
    }
    log_debug("create coap context: %p", context);

    ret = coap_service_register(context);
    if (AWSS_SUCCESS != ret){
        log_err("coap register service fail");
        goto err;
    }

    awss_coap_server_loop(context);

    g_alcs_context = context;
    log_debug("awss coap init success");

    return AWSS_SUCCESS;

err:
    if (context)
        CoAPContext_free(context);

    return ret;
}


void awss_coap_deinit(void)
{
    log_debug("awss coap deinit");
    g_alcs_running = 0;

    HAL_ThreadDelete(g_coap_thread);
    g_coap_thread = NULL;

    if (g_alcs_context){
        CoAPContext_free(g_alcs_context);
        g_alcs_context = NULL;
    }
}


