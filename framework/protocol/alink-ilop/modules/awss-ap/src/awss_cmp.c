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
#include "awss_network.h"
#include "lite-utils.h"
#include "iot_import.h"
#include "iot_export.h"
#include "iot_export_cmp.h"

#define __AWSS_AP_UT__  1

#ifdef __AWSS_AP_UT__
#ifdef __HUA_DONG_2_PRE__//pre
#if 0
#define IOTX_PRODUCT_KEY        "yfTuLfBJTiL"
#define IOTX_DEVICE_NAME        "TestDeviceForDemo"
#define IOTX_DEVICE_SECRET      "fSCl9Ns5YPnYN8Ocg0VEel1kXFnRlV6c"
#define IOTX_DEVICE_ID          "IoTxHttpTestDev_001"
#endif
#define IOTX_PRODUCT_KEY        "a1VIroQgJgg"
#define IOTX_DEVICE_NAME        "huasan_test"
#define IOTX_DEVICE_SECRET      "PfpIy5z8pOnm6wa6YTZH3yVYiGjAgvnn"
#define IOTX_DEVICE_ID          "IoTxHttpTestDev_001"
#else//daily
#define IOTX_PRODUCT_KEY        "p1lfqbgUBmD"
#define IOTX_PRODUCT_SECRET     "5TlMNmow5NCC2gqs"
#define IOTX_DEVICE_NAME        "rFxQZUvlQQtjdfXiXVQA"
#define IOTX_DEVICE_SECRET      "M1pxjNFrCPVIA8XT34rJGsetyFGbElEE"
#define IOTX_DEVICE_ID          "IoTxHttpTestDev_001"
#endif
#endif

#define     AWSS_ACCS_REQUEST_TIMEROUT  (3*1000)

static void __dump_cmp_msg(char *desc, iotx_cmp_message_info_pt msg)
{
    log_info("%s, timestamp: %lld", desc, HAL_UptimeMs());
    log_info("type %d", msg->message_type);
    log_info("URI %s", msg->URI);
    log_info("URI_type %d", msg->URI_type);
    log_info("code %d", msg->code);
    log_info("id %d", msg->id);
    log_info("method %s", msg->method);
    log_info("parameter %s", (char*)msg->parameter);

    return;
}

static char *__get_cmp_uri(const char *method)
{
    char *uri = LITE_malloc(AWSS_URI_STR_MAX_LENGTH);
    awss_net_method_to_path_convert(method, AWSS_CLOUD_URI_PREFIX_FMT, uri, AWSS_URI_STR_MAX_LENGTH);

    log_debug("===============uri: %s, method: %s", uri, method);

    return uri;
}

static void __cmp_event_handle(void *pcontext, iotx_cmp_event_msg_pt msg, void *user_data)
{
    printf("event %d\n", msg->event_id);

    if (IOTX_CMP_EVENT_REGISTER_RESULT == msg->event_id) {
        iotx_cmp_event_result_pt result = (iotx_cmp_event_result_pt)msg->msg;

        printf("register result\n");
        printf("result %d\n", result->result);
        printf("URI %s\n", result->URI);
        printf("URI_type %d\n", result->URI_type);
    } else if  (IOTX_CMP_EVENT_UNREGISTER_RESULT == msg->event_id) {
        iotx_cmp_event_result_pt result = (iotx_cmp_event_result_pt)msg->msg;

        printf("unregister result\n");
        printf("result %d\n", result->result);
        printf("URI %s\n", result->URI);
        printf("URI_type %d\n", result->URI_type);
    }
}


static int __cmp_register_service(iotx_cmp_uri_types_t uri_type,
    const char *method, iotx_cmp_message_types_t msg_type, iotx_cmp_register_func_fpt call_back, void *user_data)
{
    int ret = AWSS_ERROR;
    char *uri = NULL;
    iotx_cmp_register_param_t register_param = {0};

    uri = __get_cmp_uri(method);
    log_debug("enrollee checkin uri: %s", uri);

    //regiser enrollee checkin service
    register_param.URI_type = uri_type;
    register_param.URI = uri;
    register_param.message_type = msg_type;
    register_param.register_func = call_back;
    register_param.user_data = NULL;
    ret = IOT_CMP_Register(&register_param, NULL);
    if (FAIL_RETURN == ret) {
        ret = AWSS_ERROR;
        log_err("register service fail, uri: %s, type: %d\n", uri, uri_type);
        goto end;
    }
    ret = AWSS_SUCCESS;

end:
    if (uri)
        LITE_free(uri);

    return ret;
}


awss_msg_t *awss_cmp_service_invoke(awss_msg_t *req_msg, iotx_cmp_send_peer_t *cloud_peer)
{
    awss_msg_t *p_rsp = NULL;
    iotx_cmp_message_info_t message_info = {0};

    if (!req_msg)
        return NULL;

#ifdef __AWSS_AP_UT__
    strcpy(cloud_peer->product_key, IOTX_PRODUCT_KEY);
    strcpy(cloud_peer->device_name, IOTX_DEVICE_NAME);
#endif

    log_debug("cmp service invoke, uri: %s, id: %d, method: %s, params: %s\n",
        req_msg->uri, req_msg->msg_id, req_msg->method, req_msg->payload);

    unsigned msg_id = req_msg->msg_id;
    message_info.id = msg_id;
    message_info.message_type = IOTX_CMP_MESSAGE_REQUEST;
    message_info.URI = req_msg->uri;

    message_info.URI_type = IOTX_CMP_URI_SYS;
    message_info.method = req_msg->method;

    message_info.parameter = req_msg->payload;
    message_info.parameter_length = req_msg->payload_length;

    awss_request_node_t *node = (awss_request_node_t *) LITE_malloc(sizeof(awss_request_node_t));
    awss_msg_session_init(&node->session);
    node->session.id = msg_id;

    if (!awss_request_queue_push(g_awss_request_queue, node)) {
        __dump_cmp_msg("send cmp request msg:", &message_info);
        int ret = IOT_CMP_Send(cloud_peer, &message_info, NULL);
        if (ret == AWSS_SUCCESS) {
            log_debug("waiting for response, id=%d, timestamp: %lld", msg_id, HAL_UptimeMs());
            if (!awss_msg_session_timewait(&node->session, AWSS_ACCS_REQUEST_TIMEROUT)) {
                log_debug("get reponse, id=%d", msg_id);
                p_rsp = node->session.response;
            } else {
                log_warning("waiting response id=%d timeout, timestamp: %lld", msg_id, HAL_UptimeMs());
            }
        } else {
            log_err("failed to send message(len=%d).", req_msg->payload_length);
        }
        awss_request_queue_pop(g_awss_request_queue, node);
    }

    awss_msg_session_destroy(&node->session);
    LITE_free(node);

    //check session id
    if (p_rsp) {
        if (p_rsp->msg_id != req_msg->msg_id) {
            log_err("The response message id matching error, req_id: %d, resp_id: %d",
                req_msg->msg_id, p_rsp->msg_id);

            LITE_free(p_rsp);
            p_rsp = NULL;
        }
    }
    else
        log_err("service invoke fail!");

    return p_rsp;
}

static void awss_cmp_send_callback(iotx_cmp_send_peer_pt source, iotx_cmp_message_info_pt msg, void *user_data)
{
    __dump_cmp_msg("receive cmp response msg:", msg);

    if (msg->message_type != IOTX_CMP_MESSAGE_RESPONSE) {
        log_err("unknown msg type: %s", msg->message_type);
        return;
    }

    int buf_sz = sizeof(awss_msg_t) + msg->parameter_length + 1;

    log_debug("receive response msg: %s", msg->parameter);
    awss_msg_t *resp_msg = LITE_malloc(buf_sz);
    if (resp_msg) {
        memset(resp_msg, 0, buf_sz);
        resp_msg->msg_id = (uint32_t)msg->id;
        resp_msg->code = msg->code;
        resp_msg->payload_length = msg->parameter_length;
        memcpy(resp_msg->payload, msg->parameter, msg->parameter_length);

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
}


static void awss_cmp_service_callback(iotx_cmp_send_peer_pt source, iotx_cmp_message_info_pt msg, void *user_data)
{
    char *uri = NULL;
    int ret = AWSS_ERROR;
    int code = 200;
    const char *resp_method = NULL;
    const char *resp_data = "{}";

    __dump_cmp_msg("receive cmp request msg:", msg);

    if (msg->message_type != IOTX_CMP_MESSAGE_REQUEST) {
            log_err("unknown msg type: %s", msg->message_type);
            return;
    }

    if (strncmp(msg->method, AWSS_RT_METHOD_ENROLLEE_CHECKIN,
        strlen(AWSS_RT_METHOD_ENROLLEE_CHECKIN)) == 0) {
        ret = awss_net_device_checkin_handle(msg->parameter, msg->parameter_length, NULL, NULL);
        if (AWSS_SUCCESS != ret) {
            log_err("handle enrollee checkin msg fail");

            code = 400;
        }
        resp_method = AWSS_RT_METHOD_ENROLLEE_CHECKIN_REPLY;
        uri = __get_cmp_uri(resp_method);
    }
    else if (strncmp(msg->method, AWSS_RT_METHOD_WHITELIST_PUSH,
        strlen(AWSS_RT_METHOD_WHITELIST_PUSH)) == 0) {
        ret = awss_net_whitelist_push_handle(msg->parameter, msg->parameter_length, NULL, NULL);
        if (ret != AWSS_SUCCESS) {
            log_err("handle whitelist push fail");
            code = 400;
        }
        resp_method = AWSS_RT_METHOD_WHITELIST_PUSH_REPLY;
        uri = __get_cmp_uri(resp_method);
    }
    else {
        log_warning("unknown method: %s", msg->method);
        goto end;
    }

    //send response msg
    iotx_cmp_message_info_t message_info = {0};

    message_info.id = msg->id;
    message_info.message_type = IOTX_CMP_MESSAGE_RESPONSE;
    message_info.URI = uri;
    message_info.code = code;
    message_info.URI_type = IOTX_CMP_URI_SYS;
    message_info.method = (char *)resp_method;
    message_info.parameter = (char *)resp_data;
    message_info.parameter_length = strlen(resp_data);

    __dump_cmp_msg("send cmp response msg:", &message_info);
    ret = IOT_CMP_Send(source, &message_info, NULL);
    if (FAIL_RETURN == ret) {
        log_err("cmp send error, uri: %s, params: %s", uri, resp_data);
    }
end:
    if (uri)
        LITE_free(uri);

    return;
}


static int awws_cmp_register_service(void)
{
    int ret = AWSS_ERROR;

    //get enrollee checkin uri;
    ret = __cmp_register_service(IOTX_CMP_URI_SYS, AWSS_RT_METHOD_ENROLLEE_CHECKIN,
        IOTX_CMP_MESSAGE_REQUEST, awss_cmp_service_callback, NULL);
    if (FAIL_RETURN == ret) {
        log_err("register service fail, method: %s\n", AWSS_RT_METHOD_ENROLLEE_CHECKIN);
        return AWSS_ERROR;
    }

    //register whitelist push service
    ret = __cmp_register_service(IOTX_CMP_URI_SYS, AWSS_RT_METHOD_WHITELIST_PUSH,
        IOTX_CMP_MESSAGE_REQUEST, awss_cmp_service_callback, NULL);
    if (FAIL_RETURN == ret) {
        log_err("register service fail, method: %s\n", AWSS_RT_METHOD_WHITELIST_PUSH);
        return AWSS_ERROR;
    }

    //register device fund reply service
    ret = __cmp_register_service(IOTX_CMP_URI_SYS, AWSS_CLOUD_METHOD_DEVICE_FUND_REPLY,
        IOTX_CMP_MESSAGE_RESPONSE, awss_cmp_send_callback, NULL);
    if (FAIL_RETURN == ret) {
        log_err("register service fail, method: %s\n", AWSS_CLOUD_METHOD_DEVICE_FUND_REPLY);
        return AWSS_ERROR;
    }

    //register cipher get reply service
    ret = __cmp_register_service(IOTX_CMP_URI_SYS, AWSS_CLOUD_METHOD_CIPHER_GET_REPLY,
        IOTX_CMP_MESSAGE_RESPONSE, awss_cmp_send_callback, NULL);
    if (FAIL_RETURN == ret) {
        log_err("register service fail, method: %s\n", AWSS_CLOUD_METHOD_CIPHER_GET_REPLY);
        return AWSS_ERROR;
    }

    return AWSS_SUCCESS;
}

#ifndef CMP_SUPPORT_MULTI_THREAD
static void *g_cmp_thread = NULL;
static uint32_t g_cmp_running = 0;

void *cmp_server_yield(void *param)
{
    log_debug("Enter to cmp yield");
    while(g_cmp_running){
        log_debug("cmp yield");
        IOT_CMP_Yield(30000, NULL);
    }

    return NULL;
}

static void awss_cmp_server_loop(void *param)
{
    int stack_used;
    HAL_ThreadCreate(&g_cmp_thread, cmp_server_yield, NULL, NULL, &stack_used);
}
#endif

int awss_cmp_init(void)
{
    int ret = AWSS_ERROR;
    iotx_cmp_init_param_t param = {0};
    int user_data = 10;

    param.product_key = LITE_malloc(CMP_PRODUCT_KEY_LEN);
    param.device_name = LITE_malloc(CMP_DEVICE_NAME_LEN);
    param.device_secret = LITE_malloc(CMP_DEVICE_SECRET_LEN);
    param.device_id = LITE_malloc(CMP_DEVICE_ID_LEN);

#ifdef __AWSS_AP_UT__
    strncpy(param.product_key, IOTX_PRODUCT_KEY, strlen(IOTX_PRODUCT_KEY));
    strncpy(param.device_name, IOTX_DEVICE_NAME, strlen(IOTX_DEVICE_NAME));
    strncpy(param.device_secret, IOTX_DEVICE_SECRET, strlen(IOTX_DEVICE_SECRET));
    strncpy(param.device_id, IOTX_DEVICE_ID, strlen(IOTX_DEVICE_ID));
#else
    HAL_GetProductKey(param.product_key);
    HAL_GetDeviceName(param.device_name);
    HAL_GetDeviceSecret(param.device_secret);
    HAL_GetDeviceID(param.device_id);
#endif
    param.domain_type = IOTX_CMP_CLOUD_DOMAIN_SH;

    param.event_func = __cmp_event_handle;
    param.user_data = &user_data;

    log_debug("awss cmp init\n");
    ret = IOT_CMP_Init(&param, NULL);
    if (FAIL_RETURN == ret) {
        log_err("init fail\n");
        return AWSS_ERROR;
    }

    log_debug("awss cmp register\n");
    ret = awws_cmp_register_service();
    RET_GOTO(ret, err, "awss cmp register fail");

    log_debug("awss cmp register success \n");

#ifndef CMP_SUPPORT_MULTI_THREAD
    g_cmp_running = 1;
    awss_cmp_server_loop(NULL);
#endif

    return SUCCESS_RETURN;

err:
    IOT_CMP_Deinit(NULL);
    return ret;
}

void awss_cmp_deinit(void)
{
    log_debug("awss cmp deinit");

#ifndef CMP_SUPPORT_MULTI_THREAD
    g_cmp_running = 0;
    HAL_ThreadDelete(g_cmp_thread);
    g_cmp_thread = NULL;
#endif
    IOT_CMP_Deinit(NULL);
    return;
}


