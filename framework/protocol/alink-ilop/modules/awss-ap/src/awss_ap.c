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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include "iot_import.h"
#include "iot_export.h"
#include "iot_import_awss_ap.h"
#include "awss_ap.h"
#include "awss_network.h"
#include "work_queue.h"
#include "json_parser.h"
#include "lite-log.h"
#include "lite-list.h"
#include "awss_devlist.h"
#include "aes.h"

#define __AWSS_AP_UT__  1

#define AES_KEY_STR_LEN                     32
#define AES_CIPHER_PWD_STR_LEN              128
#define AES_PLAIN_PWD_STR_LEN               64
#define AWSS_REQUEST_RETRY_CNT              (3)
#define AWSS_AP_DISCOVERY_DEVICE_INTERVAL   (60 * 1000) //ms

#define AWSS_AHA_AP_SSID                "aha"
#define AWSS_AHA_AP_PWD                 "12345678"

#define AWSS_ADHA_AP_SSID               "adha"
#define AWSS_ADHA_AP_PWD                "08d9f22c60157fd01f57645d791a0b610fe0a558c104d6a1f9d9c0a9913c"

typedef enum {
    AWSS_STATE_INITIAL         = 0,
    AWSS_STATE_DISCOVER        = 1,
    AWSS_STATE_CONFIGURE       = 2
} awss_state_t;

enum{
    AWSS_TASK_DEVICE_ATTACH,
    AWSS_TASK_DEVICE_CHECKIN,
    AWSS_TAST_DEVICE_WHILITE_PUSH
};

typedef struct {
    list_head_t list_node;
    uint8_t task_type;
    void *task_data;
}awss_task_t;

static LIST_HEAD(g_awss_tast_head);


static void *g_awss_thread = NULL;
static uint32_t g_awss_running = 0;
static void *g_awss_task_mutex = NULL;
static void *g_awss_task_psem = NULL;

static int g_awss_state = AWSS_STATE_INITIAL;
static void *switchap_mutex = NULL;
static dev_id_t g_checkin_devid = {"", ""};
static int g_duration_sec = 0;

static void awss_config_timer(struct work_struct *work);
static void awss_switchap_timer(struct work_struct *work);
static void awss_debug_timer(struct work_struct *work);
static int awss_config_timeout();
static void awss_task_schedule(awss_task_t *task);

static struct work_struct debug_timer_work = {
    .func = (work_func_t) &awss_debug_timer,
    .prio = DEFAULT_WORK_PRIO,
    .name = "awss debug timer",
};

static struct work_struct config_timer_work = {
    .func = (work_func_t) &awss_config_timer,
    .prio = DEFAULT_WORK_PRIO,
    .name = "awss checkin timer",
};

static struct work_struct switchap_timer_work = {
    .func = (work_func_t) &awss_switchap_timer,
    .prio = DEFAULT_WORK_PRIO,
    .name = "awss switchap timer",
};


static int __get_awss_state()
{
    return g_awss_state;
}

static void __set_awss_state(int state)
{
    g_awss_state = state;
}


static bool is_ascii_encoding(char *uuid_str)
{
    int len = strlen(uuid_str);
    int i = 0;
    while (i < len) {
        if ((uuid_str[i++] & 0x80) == 0x80) {
            return false;
        }
    }

    return true;
}


static void awss_checkin_device_set(const char *product_key, const char *device_name)
{
    strncpy(g_checkin_devid.product_key, product_key, sizeof(g_checkin_devid.product_key) - 1);
    strncpy(g_checkin_devid.device_name, device_name, sizeof(g_checkin_devid.device_name) - 1);

    return;
}


static bool awss_is_checkin_device(const char *product_key, const char *device_name)
{
#ifdef __AWSS_AP_UT__
//    return true;
#endif
    if (g_checkin_devid.product_key[0] != '\0' &&
        strcmp(g_checkin_devid.product_key, product_key) != 0)
        return false;

    if (g_checkin_devid.device_name[0] != '\0' &&
        strcmp(g_checkin_devid.device_name, device_name) != 0)
        return false;

    return true;
}

static void awss_debug_timer(struct work_struct *work)
{
    g_duration_sec -= 5;
    log_info("=============awss service remain %d s", g_duration_sec);

    if (g_duration_sec > 0) {
        queue_delayed_work(work, 5*1000);
    }
    else {
        g_duration_sec = 0;
    }

    return;
}

static void awss_config_timer(struct work_struct *work)
{
    log_debug("====================awss checkin timeout");
    awss_config_timeout();
    log_debug("====================awss checkin timeout return");

    return;
}


static void awss_switchap_timer(struct work_struct *work)
{
    log_debug("====================awss switchap timeout");
    awss_devlist_clean(&g_auth_devlist);
    log_debug("====================awss switchap timeout return");

    return;
}



//#define CONFIG_USE_OPENSSL  1
//aesDecryptString
static int awss_encrypt_passwd(dev_info_t *dev_info, char *aes_cipher,
                               char *passwd, char *cipher_buff, int cipher_bfsz)
{
    const uint8_t *key = NULL;
    uint8_t *iv = NULL;
    uint8_t cipher[AES_PLAIN_PWD_STR_LEN] = {0};
    uint8_t plain_text[AES_PLAIN_PWD_STR_LEN + 1] = {0};
    uint8_t iv_bytes[AES_KEY_STR_LEN + 1] = {0};
    uint8_t key_bytes[AES_KEY_STR_LEN + 1] = {0};
    mbedtls_aes_context aes_ctx;

    strncpy((char *)plain_text, passwd, AES_PLAIN_PWD_STR_LEN);

    uint8_t key256[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    /* decrypt using the key/iv */
    uint8_t iv256[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    switch (dev_info->security) {
        case 0:
            strncpy(cipher_buff, passwd, cipher_bfsz - 1);
            break;
        case 1://默认256bit秘钥
            iv = iv256;
            key = key256;

            mbedtls_aes_init(&aes_ctx);
            mbedtls_aes_setkey_enc(&aes_ctx, key, 256);
            mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, AES_PLAIN_PWD_STR_LEN, iv, plain_text, cipher);
            LITE_hexbuf_convert(cipher, cipher_buff, sizeof(cipher), 0);
            //utils_hex_to_str((uint8_t *)cipher, sizeof(cipher), cipher_buff, cipher_bfsz);
            mbedtls_aes_free(&aes_ctx);
            break;
        case 2://使用AES256默认key和iv的前128bit
            iv = iv256;
            key = key256;

            //加密
            mbedtls_aes_init(&aes_ctx);
            mbedtls_aes_setkey_enc(&aes_ctx, key, 128);
            mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, AES_PLAIN_PWD_STR_LEN, iv, plain_text, cipher);

            //utils_hex_to_str((uint8_t *)cipher, sizeof(cipher), cipher_buff, cipher_bfsz);
            LITE_hexbuf_convert(cipher, cipher_buff, sizeof(cipher), 0);
            mbedtls_aes_free(&aes_ctx);

#if 1
            log_debug("aes encrypt: plain_text: %s, cipher_pwd: %s", plain_text, cipher_buff);
            //解密
            memset(plain_text, 0, sizeof(plain_text));
            mbedtls_aes_init(&aes_ctx);
            mbedtls_aes_setkey_dec(&aes_ctx, key, 128);
            mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, AES_PLAIN_PWD_STR_LEN, iv, cipher, plain_text);
            log_debug("aes decrypt: plain_text: %s", plain_text);
            mbedtls_aes_free(&aes_ctx);
#endif

            break;
        default :
            LITE_hexstr_convert(dev_info->random, iv_bytes, strlen(dev_info->random));

            LITE_hexstr_convert(aes_cipher, key_bytes, strlen(aes_cipher));
            //utils_str_to_hex(dev_info->random, strlen(dev_info->random), iv_bytes, sizeof(iv_bytes));
            //utils_str_to_hex(aes_cipher, strlen(aes_cipher), key_bytes, sizeof(key_bytes));

            #define AES_BLOCK_SIZE  16
            mbedtls_aes_init(&aes_ctx);
            mbedtls_aes_setkey_enc(&aes_ctx, key_bytes, 128);
            mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, AES_PLAIN_PWD_STR_LEN, iv_bytes, plain_text, cipher);
            //utils_hex_to_str((uint8_t *)cipher, sizeof(cipher), cipher_buff, cipher_bfsz);
            LITE_hexbuf_convert(cipher, cipher_buff, sizeof(cipher), 0);
            mbedtls_aes_free(&aes_ctx);

#if 1
            log_debug("random_hex: %s, key_hex: %s", dev_info->random, aes_cipher);
            log_debug("aes encrypt: plain_text: %s, cipher_pwd: %s", plain_text, cipher_buff);

            //解密
            memset(plain_text, 0, sizeof(plain_text));
            LITE_hexstr_convert(dev_info->random, iv_bytes, strlen(dev_info->random));
            LITE_hexstr_convert(aes_cipher, key_bytes, strlen(aes_cipher));
            //utils_str_to_hex(dev_info->random, strlen(dev_info->random), iv_bytes, sizeof(iv_bytes));
            //utils_str_to_hex(aes_cipher, strlen(aes_cipher), key_bytes, sizeof(key_bytes));

            mbedtls_aes_init(&aes_ctx);
            mbedtls_aes_setkey_dec(&aes_ctx, key_bytes, 128);
            mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, AES_PLAIN_PWD_STR_LEN, iv_bytes, cipher, plain_text);
            log_debug("aes decrypt: plain_text: %s", plain_text);
            mbedtls_aes_free(&aes_ctx);
#endif
            break;
    }

    log_debug("security: %d, cipher pwd: %s", dev_info->security, cipher_buff);

    return AWSS_SUCCESS;
}


static int awss_switch_device_ap(dev_info_t *dev_info, char *aes_cipher, char *ssid, char *passwd)
{
    int ret = AWSS_ERROR;
    char chipher_pwd[AES_CIPHER_PWD_STR_LEN + 1] = {0};
    char xssid[PRODUCT_SSID_LEN] = {0};

    log_debug("ap info: ssid: %s, pwd: %s", ssid, passwd);
    ret = awss_encrypt_passwd(dev_info, aes_cipher, passwd, chipher_pwd, sizeof(chipher_pwd));
    RET_RETURN(ret, "encrypt wifi passwd fail");

    log_debug("encrypt ap info: ssid: %s, passwd chipher: %s", ssid, chipher_pwd);
    if (!is_ascii_encoding(ssid)) {
        //utils_hex_to_str((uint8_t *)ssid, strlen(ssid), xssid, sizeof(xssid));
        LITE_hexbuf_convert(ssid, xssid, strlen(ssid), 0);
        log_debug("xssid: %s", xssid);

        ssid = xssid;
    }

    //增加SwitchAP重试
    int try_cnt = 0;
    while (try_cnt++ < AWSS_REQUEST_RETRY_CNT) {
        ret = awss_net_device_switchap(dev_info, ssid, chipher_pwd);
        if (ret == AWSS_SUCCESS) {
            break;
        }

        log_warning("send switchap msg fail, ssid: %s, passwd: %d, addr: %s, try count: %d",
                 ssid, chipher_pwd, dev_info->ip, try_cnt);
    }

    if (ret == AWSS_SUCCESS) {
        //解析resp_buff,判断是否切换成功
        log_debug("switch ap success, ssid: %s, passwd: %s, addr: %s, try count: %d",
                 ssid, chipher_pwd, dev_info->ip, try_cnt);
    }

    return ret;
}



static awss_dev_t *awss_request_devinfo_by_network(const char *ip_addr)
{
    int ret = AWSS_ERROR;
    awss_dev_t *dev = NULL;
    int try_cnt = 0;
    dev_info_t *dev_info = NULL;

    while (try_cnt++ < AWSS_REQUEST_RETRY_CNT) {
        dev_info = awss_net_device_info_get(ip_addr);
        if (dev_info) {
            break;
        }

        log_warning("get device info fail, ip address: %s, try count: %d",
                 ip_addr, try_cnt);
        continue;
    }
    if (NULL == dev_info) {
        log_warning("get device info fail, ip address: %s", ip_addr);
        goto end;
    }

    dev = awss_devlist_new_device();
    memcpy(&dev->dev_info, dev_info, sizeof(dev->dev_info));

end:
    if (dev_info) {
        LITE_free(dev_info);
    }

    return dev;
}


static int awss_switch_state(int state)
{
    int ret = AWSS_SUCCESS;

    log_debug("switch awss service mode: %d", state);

    __set_awss_state(state);
    if (AWSS_STATE_DISCOVER == state) {
        product_set_aha_ap_info(AWSS_AHA_AP_SSID, AWSS_AHA_AP_PWD, 0, 1);
        ret = product_set_aha_ap_info(AWSS_ADHA_AP_SSID, AWSS_ADHA_AP_PWD, 1, 0);
        if (ret != 0) {
            log_err("switch ap ssid to %s fail", AWSS_ADHA_AP_SSID);
        }
        log_debug("switch ap, ssid: %s, pwd: %s", AWSS_ADHA_AP_SSID, AWSS_ADHA_AP_PWD);
    } else if (AWSS_STATE_CONFIGURE == state) {
        //切换为配网ssid
        product_set_aha_ap_info(AWSS_ADHA_AP_SSID, AWSS_ADHA_AP_PWD, 0, 0);
        ret = product_set_aha_ap_info(AWSS_AHA_AP_SSID, AWSS_AHA_AP_PWD, 1, 1);
        if (ret != 0) {
            log_err("switch ap ssid to %s fail", AWSS_AHA_AP_SSID);
        }
        log_debug("switch ap, ssid: %s, pwd: %s", AWSS_AHA_AP_SSID, AWSS_AHA_AP_PWD);
    } else {
        log_info("awss state: %d, nothing todo!", state);
    }

    return ret;
}




int __checkin_device(dev_id_t *dev_id)
{
    int ret = AWSS_SUCCESS;

    //log_debug("awss checkin device, productKey: %s, deviceName: %s, period: %d",
    //    dev_id->product_key, dev_id->device_name, dev_id->period);

    if (__get_awss_state() == AWSS_STATE_INITIAL)
        return ret;

    if (dev_id->period == 0) {
        awss_switch_state(AWSS_STATE_DISCOVER);

        cancel_work(&debug_timer_work);
        g_duration_sec = 0;

        cancel_work(&config_timer_work);
        awss_devlist_clean(&g_auth_devlist);

        awss_checkin_device_set("", "");
    }
    else {
        //启动timer
        queue_delayed_work(&config_timer_work, dev_id->period * 1000);

        //debug timer
        g_duration_sec = dev_id->period;
        queue_delayed_work(&debug_timer_work, 5*1000);

        awss_checkin_device_set(dev_id->product_key, dev_id->device_name);

        //切换为配网ssid
        ret = awss_switch_state(AWSS_STATE_CONFIGURE);
    }

    return ret;
}


int awss_checkin_device(const char *product_key, const char *device_name, uint32_t period)
{
    int ret = AWSS_SUCCESS;
    log_debug("awss checkin device, period: %d, productkey: %s, devicename: %s", period, product_key, device_name);
    if (__get_awss_state() == AWSS_STATE_INITIAL)
        return ret;

    dev_id_t *dev_id = LITE_malloc(sizeof(dev_id_t));;
    strncpy(dev_id->product_key, product_key, sizeof(dev_id->product_key));
    strncpy(dev_id->device_name, device_name, sizeof(dev_id->device_name));
    dev_id->period= period;

    awss_task_t *checkin_task = LITE_malloc(sizeof(awss_task_t));
    checkin_task->task_data = dev_id;
    checkin_task->task_type = AWSS_TASK_DEVICE_CHECKIN;

    awss_task_schedule(checkin_task);

    return ret;
}


static int awss_config_timeout()
{
    log_debug("awss checkint timeout");

    int ret = awss_switch_state(AWSS_STATE_DISCOVER);

    //cancel debug worker
    cancel_work(&debug_timer_work);
    g_duration_sec = 0;

    awss_checkin_device_set("", "");
    awss_devlist_clean(&g_auth_devlist);

    return ret;
}


void awss_auth_device(dev_info_t *dev_info)
{
    if (AWSS_STATE_CONFIGURE != __get_awss_state()) {
        return;
    }

    log_debug("auth device, mac: %s", dev_info->mac);
    awss_dev_t *dev = awss_devlist_get(dev_info->mac, &g_auth_devlist);
    if (NULL == dev)
        return;

    if(dev->state_flag != DEV_STATE_CHECKIN &&
        awss_net_device_established(dev->dev_info.mac, dev->dev_info.ip)) {
        log_debug("auth device, mac: %s, productkey: %s", dev->dev_info.mac, dev->dev_info.product_key);

        awss_net_authed_device_notify(&dev->dev_info);

        //设备配网成功通知钉钉C1
#ifdef AWSS_DINGDING_CUSTOM
        awss_dding_notify_authed_device(dev);
#endif
        dev->state_flag = DEV_STATE_CHECKIN;
    }

    awss_device_put(dev);

    return;
}


static bool awss_verify_device_sign(dev_info_t *dev_info, int *period)
{
    dev_id_t devid[1];
    uint8_t devid_cnt = 1;

    devid[0].device_name[0] = '\0';
    devid[0].product_key[0] = '\0';
    int ret = awss_net_device_sign_verify(dev_info, 1, devid, &devid_cnt);
    if (ret == AWSS_SUCCESS && devid_cnt == 1){
        *period = devid[0].period;
        return true;
    }

    log_debug("");
    return false;
}


static void awss_discover_device(dev_info_t *dev_info)
{
    awss_dev_t *dev = NULL;

    if (AWSS_STATE_DISCOVER != __get_awss_state()) {
        return;
    }

    if (awss_net_device_established(dev_info->mac, dev_info->ip)) {
        log_debug("attach device, mac: %s, ip: %s, device connection established!", dev_info->mac, dev_info->ip);
        awss_devlist_delete(dev_info->mac, &g_dscv_devlist);
        return;
    }

    /*检查是否已经存在设备列表中*/
    dev = awss_devlist_get(dev_info->mac, &g_dscv_devlist);
    if ((NULL != dev) && (dev->time_stamp + dev->period * 1000 > HAL_UptimeMs())
        && strcmp(dev->dev_info.product_key, dev_info->product_key) == 0
        && strcmp(dev->dev_info.device_name, dev_info->device_name) == 0) {
        log_debug("existing device, mac: %s, productkey: %s, devicename: %s",
            dev_info->mac, dev_info->product_key, dev_info->device_name);

        goto end;
    }

    int period = 0;
    if(!awss_verify_device_sign(dev_info, &period)){
        log_err("verify device sign fail, mac: %s, productkey: %s, devicename: %s", dev_info->mac, dev_info->product_key, dev_info->device_name);

        if (dev)
            awss_devlist_delete(dev_info->mac, &g_dscv_devlist);
        goto end;
    }
    else if(dev) {//update device info
        memcpy(&dev->dev_info, dev_info, sizeof(dev->dev_info));
        dev->time_stamp = HAL_UptimeMs();
        dev->period = period;

        //move to list head
        awss_devlist_move_to_head(dev, &g_dscv_devlist);
    }
    else {
        awss_devlist_flush(&g_dscv_devlist);

        awss_dev_t *new_dev = awss_devlist_new_device();
        memcpy(&new_dev->dev_info, dev_info, sizeof(new_dev->dev_info));
        new_dev->state_flag = DEV_STATE_DISC;
        new_dev->period = period;
        new_dev->time_stamp = HAL_UptimeMs();
        awss_devlist_add(new_dev, &g_dscv_devlist);
    }

    __dump_dev_list(&g_dscv_devlist, "discovery");

end:
    if (dev)
        awss_device_put(dev);

    return;
}


static int awss_join_device(dev_info_t *dev_info)
{
    int ret = AWSS_ERROR;
    awss_dev_t *dev = NULL;

    if (AWSS_STATE_CONFIGURE != __get_awss_state()) {
        return ret;
    }

    dev = awss_devlist_get(dev_info->mac, &g_auth_devlist);
    if (NULL != dev) {
        ret = AWSS_SUCCESS;
        goto end;
    }
    __dump_dev_list(&g_auth_devlist, "authorize");

    dev = awss_devlist_get(dev_info->mac, &g_dscv_devlist);
    if (NULL != dev) {
        memcpy(&dev->dev_info, dev_info, sizeof(dev->dev_info));
    }
    else {
        int period = 0;
        if(!awss_verify_device_sign(dev_info, &period)){
            log_err("verify device sign fail, mac: %s, productkey: %s, devicename: %s", dev_info->mac, dev_info->product_key, dev_info->device_name);
            goto end;
        }

        dev = awss_devlist_new_device();
        memcpy(&dev->dev_info, dev_info, sizeof(dev->dev_info));
        dev->period = period;
        awss_device_hold(dev);
        awss_devlist_add(dev, &g_dscv_devlist);
    }

    dev->state_flag = DEV_STATE_JOIN;
    awss_net_joined_device_notify(&dev->dev_info);
    //check productkey & devicename
    if (!awss_is_checkin_device(dev_info->product_key, dev_info->device_name)) {
        log_info("unknown device productkey: %s, devicename: %s", dev_info->product_key, dev_info->device_name);
        goto end;
    }

    //get ace secrity
    char aes_cipher[AES_KEY_STR_LEN + 1] = {0};
    if (dev->dev_info.security >= 3 &&
        AWSS_SUCCESS != awss_net_encrypt_cipher_get(&dev->dev_info, aes_cipher, sizeof(aes_cipher))) {
        log_err("get aes password fail, productkey: %s, devicename: %s",
            dev->dev_info.product_key, dev->dev_info.device_name);

        awss_net_getting_cipher_notify(&dev->dev_info, -1, "get cipher failure");
        goto end;
    }
    else
        awss_net_getting_cipher_notify(&dev->dev_info, 0, "get cipher success");

    //get ap info
    char ssid[PRODUCT_SSID_LEN + 1] = {0};
    char passwd[PRODUCT_PWD_LEN + 1] = {0};
    char ifname[PRODUCT_IFNAME_LEN + 1] = {0};
    ret = product_get_extranet_ap_info(ssid, passwd, ifname);
    RET_GOTO(ret, end, "get ap info fail");

    //switchap
    ret = awss_switch_device_ap(&dev->dev_info, aes_cipher, ssid, passwd);
    //创建统计数据节点
    if (AWSS_SUCCESS == ret) {
        awss_net_device_switchap_result_notify(&dev->dev_info, 0, "success");
        awss_devlist_move_to_head(dev, &g_auth_devlist);
        queue_delayed_work(&switchap_timer_work, 60 * 1000);
    } else {
        awss_net_device_switchap_result_notify(&dev->dev_info, -1, "failure");
    }

end:

    if (dev)
        awss_device_put(dev);

    return ret;
}


static void __attach_device(dev_info_t *dev_info)
{
    int state = __get_awss_state();

    log_debug("attach device, mac: %s, ip: %s", dev_info->mac, dev_info->ip);

    if (AWSS_STATE_DISCOVER == state ) {
        awss_discover_device(dev_info);
    }
    else if (AWSS_STATE_CONFIGURE == state ) {
        HAL_MutexLock(switchap_mutex);
        awss_join_device(dev_info);
        HAL_MutexUnlock(switchap_mutex);

        awss_auth_device(dev_info);
    }

    return;
}


static awss_task_t *awss_task_get(void)
{
    awss_task_t *pos, *next, *tast_node = NULL;
    HAL_MutexLock(g_awss_task_mutex);
    list_for_each_entry_safe(pos, next, &g_awss_tast_head, list_node, awss_task_t) {
        tast_node = pos;
        list_del(&pos->list_node);
        break;
    }
    HAL_MutexUnlock(g_awss_task_mutex);

    return tast_node;
}

static void awss_task_free(awss_task_t *task)
{
    if (NULL == task)
        return;

    if (task->task_data)
        LITE_free(task->task_data);

    LITE_free(task);

    return;
}


static void awss_task_destroy()
{
    awss_task_t *pos, *next;

    HAL_MutexLock(g_awss_task_mutex);
    list_for_each_entry_safe(pos, next, &g_awss_tast_head, list_node, awss_task_t) {
        list_del(&pos->list_node);
        if (pos->task_data)
            LITE_free(pos->task_data);
        LITE_free(pos);
    }
    HAL_MutexUnlock(g_awss_task_mutex);

    return;
}


static void awss_task_schedule(awss_task_t *task)
{
    HAL_MutexLock(g_awss_task_mutex);
    list_add(&task->list_node, &g_awss_tast_head);
    HAL_MutexUnlock(g_awss_task_mutex);

    HAL_SemaphorePost(g_awss_task_psem);
}


void awss_attach_device(dev_info_t *dev_info)
{
    awss_task_t *task_node = LITE_malloc(sizeof(awss_task_t));
    task_node->task_data = (void *)LITE_malloc(sizeof(dev_info_t));
    memcpy(task_node->task_data, dev_info, sizeof(dev_info_t));

    task_node->task_type = AWSS_TASK_DEVICE_ATTACH;

    awss_task_schedule(task_node);

    return;
}


void *awss_ap_main_loop(void *param)
{
    awss_task_t *tast_node = NULL;
    uint64_t last_discovery = 0;
    int ret = AWSS_ERROR;

    while(g_awss_running){
        while(tast_node = awss_task_get()){
            log_debug("----------------------task type: %d, timestamp: %lld", tast_node->task_type, HAL_UptimeMs());

            if (AWSS_TASK_DEVICE_ATTACH == tast_node->task_type){
                __attach_device((dev_info_t *)tast_node->task_data);
            }
            else if(AWSS_TASK_DEVICE_CHECKIN == tast_node->task_type){
                __checkin_device((dev_id_t*)tast_node->task_data);
                dev_info_t *dev_info = awss_net_search_device();
                if (dev_info){
                    __attach_device(dev_info);
                    LITE_free(dev_info);
                }
            }
            else
                log_warning("unknown task type: %s", tast_node->task_type);

            awss_task_free(tast_node);
        }

        HAL_SemaphoreWait(g_awss_task_psem, 30000);
        if (last_discovery + AWSS_AP_DISCOVERY_DEVICE_INTERVAL < HAL_UptimeMs()) {
#if 1
            //discovery new devices
            log_debug("discovery new device");
            dev_info_t *dev_info = awss_net_search_device();
            if (dev_info){
                awss_attach_device(dev_info);
                LITE_free(dev_info);
            }
#endif
            last_discovery = HAL_UptimeMs();
        }

        __dump_dev_list(&g_dscv_devlist, "discovery");
        __dump_dev_list(&g_deleted_devlist, "deleted");
    }

    return NULL;
}


int awss_ap_init()
{
    int ret = AWSS_ERROR;
    int stack_used = 0;

    log_debug("awss ap init");

    switchap_mutex = HAL_MutexCreate();
    g_awss_task_mutex = HAL_MutexCreate();
    g_awss_task_psem = HAL_SemaphoreCreate();

    awss_devlist_init();

    ret = work_queue_init();
    if (ret != AWSS_SUCCESS){
        log_err("work queue fail");
        goto err;
    }

    ret = awss_net_init();
    if (ret != AWSS_SUCCESS){
        log_err("awss network fail");
        goto err;
    }

    awss_switch_state(AWSS_STATE_DISCOVER);

    g_awss_running = 1;
    //IOT_DumpMemoryStats(IOT_LOG_DEBUG);
    HAL_ThreadCreate(&g_awss_thread, awss_ap_main_loop, NULL, NULL, &stack_used);

    return ret;

err:
    return ret;
}


void awss_ap_exit()
{
    __set_awss_state(AWSS_STATE_INITIAL);

    g_awss_running = 0;

    cancel_work(&config_timer_work);
    cancel_work(&switchap_timer_work);

    awss_net_deinit();

    work_queue_stop();

    awss_task_destroy();

    if (switchap_mutex)
        HAL_MutexDestroy(switchap_mutex);
    switchap_mutex = NULL;

    if (g_awss_task_mutex)
        HAL_MutexDestroy(g_awss_task_mutex);
    g_awss_task_mutex = NULL;

    if (g_awss_task_psem)
        HAL_SemaphoreDestroy(g_awss_task_psem);
    g_awss_task_psem = NULL;

    awss_devlist_deinit();

    return;
}

