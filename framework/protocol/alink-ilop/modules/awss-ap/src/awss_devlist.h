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

#ifndef __AWSS_DEVLIST__H__
#define __AWSS_DEVLIST__H__

#include <unistd.h>
#include <stdint.h>
#include "lite-list.h"
#include "iot_import_product.h"

#ifdef __cplusplus
extern "C" {
#endif


#define AWSS_SIGN_RANDOM_LEN         4
#define AWSS_VRSION_LEN              64
#define AWSS_DEVICE_SIGN_LEN         32
#define AWSS_DEVICE_MAC_LEN          17
#define AWSS_DEVICE_IP_LEN           15
#define AWSS_DEVICE_RAND_LEN         32

typedef struct {
    uint8_t security;       //设备支持的加密类型
    char version[AWSS_VRSION_LEN];
    char sign[AWSS_DEVICE_SIGN_LEN + 1];
    char ip[AWSS_DEVICE_IP_LEN + 1];
    char mac[AWSS_DEVICE_MAC_LEN + 1];
    char device_name[DEVICE_NAME_MAXLEN + 1];
    char product_key[PRODUCT_KEY_MAXLEN + 1];
    char random[AWSS_DEVICE_RAND_LEN + 1];    //秘钥生成随机数
}dev_info_t;


typedef struct {
    list_head_t list_node;
    uint64_t time_stamp;
    uint8_t state_flag;
    uint8_t ref_cnt;
    uint32_t period;
    dev_info_t dev_info;
} awss_dev_t;


typedef enum {
    DEV_STATE_DISC     = 0,     //发现设备信息
    DEV_STATE_JOIN     = 1,     //连接到aha热点
    DEV_STATE_CHECKIN  = 2      //入网成功
} dev_state_t;

typedef enum {
    DEV_TYPE_WIFI = 0,
    DEV_TYPE_ETHERNET = 1,
    DEV_TYPE_AWSS_AP = 2
} dev_type_t;

extern list_head_t g_dscv_devlist;
extern list_head_t g_auth_devlist;
extern list_head_t g_deleted_devlist;

void __dump_devinfo(dev_info_t *dev_info);

void __dump_device(awss_dev_t *dev);

void __dump_dev_list(list_head_t *head, const char *desc);

awss_dev_t *awss_devlist_new_device();

void awss_device_hold(awss_dev_t *dev);

void awss_device_put(awss_dev_t *dev);

void awss_devlist_flush(list_head_t *head);

void awss_devlist_clean(list_head_t *head);

void awss_devlist_add(awss_dev_t *dev, list_head_t *head);

void awss_devlist_move_to_head(awss_dev_t *dev, list_head_t *head);

awss_dev_t *awss_devlist_get(char *mac, list_head_t *head);

void awss_devlist_delete(char *mac, list_head_t *head);

int awss_devlist_init();

void awss_devlist_deinit();

#ifdef __cplusplus
}
#endif
#endif

