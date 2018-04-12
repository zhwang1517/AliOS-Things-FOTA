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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include "lite-utils.h"
#include "lite-log.h"
#include "awss_devlist.h"
#include "awss_ap.h"
#include "iot_import_awss_ap.h"

#define AWSS_DSCV_DEVICE_TTL            (3600*24*1000)
#define AWSS_DEVICE_LIST_SIZE           20

#define os_printf(args...)          printf(args)


//发现设备列表
LIST_HEAD(g_dscv_devlist);
//授权接入设备列表
LIST_HEAD(g_auth_devlist);
LIST_HEAD(g_deleted_devlist);

static void *awss_devlist_mutex = NULL;
static void *switchap_mutex = NULL;

static void __free_device(awss_dev_t *dev)
{
    if (!list_empty(&dev->list_node))
        list_del(&dev->list_node);

    LITE_free(dev);
    return;
}



static void __remove_device(awss_dev_t *dev)
{
    dev->ref_cnt--;

    list_move(&dev->list_node, &g_deleted_devlist);

    if (dev->ref_cnt == 0)
        __free_device(dev);
    else
        log_warning("dev_info->ref_cnt: %d", dev->ref_cnt);

    return;
}


void __dump_devinfo(dev_info_t *dev_info)
{
    os_printf("dev_info:\n");
    os_printf("\tmac: %s, ip: %s, version: %s, \n"
              "\tproductkey: %s, devname: %s, \n"
              "\trandom: %s, security:%d, sign: %s\n",
              dev_info->mac, dev_info->ip, dev_info->version,
              dev_info->product_key, dev_info->device_name,
              dev_info->random, dev_info->security, dev_info->sign);

    return;
}


void __dump_device(awss_dev_t *dev)
{
    __dump_devinfo(&dev->dev_info);
    os_printf("dev_state:\n");
    os_printf("\tstate_flag: 0x%02x, ref_cnt: %d, period: %d, time_stamp: %llu\n\n",
              dev->state_flag, dev->ref_cnt, dev->period, dev->time_stamp);

    return;
}


void __dump_dev_list(list_head_t *head, const char *desc)
{
    awss_dev_t *pos;

    HAL_MutexLock(awss_devlist_mutex);
    os_printf("%s device list:\n", desc);
    list_for_each_entry(pos, head, list_node, awss_dev_t) {
        __dump_device(pos);
    }
    HAL_MutexUnlock(awss_devlist_mutex);

    return;
}



static void convert_to_lower_string(const char *src_str, char *dst_buff, int buff_size)
{
    int len, i = 0;
    len = strlen(src_str);

    if (buff_size <= len) {
        return;
    }

    while (i < len) {
        dst_buff[i] = tolower(src_str[i]);
        i++;
    }
    dst_buff[i] = '\0';

    return;
}

static int compare_mac_addr(const char *src_mac, const char *dst_mac)
{
    char src_new[AWSS_DEVICE_MAC_LEN + 1] = {0};
    char dst_new[AWSS_DEVICE_MAC_LEN + 1] = {0};

    convert_to_lower_string(src_mac, src_new, sizeof(src_new));
    convert_to_lower_string(dst_mac, dst_new, sizeof(dst_new));

    return strcmp(src_new, dst_new);
}


static int get_ip_by_mac(const char *mac, char ip[AWSS_DEVICE_IP_LEN + 1])
{
    int ret = AWSS_ERROR;
    FILE *fp = NULL;
    const char *arp_file = "/proc/net/arp";
    char line[256] = {0};

    if((fp = fopen(arp_file, "r")) == NULL) {
        log_err("fopen(%s) error", arp_file);
        return ret;
    }

    char ip_addr[AWSS_DEVICE_IP_LEN + 1] = {0};//br_name or if_name
    uint32_t hw_type = 0;
    uint32_t flags = 0;
    char mac_addr[AWSS_DEVICE_MAC_LEN + 1] = {0};
    char mask[AWSS_DEVICE_IP_LEN + 1] = {0};
    char ifname[PRODUCT_IFNAME_LEN + 1] = {0};

    //skip first line
    if (fgets(line, sizeof(line), fp) == NULL)
        goto end;

    while ( (fgets(line, sizeof(line), fp)) != NULL) {
        log_debug("gets: %s", line);
        int arg_cnt = sscanf(line, "%s  %x   %x    %s %s  %s",
            ip_addr, &hw_type, &flags, mac_addr, mask, ifname);
        if (arg_cnt != 6)
            continue;

        //log_debug("ip_addr: %s, mac_addr: %s, ifname: %s",
        //    mac_addr, mac_addr, ifname);
        if (compare_mac_addr(mac_addr, mac) == 0) {
            strncpy(ip, ip_addr, AWSS_DEVICE_IP_LEN);
            ret = AWSS_SUCCESS;
            break;
        }
    }

end:
    if (fp)
        fclose(fp);

    return ret;
}

awss_dev_t *awss_devlist_new_device()
{
    awss_dev_t *dev = LITE_malloc(sizeof(awss_dev_t));
    if (dev) {
        memset(dev, 0, sizeof(awss_dev_t));
        dev->state_flag = DEV_STATE_DISC;
        dev->ref_cnt = 1;
        dev->time_stamp = HAL_UptimeMs();
        INIT_LIST_HEAD(&dev->list_node);
    }

    return dev;
}


void awss_device_hold(awss_dev_t *dev)
{
    dev->ref_cnt++;
    return;
}


void awss_device_put(awss_dev_t *dev)
{
    HAL_MutexLock(awss_devlist_mutex);
    dev->ref_cnt--;

    /*引用计数为0，释放节点*/
    if (dev->ref_cnt == 0) {
        __free_device(dev);
    }
    HAL_MutexUnlock(awss_devlist_mutex);

    return;
}


void awss_devlist_flush(list_head_t *head)
{
    awss_dev_t *pos, *next;
    int count = 0;

    HAL_MutexLock(awss_devlist_mutex);
    list_for_each_entry_safe(pos, next, head, list_node, awss_dev_t) {
        if (awss_net_device_established(pos->dev_info.mac, pos->dev_info.ip) ||
            pos->time_stamp + AWSS_DSCV_DEVICE_TTL <= HAL_UptimeMs()) {
            log_warning("remove older device", count);
            __remove_device(pos);
            continue;
        }
        count++;
    }

    //remove last device
    if (count > AWSS_DEVICE_LIST_SIZE) {
        log_warning("devlist count: %d, remove last device", count);
        awss_dev_t *last_dev = list_entry(head->prev, awss_dev_t, list_node);
        __remove_device(last_dev);
    }
    HAL_MutexUnlock(awss_devlist_mutex);

    return;
}


void awss_devlist_clean(list_head_t *head)
{
    awss_dev_t *pos, *next;

    HAL_MutexLock(awss_devlist_mutex);
    list_for_each_entry_safe(pos, next, head, list_node, awss_dev_t) {
        __remove_device(pos);
    }

    HAL_MutexUnlock(awss_devlist_mutex);

    return;
}


void awss_devlist_add(awss_dev_t *dev, list_head_t *head)
{
    awss_dev_t *pos, *next = NULL;

    HAL_MutexLock(awss_devlist_mutex);

    list_for_each_entry_safe(pos, next, head, list_node, awss_dev_t) {
        if (compare_mac_addr(dev->dev_info.mac, pos->dev_info.mac) == 0) {
            __remove_device(pos);
        }
    }

    list_add(&dev->list_node, head);

    HAL_MutexUnlock(awss_devlist_mutex);

    return;
}

void awss_devlist_move_to_head(awss_dev_t *dev, list_head_t *head)
{
    //move to list head
    HAL_MutexLock(awss_devlist_mutex);
    list_move(&dev->list_node, head);
    HAL_MutexUnlock(awss_devlist_mutex);
}

awss_dev_t *awss_devlist_get(char *mac, list_head_t *head)
{
    awss_dev_t *pos;
    awss_dev_t *dev = NULL;

    HAL_MutexLock(awss_devlist_mutex);
    list_for_each_entry(pos, head, list_node, awss_dev_t) {
        if (compare_mac_addr(mac, pos->dev_info.mac) == 0) {
            dev = pos;
            dev->ref_cnt++;
            break;
        }
    }
    HAL_MutexUnlock(awss_devlist_mutex);

    return dev;
}


void awss_devlist_delete(char *mac, list_head_t *head)
{
    awss_dev_t *pos, *next;

    HAL_MutexLock(awss_devlist_mutex);
    list_for_each_entry_safe(pos, next, head, list_node, awss_dev_t) {
        if (compare_mac_addr(mac, pos->dev_info.mac) == 0) {
            __remove_device(pos);
        }
    }
    HAL_MutexUnlock(awss_devlist_mutex);
}


int awss_devlist_init()
{
    log_debug("awss init");
    awss_devlist_mutex = HAL_MutexCreate();
    if (NULL == awss_devlist_mutex)
        return AWSS_ERROR;

    INIT_LIST_HEAD(&g_dscv_devlist);
    INIT_LIST_HEAD(&g_auth_devlist);
    INIT_LIST_HEAD(&g_deleted_devlist);

    return AWSS_SUCCESS;
}


void awss_devlist_deinit()
{
    awss_devlist_clean(&g_dscv_devlist);
    awss_devlist_clean(&g_auth_devlist);
    awss_devlist_clean(&g_deleted_devlist);

    if (awss_devlist_mutex) {
        HAL_MutexDestroy(awss_devlist_mutex);
        awss_devlist_mutex = NULL;
    }
    awss_devlist_mutex  = NULL;

    return;
}

