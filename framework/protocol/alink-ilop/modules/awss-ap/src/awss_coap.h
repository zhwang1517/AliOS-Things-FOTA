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

#ifndef __AWSS_COAP__H__
#define __AWSS_COAP__H__

#include <unistd.h>
#include "awss_network.h"

#ifdef __cplusplus
extern "C" {
#endif
#define AWSS_ALCS_PORT                  (5683)
#define AWSS_ALCS_MC_ADDR               "224.0.1.187"

int awss_coap_event_notify(const char *uri, unsigned char *payload, unsigned short length);
awss_msg_t *awss_coap_service_invoke(awss_msg_t *req, NetworkAddr *remote);
int awss_coap_init(void);
void awss_coap_deinit(void);

#ifdef __cplusplus
}
#endif
#endif

