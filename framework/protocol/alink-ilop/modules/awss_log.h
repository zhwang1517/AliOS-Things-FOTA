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

#ifndef __AWSS_LOG_H__
#define __AWSS_LOG_H__

#include <stdio.h>
#include "iot_import.h"
#include "awss_ap.h"

extern unsigned int awss_log_level;
static inline unsigned int log_get_level(void)
{
    return awss_log_level;
}

static inline void log_set_level(int level)
{
    awss_log_level = level;
}

enum LOG_LEVEL {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_FATAL,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
};

#define LOG_LEVEL  log_get_level()

/*
 * color def.
 * see http://stackoverflow.com/questions/3585846/color-text-in-terminal-applications-in-unix
 */
#define COL_DEF "\x1B[0m"   //white
#define COL_RED "\x1B[31m"  //red
#define COL_GRE "\x1B[32m"  //green
#define COL_BLU "\x1B[34m"  //blue
#define COL_YEL "\x1B[33m"  //yellow
#define COL_WHE "\x1B[37m"  //white
#define COL_CYN "\x1B[36m"


#define log_print(CON, MOD, COLOR, LVL, FMT, ...) \
do {\
    if (CON) {\
        HAL_Printf(COLOR"<%s> [%s#%d] : ",\
			LVL, __FUNCTION__, __LINE__);\
        HAL_Printf(FMT COL_DEF"\r\n", ##__VA_ARGS__);\
    }\
}while(0)

#define log_fatal(FMT, ...) \
    log_print(LOG_LEVEL >= LOG_LEVEL_FATAL, "ALINK", COL_RED, "FATAL", FMT, ##__VA_ARGS__)
#define log_error(FMT, ...) \
    log_print(LOG_LEVEL >= LOG_LEVEL_ERROR, "ALINK", COL_YEL, "ERROR", FMT, ##__VA_ARGS__)
#define log_warn(FMT, ...) \
    log_print(LOG_LEVEL >= LOG_LEVEL_WARN, "ALINK", COL_BLU, "WARN", FMT, ##__VA_ARGS__)
#define log_info(FMT, ...) \
    log_print(LOG_LEVEL >= LOG_LEVEL_INFO, "ALINK", COL_GRE, "INFO", FMT, ##__VA_ARGS__)
#define log_debug(FMT, ...) \
    log_print(LOG_LEVEL >= LOG_LEVEL_DEBUG, "ALINK", COL_WHE, "DEBUG", FMT, ##__VA_ARGS__)


/******************************************/
#define CALL_FUCTION_FAILED         "Call function \"%s\" failed\n"
#define RET_FAILED(ret)  (ret != AWSS_SUCCESS)

#define RET_GOTO(Ret,gotoTag,strError, args...)         \
      {\
        if ( RET_FAILED(Ret) )    \
        {   \
            log_error(strError, ##args); \
            goto gotoTag; \
        }\
      }

#define RET_FALSE(Ret,strError,args...)         \
    {\
        if ( RET_FAILED(Ret) )    \
        {   \
            log_error(strError, ##args); \
            return false; \
        }\
     }

#define RET_RETURN(Ret,strError,args...)         \
    {\
        if ( RET_FAILED(Ret) )    \
        {   \
            log_error(strError, ##args); \
            return Ret; \
        }\
    }
#define RET_LOG(Ret,strError,args...)         \
    {\
        if ( RET_FAILED(Ret) )    \
        {   \
            log_error(strError, ##args); \
        }\
    }

#define PTR_RETURN(Pointer,Ret,strError,args...)         \
    {\
        if ( !Pointer)    \
        {   \
            log_error(strError, ##args); \
            return Ret; \
        }\
     }

#define PTR_FALSE(Pointer,strError,args...)         \
    {\
        if ( !Pointer)    \
        {   \
            log_error(strError, ##args); \
            return FALSE; \
        }\
    }
#define PTR_LOG(Pointer,strError,args...)         \
    {\
        if ( !Pointer)    \
        {   \
            log_error(strError, ##args); \
        }\
    }


#define PTR_GOTO(Pointer, gotoTag, strError, args...)         \
    {\
        if ( !Pointer)    \
        {   \
            log_error(strError, ##args); \
            goto gotoTag; \
        }\
     }

#define POINTER_RETURN(Pointer,strError,args...)         \
    {\
        if ( !Pointer)    \
        {   \
            log_error(strError, ##args); \
            return Pointer; \
        }\
     }

#endif
