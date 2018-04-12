#include <stdio.h>
#include <stdlib.h>
#include "awss_ap.h"
#include "lite-log.h"
#include "awss_network.h"
#include "iot_export.h"

#define AWSS_TEST_PRODUCT_KEY        "yfTuLfBJTiL"
#define AWSS_TEST_DEVICE_NAME        "TestDeviceForDemo"

dev_info_t dev_info;

static void __init_devinfo(void)
{
    memset(&dev_info, 0, sizeof(dev_info));
    strcpy(dev_info.random, "test_random_str");
    strcpy(dev_info.device_name, AWSS_TEST_DEVICE_NAME);
    strcpy(dev_info.ip, "192.168.10.100");
    strcpy(dev_info.mac, "01:01:01:01:01:01");
    strcpy(dev_info.product_key, AWSS_TEST_PRODUCT_KEY);
    strcpy(dev_info.sign, "test_sign_str");
    dev_info.security = 5;
    strcpy(dev_info.version, "1.8");
    return;
}

static int __awss_notification_ut(void)
{
    awss_net_service_enable_notify(AWSS_TEST_PRODUCT_KEY, AWSS_TEST_DEVICE_NAME, 0, "success");
    awss_net_joined_device_notify(&dev_info);
    awss_net_getting_cipher_notify(&dev_info, 0, "success");
    awss_net_device_switchap_result_notify(&dev_info, 0, "success");

    return 0;
}

const char *env_str[] = {"none", "crit", "error", "warn", "info", "debug"};

static void usage(void)
{
    printf("\nawss-example -m mode -l log_level\n");
    printf("\t -m awss ap mode, 'discover', 'config', default mode: 'discover'\n");
    printf("\t -l log level, debug/info/warn/error/crit/none\n");
    printf("\t -h show help text\n");
}

static char log_level = LOG_DEBUG_LEVEL;
extern char *optarg;
static int g_mode = 1;

void parse_opt(int argc, char *argv[])
{
    int ch;

    while ((ch = getopt(argc, argv, "m:l:h")) != -1) {
        switch ((char)ch) {
        case 'm':
            if (!strcmp(optarg, "discover"))
                g_mode = 1;
            else if (!strcmp(optarg, "config"))
                g_mode = 2;
            else {
                g_mode = 1;
                printf("unknow opt %s, use default mode: discover\n", optarg);
            }
            break;
        case 'l':
            if (!strcmp(optarg, "debug"))
                log_level = LOG_DEBUG_LEVEL;
            else if (!strcmp(optarg, "info"))
                log_level = LOG_INFO_LEVEL;
            else if (!strcmp(optarg, "warn"))
                log_level = LOG_WARNING_LEVEL;
            else if (!strcmp(optarg, "error"))
                log_level = LOG_ERR_LEVEL;
            else if (!strcmp(optarg, "crit"))
                log_level = LOG_CRIT_LEVEL;
            else if (!strcmp(optarg, "none"))
                log_level = LOG_EMERG_LEVEL;
            else
                log_level = LOG_DEBUG_LEVEL;
            break;
        case 'h':
        default:
            usage();
            exit(0);
        }
    }

    printf("awss ap mode: %d, log level: %d\n",
            g_mode, log_level);
}

int main(int argc, char *argv[])
{
    parse_opt(argc, argv);

    LITE_openlog("awss_ap");
    //log_set_level(LOG_LEVEL_DEBUG);

    LITE_set_loglevel(log_level);

    log_debug("awss_ap start");
    __init_devinfo();

    int ret = awss_ap_init();
    if (ret != AWSS_SUCCESS){
        log_err("awss ap init fail");
        return ret;
    }

    while(1){
        log_debug("================================");

        //IOT_DumpMemoryStats(IOT_LOG_DEBUG);
        //LITE_dump_malloc_free_stats(IOT_LOG_DEBUG);
        //__awss_notification_ut();
        sleep(30);
    }

    return 0;
}

