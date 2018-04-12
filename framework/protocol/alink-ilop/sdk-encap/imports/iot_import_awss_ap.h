#ifndef __IMPORT_PRODUCT_AWSS_AP_H__
#define __IMPORT_PRODUCT_AWSS_AP_H__



#define PRODUCT_IFNAME_LEN      (32)
#define PRODUCT_MAC_LEN         (17)
#define PRODUCT_SSID_LEN        (128)
#define PRODUCT_PWD_LEN         (128)
#define PRODUCT_DEVICEID_LEN    (128)

/*
 * @brief: 获取aha&adha热点所在桥的接口名称
 *
*/
char *product_get_aha_bridge_ifname(char ifname_str[PRODUCT_IFNAME_LEN + 1]);

char *product_get_adha_port_ifname(char ifname_str[PRODUCT_IFNAME_LEN + 1]);

char *product_get_extranet_ap_port_ifname(char ifname_str[PRODUCT_IFNAME_LEN + 1]);

//int product_get_extranet_ap_info(char ssid_str[PRODUCT_SSID_LEN + 1], char pwd_str[PRODUCT_PWD_LEN + 1]);
int product_get_extranet_ap_info(char ssid_str[PRODUCT_SSID_LEN + 1],
                        char pwd_str[PRODUCT_PWD_LEN + 1],
                        char ifname_str[PRODUCT_IFNAME_LEN + 1]);

int product_set_aha_ap_info(const char *ssid_str, const char *pwd_str, int enable_state, int visible_flag);

int product_save_adha_ap_state(int enable_state);

/**
 * @brief Get product LAN side route ifname string.
 *
 * @param[out] ifname_str @n Buffer for using to store ifname string.
 * @return A pointer to the start address of ifname_str.
 * @see None.
 * @note Only for the router product.
 */
    char *product_get_lan_ifname(char ifname_str[PRODUCT_IFNAME_LEN + 1]);

/**
 * @brief Get aha ap bridge port name string.
 *
 * @param[out] ifname_str @n Buffer for using to store bridge port ifname string.
 * @return A pointer to the start address of ifname_str.
 * @see None.
 * @note Only for the router product.
 */
    char *product_get_aha_port_ifname(char ifname_str[PRODUCT_IFNAME_LEN + 1]);

/**
 * @brief Get adha ap bridge port name string.
 *
 * @param[out] ifname_str @n Buffer for using to store bridge port ifname string.
 * @return A pointer to the start address of ifname_str.
 * @see None.
 * @note Only for the router product.
 */
    char *product_get_adha_port_ifname(char ifname_str[PRODUCT_IFNAME_LEN + 1]);


/**
 * @brief Get extranet ap SSID&PASSWD string.
 *
 * @param[out] ssid_str @n Buffer for using to store ssid string.
 * @param[out] pwd_str @n Buffer for using to store password string.
 * @return 0: success, otherwise: failure.
 * @see None.
 * @note Only for the router product..
 */
    //int product_get_extranet_ap_info(char ssid_str[PRODUCT_SSID_LEN + 1], char pwd_str[PRODUCT_PWD_LEN + 1]);
    int product_get_extranet_ap_info(char ssid_str[PRODUCT_SSID_LEN + 1],
                        char pwd_str[PRODUCT_PWD_LEN + 1],
                        char ifname_str[PRODUCT_IFNAME_LEN + 1]);


/**
 * @brief Set adha/aha ap information.
 *
 * @param[in] ssid_str @n point to ssid string.
 * @param[in] pwd_str @n point to to passworld string.
 * @param[in] enable_state @n ap enable state,1: enable, 0: disable.
 * @param[in] visible_flag @n ssid visible flag,1: visible, 0: hidden.
 * @return 0: success, otherwise: failure.
 * @see None.
 * @note Only for the router product..
 */
    int product_set_aha_ap_info(const char *ssid_str, const char *pwd_str, int enable_state, int visible_flag);

/**
 * @brief Save adha ap enable state.
 *
 * @param[in] enable_state @n ap enable state.
 * @return 0: success, otherwise: failure.
 * @see None.
 * @note Only for the router product..
 */
    int product_save_adha_ap_state(int enable_state);


#endif  /* __IMPORT_PRODUCT_H__ */
