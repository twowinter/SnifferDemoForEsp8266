/*
 * File	: user_main.c
 * This file is Espressif's sniffer demo.
 * Copyright (C) 2013 - 2016, Espressif Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 3 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/******************************************************************************
 * Copyright 2013-2014 Espressif Systems (Wuxi)
 *
 * FileName: user_main.c
 *
 * Description: entry file of user application
 *
 * Modification history:
 *     2014/1/1, v1.0 create this file.
*******************************************************************************/
#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"

#include "user_interface.h"

void user_rf_pre_init(void)
{
}

os_timer_t check_sniffer;
os_timer_t check_sniffer_2;

typedef enum _encrytion_mode {
    ENCRY_NONE           = 1,
    ENCRY_WEP,
    ENCRY_TKIP,
    ENCRY_CCMP
} ENCYTPTION_MODE;

struct router_info {
    SLIST_ENTRY(router_info)     next;

    u8  bssid[6];
    u8  channel;
    u8  authmode;

    u16 rx_seq;
    u8  encrytion_mode;
    u8  iv[8];
    u8  iv_check;
};

SLIST_HEAD(router_info_head, router_info) router_list;

os_timer_t channel_timer;
uint8  current_channel;
uint16 channel_bits;
struct rst_info rtc_info;
void   wifi_scan_done(void *arg, STATUS status);

struct RxControl {
    signed rssi:8;
    unsigned rate:4;
    unsigned is_group:1;
    unsigned:1;
    unsigned sig_mode:2;
    unsigned legacy_length:12;
    unsigned damatch0:1;
    unsigned damatch1:1;
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned MCS:7;
    unsigned CWB:1;
    unsigned HT_length:16;
    unsigned Smoothing:1;
    unsigned Not_Sounding:1;
    unsigned:1;
    unsigned Aggregation:1;
    unsigned STBC:2;
    unsigned FEC_CODING:1;
    unsigned SGI:1;
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;
    unsigned channel:4;
    unsigned:12;
};
 
struct Ampdu_Info
{
  uint16 length;
  uint16 seq;
  uint8  address3[6];
};

struct sniffer_buf {
    struct RxControl rx_ctrl;
    uint8_t  buf[36];
    uint16_t cnt;
    struct Ampdu_Info ampdu_info[1];
};

struct sniffer_buf2{
    struct RxControl rx_ctrl;
    uint8 buf[112];
    uint16 cnt;
    uint16 len; //length of packet
};

void ICACHE_FLASH_ATTR
sniffer_wifi_promiscuous_rx(uint8 *buf, uint16 buf_len)
{
	uint16 i;
	uint16 len;
	uint16 cnt = 0;
	struct router_info *info = NULL;
	struct sniffer_buf * sniffer = (struct sniffer_buf *)buf;
	if(buf_len == 12){
		os_printf("%sM%d%s\n", sniffer->rx_ctrl.CWB?"H4":"H2", sniffer->rx_ctrl.MCS,  sniffer->rx_ctrl.FEC_CODING?"L ":"");
		return;
	} else if (buf_len == 128) {
		//os_printf("manage pack\n");
        return; //manage pack
    }
#if 1	
    len = sniffer->ampdu_info[0].length;
	buf += sizeof(struct RxControl);

	SLIST_FOREACH(info, &router_list, next) {
		if ((buf[1] & 0x01) == 0x01) {	// just toDS
			if (os_memcmp(info->bssid, buf + 4, 6) == 0) {
				if (current_channel - 1 != info->channel) {	// check channel
					return;
				} else {
					break;
				}
			}
		}
	}

	if (info == NULL) {
		return;
	}
	if(sniffer->cnt > 1)
		os_printf("rx ampdu %d\n", sniffer->cnt);
    while(cnt < sniffer->cnt){
	   	len = sniffer->ampdu_info[cnt++].length;
		os_printf("len = %d\n",len);
	}
#endif
}


void ICACHE_FLASH_ATTR
sniffer_channel_timer_cb(void *arg)
{
	uint8 i;

	for (i = current_channel; i < 14; i++) {
		if ((channel_bits & (1 << i)) != 0) {
			current_channel = i + 1;
			wifi_set_channel(i);
			os_printf("current channel2 %d--------------------------------------------%d\n", i, system_get_time());
			os_timer_arm(&channel_timer, 5000, 0);
			break;
		}
	}

	if (i == 14) {
		current_channel = 1;
		for (i = current_channel; i < 14; i++) {
			if ((channel_bits & (1 << i)) != 0) {
				current_channel = i + 1;
				wifi_set_channel(i);
				os_printf("current channel3 %d--------------------------------------------%d\n", i, system_get_time());
				os_timer_arm(&channel_timer, 5000, 0);
				break;
			}
		}
	}
}

void ICACHE_FLASH_ATTR
sniffer_wifi_scan_done(void *arg, STATUS status)
{
	uint8 ssid[33];

	channel_bits = 0;
	current_channel = 1;

	struct router_info *info = NULL;

	while((info = SLIST_FIRST(&router_list)) != NULL){
		SLIST_REMOVE_HEAD(&router_list, next);

		os_free(info);
	}

	if (status == OK) {
		uint8 i;
		struct bss_info *bss = (struct bss_info *)arg;

		while (bss != NULL) {

			if (bss->channel != 0) {
				struct router_info *info = NULL;

				os_printf("ssid %s, channel %d, authmode %d, rssi %d\n",
						bss->ssid, bss->channel, bss->authmode, bss->rssi);
				channel_bits |= 1 << (bss->channel);

				info = (struct router_info *)os_zalloc(sizeof(struct router_info));
				info->authmode = bss->authmode;
				info->channel = bss->channel;
				os_memcpy(info->bssid, bss->bssid, 6);

				SLIST_INSERT_HEAD(&router_list, info, next);
			}
			bss = STAILQ_NEXT(bss, next);
		}

		for (i = current_channel; i < 14; i++) {
			if ((channel_bits & (1 << i)) != 0) {
				current_channel = i + 1;
				wifi_set_channel(i);
				os_printf("current channel1 %d--------------------------------------------%d\n", i, system_get_time());
				break;
			}
		}
        while((info = SLIST_FIRST(&router_list)) != NULL){
		    SLIST_REMOVE_HEAD(&router_list, next);
		    os_free(info);
	    } 
		
		wifi_set_channel(1);
        wifi_promiscuous_enable(0);
        wifi_set_promiscuous_rx_cb(sniffer_wifi_promiscuous_rx);
        wifi_promiscuous_enable(1);

		os_timer_disarm(&channel_timer);
		os_timer_setfn(&channel_timer, sniffer_channel_timer_cb, NULL);
		os_timer_arm(&channel_timer, 5000, 0);
	} else {
		os_printf("err, scan status %d\n", status);
	}
}

void sniffer_system_init_done(void);

void ICACHE_FLASH_ATTR
check_cb(void)
{
    sniffer_system_init_done();
    os_printf("open sniffer\n\r");
    
}

void ICACHE_FLASH_ATTR
check_cb_2(void)
{
    wifi_promiscuous_enable(0); //turn off sniffer mode
    os_printf("turn off sniffer:%d\n\r",system_get_free_heap_size());

    sniffer_system_init_done();
    
    //os_timer_disarm(&check_sniffer_2);
    //os_timer_setfn(&check_sniffer_2, (os_timer_func_t *)check_cb, NULL);
    //os_timer_arm(&check_sniffer_2, 1000, 0);
}

void ICACHE_FLASH_ATTR
sniffer_system_init_done(void)
{
	SLIST_INIT(&router_list);

	wifi_station_scan(NULL,sniffer_wifi_scan_done);
	//os_timer_disarm(&check_sniffer);
    //os_timer_setfn(&check_sniffer, (os_timer_func_t *)check_cb_2, NULL);
    //os_timer_arm(&check_sniffer, 5000, 0);
}



/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void user_init(void)
{
    os_printf("SDK version:%s\n", system_get_sdk_version());   

	wifi_set_opmode(STATION_MODE);
    system_init_done_cb(sniffer_system_init_done);
}

