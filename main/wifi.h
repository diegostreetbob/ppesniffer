#ifndef _CONNECT_H_
#define _CONNECT_H_
//
#define SSID CONFIG_WIFI_SSID
#define PASSWORD CONFIG_WIFI_PASSWORD
//sniffing
#define SSID_MAX_LEN (32+1) //max length of a SSID
#define CONFIG_SNIFFING_TIME 20//en segundos
#define CHANNEL_TO_SNIFF 6//canal de escucha
//
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "cJSON.h"
//
typedef struct
{
	int16_t fctl;			 //frame control
	int16_t duration;		 //duration id
	uint8_t da[6];			 //receiver address
	uint8_t sa[6];			 //sender address
	uint8_t bssid[6];		 //filtering address
	int16_t seqctl;			 //sequence control
	unsigned char payload[]; //network data ended with 4 bytes csum (CRC32)
} __attribute__((packed)) wifi_ieee80211_mac_hdr_t;
//
typedef struct
{
	char mac[13];
	int8_t rssi;
	u8_t numFixedMacs;
	u8_t numRandomMacs;
	u8_t isFixed;
	u8_t isInitialized;//para asegurarnos que esta inicializado
} Request_t;
//
void wifiInit();
//sniffing
void wifi_sniffer_init(void);
void wifi_sniffer_packet_handler(void *buff,	wifi_promiscuous_pkt_type_t type);
void getSsid(char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len);
//tarea
void sniffer_task(void *pvParameter);
void wifi_sniffer_start(void);
void wifi_ap_start(void);



#endif