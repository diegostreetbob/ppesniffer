/*
 * mqtt.h
 *
 *  Created on: 29 jun. 2021
 *      Author: d7610
 */

#ifndef MQTT_H_
#define MQTT_H_
//
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "esp_log.h"
#include "mqtt_client.h"
//
typedef struct{
    esp_mqtt_client_handle_t client;
    const char *client_id;
    void (*ptfPublishMessage)(void *pvParameters);
    void (*ptfReceibeMessage)(void *pvParameters);
    esp_mqtt_client_handle_t (*ptfMqtt_app_start)(void);
    int (*ptfEsp_mqtt_client_subscribe)(esp_mqtt_client_handle_t client, const char *topic, int qos);
}MqttApp;

typedef struct{
    char topic[25];
    int topic_len;
    char data[25];
    int data_len;
}ArrivedMsg;
//
static void log_error_if_nonzero(const char *message, int error_code);
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data);
esp_mqtt_client_handle_t mqtt_app_start(void);
void publishMessage(void *pvParameters);
void receibeMessage(void *pvParameters);
MqttApp newMqttApp(void);

#endif /* MQTT_H_ */
