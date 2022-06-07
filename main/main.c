#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "esp_event_loop.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "cJSON.h"
#include "wifi.h"
#include "mqtt_client.h"
#include "mqtt.h"

#define TAG "MQTT"
//usadas en otros componentes mediante extern
xQueueHandle sniffingQueue;
xQueueHandle arrivedMsgQueue;
TaskHandle_t taskHandle;
TaskHandle_t taskHandlePublishMessage;
TaskHandle_t taskHandleReceibeMessage;
MqttApp mqttApp;
//
void distributor(void *para)
{
	uint32_t command = 0;
	while (true)
	{
		ESP_LOGI("distributor", "inside while waiting command");
		xTaskNotifyWait(0, 0, &command, portMAX_DELAY); //quedamos a la espera de la notificacion
		ESP_LOGI("distributor", "command:%d", command);
		switch (command)
		{
		case SYSTEM_EVENT_STA_GOT_IP: //tenemos ip
			ESP_LOGI("distributor", "SYSTEM_EVENT_STA_GOT_IP");
			mqttApp.client = mqttApp.ptfMqtt_app_start(); //iniciamos el cliente mqtt
			break;
		case MQTT_EVENT_CONNECTED: //cliente conectado
			ESP_LOGI("distributor", "MQTT_EVENT_CONNECTED");
			mqttApp.ptfEsp_mqtt_client_subscribe(mqttApp.client, mqttApp.client_id, 0); //se subscribe a un topic que es un client_id
			wifi_sniffer_start();														//se inicia el modo sniffer
			break;
		case MQTT_EVENT_ERROR:
			ESP_LOGI("distributor", "MQTT_EVENT_ERROR");
			//Si hay wifi pero no hay internet o si ha caido el servidor mqtt
			esp_restart(); //ojo a esto
			break;
		case SYSTEM_EVENT_STA_START:
			ESP_LOGI("distributor", "WIFI_TRY_CONNEECTING");
			break;
		default:
			ESP_LOGI("distributor", "command:%d", command);
			break;
		}
	}
}


void app_main()
{
  sniffingQueue = xQueueCreate(1, 153+15);
  arrivedMsgQueue = xQueueCreate(1, sizeof(ArrivedMsg)+2);
  mqttApp=newMqttApp();
  wifi_sniffer_init();
  xTaskCreate(distributor, "distributor", 1024 * 5, NULL, 10, &taskHandle);
  xTaskCreate(mqttApp.ptfPublishMessage, "publishMessage", 2048, NULL, 5, &taskHandlePublishMessage);
  xTaskCreate(mqttApp.ptfReceibeMessage, "receibeMessage", 2048, NULL, 5, &taskHandleReceibeMessage);
//wifi_ap_start();
}
