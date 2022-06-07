#include "mqtt.h"

static const char *TAG = "mqtt.c";
//certificados
extern const uint8_t client_cert_pem_start[] asm("_binary_client_pem_start");
extern const uint8_t client_cert_pem_end[] asm("_binary_client_pem_end");
extern const uint8_t client_key_pem_start[] asm("_binary_client_key_start");
extern const uint8_t client_key_pem_end[] asm("_binary_client_key_end");
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_pem_end");
//para darle acceso desde fuera de este módulo
extern TaskHandle_t taskHandle;
extern xQueueHandle sniffingQueue;
extern xQueueHandle arrivedMsgQueue;
extern MqttApp mqttApp;

static void log_error_if_nonzero(const char *message, int error_code)
{
    if (error_code != 0) {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
}

/*
 * @brief Event handler registered to receive MQTT events
 *
 *  This function is called by the MQTT client event loop.
 *
 * @param handler_args user data registered to the event.
 * @param base Event base for the handler(always MQTT Base in this example).
 * @param event_id The id for the received event.
 * @param event_data The data for the event, esp_mqtt_event_handle_t.
 */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = event_data;
    esp_mqtt_client_handle_t client = event->client;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
    ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        xTaskNotify(taskHandle, MQTT_EVENT_CONNECTED, eSetValueWithOverwrite);
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
          esp_mqtt_client_reconnect(client);
          break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        ArrivedMsg arrivedMsg;
        //Verificamos que los tamaños de topic y mensaje entran en los buffers
        if (event->topic_len < sizeof(arrivedMsg.topic) && event->data_len < sizeof(arrivedMsg.data))
        {
            //Copiamos
            strcpy(arrivedMsg.topic,event->topic);
            arrivedMsg.topic_len=event->topic_len;
            strcpy(arrivedMsg.data,event->data);
            arrivedMsg.data_len=event->data_len;
            //enviamos
            xQueueSend(arrivedMsgQueue, (void *)&arrivedMsg , 1000 / portTICK_PERIOD_MS);
        }else{
            ESP_LOGE(TAG, "sizeof topic or sizeof data out of limits"); 
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
            log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            log_error_if_nonzero("captured as transport's socket errno",  event->error_handle->esp_transport_sock_errno);
            ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
        }
        xTaskNotify(taskHandle, MQTT_EVENT_ERROR, eSetValueWithOverwrite);
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}

esp_mqtt_client_handle_t mqtt_app_start(void)
{
    const esp_mqtt_client_config_t mqtt_cfg = {
       // .uri = "mqtts://diegomguillen.com:8883",
    	.uri = CONFIG_BROKER_URL,
        .client_id=CONFIG_CLIENT_ID,
        .client_cert_pem = (const char *)client_cert_pem_start,
        .client_key_pem = (const char *)client_key_pem_start,
        .cert_pem = (const char *)server_cert_pem_start,
    };

    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);
    return client;
}
//
void receibeMessage(void *pvParameters)
{
    ArrivedMsg arrivedMsg;
	ESP_LOGI("receibeMessage", "inside receibeMessage");
    while(1)
    {
    	ESP_LOGI("receibeMessage", "inside while waiting queue");
    	xQueueReceive(arrivedMsgQueue, &arrivedMsg, portMAX_DELAY);
        printf("receibeMessage TOPIC=%.*s\r\n", arrivedMsg.topic_len, arrivedMsg.topic);
        printf("receibeMessage DATA=%.*s\r\n", arrivedMsg.data_len, arrivedMsg.data);
    }
}
//
void publishMessage(void *pvParameters)
{
    char data[153 + 20];
    char topicToSend[20] = "sniffer/"; //ojo que el clientid sea de 8 caracteres máximo
    strcat(topicToSend, mqttApp.client_id);
    while (1)
    {
        ESP_LOGI("publishMessage", "inside while waiting queue");
        xQueueReceive(sniffingQueue, data, portMAX_DELAY);
        ESP_LOGI("publishMessage", "QueueReceived");
        //Importante esta comprobación
        if (mqttApp.client != NULL)
        {
            ESP_LOGI("publishMessage", "data:%s", data);
            esp_mqtt_client_publish(mqttApp.client, topicToSend, data, strlen(data), 0, false);
        }
        else
        {
            ESP_LOGE("publishMessage", "client null");
        }
    }
}

MqttApp newMqttApp(void){
    MqttApp mqttApp;
    mqttApp.client_id=CONFIG_CLIENT_ID;
    mqttApp.ptfPublishMessage=publishMessage;
    mqttApp.ptfReceibeMessage=receibeMessage;
    mqttApp.ptfMqtt_app_start=mqtt_app_start;
    mqttApp.ptfEsp_mqtt_client_subscribe=esp_mqtt_client_subscribe;
    return mqttApp;
}


