#include "wifi.h"
//
//
#define REQUEST_TRAIN_SIZE 20
//
char *TAG = "wifi";
//
extern xQueueHandle sniffingQueue;
extern TaskHandle_t taskHandle;
//prototipos de funciones static han de ir aqui, no el los .h
static void event_handler(void* event_handler_arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
static u8_t is_a_fixed_mac(char *mac);
static u8_t processRequestTrain(Request_t *requestTrain,Request_t *request, const u8_t requestTrainSize);
static void initializeRequestTrain(Request_t *requestTrain, const u8_t requestTrainSize);
//
static void event_handler(void* event_handler_arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
	static u8_t retries=0;
	switch (event_id)
	{
	case SYSTEM_EVENT_STA_START:
		esp_wifi_connect();
		ESP_LOGI(TAG, "connecting...\n");
		break;
	case SYSTEM_EVENT_STA_CONNECTED:
		ESP_LOGI(TAG, "connected\n");
		retries=0;
		break;
	case IP_EVENT_STA_GOT_IP:
		ESP_LOGI(TAG, "got ip\n");
		//notificamos que se ha conectado
		xTaskNotify(taskHandle, SYSTEM_EVENT_STA_GOT_IP, eSetValueWithOverwrite);
		break;
	case SYSTEM_EVENT_STA_DISCONNECTED:
	    //estrategia de conexión si al arrancar no se encuentra el wifi
		ESP_LOGI(TAG, "disconnected\n");
		vTaskDelay(pdMS_TO_TICKS(5000));
		retries++;
		ESP_LOGI(TAG, "connecting at attempt %d\n",retries);
		esp_wifi_connect();
		if (retries == 50)
		{
			ESP_LOGE(TAG, "Restarting...");
			esp_restart();
		}
		break;
	default:
		break;
	}
}


void wifi_sniffer_init(void)
{
	const wifi_country_t wifi_country = {.cc = "ES", .schan = 1, .nchan = 11, .policy = WIFI_COUNTRY_POLICY_AUTO};
	ESP_ERROR_CHECK(nvs_flash_init());
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_sta();
	wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
	ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, NULL));
	ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event_handler, NULL));
	ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country)); /* set country for channel range [1, 13] */
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	//Para configurar la parte de access pint
	esp_wifi_set_mode(WIFI_MODE_AP);
	wifi_config_t ap_config = {
		.ap = {
			.ssid = "esp-",
			.channel = 1,
			.authmode = WIFI_AUTH_OPEN,
			.ssid_hidden = 1,		 //ssid hide
			.max_connection = 0,	 //no permitimos clientes
			.beacon_interval = 60000 //600x1024us=61.44s
		}};
	esp_wifi_set_config(WIFI_IF_AP, &ap_config);
	//Para configurar la parte de station
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA)); //cliente y station
	wifi_config_t wifi_config =
		{
			.sta =
				{
					.ssid = CONFIG_WIFI_SSID,
					.password = CONFIG_WIFI_PASSWORD}};
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
	ESP_ERROR_CHECK(esp_wifi_start());
}

void wifi_sniffer_start(void){
	//Filtro paquetes managment
	wifi_promiscuous_filter_t filter;
	filter.filter_mask = WIFI_EVENT_MASK_AP_PROBEREQRECVED; //WIFI_PROMIS_FILTER_MASK_MGMT;
	esp_wifi_set_promiscuous_filter(&filter);
	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
	esp_wifi_set_channel(CHANNEL_TO_SNIFF, WIFI_SECOND_CHAN_NONE);
}


void wifi_sniffer_deinit()
{
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false)); //set as 'false' the promiscuous mode
	ESP_ERROR_CHECK(esp_wifi_stop());				  //it stop soft-AP and free soft-AP control block
	ESP_ERROR_CHECK(esp_wifi_deinit());				  //free all resource allocated in esp_wifi_init() and stop WiFi task
}


/*
 * A grandes rasgos este marcador hace que el código compilado se coloque en una secci�n llamada �.dram.text�.
 * El gestor de arranque ESP32, copiar esas secciones de código en la RAM real al inicio y antes de dar control
 * a la aplicación.
 * A efectos prácticos, el código compilado se encuentra en la flash pero con este marcador podemos hacer que se
 * encuentre en la RAM de manera que el código se ejecutar de una manera más rápida [15].
 */
IRAM_ATTR void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
	static u8_t firstTimeInit=false;
	static u8_t isProcessingRequestTrain = false; //cuando se esté procesado el request train no se atiende
	if (isProcessingRequestTrain == false)
	{
		static u8_t numResquest = 0;
		static TickType_t xPreviousRequestTime; //tiempo request n-1
		//
		static Request_t requestTrain[REQUEST_TRAIN_SIZE];// = {0}; //vector requestTrain
		if (firstTimeInit == false)
		{
			//inicializamos requestTrain
			initializeRequestTrain(requestTrain, REQUEST_TRAIN_SIZE);
			firstTimeInit=true;
		}
		//
		uint32_t interRequestTime = xTaskGetTickCount() - xPreviousRequestTime;
		//tiempo entre captura y captura de un mismo cliente para que se considere repetido o no
		const uint16_t paddingTime = 25;
		//static uint8_t nRequest;
		const uint8_t macSize = 15;
		const uint8_t payloadSize = 30;
		char *mac = NULL;		//puntero a cadena, lectura n
		mac = (char *)malloc(macSize);
		char *payload = NULL;		//puntero a cadena, payload, lo que se enviará
		payload = (char *)malloc(payloadSize);
		//si todo va bien asignando memoria
		if (mac != NULL && payload !=NULL)
		{
			int fctl = 0;
			const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
			const wifi_ieee80211_mac_hdr_t *hdr = (wifi_ieee80211_mac_hdr_t *)ppkt->payload;
			//Convertir de formato lsb first a msb first
			//hdr->fctl:            0x0000000001000000  dec 64
			//ntohs(hdr->fctl);     0x0100000000000000  dec 16384
			fctl = ntohs(hdr->fctl);
			//fctl deberíaa ser asi:0x0100000000000000
			//and con:              0x1111111100000000
			//resultado:            0x0100000000000000
			//Compromabion con:     0x0100000000000000
			if ((fctl & 0xFF00) == 0x4000)
			{ //solo los probe request
				//generamos cadena mac del source
				sprintf(mac, "%02X%02X%02X%02X%02X%02X", hdr->sa[0], hdr->sa[1], hdr->sa[2], hdr->sa[3], hdr->sa[4], hdr->sa[5]);
				//Si el tiempo entre request y request esta dentro del padding
				//consideraremos un request train:|rq|<-interRequestTime->|rq|
				numResquest++;
				if (interRequestTime <= paddingTime && numResquest < REQUEST_TRAIN_SIZE)
				{															   //numResquest<requestTrainSize para no salirnos del vector
					strcpy(requestTrain[numResquest].mac, mac);				   //copiamos mac
					requestTrain[numResquest].rssi = ppkt->rx_ctrl.rssi + 100; //copiamos rssi
				}
				else
				{
					numResquest=0;//ponemos a cero el contador
					Request_t request = {
						.isInitialized = false //no está incializado
					};
					isProcessingRequestTrain = true; //marcamos el flag
					isProcessingRequestTrain = processRequestTrain(requestTrain, &request, REQUEST_TRAIN_SIZE);
					if (request.isInitialized == true)
					{
                        sprintf(payload,"%s;%d;%d;%d;%d",request.mac, request.rssi, request.numFixedMacs, request.numRandomMacs, request.isFixed);
						ESP_LOGI(TAG, "%s", payload);//request.mac, request.rssi, request.numFixedMacs, request.numRandomMacs, request.isFixed
						xQueueSend(sniffingQueue, payload, 2000 / portTICK_PERIOD_MS);
					}
				}
				xPreviousRequestTime = xTaskGetTickCount();
			}
			//liberamos
			free(mac);
			free(payload);
		}
		else
		{
			//Si algo falla
			ESP_LOGE(TAG, "No ha sido posible asignar memoria");
		}
	}else{
		ESP_LOGE(TAG, "Processing requestTrain");
	}
}

static u8_t processRequestTrain(Request_t *requestTrain,Request_t *request, const u8_t requestTrainSize)
{
	int8_t mediaRssi=0;
	u16_t acumuladoRssi=0;
	int8_t lastRandomMacFound=-1;
	int8_t lastFixedMacFound=-1;
	u8_t numRandomMacs = 0;					  //nº de macs random
	u8_t numFixedMacs = 0;					  //nº de macs random
	//Marcamos las macs que son fixed o random
	for (u8_t i = 0; i < requestTrainSize; i++)
	{
		//Si en el train esa posición esta con un request válido, todos siempre tienen rssi>0
		if (requestTrain[i].rssi > 0)
		{
			acumuladoRssi+=requestTrain[i].rssi;//sumamos todos los valores rssi
			//guardamos la posición con fixed o random
			//si es una fixed o random incrementamos el contador
			if(is_a_fixed_mac(requestTrain[i].mac)==1){
				numFixedMacs++;
				lastFixedMacFound=i;
			}else{
				numRandomMacs++;
				lastRandomMacFound=i;//posición de la ultima macrandom encontrada
			}
		}
	}
	//Evitamos división entre cero
	if ((numFixedMacs + numRandomMacs) > 0)
	{
		//sacamos la media del rssi
		mediaRssi = acumuladoRssi / (numFixedMacs + numRandomMacs);
	}

	// Si hay al menos una mac random y cero mac fixed, generamos una mac formada por
	// el oui+ceros, osea AABBCC000000
	if (numRandomMacs > 0 && numFixedMacs == 0) //Si solo hay macs random
	{
		if (lastRandomMacFound >= 0)//aseguramos estar dentro del vector
		{
			//si tiene datos y es una random mac
			char randomMac[13] = "\0";
			strncpy(randomMac, requestTrain[lastRandomMacFound].mac, 6); //copiamos los primeros 6 caractares, el resto se mantiene a cero
			strcat(randomMac, "000000");								 //concateno 6 ceros al final
			//cargamos datos
			strcpy(request->mac, randomMac);
			request->rssi = mediaRssi;
			request->numRandomMacs = numRandomMacs;
			request->numFixedMacs = numFixedMacs;
			request->isFixed = 0;
			request->isInitialized = true;
		}
	}
	else //Si no hay macs random y hay macs fixed, o si hay macs random y si hay macs fixed
	{
		if (lastFixedMacFound >= 0) //aseguramos estar dentro del vector
		{
			//cargamos datos
			strcpy(request->mac, requestTrain[lastFixedMacFound].mac);
			request->rssi = mediaRssi;
			request->numRandomMacs = numRandomMacs;
			request->numFixedMacs = numFixedMacs;
			request->isFixed = 1;
			request->isInitialized = true;
		}
	}
	//inicializamos requestTrain
	initializeRequestTrain(requestTrain, REQUEST_TRAIN_SIZE);
	return false; //para que se atiendan las siguientes peticiones
}

static void initializeRequestTrain(Request_t *requestTrain, const u8_t requestTrainSize)
{
	//inicializamos struct
	for (u8_t i = 0; i < requestTrainSize; i++)
	{
		strcpy(requestTrain[i].mac, "000000000000");
		requestTrain[i].rssi = 0;
		requestTrain[i].isInitialized = true;
	}
}

static u8_t is_a_fixed_mac(char *mac)
{
	//mac=0C1122334455
	//mac[1] es C
	switch (mac[1])
	{
	case 50: //2 0010  rnd mac
		return 0;
	case 54: //6 0110  rnd mac
		return 0;
	case 65: //A 1010  rnd mac
		return 0;
	case 69: //E 1110  rnd mac
		return 0;
	case 70: //F 1111  rnd mac
		return 0;
	default: //fixed mac
		return 1;
	}
}

