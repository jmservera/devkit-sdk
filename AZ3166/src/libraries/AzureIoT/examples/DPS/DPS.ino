// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. 
#include "AZ3166WiFi.h"
#include "AzureIotHub.h"
#include "IoTHubMQTTClient.h"
#include "DPSClient.h"
#include "DiceRIoT.h"

#include "config.h"
#include "utility.h"
#include "SystemTickCounter.h"
#include "SystemVariables.h"

extern char* Global_Device_Endpoint;
extern char* ID_Scope;

// Indicate whether WiFi is ready
static bool hasWifi = false;
int messageCount = 1;
static bool messageSending = true;
static uint64_t send_interval_ms;

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Utilities
static void InitWiFi()
{
  Screen.print(2, "Connecting...");
  
  if (WiFi.begin() == WL_CONNECTED)
  {
    IPAddress ip = WiFi.localIP();
    Screen.print(1, ip.get_address());
    hasWifi = true;
    Screen.print(2, "Running... \r\n");
  }
  else
  {
    hasWifi = false;
    Screen.print(1, "No Wi-Fi\r\n ");
  }
}

static void SendConfirmationCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result)
{
  if (result == IOTHUB_CLIENT_CONFIRMATION_OK)
  {
    blinkSendConfirmation();
  }
}

static void MessageCallback(const char* payLoad, int size)
{
  blinkLED();
  Screen.print(1, payLoad, true);
}

static void DeviceTwinCallback(DEVICE_TWIN_UPDATE_STATE updateState, const unsigned char *payLoad, int size)
{
  char *temp = (char *)malloc(size + 1);
  if (temp == NULL)
  {
    return;
  }
  memcpy(temp, payLoad, size);
  temp[size] = '\0';
  parseTwinMessage(updateState, temp);
  free(temp);
}

static int  DeviceMethodCallback(const char *methodName, const unsigned char *payload, int size, unsigned char **response, int *response_size)
{
  LogInfo("Try to invoke method %s", methodName);
  const char *responseMessage = "\"Successfully invoke device method\"";
  int result = 200;

  if (strcmp(methodName, "start") == 0)
  {
    LogInfo("Start sending temperature and humidity data");
    messageSending = true;
  }
  else if (strcmp(methodName, "stop") == 0)
  {
    LogInfo("Stop sending temperature and humidity data");
    messageSending = false;
  }
  else
  {
    LogInfo("No method %s found", methodName);
    responseMessage = "\"No method found\"";
    result = 404;
  }

  *response_size = strlen(responseMessage);
  *response = (unsigned char *)malloc(*response_size);
  strncpy((char *)(*response), responseMessage, *response_size);

  return result;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
// Arduino sketch
void setup() {
  // put your setup code here, to run once:

  Screen.init();
  Screen.print(0, "IoT DevKit");
  Screen.print(2, "Initializing...");

  Screen.print(3, " > Serial");
  Serial.begin(115200);
  
  // Initialize the WiFi module
  Screen.print(3, " > WiFi");
  hasWifi = false;
  InitWiFi();
  if (!hasWifi)
  {
    return;
  }

  Screen.print(3, " > Sensors");
  SensorInit();

  Screen.print(3, " > DPS");
  Screen.print(3, " > DPS");

  const char* registrationId = GetBoardID();
  // Transfer control to DICE|RIoT
  if(DiceRIoTStart(registrationId) != 0)
  {
      LogError("Untrusted device.");
      return;
  }

  // Transfer control to firmware
  if(DPSClientStart(Global_Device_Endpoint, ID_Scope, registrationId))
  {
    Screen.print(2, "DPS connected!\r\n");
  }
  else
  {
    Screen.print(2, "DPS Failed!\r\n");
    return;
  }

  Screen.print(3, " > IoT Hub(DPS)");
  IoTHubMQTT_Init(true);

  IoTHubMQTT_SetSendConfirmationCallback(SendConfirmationCallback);
  IoTHubMQTT_SetMessageCallback(MessageCallback);
  IoTHubMQTT_SetDeviceTwinCallback(DeviceTwinCallback);
  IoTHubMQTT_SetDeviceMethodCallback(DeviceMethodCallback);
}

void loop()
{
  if (messageSending && 
      (int)(SystemTickCounterRead() - send_interval_ms) >= getInterval())
  {
    // Send teperature data
    char messagePayload[MESSAGE_MAX_LEN];

    bool temperatureAlert = readMessage(messageCount++, messagePayload);
    EVENT_INSTANCE* message = GenerateEvent(messagePayload, MESSAGE);
    AddProp(message, "temperatureAlert", temperatureAlert ? "true" : "false");
    IoTHubMQTT_SendEventInstance(message);
    
    send_interval_ms = SystemTickCounterRead();
  }
  else
  {
    IoTHubMQTT_Check();
  }
  delay(10);
}