#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "MQTTClient.h"
#include "openssl/hmac.h"
// 设备三元组+region
#define RegionID  "cn-shanghai"
#define ProductKey "替换ProductKey"
#define DeviceName "替换DeviceName"
#define DeviceSecret "替换DeviceSecret"
// 消息通信
#define TOPIC       "/sys/替换ProductKey/替换DeviceName/thing/event/property/post"
#define PAYLOAD     "{\"id\":123456,\"params\": {\"temperature\":11,\"humidity\":69},\"method\": \"thing.event.property.post\"}"
#define QOS         1
#define TIMEOUT     10000L

//MqttServerAddr
int getMqttServerAddr(char* dest, int len)
{
    //${productKey}.iot-as-mqtt.${regionId}.aliyuncs.com:1883
    char tmp[512]={'\0'};
    snprintf(tmp,sizeof(tmp),"%s.iot-as-mqtt.%s.aliyuncs.com:1883", ProductKey, RegionID);
    if(strlen(tmp)+1>len)
    {
        printf("no enough space for MqttServerAddr\n");
        return -1;
    }
    memcpy(dest,tmp,strlen(tmp)+1);
    printf("MqttServerAddr: %s\n", dest);
    return 0;
}

//MqttClientID 
int getMqttClientID(char* dest, int len, int clientDevice, int timestamp)
{
    //mqttClientId: clientDevice+"|securemode=3,signmethod=hmacsha1,timestamp="+timestamp+"|"
    char tmp[512]={'\0'};
    snprintf(tmp,sizeof(tmp),"%d|securemode=3,signmethod=hmacsha1,timestamp=%d|", clientDevice, timestamp);
    if(strlen(tmp)+1>len)
    {
        printf("no enough space for MqttClientID\n");
        return -1;
    }
    memcpy(dest,tmp,strlen(tmp)+1);
    printf("MqttClientID: %s\n", dest);
    return 0;
}
//UserName
int getMqttUserName(char* dest, int len)
{
    //$mqttUsername: deviceName+"&"+productKey
    char tmp[512]={'\0'};
    snprintf(tmp,sizeof(tmp),"%s&%s", DeviceName, ProductKey);
    if(strlen(tmp)+1>len)
    {
        printf("no enough space for UserName\n");
        return -1;
    }
    memcpy(dest,tmp,strlen(tmp)+1);
    printf("UserName: %s\n", dest);
    return 0;
}

//Password
int sha1Signature(char *hmac_sigbuf, const int hmac_buflen, int clientDevice, int timestamp)
{
    char                    signature[41] = {'\0'};
    char                    hmac_source[512];
    unsigned char           digest[512] = {'\0'};
    unsigned int            digest_len = 0;

    memset(signature, 0, sizeof(signature));
    memset(hmac_source, 0, sizeof(hmac_source));
    snprintf(hmac_source, sizeof(hmac_source),
        "clientId%ddeviceName%sproductKey%stimestamp%d",
        clientDevice, DeviceName, ProductKey, timestamp);

    HMAC(EVP_sha1(), DeviceSecret, strlen(DeviceSecret), (unsigned char*)hmac_source,
        strlen(hmac_source), digest, &digest_len);

    for(int i = 0; i < 20; i++)
        sprintf(&signature[i*2], "%02x", (unsigned int)digest[i]);

    memcpy(hmac_sigbuf, signature, hmac_buflen);
    printf("### signature: %s\n", hmac_sigbuf);
    return 0;
}




int main(int argc, char* argv[])
{
    MQTTClient client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    int rc;

    char serverAddr[512];
    char serverClient[512];
    char userName[512];
    char password[512];
    //设备id
    int clientDevice = 1234;
    //设备当前时间戳
    int timestamp = 56789;

    if(getMqttServerAddr(serverAddr,512)!=0)
    {
        exit(1);
    }
    if(getMqttClientID(serverClient,512,clientDevice,timestamp)!=0)
    {
        exit(1);
    }
    if(getMqttUserName(userName,512)!=0)
    {
        exit(1);
    }
    if(sha1Signature(password,512,clientDevice,timestamp)!=0)
    {
        exit(1);
    }

    MQTTClient_create(&client, serverAddr, serverClient,
        MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 30;
    conn_opts.cleansession = 1;
    conn_opts.username = userName;
    conn_opts.binarypwd.data = (void*)password;
    conn_opts.binarypwd.len = strlen(password);

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
    {
        printf("Failed to connect, return code %d\n", rc);
        exit(-1);
    }
    pubmsg.payload = PAYLOAD;
    pubmsg.payloadlen = strlen(PAYLOAD);
    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    MQTTClient_publishMessage(client, TOPIC, &pubmsg, &token);
    printf("Waiting for up to %d seconds for publication of %s\n"
            "on topic %s for client with ClientID: %s\n",
            (int)(TIMEOUT/1000), PAYLOAD, TOPIC, serverClient);
    rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
    printf("Message with delivery token %d delivered\n", token);
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return rc;
}