#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <chrono>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/hmac.h>

using namespace std;

string hmacEncode(string param, string secret)
{

    const char *key = secret.c_str();
    const char *input = param.c_str();
    const EVP_MD *engine = NULL;
    engine = EVP_sha256();

    unsigned char *p = (unsigned char *)malloc(1024);
    char buf[1024] = {0};
    char tmp[3] = {0};
    unsigned int output_length = 0;
    p = (unsigned char *)malloc(EVP_MAX_MD_SIZE);

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, strlen(key), engine, NULL);
    HMAC_Update(ctx, (unsigned char *)input, strlen(input)); // input is OK; &input is WRONG !!!

    HMAC_Final(ctx, p, &output_length);
    for (int i = 0; i < 32; i++)
    {
        sprintf(tmp, "%02x", p[i]);
        strcat(buf, tmp);
    }
    return string(buf);
}

int main(int, char **)
{
    CURL *curl;
    CURLcode res;

    unsigned long long timestamp = chrono::duration_cast<chrono::milliseconds>(chrono::_V2::system_clock::now().time_since_epoch()).count();

    string api_key = "WT***************3TB";
    string secret_key = "Ik**************4vE";

    string reqParam = "api_key=" + api_key + "&order_type=Market&qty=5&side=Buy&symbol=MATICUSDT&time_in_force=GoodTillCancel&timestamp=" + to_string(timestamp);

    string sign = hmacEncode(reqParam, secret_key);

    string json = "{\"api_key\":\"" + api_key + "\",\"side\"=\"Buy\",\"symbol\"=\"MATICUSDT\",\"order_type\":\"Market\",\"qty\":2,\"time_in_force\":\"GoodTillCancel\",\"timestamp\":" + to_string(timestamp) + " ,\"sign\":\"" + sign + "\"}";

    cout << json << endl;

    curl = curl_easy_init();
    if (curl)
    {
        // set params
        curl_easy_setopt(curl, CURLOPT_POST, 1);          // post req
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.bybit.com/private/linear/order/create"); // url
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);

        // Header "Content-Type: application/json"
        struct curl_slist *headers = NULL;
        curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);
    }
    return 0;
}
