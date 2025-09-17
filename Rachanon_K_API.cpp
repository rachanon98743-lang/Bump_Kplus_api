#include "Rachanon_K_API.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include "ArduinoJson-v7.0.2.h"
#include <mbedtls/base64.h>

String encodeBase64(const String &input) {
    const char* input_cstr = input.c_str();
    size_t input_len = strlen(input_cstr);

    size_t output_len = 0;
    size_t buf_len = 4 * ((input_len + 2) / 3) + 1; // ขนาด buffer สำหรับ Base64
    unsigned char output[buf_len];

    int ret = mbedtls_base64_encode(output, buf_len, &output_len,
                                    (const unsigned char*)input_cstr, input_len);
    if (ret != 0) {
        Serial.printf("Base64 encode error: %d\n", ret);
        return "";
    }

    return String((char*)output);
}

static const char * TAG = "Rachanon_K_API";
String partnerTxnUid;
String partnerId;
String partnerSecret;
String requestDt;
String merchantId;
#define API_HOST "openapi-sandbox.kasikornbank.com"

Rachanon_K_API::Rachanon_K_API(String apiKey, String apiSecret, String authCode) {
    this->apiKey = apiKey;
    this->apiSecret = apiSecret;
    this->authCode = authCode;
}




bool Rachanon_K_API::setClock() {
    if(WiFi.status() != WL_CONNECTED) {
        ESP_LOGE(TAG, "WiFi not connected");
        return false;
    }

    // ใช้ NTP server IP เผื่อ DNS ไม่ work
    configTime(7*3600, 0, "129.6.15.28", "129.6.15.29");
    ESP_LOGV(TAG, "Waiting for NTP time sync");

    time_t nowSecs = 0;
    int tries = 0;
    while(tries < 30) { // เพิ่ม retry
        nowSecs = time(nullptr);
        if(nowSecs > 1690000000) break;
        delay(500);
        tries++;
    }

    if(tries == 30) {
        ESP_LOGE(TAG, "NTP sync failed");
        return false;
    }

    ESP_LOGV(TAG, "Current time: %ld", nowSecs);
    return true;
}


bool Rachanon_K_API::verifyToken() {
    if (accessToken.length() == 0) return false;
    uint32_t now = millis();
    if (now - accessTokenUpdateAt >= expiresIn * 1000) return false; // หมดอายุแล้ว
    return true; // ยังใช้ได้
}

bool Rachanon_K_API::genToken() {
    WiFiClientSecure *client = new WiFiClientSecure;
    if(!client) {
        ESP_LOGE(TAG, "create WiFiClientSecure fail");
        return false;
    }

    bool ok = false;
    const char* scbRootCACert = \
"-----BEGIN CERTIFICATE-----\n"\
"MIIGmzCCBYOgAwIBAgIMUHkPQ9HiEV14N4eYMA0GCSqGSIb3DQEBCwUAMFAxCzAJ\n"\
"BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H\n"\
"bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yNTAyMTEwODE1MzFaFw0y\n"\
"NjAzMTUwODE1MzBaMIGKMQswCQYDVQQGEwJUSDEQMA4GA1UECBMHQmFuZ2tvazET\n"\
"MBEGA1UEBxMKUGhheWEgVGhhaTEsMCoGA1UEChMjS2FzaWtvcm5iYW5rIFB1Ymxp\n"\
"YyBDb21wYW55IExpbWl0ZWQxJjAkBgNVBAMTHW9wZW5hcGktdGVzdC5rYXNpa29y\n"\
"bmJhbmsuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmFcYWAxS\n"\
"8XZbYzkYC4uE1soBelcH6VHYNxDbXplyGiQM5/l+FbPwBhaGZV1FHPj1vuyFhOV2\n"\
"lMJzwt9FYXrh8aZwJpI4JObTosnyZ6/T5DM+EPMhm6kqMBVmFVia+UrB51Q3TJWI\n"\
"ZIWwtheKjGUQuOoUz+UetMzfv63doWZQqI1lVDuoeR8/nKMIq3zYu8GV8yLX+BcQ\n"\
"ltt37vcvhScNHJ6dZnRHBMdu17UFvyxt7hQactuxbpRgg7Xe+sP68ea38Z9K8CRw\n"\
"PnI1Nc+NlC0b6oKsyrkL/MTxybqqKewLKNei612GsSvl7x56RmLNHTasGpxAcQlH\n"\
"fOaKnX4EZvzrswIDAQABo4IDODCCAzQwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB\n"\
"/wQCMAAwgY4GCCsGAQUFBwEBBIGBMH8wRAYIKwYBBQUHMAKGOGh0dHA6Ly9zZWN1\n"\
"cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzcnNhb3Zzc2xjYTIwMTguY3J0MDcG\n"\
"CCsGAQUFBzABhitodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9nc3JzYW92c3Ns\n"\
"Y2EyMDE4MFYGA1UdIARPME0wQQYJKwYBBAGgMgEUMDQwMgYIKwYBBQUHAgEWJmh0\n"\
"dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAgGBmeBDAECAjBK\n"\
"BgNVHREEQzBBgh1vcGVuYXBpLXRlc3Qua2FzaWtvcm5iYW5rLmNvbYIgb3BlbmFw\n"\
"aS1zYW5kYm94Lmthc2lrb3JuYmFuay5jb20wHQYDVR0lBBYwFAYIKwYBBQUHAwEG\n"\
"CCsGAQUFBwMCMB8GA1UdIwQYMBaAFPjvf/LNeGeo3m+PJI2I8YcDArPrMB0GA1Ud\n"\
"DgQWBBS/F93S4c39yvDXVVgAzLd0Oe33JzCCAX4GCisGAQQB1nkCBAIEggFuBIIB\n"\
"agFoAHUAZBHEbKQS7KeJHKICLgC8q08oB9QeNSer6v7VA8l9zfAAAAGU9BPqjwAA\n"\
"BAMARjBEAiAFDcq881W9zEHmvRwTPQWMaplnX7mdop+u24CL2jhnowIgRb0EIjqR\n"\
"uaF1gzHCmthAOmK2v3RiUDsdE7wB9aHjc8kAdgAOV5S8866pPjMbLJkHs/eQ35vC\n"\
"PXEyJd0hqSWsYcVOIQAAAZT0E+vkAAAEAwBHMEUCIQDz3a2fCB9Qlzzzey390dRG\n"\
"SlSmQmsHPtWDcRwpUVP6AAIgNyPG9T0ZORq+7pzKrWtgo0f5FtT3mJCkrGooQSgm\n"\
"itkAdwAlL5TCKynpbp9BGnIHK2lcW1L/l6kNJUC7/NxR7E3uCwAAAZT0E+pWAAAE\n"\
"AwBIMEYCIQDCFnfJuh8quUT47V6QR0es3rnmszcS90zK7JOGWwmKrQIhAKKQ/74d\n"\
"fkMrKMkI9R6S4RO3v+vzagEBCxN8J0Y8BB0mMA0GCSqGSIb3DQEBCwUAA4IBAQAl\n"\
"nM1hZejsy1cDICE2RqAEKbvoO1AqG+235nMkKd5AGR8jXfbiR9wsgRlAZm3NtSCD\n"\
"Qt9Q5IGl6g9xEFEkONUwCkd4H0nw2Tb9viNJ463NN0rsd/2xtMZ1lPVBhx0wwDCD\n"\
"y5UEOjen9QDXHTP6UL4zjb2eePPu3yISw94hDr7Ur7XB3HyG3n6X+/PI7BSEBcZ8\n"\
"hgJpLJ9thE0s84r2QREifceVVL0eN2hD7M7OywnoTObhu1+EOKCuOKqN23NjaXK9\n"\
"1B14H3+/mJZwhQI/I7n6O4R5Ww+1MPnxXiRTwHF21AWb5tN3ZkFlXf4jh+xK0ngG\n"\
"3Y/7ebXNEA8+F00dW6nc\n"\
"-----END CERTIFICATE-----\n"\
"-----BEGIN CERTIFICATE-----\n"\
"MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw\n"\
"HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs\n"\
"U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx\n"\
"MjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52\n"\
"LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw\n"\
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP\n"\
"UGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3\n"\
"idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM\n"\
"abO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1\n"\
"lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq\n"\
"o8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA\n"\
"AaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G\n"\
"A1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F\n"\
"JK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6\n"\
"Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl\n"\
"aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+\n"\
"MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\n"\
"b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz\n"\
"EdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb\n"\
"0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0\n"\
"6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw\n"\
"fpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz\n"\
"hriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e\n"\
"SPY=\n"\
"-----END CERTIFICATE-----\n"\
"-----BEGIN CERTIFICATE-----\n"\
"MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\n"\
"A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\n"\
"Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\n"\
"MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\n"\
"A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n"\
"hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\n"\
"RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\n"\
"gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\n"\
"KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\n"\
"QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\n"\
"XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\n"\
"DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\n"\
"LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\n"\
"RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\n"\
"jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\n"\
"6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\n"\
"mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\n"\
"Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\n"\
"WD9f\n"\
"-----END CERTIFICATE-----\n";
const char* scbclientCert = \
"-----BEGIN CERTIFICATE-----\n"\
"MIIDZDCCAkygAwIBAgIUXAFPPIpZYBrNg4ENxSIBmTG3yuYwDQYJKoZIhvcNAQEL\n"\
"BQAwbDELMAkGA1UEBhMCVEgxETAPBgNVBAgMCFNvbmdraGxhMREwDwYDVQQHDAhO\n"\
"YXRoYXdlZTEQMA4GA1UECgwHUG9yamFpaTEQMA4GA1UECwwHUG9yamFpaTETMBEG\n"\
"A1UEAwwKYXJkdWluby5jYzAeFw0yNTA5MTAwMzQyMzJaFw0yNzA5MTAwMzQyMzJa\n"\
"MGwxCzAJBgNVBAYTAlRIMREwDwYDVQQIDAhTb25na2hsYTERMA8GA1UEBwwITmF0\n"\
"aGF3ZWUxEDAOBgNVBAoMB1BvcmphaWkxEDAOBgNVBAsMB1BvcmphaWkxEzARBgNV\n"\
"BAMMCmFyZHVpbm8uY2MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx\n"\
"bpWvqQKF2dppcqfJVC0U3DDem6MxAaKBrebiksv1W/s3xeN2vX/11EXhivsckXyC\n"\
"gV7px+s2jQe7u/l8TCoIDiiTxy7YDZ/eNnQCvBUKYaKpVW6xW9btufYJQGe3/Abc\n"\
"dwWq9jVY/NephRvSZZBkut2VwK9CATZYtoSkSwGSW4unpNaeh0uMFiUDWpvXQLmT\n"\
"wwCwVeTms7qCR6bKBcsL4FiD1wk1Mws9eySlz0tQTjKoEEwz+5b4HHCZtBgqw3cZ\n"\
"nlBJl78n0eqX94A7YETYG8nbAMBDl+Q8FPqT+TNeBk77HFjJML41NmBmAwh2CT/p\n"\
"RE1pdsf+O9U7NnHgsJkDAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJFWPxuSRvU5\n"\
"vJYo5m3tEYuX51o9AnY3BqYYGwBLgGZ3NPOrgDXE05dp0tFZBfAIw7sunP7qtAFy\n"\
"B+OuqbfZ2d8SuU9gGuTd83kQ8LM/ceKIZ3vqbtUu8HcomDRo9L2lt2pMplRPdX6A\n"\
"LaX5Xt1IjzbrHRoI4qby5HfTb7HUVMDzZ8KpY1RLvgLo5L9asAoBEkr9c2gJJ0sZ\n"\
"5eArLpzNjIja88D/ggLQ6fbVTJv6WXH02hZUQ2JKTLm1jq/UKaf/Q9hHJbUA2Tjx\n"\
"sgrCh7C0V/ut+L7chac+g81i9PWY0fs+vCUUnzbYVAZr/agLFrB8JzNvW73x/R49\n"\
"53tLZ23VU1A=\n"\
"-----END CERTIFICATE-----\n";
const char* scbPrivateKey = \
"-----BEGIN PRIVATE KEY-----\n"\
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxbpWvqQKF2dpp\n"\
"cqfJVC0U3DDem6MxAaKBrebiksv1W/s3xeN2vX/11EXhivsckXyCgV7px+s2jQe7\n"\
"u/l8TCoIDiiTxy7YDZ/eNnQCvBUKYaKpVW6xW9btufYJQGe3/AbcdwWq9jVY/Nep\n"\
"hRvSZZBkut2VwK9CATZYtoSkSwGSW4unpNaeh0uMFiUDWpvXQLmTwwCwVeTms7qC\n"\
"R6bKBcsL4FiD1wk1Mws9eySlz0tQTjKoEEwz+5b4HHCZtBgqw3cZnlBJl78n0eqX\n"\
"94A7YETYG8nbAMBDl+Q8FPqT+TNeBk77HFjJML41NmBmAwh2CT/pRE1pdsf+O9U7\n"\
"NnHgsJkDAgMBAAECggEAMdIdUb+hJ7huLaG2Hz/1kJ/rUPZeskoFOWh9Ji2V+4Ui\n"\
"WxzDq/m1zm8WWChQLktjrLlqzzYFg8HB5CL6AL7aJnzjQ+tv6daZhym/FW1+cvXL\n"\
"WMTWWhKxnPrUbPCarvyjaJA7FTAg9qW4YK8xirhd/QrDYWNDUsNIYUyOnhs5i8CU\n"\
"qXOMWdFD4l+3OMv0ey6TiMluq1A9iVkCFUqtXQI1B4Pp6J5WaYdLCdmYgzD5zJoV\n"\
"YB9O+T8Cwk8wyqAnyaFSl5jp4Zgl4poIxzR5Vl6Y8gxZ6dOWnFm8raNAqdQKYSNi\n"\
"rE+MlRH3qx7a4IMelPsZgqpbo4vgIANcxEQR7sXBkQKBgQDoX28DVa8+n9wUhTsm\n"\
"3T0U2H0IfdORe/AoKO7CrNljo/UZeSnfD0RaH/rvyplw3s0zoeckvdrmZeX+5nA5\n"\
"1gKO3+4Lu6A67KjHrYPu2KuHe1ApxpbcVJZ935X0QbyMw6k0gkuiDpXzqoEfyGN9\n"\
"vAtOsdzV5GcSkEL63oCBbRUYHQKBgQDDeRCLkMWbodyAR1KpUuTqtyRd6HWSMQ0k\n"\
"zjGKRxS52XrEAC8HQonhig69Lag/eYvgFPsemyHxEw/dtkG/iK8KqFHmMxGJ0CeA\n"\
"4ohCvvC8WhQa3EYMVWO2VV/b0gS5OmCcmsi+dIK95SAtLRtW3OoR2ywr9CNF3FNS\n"\
"nlyKfwTrnwKBgGkVRzml1QMn/bmV6oMPx6CWqixd4oBHIPq4UAjfa8ugiKWFYocJ\n"\
"+2oaTjuETlF5oCh6TfISnVxVtmXIRfYRrsR3xcmuhq4++bCa6i/n8eHpxP2vXeez\n"\
"pP61TrXPyHmLvggN6DAYEn3HnG8ICt4AXMiwrGJZ0LbXYELcvhZJgyGNAoGAWZel\n"\
"o7JpQBoCDLGkC4O49HOYsYoYSTc+RP5U6oIF1+D8SdWjuHog5ET42HCSyvUUzVIQ\n"\
"f0ivV+Vawk4E+JrXT9UyJIaHpVjIomQx/BW0FUBcMqt/V6vTlgCvfPtXuuYs3dp7\n"\
"4/9W5V6dTtd7zmZWynRgXIz7lcuUTSvUUo5BXRUCgYEAzekK/kz1iAlfsVfH2tri\n"\
"vqyvXQEfxT3MHiTtoQZ6GKqOoNa+7yFDnq7nriqNJx0lyyHjQSmrfqeZJdjla4ma\n"\
"I9aJKMp9f26/94QOwfY4G4uIfoq9n6stcYU+GNwyMuE3l/28FxZ9Gg0EwKK7V2Ux\n"\
"X0Lzhe+1ZNEeOS32ksPoVu4=\n"\
"-----END PRIVATE KEY-----\n";
client->setCertificate(scbclientCert);
client->setPrivateKey(scbPrivateKey);
client->setCACert(scbRootCACert);
time_t t = time(nullptr);
            struct tm * now = localtime(&t);
            char buf[32];
            sprintf(buf, "%04d-%02d-%02dT%02d:%02d:%02d",
                    now->tm_year+1900, now->tm_mon+1, now->tm_mday,
                    now->tm_hour, now->tm_min, now->tm_sec);
            String requestDt(buf);
            ESP_LOGE(TAG, "time %s",requestDt.c_str());
    //client->setInsecure(); // TODO: add CACert
    {
        HTTPClient http;
        if (http.begin(*client, "https://" API_HOST "/v2/oauth/token")) {
            String credentials = this->apiKey + ":" + this->apiSecret;
            String base64Cred = encodeBase64(credentials);

            http.addHeader("Content-Type", "application/x-www-form-urlencoded");
            http.addHeader("Authorization", "Basic " + base64Cred);
            http.addHeader("env-id", "OAUTH2");
            http.addHeader("x-test-mode", "true");
            

            String payload = "grant_type=client_credentials";
            int status = http.POST(payload);
            String resp = http.getString();

            if (status == HTTP_CODE_OK) {
                // ใช้ JsonDocument แค่ตัวเดียว
                DynamicJsonDocument doc(512);
                auto error = deserializeJson(doc, resp);
                if(!error) {
                    if(!doc["access_token"].isNull()) {
                        this->accessToken = doc["access_token"].as<String>();
                        this->expiresIn = doc["expires_in"].as<uint32_t>();
                        this->accessTokenUpdateAt = millis();
                        ESP_LOGI(TAG, "access_token: %s", this->accessToken.c_str());
                        ESP_LOGI(TAG, "expires_in: %d", this->expiresIn);
                        ok = true;
                    } else {
                        ESP_LOGE(TAG, "access_token not found in response");
                    }
                } else {
                    ESP_LOGE(TAG, "JSON parse error: %s", error.c_str());
                }
            } else {
                ESP_LOGE(TAG, "HTTP POST failed, status: %d", status);
            }
            http.end();
        } else {
            ESP_LOGE(TAG, "HTTP begin failed");
        }
    }

    delete client;
    return ok;
}

bool Rachanon_K_API::tokenRefresh() {
    if (this->verifyToken()) {
        return true; // ยังไม่หมดอายุ
    }
    return this->genToken(); // ถ้าหมดอายุ → ขอใหม่
}

/*
 * Ref1 & Ref2 & Ref3 => English capital letter and number only.
*/
bool Rachanon_K_API::QRCodeTag30Create(double amount, String ref1, String ref2, String ref3, String ref4, String *qrRawData) {
    if (!this->verifyToken()) {
        if (!this->genToken()) {
            return false;
        }
    }

    // QR Tag 30
    WiFiClientSecure *client = new WiFiClientSecure;
    if(!client) {
        ESP_LOGE(TAG, "create WiFiClientSecure fail");
        return false;
    }

    bool ok = false;
      const char* scbRootCACert = \
"-----BEGIN CERTIFICATE-----\n"\
"MIIGmzCCBYOgAwIBAgIMUHkPQ9HiEV14N4eYMA0GCSqGSIb3DQEBCwUAMFAxCzAJ\n"\
"BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H\n"\
"bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yNTAyMTEwODE1MzFaFw0y\n"\
"NjAzMTUwODE1MzBaMIGKMQswCQYDVQQGEwJUSDEQMA4GA1UECBMHQmFuZ2tvazET\n"\
"MBEGA1UEBxMKUGhheWEgVGhhaTEsMCoGA1UEChMjS2FzaWtvcm5iYW5rIFB1Ymxp\n"\
"YyBDb21wYW55IExpbWl0ZWQxJjAkBgNVBAMTHW9wZW5hcGktdGVzdC5rYXNpa29y\n"\
"bmJhbmsuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmFcYWAxS\n"\
"8XZbYzkYC4uE1soBelcH6VHYNxDbXplyGiQM5/l+FbPwBhaGZV1FHPj1vuyFhOV2\n"\
"lMJzwt9FYXrh8aZwJpI4JObTosnyZ6/T5DM+EPMhm6kqMBVmFVia+UrB51Q3TJWI\n"\
"ZIWwtheKjGUQuOoUz+UetMzfv63doWZQqI1lVDuoeR8/nKMIq3zYu8GV8yLX+BcQ\n"\
"ltt37vcvhScNHJ6dZnRHBMdu17UFvyxt7hQactuxbpRgg7Xe+sP68ea38Z9K8CRw\n"\
"PnI1Nc+NlC0b6oKsyrkL/MTxybqqKewLKNei612GsSvl7x56RmLNHTasGpxAcQlH\n"\
"fOaKnX4EZvzrswIDAQABo4IDODCCAzQwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB\n"\
"/wQCMAAwgY4GCCsGAQUFBwEBBIGBMH8wRAYIKwYBBQUHMAKGOGh0dHA6Ly9zZWN1\n"\
"cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzcnNhb3Zzc2xjYTIwMTguY3J0MDcG\n"\
"CCsGAQUFBzABhitodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9nc3JzYW92c3Ns\n"\
"Y2EyMDE4MFYGA1UdIARPME0wQQYJKwYBBAGgMgEUMDQwMgYIKwYBBQUHAgEWJmh0\n"\
"dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAgGBmeBDAECAjBK\n"\
"BgNVHREEQzBBgh1vcGVuYXBpLXRlc3Qua2FzaWtvcm5iYW5rLmNvbYIgb3BlbmFw\n"\
"aS1zYW5kYm94Lmthc2lrb3JuYmFuay5jb20wHQYDVR0lBBYwFAYIKwYBBQUHAwEG\n"\
"CCsGAQUFBwMCMB8GA1UdIwQYMBaAFPjvf/LNeGeo3m+PJI2I8YcDArPrMB0GA1Ud\n"\
"DgQWBBS/F93S4c39yvDXVVgAzLd0Oe33JzCCAX4GCisGAQQB1nkCBAIEggFuBIIB\n"\
"agFoAHUAZBHEbKQS7KeJHKICLgC8q08oB9QeNSer6v7VA8l9zfAAAAGU9BPqjwAA\n"\
"BAMARjBEAiAFDcq881W9zEHmvRwTPQWMaplnX7mdop+u24CL2jhnowIgRb0EIjqR\n"\
"uaF1gzHCmthAOmK2v3RiUDsdE7wB9aHjc8kAdgAOV5S8866pPjMbLJkHs/eQ35vC\n"\
"PXEyJd0hqSWsYcVOIQAAAZT0E+vkAAAEAwBHMEUCIQDz3a2fCB9Qlzzzey390dRG\n"\
"SlSmQmsHPtWDcRwpUVP6AAIgNyPG9T0ZORq+7pzKrWtgo0f5FtT3mJCkrGooQSgm\n"\
"itkAdwAlL5TCKynpbp9BGnIHK2lcW1L/l6kNJUC7/NxR7E3uCwAAAZT0E+pWAAAE\n"\
"AwBIMEYCIQDCFnfJuh8quUT47V6QR0es3rnmszcS90zK7JOGWwmKrQIhAKKQ/74d\n"\
"fkMrKMkI9R6S4RO3v+vzagEBCxN8J0Y8BB0mMA0GCSqGSIb3DQEBCwUAA4IBAQAl\n"\
"nM1hZejsy1cDICE2RqAEKbvoO1AqG+235nMkKd5AGR8jXfbiR9wsgRlAZm3NtSCD\n"\
"Qt9Q5IGl6g9xEFEkONUwCkd4H0nw2Tb9viNJ463NN0rsd/2xtMZ1lPVBhx0wwDCD\n"\
"y5UEOjen9QDXHTP6UL4zjb2eePPu3yISw94hDr7Ur7XB3HyG3n6X+/PI7BSEBcZ8\n"\
"hgJpLJ9thE0s84r2QREifceVVL0eN2hD7M7OywnoTObhu1+EOKCuOKqN23NjaXK9\n"\
"1B14H3+/mJZwhQI/I7n6O4R5Ww+1MPnxXiRTwHF21AWb5tN3ZkFlXf4jh+xK0ngG\n"\
"3Y/7ebXNEA8+F00dW6nc\n"\
"-----END CERTIFICATE-----\n"\
"-----BEGIN CERTIFICATE-----\n"\
"MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw\n"\
"HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs\n"\
"U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx\n"\
"MjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52\n"\
"LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw\n"\
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP\n"\
"UGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3\n"\
"idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM\n"\
"abO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1\n"\
"lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq\n"\
"o8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA\n"\
"AaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G\n"\
"A1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F\n"\
"JK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6\n"\
"Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl\n"\
"aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+\n"\
"MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\n"\
"b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz\n"\
"EdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb\n"\
"0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0\n"\
"6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw\n"\
"fpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz\n"\
"hriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e\n"\
"SPY=\n"\
"-----END CERTIFICATE-----\n"\
"-----BEGIN CERTIFICATE-----\n"\
"MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\n"\
"A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\n"\
"Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\n"\
"MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\n"\
"A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n"\
"hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\n"\
"RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\n"\
"gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\n"\
"KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\n"\
"QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\n"\
"XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\n"\
"DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\n"\
"LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\n"\
"RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\n"\
"jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\n"\
"6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\n"\
"mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\n"\
"Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\n"\
"WD9f\n"\
"-----END CERTIFICATE-----\n";
const char* scbclientCert = \
"-----BEGIN CERTIFICATE-----\n"\
"MIIDZDCCAkygAwIBAgIUXAFPPIpZYBrNg4ENxSIBmTG3yuYwDQYJKoZIhvcNAQEL\n"\
"BQAwbDELMAkGA1UEBhMCVEgxETAPBgNVBAgMCFNvbmdraGxhMREwDwYDVQQHDAhO\n"\
"YXRoYXdlZTEQMA4GA1UECgwHUG9yamFpaTEQMA4GA1UECwwHUG9yamFpaTETMBEG\n"\
"A1UEAwwKYXJkdWluby5jYzAeFw0yNTA5MTAwMzQyMzJaFw0yNzA5MTAwMzQyMzJa\n"\
"MGwxCzAJBgNVBAYTAlRIMREwDwYDVQQIDAhTb25na2hsYTERMA8GA1UEBwwITmF0\n"\
"aGF3ZWUxEDAOBgNVBAoMB1BvcmphaWkxEDAOBgNVBAsMB1BvcmphaWkxEzARBgNV\n"\
"BAMMCmFyZHVpbm8uY2MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx\n"\
"bpWvqQKF2dppcqfJVC0U3DDem6MxAaKBrebiksv1W/s3xeN2vX/11EXhivsckXyC\n"\
"gV7px+s2jQe7u/l8TCoIDiiTxy7YDZ/eNnQCvBUKYaKpVW6xW9btufYJQGe3/Abc\n"\
"dwWq9jVY/NephRvSZZBkut2VwK9CATZYtoSkSwGSW4unpNaeh0uMFiUDWpvXQLmT\n"\
"wwCwVeTms7qCR6bKBcsL4FiD1wk1Mws9eySlz0tQTjKoEEwz+5b4HHCZtBgqw3cZ\n"\
"nlBJl78n0eqX94A7YETYG8nbAMBDl+Q8FPqT+TNeBk77HFjJML41NmBmAwh2CT/p\n"\
"RE1pdsf+O9U7NnHgsJkDAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJFWPxuSRvU5\n"\
"vJYo5m3tEYuX51o9AnY3BqYYGwBLgGZ3NPOrgDXE05dp0tFZBfAIw7sunP7qtAFy\n"\
"B+OuqbfZ2d8SuU9gGuTd83kQ8LM/ceKIZ3vqbtUu8HcomDRo9L2lt2pMplRPdX6A\n"\
"LaX5Xt1IjzbrHRoI4qby5HfTb7HUVMDzZ8KpY1RLvgLo5L9asAoBEkr9c2gJJ0sZ\n"\
"5eArLpzNjIja88D/ggLQ6fbVTJv6WXH02hZUQ2JKTLm1jq/UKaf/Q9hHJbUA2Tjx\n"\
"sgrCh7C0V/ut+L7chac+g81i9PWY0fs+vCUUnzbYVAZr/agLFrB8JzNvW73x/R49\n"\
"53tLZ23VU1A=\n"\
"-----END CERTIFICATE-----\n";
const char* scbPrivateKey = \
"-----BEGIN PRIVATE KEY-----\n"\
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxbpWvqQKF2dpp\n"\
"cqfJVC0U3DDem6MxAaKBrebiksv1W/s3xeN2vX/11EXhivsckXyCgV7px+s2jQe7\n"\
"u/l8TCoIDiiTxy7YDZ/eNnQCvBUKYaKpVW6xW9btufYJQGe3/AbcdwWq9jVY/Nep\n"\
"hRvSZZBkut2VwK9CATZYtoSkSwGSW4unpNaeh0uMFiUDWpvXQLmTwwCwVeTms7qC\n"\
"R6bKBcsL4FiD1wk1Mws9eySlz0tQTjKoEEwz+5b4HHCZtBgqw3cZnlBJl78n0eqX\n"\
"94A7YETYG8nbAMBDl+Q8FPqT+TNeBk77HFjJML41NmBmAwh2CT/pRE1pdsf+O9U7\n"\
"NnHgsJkDAgMBAAECggEAMdIdUb+hJ7huLaG2Hz/1kJ/rUPZeskoFOWh9Ji2V+4Ui\n"\
"WxzDq/m1zm8WWChQLktjrLlqzzYFg8HB5CL6AL7aJnzjQ+tv6daZhym/FW1+cvXL\n"\
"WMTWWhKxnPrUbPCarvyjaJA7FTAg9qW4YK8xirhd/QrDYWNDUsNIYUyOnhs5i8CU\n"\
"qXOMWdFD4l+3OMv0ey6TiMluq1A9iVkCFUqtXQI1B4Pp6J5WaYdLCdmYgzD5zJoV\n"\
"YB9O+T8Cwk8wyqAnyaFSl5jp4Zgl4poIxzR5Vl6Y8gxZ6dOWnFm8raNAqdQKYSNi\n"\
"rE+MlRH3qx7a4IMelPsZgqpbo4vgIANcxEQR7sXBkQKBgQDoX28DVa8+n9wUhTsm\n"\
"3T0U2H0IfdORe/AoKO7CrNljo/UZeSnfD0RaH/rvyplw3s0zoeckvdrmZeX+5nA5\n"\
"1gKO3+4Lu6A67KjHrYPu2KuHe1ApxpbcVJZ935X0QbyMw6k0gkuiDpXzqoEfyGN9\n"\
"vAtOsdzV5GcSkEL63oCBbRUYHQKBgQDDeRCLkMWbodyAR1KpUuTqtyRd6HWSMQ0k\n"\
"zjGKRxS52XrEAC8HQonhig69Lag/eYvgFPsemyHxEw/dtkG/iK8KqFHmMxGJ0CeA\n"\
"4ohCvvC8WhQa3EYMVWO2VV/b0gS5OmCcmsi+dIK95SAtLRtW3OoR2ywr9CNF3FNS\n"\
"nlyKfwTrnwKBgGkVRzml1QMn/bmV6oMPx6CWqixd4oBHIPq4UAjfa8ugiKWFYocJ\n"\
"+2oaTjuETlF5oCh6TfISnVxVtmXIRfYRrsR3xcmuhq4++bCa6i/n8eHpxP2vXeez\n"\
"pP61TrXPyHmLvggN6DAYEn3HnG8ICt4AXMiwrGJZ0LbXYELcvhZJgyGNAoGAWZel\n"\
"o7JpQBoCDLGkC4O49HOYsYoYSTc+RP5U6oIF1+D8SdWjuHog5ET42HCSyvUUzVIQ\n"\
"f0ivV+Vawk4E+JrXT9UyJIaHpVjIomQx/BW0FUBcMqt/V6vTlgCvfPtXuuYs3dp7\n"\
"4/9W5V6dTtd7zmZWynRgXIz7lcuUTSvUUo5BXRUCgYEAzekK/kz1iAlfsVfH2tri\n"\
"vqyvXQEfxT3MHiTtoQZ6GKqOoNa+7yFDnq7nriqNJx0lyyHjQSmrfqeZJdjla4ma\n"\
"I9aJKMp9f26/94QOwfY4G4uIfoq9n6stcYU+GNwyMuE3l/28FxZ9Gg0EwKK7V2Ux\n"\
"X0Lzhe+1ZNEeOS32ksPoVu4=\n"\
"-----END PRIVATE KEY-----\n";
client->setCertificate(scbclientCert);
client->setPrivateKey(scbPrivateKey);
client->setCACert(scbRootCACert);
time_t t = time(nullptr);
            struct tm * now = localtime(&t);
            char buf[32];
            sprintf(buf, "%04d-%02d-%02dT%02d:%02d:%02d+07:00",
                    now->tm_year+1900, now->tm_mon+1, now->tm_mday,
                    now->tm_hour, now->tm_min, now->tm_sec);
            String requestDt(buf);
            ESP_LOGE(TAG, "time %s",requestDt);
    ///client->setInsecure(); // TODO: add CACert
    {
        HTTPClient http;
        if (http.begin(*client, "https://" API_HOST "/v1/qrpayment/request")) {
            http.addHeader("Authorization", "Bearer " + this->accessToken);
            http.addHeader("Content-Type", "application/json");
            http.addHeader("env-id", "QR002");
	        http.addHeader("x-test-mode", "true");
	        

	    
            String payload = "";
            payload += "{";
            payload += "\"partnerTxnUid\": \"PARTNERTEST0001\", ";
            payload += "\"partnerId\": \"PTR1051673\", ";
            payload += "\"partnerSecret\": \"d4bded59200547bc85903574a293831b\", ";
            payload += "\"requestDt\": \"" + requestDt + "\", ";
            payload += "\"merchantId\": \"KB102057149704\", ";
            payload += "\"qrType\": \"3\", ";
            payload += "\"txnAmount\": \"" + String(amount, 2) + "\", ";
            payload += "\"txnCurrencyCode\": \"THB\", ";
            payload += "\"reference1\": \"INV001\", ";
            payload += "\"reference2\": \"HELLOWORLD\", ";
            payload += "\"reference3\": \"INV001\", ";
            payload += "\"reference4\": \"INV001\", ";
            payload += "\"metadata\": \"Coin1:" + String(amount, 2) + "THB\" ";
            payload += "}";
            this->statusCode = http.POST(payload);
            if (this->statusCode == HTTP_CODE_OK) {
                String payload = http.getString();
                ESP_LOGV(TAG, "%s", payload.c_str());

                DynamicJsonDocument doc(4096);
                if (deserializeJson(doc, payload) == DeserializationError::Ok) {
                    int code = 0;
                    if (!doc["statusCode"].isNull()) {
                        code = doc["statusCode"].as<int>();
                    }
                        if (!doc["qrCode"].isNull()) {
                            *qrRawData = doc["qrCode"].as<String>();
                            partnerTxnUid = doc["partnerTxnUid"].as<String>();
                            partnerId = doc["partnerId"].as<String>();
                            ESP_LOGI(TAG, "qrCode: %s", qrRawData->c_str());
                            
                            this->lastAmount = amount;
                            this->lastRef1 = ref1;
			                this->lastRef2 = ref2;
			                this->lastRef3 = ref3;
			                this->lastRef4 = ref4;
                            this->partnerTxnUid = partnerTxnUid;
                            this->partnerId = partnerId;


                            time_t t = time(nullptr);
                            t += 7 * 60 * 60; // +7
                            struct tm * now = localtime(&t);
                            this->lastTransactionDate = "";
                            this->lastTransactionDate += String(now->tm_year + 1900);
                            this->lastTransactionDate += "-";
                            if ((now->tm_mon + 1) < 10) {
                                this->lastTransactionDate += "0";
                            }
                            this->lastTransactionDate += String(now->tm_mon + 1);
                            this->lastTransactionDate += "-";
                            if (now->tm_mday < 10) {
                                this->lastTransactionDate += "0";
                            }
                            this->lastTransactionDate += String(now->tm_mday);
                            
                            ok = true;
                        
                        
                    } else {
                    ESP_LOGE(TAG, "json decode fail");
                    }
            } else {
                ESP_LOGE(TAG, "GET... failed, error: %s", http.errorToString(this->statusCode).c_str());
            }
        } else {
            ESP_LOGE(TAG, "Unable to connect");
        }
        }

        http.end();
    }
  
    delete client;

    return ok;
}

bool Rachanon_K_API::checkPaymentConfirm(bool *paymentAreConfirm) {
    *paymentAreConfirm = false;

   /* if (!this->verifyToken()) {
        if (!this->genToken()) {
            ESP_LOGE(TAG, "Failed to refresh token");
            return false;
        }
    }*/

    WiFiClientSecure *client = new WiFiClientSecure;
    if (!client) {
        ESP_LOGE(TAG, "create WiFiClientSecure fail");
        return false;
    }


      const char* scbRootCACert = \
"-----BEGIN CERTIFICATE-----\n"\
"MIIGmzCCBYOgAwIBAgIMUHkPQ9HiEV14N4eYMA0GCSqGSIb3DQEBCwUAMFAxCzAJ\n"\
"BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H\n"\
"bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yNTAyMTEwODE1MzFaFw0y\n"\
"NjAzMTUwODE1MzBaMIGKMQswCQYDVQQGEwJUSDEQMA4GA1UECBMHQmFuZ2tvazET\n"\
"MBEGA1UEBxMKUGhheWEgVGhhaTEsMCoGA1UEChMjS2FzaWtvcm5iYW5rIFB1Ymxp\n"\
"YyBDb21wYW55IExpbWl0ZWQxJjAkBgNVBAMTHW9wZW5hcGktdGVzdC5rYXNpa29y\n"\
"bmJhbmsuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmFcYWAxS\n"\
"8XZbYzkYC4uE1soBelcH6VHYNxDbXplyGiQM5/l+FbPwBhaGZV1FHPj1vuyFhOV2\n"\
"lMJzwt9FYXrh8aZwJpI4JObTosnyZ6/T5DM+EPMhm6kqMBVmFVia+UrB51Q3TJWI\n"\
"ZIWwtheKjGUQuOoUz+UetMzfv63doWZQqI1lVDuoeR8/nKMIq3zYu8GV8yLX+BcQ\n"\
"ltt37vcvhScNHJ6dZnRHBMdu17UFvyxt7hQactuxbpRgg7Xe+sP68ea38Z9K8CRw\n"\
"PnI1Nc+NlC0b6oKsyrkL/MTxybqqKewLKNei612GsSvl7x56RmLNHTasGpxAcQlH\n"\
"fOaKnX4EZvzrswIDAQABo4IDODCCAzQwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB\n"\
"/wQCMAAwgY4GCCsGAQUFBwEBBIGBMH8wRAYIKwYBBQUHMAKGOGh0dHA6Ly9zZWN1\n"\
"cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzcnNhb3Zzc2xjYTIwMTguY3J0MDcG\n"\
"CCsGAQUFBzABhitodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9nc3JzYW92c3Ns\n"\
"Y2EyMDE4MFYGA1UdIARPME0wQQYJKwYBBAGgMgEUMDQwMgYIKwYBBQUHAgEWJmh0\n"\
"dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAgGBmeBDAECAjBK\n"\
"BgNVHREEQzBBgh1vcGVuYXBpLXRlc3Qua2FzaWtvcm5iYW5rLmNvbYIgb3BlbmFw\n"\
"aS1zYW5kYm94Lmthc2lrb3JuYmFuay5jb20wHQYDVR0lBBYwFAYIKwYBBQUHAwEG\n"\
"CCsGAQUFBwMCMB8GA1UdIwQYMBaAFPjvf/LNeGeo3m+PJI2I8YcDArPrMB0GA1Ud\n"\
"DgQWBBS/F93S4c39yvDXVVgAzLd0Oe33JzCCAX4GCisGAQQB1nkCBAIEggFuBIIB\n"\
"agFoAHUAZBHEbKQS7KeJHKICLgC8q08oB9QeNSer6v7VA8l9zfAAAAGU9BPqjwAA\n"\
"BAMARjBEAiAFDcq881W9zEHmvRwTPQWMaplnX7mdop+u24CL2jhnowIgRb0EIjqR\n"\
"uaF1gzHCmthAOmK2v3RiUDsdE7wB9aHjc8kAdgAOV5S8866pPjMbLJkHs/eQ35vC\n"\
"PXEyJd0hqSWsYcVOIQAAAZT0E+vkAAAEAwBHMEUCIQDz3a2fCB9Qlzzzey390dRG\n"\
"SlSmQmsHPtWDcRwpUVP6AAIgNyPG9T0ZORq+7pzKrWtgo0f5FtT3mJCkrGooQSgm\n"\
"itkAdwAlL5TCKynpbp9BGnIHK2lcW1L/l6kNJUC7/NxR7E3uCwAAAZT0E+pWAAAE\n"\
"AwBIMEYCIQDCFnfJuh8quUT47V6QR0es3rnmszcS90zK7JOGWwmKrQIhAKKQ/74d\n"\
"fkMrKMkI9R6S4RO3v+vzagEBCxN8J0Y8BB0mMA0GCSqGSIb3DQEBCwUAA4IBAQAl\n"\
"nM1hZejsy1cDICE2RqAEKbvoO1AqG+235nMkKd5AGR8jXfbiR9wsgRlAZm3NtSCD\n"\
"Qt9Q5IGl6g9xEFEkONUwCkd4H0nw2Tb9viNJ463NN0rsd/2xtMZ1lPVBhx0wwDCD\n"\
"y5UEOjen9QDXHTP6UL4zjb2eePPu3yISw94hDr7Ur7XB3HyG3n6X+/PI7BSEBcZ8\n"\
"hgJpLJ9thE0s84r2QREifceVVL0eN2hD7M7OywnoTObhu1+EOKCuOKqN23NjaXK9\n"\
"1B14H3+/mJZwhQI/I7n6O4R5Ww+1MPnxXiRTwHF21AWb5tN3ZkFlXf4jh+xK0ngG\n"\
"3Y/7ebXNEA8+F00dW6nc\n"\
"-----END CERTIFICATE-----\n"\
"-----BEGIN CERTIFICATE-----\n"\
"MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw\n"\
"HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs\n"\
"U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx\n"\
"MjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52\n"\
"LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw\n"\
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP\n"\
"UGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3\n"\
"idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM\n"\
"abO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1\n"\
"lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq\n"\
"o8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA\n"\
"AaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G\n"\
"A1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F\n"\
"JK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6\n"\
"Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl\n"\
"aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+\n"\
"MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\n"\
"b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz\n"\
"EdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb\n"\
"0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0\n"\
"6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw\n"\
"fpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz\n"\
"hriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e\n"\
"SPY=\n"\
"-----END CERTIFICATE-----\n"\
"-----BEGIN CERTIFICATE-----\n"\
"MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G\n"\
"A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp\n"\
"Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4\n"\
"MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG\n"\
"A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n"\
"hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8\n"\
"RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT\n"\
"gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm\n"\
"KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd\n"\
"QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ\n"\
"XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw\n"\
"DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o\n"\
"LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU\n"\
"RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp\n"\
"jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK\n"\
"6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX\n"\
"mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs\n"\
"Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH\n"\
"WD9f\n"\
"-----END CERTIFICATE-----\n";
const char* scbclientCert = \
"-----BEGIN CERTIFICATE-----\n"\
"MIIDZDCCAkygAwIBAgIUXAFPPIpZYBrNg4ENxSIBmTG3yuYwDQYJKoZIhvcNAQEL\n"\
"BQAwbDELMAkGA1UEBhMCVEgxETAPBgNVBAgMCFNvbmdraGxhMREwDwYDVQQHDAhO\n"\
"YXRoYXdlZTEQMA4GA1UECgwHUG9yamFpaTEQMA4GA1UECwwHUG9yamFpaTETMBEG\n"\
"A1UEAwwKYXJkdWluby5jYzAeFw0yNTA5MTAwMzQyMzJaFw0yNzA5MTAwMzQyMzJa\n"\
"MGwxCzAJBgNVBAYTAlRIMREwDwYDVQQIDAhTb25na2hsYTERMA8GA1UEBwwITmF0\n"\
"aGF3ZWUxEDAOBgNVBAoMB1BvcmphaWkxEDAOBgNVBAsMB1BvcmphaWkxEzARBgNV\n"\
"BAMMCmFyZHVpbm8uY2MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx\n"\
"bpWvqQKF2dppcqfJVC0U3DDem6MxAaKBrebiksv1W/s3xeN2vX/11EXhivsckXyC\n"\
"gV7px+s2jQe7u/l8TCoIDiiTxy7YDZ/eNnQCvBUKYaKpVW6xW9btufYJQGe3/Abc\n"\
"dwWq9jVY/NephRvSZZBkut2VwK9CATZYtoSkSwGSW4unpNaeh0uMFiUDWpvXQLmT\n"\
"wwCwVeTms7qCR6bKBcsL4FiD1wk1Mws9eySlz0tQTjKoEEwz+5b4HHCZtBgqw3cZ\n"\
"nlBJl78n0eqX94A7YETYG8nbAMBDl+Q8FPqT+TNeBk77HFjJML41NmBmAwh2CT/p\n"\
"RE1pdsf+O9U7NnHgsJkDAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJFWPxuSRvU5\n"\
"vJYo5m3tEYuX51o9AnY3BqYYGwBLgGZ3NPOrgDXE05dp0tFZBfAIw7sunP7qtAFy\n"\
"B+OuqbfZ2d8SuU9gGuTd83kQ8LM/ceKIZ3vqbtUu8HcomDRo9L2lt2pMplRPdX6A\n"\
"LaX5Xt1IjzbrHRoI4qby5HfTb7HUVMDzZ8KpY1RLvgLo5L9asAoBEkr9c2gJJ0sZ\n"\
"5eArLpzNjIja88D/ggLQ6fbVTJv6WXH02hZUQ2JKTLm1jq/UKaf/Q9hHJbUA2Tjx\n"\
"sgrCh7C0V/ut+L7chac+g81i9PWY0fs+vCUUnzbYVAZr/agLFrB8JzNvW73x/R49\n"\
"53tLZ23VU1A=\n"\
"-----END CERTIFICATE-----\n";
const char* scbPrivateKey = \
"-----BEGIN PRIVATE KEY-----\n"\
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxbpWvqQKF2dpp\n"\
"cqfJVC0U3DDem6MxAaKBrebiksv1W/s3xeN2vX/11EXhivsckXyCgV7px+s2jQe7\n"\
"u/l8TCoIDiiTxy7YDZ/eNnQCvBUKYaKpVW6xW9btufYJQGe3/AbcdwWq9jVY/Nep\n"\
"hRvSZZBkut2VwK9CATZYtoSkSwGSW4unpNaeh0uMFiUDWpvXQLmTwwCwVeTms7qC\n"\
"R6bKBcsL4FiD1wk1Mws9eySlz0tQTjKoEEwz+5b4HHCZtBgqw3cZnlBJl78n0eqX\n"\
"94A7YETYG8nbAMBDl+Q8FPqT+TNeBk77HFjJML41NmBmAwh2CT/pRE1pdsf+O9U7\n"\
"NnHgsJkDAgMBAAECggEAMdIdUb+hJ7huLaG2Hz/1kJ/rUPZeskoFOWh9Ji2V+4Ui\n"\
"WxzDq/m1zm8WWChQLktjrLlqzzYFg8HB5CL6AL7aJnzjQ+tv6daZhym/FW1+cvXL\n"\
"WMTWWhKxnPrUbPCarvyjaJA7FTAg9qW4YK8xirhd/QrDYWNDUsNIYUyOnhs5i8CU\n"\
"qXOMWdFD4l+3OMv0ey6TiMluq1A9iVkCFUqtXQI1B4Pp6J5WaYdLCdmYgzD5zJoV\n"\
"YB9O+T8Cwk8wyqAnyaFSl5jp4Zgl4poIxzR5Vl6Y8gxZ6dOWnFm8raNAqdQKYSNi\n"\
"rE+MlRH3qx7a4IMelPsZgqpbo4vgIANcxEQR7sXBkQKBgQDoX28DVa8+n9wUhTsm\n"\
"3T0U2H0IfdORe/AoKO7CrNljo/UZeSnfD0RaH/rvyplw3s0zoeckvdrmZeX+5nA5\n"\
"1gKO3+4Lu6A67KjHrYPu2KuHe1ApxpbcVJZ935X0QbyMw6k0gkuiDpXzqoEfyGN9\n"\
"vAtOsdzV5GcSkEL63oCBbRUYHQKBgQDDeRCLkMWbodyAR1KpUuTqtyRd6HWSMQ0k\n"\
"zjGKRxS52XrEAC8HQonhig69Lag/eYvgFPsemyHxEw/dtkG/iK8KqFHmMxGJ0CeA\n"\
"4ohCvvC8WhQa3EYMVWO2VV/b0gS5OmCcmsi+dIK95SAtLRtW3OoR2ywr9CNF3FNS\n"\
"nlyKfwTrnwKBgGkVRzml1QMn/bmV6oMPx6CWqixd4oBHIPq4UAjfa8ugiKWFYocJ\n"\
"+2oaTjuETlF5oCh6TfISnVxVtmXIRfYRrsR3xcmuhq4++bCa6i/n8eHpxP2vXeez\n"\
"pP61TrXPyHmLvggN6DAYEn3HnG8ICt4AXMiwrGJZ0LbXYELcvhZJgyGNAoGAWZel\n"\
"o7JpQBoCDLGkC4O49HOYsYoYSTc+RP5U6oIF1+D8SdWjuHog5ET42HCSyvUUzVIQ\n"\
"f0ivV+Vawk4E+JrXT9UyJIaHpVjIomQx/BW0FUBcMqt/V6vTlgCvfPtXuuYs3dp7\n"\
"4/9W5V6dTtd7zmZWynRgXIz7lcuUTSvUUo5BXRUCgYEAzekK/kz1iAlfsVfH2tri\n"\
"vqyvXQEfxT3MHiTtoQZ6GKqOoNa+7yFDnq7nriqNJx0lyyHjQSmrfqeZJdjla4ma\n"\
"I9aJKMp9f26/94QOwfY4G4uIfoq9n6stcYU+GNwyMuE3l/28FxZ9Gg0EwKK7V2Ux\n"\
"X0Lzhe+1ZNEeOS32ksPoVu4=\n"\
"-----END PRIVATE KEY-----\n";
client->setCertificate(scbclientCert);
client->setPrivateKey(scbPrivateKey);
client->setCACert(scbRootCACert);
//client->setInsecure();
    bool ok = false;

    HTTPClient http;
    const char* endpoint = "https://" API_HOST "/exercise/ssl";

    if (http.begin(*client, endpoint)) {
        // Header ตาม Exercise
        http.addHeader("Authorization", "Bearer " + this->accessToken);
        http.addHeader("Content-Type", "application/json");
        http.addHeader("x-test-mode", "true");

        // เวลา request ปัจจุบัน
      /*  time_t t = time(nullptr);
        struct tm * now = localtime(&t);
        char buf[32];
        sprintf(buf, "%04d-%02d-%02dT%02d:%02d:%02d+07:00",
                now->tm_year + 1900, now->tm_mon + 1, now->tm_mday,
                now->tm_hour, now->tm_min, now->tm_sec);
        String requestDt(buf);

        // Payload สำหรับ Exercise: QR Requested
        String payload = "";
        payload += "{";
        payload += "\"partnerTxnUid\": \"PARTNERTEST0012\", ";
        payload += "\"partnerId\": \"PTR1051673\", ";
        payload += "\"partnerSecret\": \"d4bded59200547bc85903574a293831b\", ";
        payload += "\"requestDt\": \"" + requestDt + "\", ";
        payload += "\"merchantId\": \"KB102057149704\", ";
        payload += "\"origPartnerTxnUid\": \"PARTNERTEST0007\" ";
        payload += "}";

        this->statusCode = http.POST(payload);
        String resp = http.getString();
        ESP_LOGE(TAG, "Response: %s", resp.c_str()); 
        ESP_LOGI(TAG, "Payload: %s", payload.c_str());   
        if (this->statusCode == HTTP_CODE_OK) {
            String resp = http.getString();
            DynamicJsonDocument doc(1024);
            if (deserializeJson(doc, resp) == DeserializationError::Ok) {
                String status = doc["qrStatus"] | "";
                ESP_LOGI(TAG, "QR Status: %s", status.c_str());
                *paymentAreConfirm = (status == "Paid"); // true ถ้า Paid
                ok = true;
            } else {
                ESP_LOGE(TAG, "JSON decode failed");
            }
        } else {
            ESP_LOGE(TAG, "POST request failed, status=%d", this->statusCode);
        }*/
        http.end();
    } else {
        ESP_LOGE(TAG, "Unable to connect to endpoint");
    }

    delete client;
    return ok;
}
