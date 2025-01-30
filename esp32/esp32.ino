#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "netif/ppp/pppapi.h"
#include "netif/ppp/pppos.h"
#include "driver/uart.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

// UART configuration
#define UART_PORT_NUM      UART_NUM_1
#define UART_BAUD_RATE     115200
#define UART_RX_PIN        10
#define UART_TX_PIN        11
#define UART_BUF_SIZE      1024

// PPP configuration
static ppp_pcb *ppp;
static struct netif ppp_netif;

// TLS configuration
#define LOCAL_PORT     54321  // Local port for receiving UDP packets
#define SERVER_PORT    12345  // Remote port for sending UDP packets
#define SERVER_IP      "192.168.2.1"  // Remote IP address

// Placeholder for certificates and keys
static const char *ca_cert = 
"-----BEGIN CERTIFICATE-----\n"
"MIIFHTCCAwWgAwIBAgIUHe4moVPBhLXJ4rjl7QbL5cow730wDQYJKoZIhvcNAQEL\n"
"BQAwHjEcMBoGA1UEAwwTc2VydmVyLm15ZG9tYWluLmNvbTAeFw0yNTAxMTcwNzQ2\n"
"MTVaFw0yNjAxMTcwNzQ2MTVaMB4xHDAaBgNVBAMME3NlcnZlci5teWRvbWFpbi5j\n"
"b20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQf5CIqkXWosXLaPY0\n"
"ZC/JCdc8RDcUjDpxKPl5pEC8jGYM2RkGRUJT479PMunsV460vyrZbZxnQ1xAU2Tz\n"
"5e5+Rm+xVvn5B1kbiYnHcacNIDQzN4FV26oUDYf9KdyWnvHX5A1k35lFZesSe7sG\n"
"mcjjWorBVFRXHY1/A/YHytHSb6dyv/3eO07Hr/iIzTvYeheTOuZjKJTN1pJq0dv9\n"
"CAfRiz5ryQ9eH3lwTbH3Ksz5TAZ+VkoIWsQzwoVT4Czw49b7mmYc+ESSfOWmOHXM\n"
"RBBTf1CCrfT85bYc9exa+hn86H1EYYQITmQvvj23QrIURYqvSUvqQbGfmXB+Xsvh\n"
"q4kwnrik5xGLKzuv2Fmi3fLu7dNGxrCfhq8/Gins5hU4JEylxipEZ70+2eJzKoZm\n"
"GWxkpg5GS2ogZXnf8w/aNG+Ebft29GvHhvfCUrq4IpOEl7pN8qEIEsmQn1M+ag8T\n"
"5z7bxySdqPkM6wS5Wcegc+cf5ojRcAtLVTvn/eR178uvqFFha/JlBB2l6rl/DTT8\n"
"4XX0Re/lD2olcDC1UcUvlqd44JJmQaQFzzxD70QWhnOmgzaowpc9vu4jI5kp1+ji\n"
"WyOcFaDQR/3BGfSMb7skZ3Ymf5raAGHENEhGZ8wGW1P688swGTy2llqGeCm1/nBZ\n"
"c/p29GhEJBtWLdRS/TuGek1WewIDAQABo1MwUTAdBgNVHQ4EFgQUQ8OUPYAanNAm\n"
"qVRpGVERsvsJY2EwHwYDVR0jBBgwFoAUQ8OUPYAanNAmqVRpGVERsvsJY2EwDwYD\n"
"VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAzp/mLtPdzI8n4IHqNc50\n"
"RIY1dp2GzmsOcY4OO8cR9uz0aJxic4y+pabzPHQXhn6QdWWW+HqlO0DTPU9pT1+O\n"
"POKl3HKCbcVFgoqmt5gb9dUtQzeat9Ru1jRcnDCAorcpU8vcQ/1sPFr1o2TPD0tM\n"
"UjN1+vAcdHbPUw6dP1HS5ghAcmihOhNTigyMb/Mlp3vCVv0MaRFtELImuNf5QYuo\n"
"QJ6nenY5+GI3H+eDjtZE7CeLwhpL1mCDjcxToH9AgtqhzUofgVtI1V8uaiMUzJk6\n"
"vtgzf3sSTHmM8rcNYjwNHzTN6WLcMuR33WO7jSiBu1Kc3szVxBttNYfPMevlCwyw\n"
"I1DAw95pCRH1TQQMGSxL4Lafv9NHB9GDQgJthgXfRi8bTBtl5GzxnhMTIvJIRHBx\n"
"rWzucXCfyY3r8uTm5Nicu009tQp5RYSsU9CpTSgktAhVGf2PA2K442GEiV2s3BP4\n"
"SlwYAKXF7Wr9RsLCwMO5ysm6ijrjMKgHDfB11EQDfIfzRrs6esqfJYsW0zwNzSA+\n"
"z9lMu7WFIIm5q1oukSQThTCXJqyadL1vJdXBEJyhwxy7jc53tgpt15FtFisC+Yao\n"
"znhm808Nb+wBNzPg2zg/0CdGj63ZSzi3Ckt4OMz528hjCyP9P8vIeAENgyD9maz4\n"
"XdnK2P28RkdcQu5C36yaG3I=\n"
"-----END CERTIFICATE-----\n";

static const char *client_key = 
  "-----BEGIN PRIVATE KEY-----\n"
  "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\n"
  "svx9YsPNFqwKvTTrYmWNRXdeyqy9mQ==\n"
  "-----END PRIVATE KEY-----\n";

static const char *client_cert = 
  "-----BEGIN CERTIFICATE-----\n"
    "MIIEtjCCAp4CFGM+vE3lL2MQuRxv4LATxH2o6Wo2MA0GCSqGSIb3DQEBCwUAMB4x\n"
    "HDAaBgNVBAMME3NlcnZlci5teWRvbWFpbi5jb20wHhcNMjUwMTE3MDc0NzIzWhcN\n"
    "MjYwMTE3MDc0NzIzWjARMQ8wDQYDVQQDDAZjbGllbnQwggIiMA0GCSqGSIb3DQEB\n"
    "AQUAA4ICDwAwggIKAoICAQDNNcTHMdy/ObvobU8UORLbv4uXXmpIB4UORqohp2Mk\n"
    "MmuVM2yorYTyXelPrfMZoWNAP0BzneY4Fq0l5qVgINj7S0Ko3PPNVTKHkmxaRILJ\n"
    "8wAaPxLpxaG87TVjW1tUTLOoJcqt1RjeJrmR8JuPW2oduQkGqYnM3yRG5jMrWpsU\n"
    "xNHJaz3gRQnapvIMQEPD9aKq0vUMwPDuerGo8kV0qtT1K/JY4ZwlU9vgd9E85rzP\n"
    "Kklal4NzPOXUG9mSJNxGV1J1ulU3OqOx2nQCmekBu+a+NS7Pnsd2fAY4wjfRKNzz\n"
    "SpP0NNG2L/v52RwAm+HRu+n1c9Sj1YNkiT9pBPHBkuHDJy+PfpUOkb5R0+2g6Gtv\n"
    "hx8LsMKed9uDmm4Xne2fMaHWfYR8m3tUnbhymSNbByrkPP7vMXOeO3iu/l2IhrCx\n"
    "SeXc9T1UtGzjn9uS5REhz5hSSV0+0oK/G4eB5r9CR+l6LhdXMgL1XDyQ+IIR35kF\n"
    "JMiPStgnIOoYLa2VHyVUzWL5+wwlKH5o99hNDLJPOFIumQyuvfxVI6rrqM/FvLFi\n"
    "a+DOFtKM8NEZITCJys8bJMmM4UkyR2oJ6/1Oxaho/oYRjtzqn/vmP0u+t6kB4C0u\n"
    "QkgtndY8XuDMWH8B5/2cCxJSwXGvfl1MEed+HqmjtS7HEBM7xNaxDUaCmY/Uwb8G\n"
    "iwIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQChqeSDaGa2dr+OPEkCIEeEFUQUSNLZ\n"
    "N2qHeK88Mvx/+NZ1MSJ8wxN9QceI9wQjHz/6ry7TMb9I+bwf2T1+MgNHOhxS5G8x\n"
    "ESbgKxwYy59PD+W8FGA5EWJFBsEqUzbpR03zxr+6byCeNyH7XoY/cyBCwjvKqi/7\n"
    "fPj8g23kfVPMjWpSweLY1aYwilMx5Gx71uVLKMYoUaNnIQlLwMMXA4ttC8TSuxjv\n"
    "jBCcPTAFePGq4rSifHn90uKVmOl4MxabMkIEKLQCQEYmyI3beo0Ti2t7lObnT6Uf\n"
    "zdbVMp1NIQRJL9bAJJS7/ehLj52tguLCaLAVpkf0sE5M84Rilvs+oRdIWHtOq7vH\n"
    "kALK8OQA0oaRDxlWeDyWBSV+4m4UYtYVLusSO7uTw635GoiFNt4aiHRLZcdGtMaQ\n"
    "I/RHdW3VR/g1mnnSdzEzx1mGA3t1BWK4Zn7fMRP2cJqErxf0M9oqgapljQVhlCA9\n"
    "ITotfTOY5tsNCy9kTMuEsgLVyDOV7wZEk58k384gKnl22/8ww+Zc4l4tFW/MT+Da\n"
    "avombOPcD37dmzCGEIG9II0ZtgICJp8vSlvl+FjBKKcbjT2WjmHdrY1rJ+B4ovjy\n"
    "SvOtJbV0BL4OpMkZzJWigBpC42BXvRJa7DHI4wT5eOet5tRGvjExQkOhF4gBx9RN\n"
    "FT+lw4G/NZ9GkQ==\n"
    "-----END CERTIFICATE-----\n";

// Function to handle PPP link status changes
static void ppp_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx) {
    struct netif *pppif = (struct netif *)ctx;

    if (err_code == PPPERR_NONE) {
        printf("PPP connection established\n");
        printf("IP address: %s\n", ip4addr_ntoa(netif_ip4_addr(pppif)));
        printf("Gateway: %s\n", ip4addr_ntoa(netif_ip4_gw(pppif)));
        printf("Netmask: %s\n", ip4addr_ntoa(netif_ip4_netmask(pppif)));
        
        // Start TLS communication once PPP is connected
        xTaskCreate(tls_communication_task, "tls_comm_task", 8192, NULL, 1, NULL);
        return;
    }
    printf("PPP connection lost: %s\n");
}

// Function to check if the PPP connection is up
bool is_ppp_connected(struct netif *ppp_netif) {
    if (ppp_netif == NULL) {
        return false; // PPP interface not initialized
    }

    // Check if the interface is up and the link is up
    if ((ppp_netif->flags & NETIF_FLAG_UP) && (ppp_netif->flags & NETIF_FLAG_LINK_UP)) {
        return true; // PPP connection is active
    }

    return false; // PPP connection is down
}

// Function to output PPP data over UART
static u32_t pppos_output_cb(ppp_pcb *pcb, u8_t *data, u32_t len, void *ctx) {
    uart_write_bytes(UART_PORT_NUM, (const char *)data, len);
    return len;
}

// Initialize UART
void uart_init() {
    uart_config_t uart_config = {
        .baud_rate = UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(UART_PORT_NUM, &uart_config);
    uart_set_pin(UART_PORT_NUM, UART_TX_PIN, UART_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    uart_driver_install(UART_PORT_NUM, UART_BUF_SIZE * 2, 0, 0, NULL, 0);
}

// Custom send callback for mbedtls
static int tls_send(void *ctx, const unsigned char *buf, size_t len) {
    int sock = *(int *)ctx;
    return send(sock, buf, len, 0);
}

// Custom recv callback for mbedtls
static int tls_recv(void *ctx, unsigned char *buf, size_t len) {
    int sock = *(int *)ctx;
    return recv(sock, buf, len, 0);
}

// Function to initialize and configure TLS
void tls_communication_task(void *pvParameters) {

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt client_crt;
    mbedtls_pk_context pkey;
    mbedtls_x509_crt ca_crt;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret;

    // const char *request = nullptr;  // Declare before any 'goto' statements
    const char *request = "Hello from ESP32 TLS client!\n";

    // esp_core_dump_init();

    // Initialize structures
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&client_crt);
    mbedtls_pk_init(&pkey);
    mbedtls_x509_crt_init(&ca_crt);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the random number generator
    const char *pers = "tls_client";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("Failed to seed RNG\n");
        goto cleanup;
    }

    // Parse client certificate
    ret = mbedtls_x509_crt_parse(&client_crt, (const unsigned char *)client_cert, strlen(client_cert) + 1);
    if (ret != 0) {
        printf("Failed to parse client certificate\n");
        goto cleanup;
    }

    // Parse client private key
    ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *)client_key, strlen(client_key) + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("Failed to parse client private key\n");
        goto cleanup;
    }

    // Parse CA certificate
    ret = mbedtls_x509_crt_parse(&ca_crt, (const unsigned char *)ca_cert, strlen(ca_cert) + 1);
    if (ret != 0) {
        printf("Failed to parse CA certificate\n");
        goto cleanup;
    }

    // Configure TLS
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        printf("Failed to configure TLS defaults\n");
        goto cleanup;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&conf, &ca_crt, NULL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    // Set client certificate and private key
    ret = mbedtls_ssl_conf_own_cert(&conf, &client_crt, &pkey);
    if (ret != 0) {
        printf("Failed to set client certificate and private key\n");
        goto cleanup;
    }

    // Setup SSL context
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        printf("Failed to setup SSL context\n");
        goto cleanup;
    }

    // Create TCP socket
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Failed to create socket\n");
        goto cleanup;
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_aton(SERVER_IP, &server_addr.sin_addr);

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to connect to server\n");
        close(sock);
        goto cleanup;
    }

    // Set socket to SSL context using custom send/recv callbacks
    mbedtls_ssl_set_bio(&ssl, &sock, tls_send, tls_recv, NULL);

    // Perform TLS handshake
    ret = mbedtls_ssl_handshake(&ssl);
    if (ret != 0) {
        printf("TLS handshake failed\n");
        goto cleanup;
    }

    printf("TLS connection established successfully\n");

    // Send and receive data over TLS
    // request = "Hello from ESP32 TLS client!\n";
    ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request, strlen(request));
    if (ret < 0) {
        printf("Failed to send data over TLS\n");
        goto cleanup;
    }

    char response[300];
    ret = mbedtls_ssl_read(&ssl, (unsigned char *)response, sizeof(response) - 1);
    if (ret < 0) {
        printf("Failed to receive data over TLS\n");
        goto cleanup;
    }

    print_cipher_suite(&ssl);

    response[ret] = '\0';
    printf("Received: %s\n", response);

    // printf("Free heap: %d bytes\n", esp_get_free_heap_size());

cleanup:
    // Cleanup
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&client_crt);
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&ca_crt);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (sock >= 0) {
        close(sock);
    }

    vTaskDelete(NULL);
}

void print_cipher_suite(mbedtls_ssl_context *ssl) {
    const char *cipher_suite = mbedtls_ssl_get_ciphersuite(ssl);
    if (cipher_suite) {
        printf("Cipher Suite: %s\n", cipher_suite);
    } else {
        printf("Cipher Suite not available.\n");
    }
}

// Main application
void setup() {
    
    Serial.begin(115200);

    // Initialize TCP/IP stack
    esp_netif_init();

    // Initialize UART
    uart_init();

    // Create PPPoS interface
    ppp = pppapi_pppos_create(&ppp_netif, pppos_output_cb, ppp_link_status_cb, &ppp_netif);
    if (ppp == NULL) {
        printf("Failed to create PPPoS interface\n");
        return;
    }

    // Set PPP as the default interface
    pppapi_set_default(ppp);

    // Connect PPP
    pppapi_connect(ppp, 0);
}

void loop() {
    uint8_t data[UART_BUF_SIZE];
    int len = uart_read_bytes(UART_PORT_NUM, data, UART_BUF_SIZE, 20 / portTICK_PERIOD_MS);
    if (len > 0) {
        pppos_input(ppp, data, len);
    }
    vTaskDelay(10 / portTICK_PERIOD_MS);
}