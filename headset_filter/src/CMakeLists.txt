idf_component_register(SRCS "pocket_wifi_filter.c" INCLUDE_DIRS "."
                    REQUIRES esp_wifi esp_netif esp_event nvs_flash lwip
                             esp_http_server esp_http_client esp_timer
                             esp_system mbedtls)
