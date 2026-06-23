/* ============================================================================
 *  POCKET WIFI FILTER - ESP-IDF edition  .  v0.14-idf, rev8
 * ----------------------------------------------------------------------------
 *  Working on hardware: AP+STA, NAPT, DHCP-DNS to clients, DNS sinkhole+forward
 *  to the DHCP-given resolver, web dashboard + basic-auth, NVS config,
 *  captive-portal detection, MAC cloning.
 * ==========================================================================*/

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_http_server.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/base64.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/lwip_napt.h"

static const char *TAG = "pwf";

/* ----------------------------- DEFAULTS -----------------------------------*/
/* Public AP name */
#define AP_SSID            "PocketFilter"
#define AP_CHANNEL         1
#define AP_MAX_CONN        8

#if defined(__has_include)
#  if __has_include("env.h")
#    include "env.h"
#  endif
#endif
#ifndef ENV_STA_SSID
#  define ENV_STA_SSID   "set-me-in-env-h"
#endif
#ifndef ENV_STA_PASS
#  define ENV_STA_PASS   "set-me-in-env-h"
#endif
#ifndef ENV_AP_PASS
#  define ENV_AP_PASS    "changeme123"
#endif
#ifndef ENV_ADMIN_USER
#  define ENV_ADMIN_USER "admin"
#endif
#ifndef ENV_ADMIN_PASS
#  define ENV_ADMIN_PASS "changeme123"
#endif
#define AP_PASS            ENV_AP_PASS
#define STA_SSID           ENV_STA_SSID
#define STA_PASS           ENV_STA_PASS
#define ADMIN_USER         ENV_ADMIN_USER
#define ADMIN_PASS         ENV_ADMIN_PASS
#define DEFAULT_BLOCKLIST  "doubleclick.net,googlesyndication.com,ads.,tracker"
#define FALLBACK_DNS       "8.8.8.8"
#define ENFORCE_WHITELIST  false

/* security monitors 0 = off, 1 = enable . */
#define ENABLE_MONITORS    0

#define ENABLE_DOH         1
#define DEAUTH_FLOOD_THRESH 20

/* ----------------------------- CONFIG (RAM, NVS-backed) -------------------*/
static char g_ap_pass[64];
static char g_sta_ssid[33];
static char g_sta_pass[64];
static char g_admin_user[32];
static char g_admin_pass[64];
static char g_blocklist[512];
static char g_clone_mac[20];

#define MAX_BLOCK 24
static char  g_block_storage[512];
static char *g_block_terms[MAX_BLOCK];
static int   g_block_n = 0;

/* ----------------------------- RUNTIME STATE ------------------------------*/
static esp_netif_t *ap_netif  = NULL;
static esp_netif_t *sta_netif = NULL;

static volatile uint32_t g_upstream_dns = 0;
static volatile bool     g_uplink_up    = false;
static volatile uint32_t g_dns_allowed  = 0;
static volatile uint32_t g_dns_blocked  = 0;
static volatile uint32_t g_doh_ok        = 0;
static volatile uint32_t g_doh_fallbacks = 0;

static volatile int  g_portal         = 0;
static volatile bool g_portal_recheck = false;

static volatile uint32_t g_deauth_total   = 0;
static volatile bool     g_deauth_alert   = false;
static volatile bool     g_eviltwin_alert = false;
static uint8_t           g_eviltwin_bssid[6] = {0};
#if ENABLE_MONITORS
static uint8_t  g_our_ap_bssid[6] = {0};
static int64_t  g_deauth_alert_until = 0;
#endif

#define RECENT_N 12
typedef struct { char name[64]; bool blocked; } dns_evt_t;
static dns_evt_t g_recent[RECENT_N];
static int g_recent_head  = 0;
static int g_recent_count = 0;
static SemaphoreHandle_t g_recent_mtx = NULL;

/* ----------------------------- HELPERS ------------------------------*/
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_mac(const char *s, uint8_t out[6]) {
    int n = 0;
    for (int i = 0; i < 6; i++) {
        int hi = hexval(s[n]), lo = hexval(s[n+1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)(hi*16 + lo);
        n += 2;
        if (i < 5) {
            if (s[n] != ':' && s[n] != '-') return false;
            n++;
        }
    }
    return true;
}

static void json_escape(const char *in, char *out, int outsz) {
    int o = 0;
    for (int i = 0; in[i] && o < outsz - 7; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"':  out[o++] = '\\'; out[o++] = '"';  break;
            case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
            case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
            case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
            case '\t': out[o++] = '\\'; out[o++] = 't';  break;
            default:
                if (c < 0x20) o += snprintf(out + o, outsz - o, "\\u%04x", c);
                else out[o++] = (char)c;
        }
    }
    out[o] = 0;
}

static void html_escape(const char *in, char *out, int outsz) {
    int o = 0;
    for (const char *p = in; *p && o < outsz - 7; p++) {
        if      (*p == '&') { memcpy(out+o, "&amp;", 5);  o += 5; }
        else if (*p == '<') { memcpy(out+o, "&lt;", 4);   o += 4; }
        else if (*p == '>') { memcpy(out+o, "&gt;", 4);   o += 4; }
        else if (*p == '"') { memcpy(out+o, "&quot;", 6); o += 6; }
        else out[o++] = *p;
    }
    out[o] = 0;
}

static bool form_field(const char *body, const char *key, char *out, int outsz) {
    size_t kl = strlen(key);
    const char *p = body;
    while ((p = strstr(p, key))) {
        if ((p == body || *(p-1) == '&') && p[kl] == '=') {
            p += kl + 1;
            int o = 0;
            while (*p && *p != '&' && o < outsz - 1) {
                if (*p == '+') { out[o++] = ' '; p++; }
                else if (*p == '%' && p[1] && p[2]) {
                    int hi = hexval(p[1]), lo = hexval(p[2]);
                    if (hi >= 0 && lo >= 0) { out[o++] = (char)(hi*16 + lo); p += 3; }
                    else { out[o++] = *p; p++; }
                } else { out[o++] = *p; p++; }
            }
            out[o] = 0;
            return true;
        }
        p += kl;
    }
    return false;
}

static void blocklist_parse(void) {
    strlcpy(g_block_storage, g_blocklist, sizeof(g_block_storage));
    g_block_n = 0;
    char *save = NULL;
    char *t = strtok_r(g_block_storage, ",\n", &save);
    while (t && g_block_n < MAX_BLOCK) {
        while (*t == ' ') t++;
        if (*t) g_block_terms[g_block_n++] = t;
        t = strtok_r(NULL, ",\n", &save);
    }
}

static void config_load(void) {
    strlcpy(g_ap_pass,    AP_PASS,           sizeof(g_ap_pass));
    strlcpy(g_sta_ssid,   STA_SSID,          sizeof(g_sta_ssid));
    strlcpy(g_sta_pass,   STA_PASS,          sizeof(g_sta_pass));
    strlcpy(g_admin_user, ADMIN_USER,        sizeof(g_admin_user));
    strlcpy(g_admin_pass, ADMIN_PASS,        sizeof(g_admin_pass));
    strlcpy(g_blocklist,  DEFAULT_BLOCKLIST, sizeof(g_blocklist));
    g_clone_mac[0] = 0;

    nvs_handle_t h;
    if (nvs_open("pwf", NVS_READONLY, &h) == ESP_OK) {
        size_t l;
        l = sizeof(g_sta_ssid);   nvs_get_str(h, "sta_ssid",  g_sta_ssid,   &l);
        l = sizeof(g_sta_pass);   nvs_get_str(h, "sta_pass",  g_sta_pass,   &l);
        l = sizeof(g_ap_pass);    nvs_get_str(h, "ap_pass",   g_ap_pass,    &l);
        l = sizeof(g_admin_user); nvs_get_str(h, "adm_user",  g_admin_user, &l);
        l = sizeof(g_admin_pass); nvs_get_str(h, "adm_pass",  g_admin_pass, &l);
        l = sizeof(g_blocklist);  nvs_get_str(h, "blocklist", g_blocklist,  &l);
        l = sizeof(g_clone_mac);  nvs_get_str(h, "clone_mac", g_clone_mac,  &l);
        nvs_close(h);
    }
    blocklist_parse();
}

static void config_save(void) {
    nvs_handle_t h;
    if (nvs_open("pwf", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "sta_ssid",  g_sta_ssid);
        nvs_set_str(h, "sta_pass",  g_sta_pass);
        nvs_set_str(h, "ap_pass",   g_ap_pass);
        nvs_set_str(h, "adm_user",  g_admin_user);
        nvs_set_str(h, "adm_pass",  g_admin_pass);
        nvs_set_str(h, "blocklist", g_blocklist);
        nvs_set_str(h, "clone_mac", g_clone_mac);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "config saved to NVS");
    }
}

static void recent_push(const char *name, bool blocked) {
    if (!g_recent_mtx) return;
    if (xSemaphoreTake(g_recent_mtx, pdMS_TO_TICKS(50)) != pdTRUE) return;
    dns_evt_t *e = &g_recent[g_recent_head];
    strlcpy(e->name, (name && name[0]) ? name : "(root)", sizeof(e->name));
    for (char *c = e->name; *c; c++)
        if (*c < 0x20 || *c == '"' || *c == '\\' || (unsigned char)*c >= 0x7f) *c = '?';
    e->blocked = blocked;
    g_recent_head = (g_recent_head + 1) % RECENT_N;
    if (g_recent_count < RECENT_N) g_recent_count++;
    xSemaphoreGive(g_recent_mtx);
}

static uint32_t ap_ip_u32(esp_netif_t *ap) {
    esp_netif_ip_info_t ip;
    esp_netif_get_ip_info(ap, &ip);
    return ip.ip.addr;
}

/* ====================== WIFI EVENTS + MAC ALLOW-LIST ======================*/
static bool mac_whitelisted(const uint8_t mac[6]) {
    if (!ENFORCE_WHITELIST) return true;
    (void)mac;
    return true;
}

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = (wifi_event_ap_staconnected_t *)data;
        if (!mac_whitelisted(e->mac)) {
            ESP_LOGW(TAG, "kicking non-whitelisted " MACSTR, MAC2STR(e->mac));
            esp_wifi_deauth_sta(e->aid);
        } else {
            ESP_LOGI(TAG, "allowed " MACSTR, MAC2STR(e->mac));
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        g_uplink_up = false;
        g_upstream_dns = 0;
        g_portal = 0;
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "uplink up, IP " IPSTR, IP2STR(&e->ip_info.ip));

        ip_napt_enable(ap_ip_u32(ap_netif), 1);
        ESP_LOGI(TAG, "NAPT enabled on AP netif - clients can now route out");

        esp_netif_dns_info_t dns = { 0 };
        if (esp_netif_get_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK
            && dns.ip.u_addr.ip4.addr != 0) {
            g_upstream_dns = dns.ip.u_addr.ip4.addr;
            ESP_LOGI(TAG, "upstream DNS (from DHCP): " IPSTR, IP2STR(&dns.ip.u_addr.ip4));
        } else {
            g_upstream_dns = 0;
            ESP_LOGW(TAG, "no DNS from DHCP; will use fallback %s", FALLBACK_DNS);
        }
        g_uplink_up = true;
        g_portal_recheck = true;
    }
}

/* ============================ WIFI BRINGUP ================================*/
static void wifi_init_apsta(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ap_netif  = esp_netif_create_default_wifi_ap();
    sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t ap = { 0 };
    strlcpy((char *)ap.ap.ssid, AP_SSID, sizeof(ap.ap.ssid));
    strlcpy((char *)ap.ap.password, g_ap_pass, sizeof(ap.ap.password));
    ap.ap.ssid_len = strlen(AP_SSID);
    ap.ap.channel = AP_CHANNEL;
    ap.ap.max_connection = AP_MAX_CONN;
    ap.ap.authmode = strlen(g_ap_pass) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;

    wifi_config_t sta = { 0 };
    strlcpy((char *)sta.sta.ssid, g_sta_ssid, sizeof(sta.sta.ssid));
    strlcpy((char *)sta.sta.password, g_sta_pass, sizeof(sta.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP,  &ap));
    if (strlen(g_sta_ssid))
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));

    if (g_clone_mac[0]) {
        uint8_t m[6];
        if (parse_mac(g_clone_mac, m) && !(m[0] & 0x01)) {
            esp_err_t e = esp_wifi_set_mac(WIFI_IF_STA, m);
            if (e == ESP_OK) ESP_LOGW(TAG, "STA MAC cloned to %s", g_clone_mac);
            else ESP_LOGE(TAG, "clone MAC set failed: %s", esp_err_to_name(e));
        } else {
            ESP_LOGE(TAG, "clone MAC '%s' invalid (need unicast AA:BB:CC:DD:EE:FF)", g_clone_mac);
        }
    }

    ESP_ERROR_CHECK(esp_wifi_start());

    esp_netif_dns_info_t dns = { 0 };
    dns.ip.u_addr.ip4.addr = esp_ip4addr_aton("192.168.4.1");
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    esp_netif_dhcps_stop(ap_netif);
    esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns);
    esp_netif_dhcps_start(ap_netif);

    ESP_LOGI(TAG, "AP '%s' up; STA %s", AP_SSID, strlen(g_sta_ssid) ? g_sta_ssid : "(none set)");
}

/* ============================ DNS FILTER =================================*/
static bool name_blocked(const char *name) {
    for (int i = 0; i < g_block_n; i++)
        if (strstr(name, g_block_terms[i])) return true;
    return false;
}

static void dns_extract_name(const uint8_t *buf, int n, char *out, int outsz) {
    int pos = 12, o = 0;
    while (pos < n && buf[pos] != 0) {
        int len = buf[pos];
        if (len <= 0 || pos + len >= n) break;
        for (int i = 0; i < len && o < outsz - 1; i++) out[o++] = (char)buf[pos + 1 + i];
        if (o < outsz - 1) out[o++] = '.';
        pos += len + 1;
    }
    if (o > 0 && out[o-1] == '.') o--;
    out[o] = 0;
    for (int i = 0; out[i]; i++) out[i] = tolower((unsigned char)out[i]);
}

/* ===================== DNS-over-HTTPS (DoH) ============================== */
#if ENABLE_DOH
#define DOH_URL       "https://cloudflare-dns.com/dns-query"
#define DOH_MAX_RESP  1500

typedef struct { uint8_t *buf; int len; int cap; } doh_acc_t;
static doh_acc_t                g_doh_acc;
static esp_http_client_handle_t g_doh_client        = NULL;
static int                      g_doh_consec_fail    = 0;
static int64_t                  g_doh_cooldown_until = 0;

static esp_err_t doh_http_event(esp_http_client_event_t *evt) {
    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        doh_acc_t *a = &g_doh_acc;
        if (a->buf) {
            int space = a->cap - a->len;
            int k = evt->data_len < space ? evt->data_len : space;
            if (k > 0) { memcpy(a->buf + a->len, evt->data, k); a->len += k; }
        }
    }
    return ESP_OK;
}

static void doh_note_fail(void) {
    if (++g_doh_consec_fail >= 3) {
        g_doh_cooldown_until = esp_timer_get_time() + 60LL * 1000 * 1000;
        g_doh_consec_fail = 0;
    }
}

static int doh_resolve(const uint8_t *query, int qlen, uint8_t *out, int outcap) {
    if (qlen <= 0 || !g_uplink_up) return -1;
    if (g_doh_cooldown_until && esp_timer_get_time() < g_doh_cooldown_until) return -1;

    if (!g_doh_client) {
        esp_http_client_config_t cfg = {
            .url               = DOH_URL,
            .method            = HTTP_METHOD_POST,
            .timeout_ms        = 4000,
            .crt_bundle_attach = esp_crt_bundle_attach,
            .keep_alive_enable = true,
            .event_handler     = doh_http_event,
        };
        g_doh_client = esp_http_client_init(&cfg);
        if (!g_doh_client) { doh_note_fail(); return -1; }
        esp_http_client_set_header(g_doh_client, "Content-Type", "application/dns-message");
        esp_http_client_set_header(g_doh_client, "Accept",       "application/dns-message");
    }

    g_doh_acc.buf = out; g_doh_acc.len = 0; g_doh_acc.cap = outcap;
    esp_http_client_set_post_field(g_doh_client, (const char *)query, qlen);

    esp_err_t err = esp_http_client_perform(g_doh_client);
    if (err != ESP_OK) {
        esp_http_client_cleanup(g_doh_client);
        g_doh_client = NULL;
        doh_note_fail();
        return -1;
    }
    if (esp_http_client_get_status_code(g_doh_client) != 200 || g_doh_acc.len <= 0) {
        doh_note_fail();
        return -1;
    }
    g_doh_consec_fail = 0;
    g_doh_cooldown_until = 0;
    return g_doh_acc.len;
}
#endif


static void dns_filter_task(void *arg) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) { ESP_LOGE(TAG, "DNS: socket() failed"); vTaskDelete(NULL); return; }
    struct sockaddr_in me = { 0 };
    me.sin_family = AF_INET; me.sin_port = htons(53); me.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&me, sizeof(me)) < 0) {
        ESP_LOGE(TAG, "DNS: bind(:53) failed"); close(s); vTaskDelete(NULL); return;
    }
    ESP_LOGI(TAG, "DNS filter listening on :53");

    uint8_t buf[512];
    while (1) {
        struct sockaddr_in cli; socklen_t cl = sizeof(cli);
        int n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&cli, &cl);
        if (n < 12) continue;

        char name[256];
        dns_extract_name(buf, n, name, sizeof(name));

        if (name_blocked(name)) {
            uint8_t r[512];
            memcpy(r, buf, n);
            r[2] = 0x81; r[3] = 0x80;
            r[6] = 0x00; r[7] = 0x01;
            r[8] = 0x00; r[9] = 0x00;
            r[10] = 0x00; r[11] = 0x00;
            uint8_t ans[] = { 0xC0,0x0C, 0x00,0x01, 0x00,0x01,
                              0x00,0x00,0x00,0x3C, 0x00,0x04, 0x00,0x00,0x00,0x00 };
            if (n + (int)sizeof(ans) <= (int)sizeof(r)) {
                memcpy(r + n, ans, sizeof(ans));
                sendto(s, r, n + sizeof(ans), 0, (struct sockaddr *)&cli, cl);
            }
            g_dns_blocked++;
            recent_push(name, true);
            ESP_LOGI(TAG, "BLOCKED %s", name);
            continue;
        }

#if ENABLE_DOH
        {
            static uint8_t dr[DOH_MAX_RESP];
            int drn = doh_resolve(buf, n, dr, sizeof(dr));
            if (drn > 0) {
                sendto(s, dr, drn, 0, (struct sockaddr *)&cli, cl);
                g_dns_allowed++; g_doh_ok++;
                recent_push(name, false);
                ESP_LOGI(TAG, "allowed %s (DoH)", name);
                continue;
            }
            g_doh_fallbacks++;
        }
#endif
        int up = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (up < 0) { ESP_LOGW(TAG, "DNS: upstream socket failed"); continue; }

        esp_netif_ip_info_t sta_ip;
        if (sta_netif && esp_netif_get_ip_info(sta_netif, &sta_ip) == ESP_OK
                      && sta_ip.ip.addr != 0) {
            struct sockaddr_in local = { 0 };
            local.sin_family = AF_INET;
            local.sin_addr.s_addr = sta_ip.ip.addr;
            local.sin_port = 0;
            bind(up, (struct sockaddr *)&local, sizeof(local));
        }

        struct sockaddr_in u = { 0 };
        u.sin_family = AF_INET;
        u.sin_port = htons(53);
        u.sin_addr.s_addr = g_upstream_dns ? g_upstream_dns : inet_addr(FALLBACK_DNS);

        struct timeval tv = { .tv_sec = 3 };
        setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        sendto(up, buf, n, 0, (struct sockaddr *)&u, sizeof(u));
        uint8_t rb[512];
        int rn = recv(up, rb, sizeof(rb), 0);
        if (rn > 0) {
            sendto(s, rb, rn, 0, (struct sockaddr *)&cli, cl);
            g_dns_allowed++;
            recent_push(name, false);
            ESP_LOGI(TAG, "allowed %s", name);
        } else {
            ESP_LOGW(TAG, "DNS upstream timeout: %s", name);
        }
        close(up);
    }
}

/* ====================== CAPTIVE-PORTAL DETECTION =========================*/
static const char *portal_str(int s) {
    return s == 1 ? "clear" : s == 2 ? "portal" : s == 3 ? "checking" : "unknown";
}

static void portal_probe(void) {
    g_portal = 3;
    esp_http_client_config_t cfg = {
        .url = "http://connectivitycheck.gstatic.com/generate_204",
        .timeout_ms = 5000,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    esp_err_t err = esp_http_client_perform(c);
    if (err == ESP_OK) {
        int st = esp_http_client_get_status_code(c);
        g_portal = (st == 204) ? 1 : 2;
        ESP_LOGI(TAG, "captive-portal probe: HTTP %d -> %s", st, portal_str(g_portal));
    } else {
        g_portal = 0;
        ESP_LOGW(TAG, "captive-portal probe failed: %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(c);
}

static void portal_task(void *arg) {
    while (1) {
        if (g_portal_recheck) { g_portal_recheck = false; portal_probe(); }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

/* ====================== SECURITY MONITORS (opt-in) =======================*/
#if ENABLE_MONITORS
static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    int len = p->rx_ctrl.sig_len;
    if (len < 24) return;
    const uint8_t *f = p->payload;
    uint8_t ftype   = (f[0] >> 2) & 0x03;
    uint8_t subtype = (f[0] >> 4) & 0x0F;
    if (ftype != 0) return;

    if (subtype == 0x0C || subtype == 0x0A) {
        g_deauth_total++;
    } else if (subtype == 0x08) {
        if (len < 38) return;
        const uint8_t *bssid = f + 16;
        if (f[36] == 0x00) {
            int sl = f[37];
            if (sl >= 1 && sl <= 32 && 38 + sl <= len) {
                char ssid[33];
                memcpy(ssid, f + 38, sl);
                ssid[sl] = 0;
                if (strcmp(ssid, AP_SSID) == 0 && memcmp(bssid, g_our_ap_bssid, 6) != 0) {
                    memcpy(g_eviltwin_bssid, bssid, 6);
                    g_eviltwin_alert = true;
                }
            }
        }
    }
}

static void monitor_task(void *arg) {
    uint32_t prev = 0;
    bool eviltwin_logged = false;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        uint32_t now = g_deauth_total;
        uint32_t delta = now - prev;
        prev = now;
        if (delta >= DEAUTH_FLOOD_THRESH) {
            g_deauth_alert = true;
            g_deauth_alert_until = esp_timer_get_time() + 30000000;  /* 30s */
            ESP_LOGW(TAG, "DEAUTH FLOOD: %u frames in 2s (total %u)", (unsigned)delta, (unsigned)now);
        }
        if (g_deauth_alert && esp_timer_get_time() > g_deauth_alert_until) g_deauth_alert = false;

        if (g_eviltwin_alert && !eviltwin_logged) {
            ESP_LOGW(TAG, "EVIL TWIN: '%s' beaconed from %02X:%02X:%02X:%02X:%02X:%02X",
                     AP_SSID, g_eviltwin_bssid[0], g_eviltwin_bssid[1], g_eviltwin_bssid[2],
                     g_eviltwin_bssid[3], g_eviltwin_bssid[4], g_eviltwin_bssid[5]);
            eviltwin_logged = true;
        } else if (!g_eviltwin_alert) {
            eviltwin_logged = false;
        }
    }
}

static void monitors_start(void) {
    esp_wifi_get_mac(WIFI_IF_AP, g_our_ap_bssid);
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    esp_wifi_set_promiscuous(true);
    xTaskCreate(monitor_task, "monitor", 3072, NULL, 4, NULL);
    ESP_LOGW(TAG, "security monitors ON (deauth + evil-twin, current channel only)");
}
#endif /* ENABLE_MONITORS */

/* =============================== WEB UI =================================== */
static const char DASHBOARD_HTML[] = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Pocket WiFi Filter</title>\n<style>\n:root{--bg:#0a0e13;--panel:#121823;--panel2:#0e141d;--line:#1f2a36;--txt:#e8eef5;--mut:#8a96a6;--ok:#3fb950;--warn:#d9a441;--bad:#f76258;--accent:#3b9eff;--accent2:#2f6bff}\n*{box-sizing:border-box;margin:0;padding:0}\nbody{background:radial-gradient(1100px 560px at 50% -200px,#10202f 0%,var(--bg) 62%);color:var(--txt);font:14px/1.55 -apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,Helvetica,Arial,sans-serif;padding:20px 16px 36px;max-width:860px;margin:0 auto;min-height:100vh}\na{color:var(--accent);text-decoration:none}\n.bar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding-bottom:16px;border-bottom:1px solid var(--line);margin-bottom:20px}\n.brand{display:flex;align-items:center;gap:12px}\n.logo{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;box-shadow:0 4px 14px rgba(59,158,255,.35);flex:none}\n.title{font-size:17px;font-weight:650;letter-spacing:.2px}\n.tagline{font-size:12px;color:var(--mut)}\n.bar-right{display:flex;align-items:center;gap:10px}\n.pill{display:inline-flex;align-items:center;gap:7px;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:5px 11px;font-size:12px;color:var(--mut)}\n.iconbtn{width:38px;height:38px;display:flex;align-items:center;justify-content:center;background:var(--panel);border:1px solid var(--line);border-radius:10px;color:var(--mut);cursor:pointer;transition:transform .25s ease,color .15s,border-color .15s;flex:none}\n.iconbtn:hover{color:var(--txt);border-color:#314156;transform:rotate(40deg)}\n.iconbtn svg{display:block}\n.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}\n.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:14px;padding:16px 17px;box-shadow:0 1px 0 rgba(255,255,255,.02) inset,0 6px 18px rgba(0,0,0,.25)}\n.card h2{font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--mut);margin-bottom:12px;font-weight:600}\n.row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.035)}\n.row:last-child{border-bottom:none}\n.row .k{color:var(--mut);white-space:nowrap}\n.row .v{font-weight:550;text-align:right}\n.dot{display:inline-block;width:8px;height:8px;border-radius:50%;vertical-align:middle}\n.num{font-size:32px;font-weight:800;line-height:1.05;letter-spacing:-.5px}\n.num.ok{color:var(--ok)}\n.num.bad{color:var(--bad)}\n.statsub{font-size:11px;color:var(--mut);margin-top:6px}\n.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}\ntable{width:100%;border-collapse:collapse;font-size:13px}\nth,td{text-align:left;padding:8px 4px;border-bottom:1px solid var(--line)}\nth{color:var(--mut);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.06em}\ntr:last-child td{border-bottom:none}\n.tag{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.03em;padding:3px 9px;border-radius:20px}\n.tag.a{background:rgba(63,185,80,.14);color:var(--ok)}\n.tag.b{background:rgba(247,98,88,.15);color:var(--bad)}\n.full{margin-bottom:14px}\n.foot{color:var(--mut);font-size:11.5px;text-align:center;margin-top:18px}\n.empty{color:var(--mut);padding:10px 4px}\n.overlay{position:fixed;inset:0;background:rgba(4,7,11,.7);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);display:none;align-items:flex-start;justify-content:center;padding:28px 16px;z-index:50;overflow:auto}\n.overlay.open{display:flex}\n.modal{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:16px;width:100%;max-width:470px;padding:22px;box-shadow:0 24px 60px rgba(0,0,0,.55);animation:pop .16s ease-out}\n@keyframes pop{from{transform:translateY(8px) scale(.985);opacity:0}to{transform:none;opacity:1}}\n.modal-head{display:flex;align-items:center;justify-content:space-between}\n.modal-head h3{font-size:17px;font-weight:650}\n.x{background:none;border:none;color:var(--mut);font-size:26px;line-height:1;cursor:pointer;padding:0 4px}\n.x:hover{color:var(--txt)}\n.modal-sub{color:var(--mut);font-size:12px;margin:5px 0 16px}\nlabel{display:block;margin-top:15px;font-size:12.5px;color:var(--mut)}\ninput,textarea{width:100%;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:9px;padding:10px;margin-top:6px;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;resize:vertical}\ninput:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,158,255,.18)}\n.hint{color:var(--mut);font-size:11px;margin-top:5px}\n.save{margin-top:20px;width:100%;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:0;border-radius:10px;padding:12px;font-weight:650;font-size:14px;cursor:pointer;box-shadow:0 6px 16px rgba(59,158,255,.3)}\n.save:hover{filter:brightness(1.07)}\n@media(max-width:560px){.grid2{grid-template-columns:1fr;gap:12px}.tagline{display:none}body{padding:16px 12px 32px}}\n</style>\n</head>\n<body>\n<div class=\"bar\">\n<div class=\"brand\"><div class=\"logo\"><svg viewBox=\"0 0 24 24\" width=\"20\" height=\"20\" fill=\"#fff\"><path d=\"M12 2 4 5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V5l-8-3z\"/></svg></div><div><div class=\"title\">Pocket WiFi Filter</div><div class=\"tagline\">Travel security gateway</div></div></div>\n<div class=\"bar-right\"><span class=\"pill\"><span class=\"dot\" id=\"livedot\" style=\"background:var(--mut)\"></span><span id=\"livetxt\">connecting</span></span><button class=\"iconbtn\" id=\"gear\" title=\"Settings\" aria-label=\"Open settings\"><svg viewBox=\"0 0 24 24\" width=\"20\" height=\"20\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"3\"></circle><path d=\"M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z\"></path></svg></button></div>\n</div>\n<div class=\"grid2\">\n<section class=\"card\"><h2>Uplink</h2><div id=\"uplink\"></div></section>\n<section class=\"card\"><h2>Access Point</h2><div id=\"ap\"></div></section>\n</div>\n<div class=\"grid2\">\n<section class=\"card\"><h2>DNS Allowed</h2><div class=\"num ok\" id=\"allowed\">--</div><div class=\"statsub\">queries permitted</div></section>\n<section class=\"card\"><h2>DNS Blocked</h2><div class=\"num bad\" id=\"blocked\">--</div><div class=\"statsub\">ads &amp; trackers stopped</div></section>\n</div>\n<section class=\"card full\"><h2>Security Monitors</h2><div id=\"sec\"></div></section>\n<section class=\"card full\"><h2>Connected Clients</h2><table><thead><tr><th>MAC Address</th><th>Signal</th></tr></thead><tbody id=\"clients\"></tbody></table></section>\n<section class=\"card\"><h2>Recent DNS Queries</h2><table><thead><tr><th>Domain</th><th>Action</th></tr></thead><tbody id=\"recent\"></tbody></table></section>\n<div class=\"foot\">Live status, refreshes every 2s &middot; uptime <span id=\"up\">--</span> &middot; <span id=\"ts\"></span></div>\n<div class=\"overlay\" id=\"overlay\">\n<div class=\"modal\">\n<div class=\"modal-head\"><h3>Settings</h3><button class=\"x\" id=\"close\" aria-label=\"Close\">&times;</button></div>\n<div class=\"modal-sub\">Saved to flash. The device reboots to apply.</div>\n<form method=\"POST\" action=\"/config\">\n<label>Upstream network (SSID)<input name=\"sta_ssid\" id=\"f_ssid\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\"></label>\n<label>Upstream password<input name=\"sta_pass\" type=\"password\" placeholder=\"leave blank to keep current\" autocomplete=\"new-password\"></label>\n<label>Clone MAC (captive-portal bypass)<input name=\"clone_mac\" id=\"f_clone\" placeholder=\"AA:BB:CC:DD:EE:FF\" autocomplete=\"off\" spellcheck=\"false\"></label>\n<div class=\"hint\">Present as an already-authorized device. Blank uses this device's own MAC.</div>\n<label>Dashboard password<input name=\"adm_pass\" type=\"password\" placeholder=\"leave blank to keep current\" autocomplete=\"new-password\"></label>\n<label>Blocklist (comma or newline separated)<textarea name=\"blocklist\" id=\"f_block\" rows=\"5\" spellcheck=\"false\"></textarea></label>\n<button type=\"submit\" class=\"save\">Save &amp; Reboot</button>\n</form>\n</div>\n</div>\n<script>\nvar CFG={ssid:'',clone_mac:'',blocklist:''};\nfunction rc(r){return r>-60?'var(--ok)':r>-75?'var(--warn)':'var(--bad)';}\nfunction pc(p){return p=='clear'?'var(--ok)':p=='portal'?'var(--warn)':'var(--mut)';}\nfunction row(k,v){return '<div class=\"row\"><span class=\"k\">'+k+'</span><span class=\"v\">'+v+'</span></div>';}\nfunction dur(s){var h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;return (h?h+'h ':'')+(m?m+'m ':'')+x+'s';}\nfunction esc(t){return (t==null?'':''+t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}\nfunction setLive(ok){document.getElementById('livedot').style.background=ok?'var(--ok)':'var(--bad)';document.getElementById('livetxt').textContent=ok?'live':'offline';}\nvar ov=document.getElementById('overlay');\ndocument.getElementById('gear').onclick=function(){document.getElementById('f_ssid').value=CFG.ssid;document.getElementById('f_clone').value=CFG.clone_mac;document.getElementById('f_block').value=CFG.blocklist;ov.classList.add('open');};\ndocument.getElementById('close').onclick=function(){ov.classList.remove('open');};\nov.onclick=function(e){if(e.target===ov)ov.classList.remove('open');};\nasync function tick(){\ntry{\nvar d=await(await fetch('/api/status')).json();\nvar u=d.uplink;\nif(d.cfg)CFG=d.cfg;\ndocument.getElementById('uplink').innerHTML=row('Status','<span class=\"dot\" style=\"background:'+(u.up?'var(--ok)':'var(--bad)')+'\"></span> '+(u.up?'Connected':'Down'))+row('Network',esc(u.ssid))+row('IP','<span class=\"mono\">'+u.ip+'</span>')+row('Signal','<span style=\"color:'+rc(u.rssi)+'\">'+u.rssi+' dBm</span>')+row('Upstream DNS',d.dns.doh?'<span style=\"color:var(--ok)\">DoH &middot; Cloudflare</span>':'<span class=\"mono\">'+u.dns+'</span>')+(d.dns.doh?row('DoH queries',d.dns.doh_ok+' ok &middot; '+d.dns.fallbacks+' fb'):'')+row('Captive portal','<span style=\"color:'+pc(u.portal)+'\">'+u.portal+'</span>')+row('STA MAC','<span class=\"mono\">'+u.mac+'</span>'+(u.cloned?' <span style=\"color:var(--warn);font-size:11px\">cloned</span>':''));\ndocument.getElementById('ap').innerHTML=row('Network name',esc(d.ap.ssid))+row('Gateway','<span class=\"mono\">'+d.ap.ip+'</span>')+row('Connected clients',d.ap.clients);\ndocument.getElementById('allowed').textContent=d.dns.allowed;\ndocument.getElementById('blocked').textContent=d.dns.blocked;\nvar s=d.security;\ndocument.getElementById('sec').innerHTML=s.monitors?(row('Deauth frames',s.deauth+(s.deauth_alert?' <span style=\"color:var(--bad);font-weight:700\">FLOOD</span>':''))+row('Evil-twin AP',s.eviltwin?'<span style=\"color:var(--bad);font-weight:700\">ALERT &middot; '+s.eviltwin_bssid+'</span>':'<span style=\"color:var(--ok)\">clear</span>')):'<div class=\"empty\">Monitors off. Set ENABLE_MONITORS to 1 and reflash to enable.</div>';\ndocument.getElementById('clients').innerHTML=d.clients.length?d.clients.map(function(c){return '<tr><td class=\"mono\">'+c.mac+'</td><td style=\"color:'+rc(c.rssi)+'\">'+c.rssi+' dBm</td></tr>';}).join(''):'<tr><td colspan=\"2\" class=\"empty\">No clients connected</td></tr>';\ndocument.getElementById('recent').innerHTML=d.recent.length?d.recent.map(function(q){return '<tr><td class=\"mono\">'+esc(q.name)+'</td><td><span class=\"tag '+(q.blocked?'b':'a')+'\">'+(q.blocked?'BLOCKED':'allowed')+'</span></td></tr>';}).join(''):'<tr><td colspan=\"2\" class=\"empty\">No queries yet</td></tr>';\ndocument.getElementById('up').textContent=dur(d.uptime_s);\ndocument.getElementById('ts').textContent=new Date().toLocaleTimeString();\nsetLive(true);\n}catch(e){setLive(false);document.getElementById('ts').textContent='reconnecting...';}\n}\ntick();setInterval(tick,2000);\n</script>\n</body>\n</html>";
static const char CONFIG_HEAD[]    = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Settings</title>\n<style>\n:root{--bg:#0d1117;--card:#161b22;--line:#21262d;--txt:#e6edf3;--mut:#8b949e;--accent:#2f81f7}\n*{box-sizing:border-box;margin:0;padding:0}\nbody{background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;padding:18px;max-width:520px;margin:0 auto}\nh1{font-size:18px;font-weight:600;margin-top:6px}\n.sub{color:var(--mut);font-size:12px;margin:4px 0 18px}\nform{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}\nlabel{display:block;margin-top:14px;font-size:13px;color:var(--mut)}\nlabel:first-child{margin-top:0}\ninput,textarea{width:100%;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:8px;padding:9px;margin-top:5px;font:13px/1.4 ui-monospace,Menlo,Consolas,monospace;resize:vertical}\nbutton{margin-top:18px;width:100%;background:var(--accent);color:#fff;border:0;border-radius:8px;padding:11px;font-weight:600;font-size:14px;cursor:pointer}\na{color:var(--accent);font-size:13px}\n.hint{color:var(--mut);font-size:11px;margin-top:3px}\n.note{margin-top:14px}\n</style></head><body>\n<h1>Settings</h1>\n<div class=\"sub\">saved to flash; device reboots to apply</div>\n<form method=\"POST\" action=\"/config\">\n<label>Upstream network (SSID)<input name=\"sta_ssid\" value=\"";
static const char CONFIG_MID1[]    = "\"></label>\n<label>Upstream password<input name=\"sta_pass\" type=\"password\" placeholder=\"leave blank to keep current\"></label>\n<label>Clone MAC (captive-portal bypass)<input name=\"clone_mac\" value=\"";
static const char CONFIG_MID2[]    = "\" placeholder=\"AA:BB:CC:DD:EE:FF\"></label>\n<div class=\"hint\">Present as an already-authorized device. Blank = use this device's own MAC.</div>\n<label>Dashboard password<input name=\"adm_pass\" type=\"password\" placeholder=\"leave blank to keep current\"></label>\n<label>Blocklist (comma or newline separated)<textarea name=\"blocklist\" rows=\"5\">";
static const char CONFIG_TAIL[]    = "</textarea></label>\n<button type=\"submit\">Save &amp; Reboot</button>\n</form>\n<p class=\"note\"><a href=\"/\">&larr; Back to dashboard</a></p>\n</body></html>";

static bool check_auth(httpd_req_t *req) {
    char hdr[200];
    bool ok = false;
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) == ESP_OK
        && strncmp(hdr, "Basic ", 6) == 0) {
        unsigned char dec[160]; size_t dl = 0;
        if (mbedtls_base64_decode(dec, sizeof(dec) - 1, &dl,
                                  (const unsigned char *)(hdr + 6), strlen(hdr + 6)) == 0) {
            dec[dl] = 0;
            char exp[160];
            snprintf(exp, sizeof(exp), "%s:%s", g_admin_user, g_admin_pass);
            if (strcmp((char *)dec, exp) == 0) ok = true;
        }
    }
    if (ok) return true;
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"PocketFilter\"");
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "Authentication required", HTTPD_RESP_USE_STRLEN);
    return false;
}

static esp_err_t root_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, DASHBOARD_HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t favicon_get_handler(httpd_req_t *req) {
    httpd_resp_set_status(req, "204 No Content");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t status_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    const int CAP = 6144;
    char *buf = malloc(CAP);
    if (!buf) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom"); return ESP_FAIL; }
    int len = 0;
#define ADD(...) do { int _w = snprintf(buf+len, CAP-len, __VA_ARGS__); if (_w > 0 && _w < (CAP-len)) len += _w; } while (0)

    bool up = g_uplink_up;
    char staip[16] = "0.0.0.0";
    esp_netif_ip_info_t sip;
    if (sta_netif && esp_netif_get_ip_info(sta_netif, &sip) == ESP_OK && sip.ip.addr)
        esp_ip4addr_ntoa(&sip.ip, staip, sizeof(staip));
    int rssi = 0;
    wifi_ap_record_t aprec;
    if (esp_wifi_sta_get_ap_info(&aprec) == ESP_OK) rssi = aprec.rssi;
    char dnss[16] = "(none)";
    if (g_upstream_dns) { esp_ip4_addr_t d; d.addr = g_upstream_dns; esp_ip4addr_ntoa(&d, dnss, sizeof(dnss)); }
    char apip[16] = "192.168.4.1";
    esp_netif_ip_info_t aip;
    if (ap_netif && esp_netif_get_ip_info(ap_netif, &aip) == ESP_OK && aip.ip.addr)
        esp_ip4addr_ntoa(&aip.ip, apip, sizeof(apip));
    uint8_t stamac[6] = {0};
    esp_wifi_get_mac(WIFI_IF_STA, stamac);
    char macs[18];
    snprintf(macs, sizeof(macs), "%02X:%02X:%02X:%02X:%02X:%02X",
             stamac[0],stamac[1],stamac[2],stamac[3],stamac[4],stamac[5]);
    bool cloned = (g_clone_mac[0] != 0);
    wifi_sta_list_t stal; memset(&stal, 0, sizeof(stal));
    esp_wifi_ap_get_sta_list(&stal);
    long long up_s = (long long)(esp_timer_get_time() / 1000000);

    char etb[18] = "--";
    if (g_eviltwin_alert)
        snprintf(etb, sizeof(etb), "%02X:%02X:%02X:%02X:%02X:%02X",
                 g_eviltwin_bssid[0],g_eviltwin_bssid[1],g_eviltwin_bssid[2],
                 g_eviltwin_bssid[3],g_eviltwin_bssid[4],g_eviltwin_bssid[5]);

    char jss[80], jcl[48], jbl[1100];
    json_escape(g_sta_ssid,  jss, sizeof(jss));
    json_escape(g_clone_mac, jcl, sizeof(jcl));
    json_escape(g_blocklist, jbl, sizeof(jbl));

    ADD("{\"uplink\":{\"up\":%s,\"ssid\":\"%s\",\"ip\":\"%s\",\"rssi\":%d,\"dns\":\"%s\",\"portal\":\"%s\",\"mac\":\"%s\",\"cloned\":%s},",
        up ? "true" : "false", jss, staip, rssi, dnss, portal_str(g_portal), macs, cloned ? "true" : "false");
    ADD("\"ap\":{\"ssid\":\"%s\",\"ip\":\"%s\",\"clients\":%d},", AP_SSID, apip, stal.num);
    ADD("\"dns\":{\"allowed\":%u,\"blocked\":%u,\"doh\":%s,\"doh_ok\":%u,\"fallbacks\":%u},", (unsigned)g_dns_allowed, (unsigned)g_dns_blocked, ENABLE_DOH ? "true" : "false", (unsigned)g_doh_ok, (unsigned)g_doh_fallbacks);
    ADD("\"uptime_s\":%lld,", up_s);
    ADD("\"security\":{\"monitors\":%s,\"deauth\":%u,\"deauth_alert\":%s,\"eviltwin\":%s,\"eviltwin_bssid\":\"%s\"},",
        ENABLE_MONITORS ? "true" : "false", (unsigned)g_deauth_total,
        g_deauth_alert ? "true" : "false", g_eviltwin_alert ? "true" : "false", etb);
    ADD("\"cfg\":{\"ssid\":\"%s\",\"clone_mac\":\"%s\",\"blocklist\":\"%s\"},", jss, jcl, jbl);

    ADD("\"clients\":[");
    for (int i = 0; i < stal.num; i++) {
        const uint8_t *m = stal.sta[i].mac;
        ADD("%s{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"rssi\":%d}",
            i ? "," : "", m[0],m[1],m[2],m[3],m[4],m[5], stal.sta[i].rssi);
    }
    ADD("],");

    dns_evt_t snap[RECENT_N]; int sc = 0;
    if (g_recent_mtx && xSemaphoreTake(g_recent_mtx, pdMS_TO_TICKS(50)) == pdTRUE) {
        sc = g_recent_count; int head = g_recent_head;
        for (int i = 0; i < sc; i++) { int idx = (head - 1 - i + RECENT_N*2) % RECENT_N; snap[i] = g_recent[idx]; }
        xSemaphoreGive(g_recent_mtx);
    }
    ADD("\"recent\":[");
    for (int i = 0; i < sc; i++)
        ADD("%s{\"name\":\"%s\",\"blocked\":%s}", i ? "," : "", snap[i].name, snap[i].blocked ? "true" : "false");
    ADD("]}");

#undef ADD
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    free(buf);
    return ESP_OK;
}

static esp_err_t config_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    char ess[80], ecl[40], ebl[1600];
    html_escape(g_sta_ssid,  ess, sizeof(ess));
    html_escape(g_clone_mac, ecl, sizeof(ecl));
    html_escape(g_blocklist, ebl, sizeof(ebl));
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req, CONFIG_HEAD);
    httpd_resp_sendstr_chunk(req, ess);
    httpd_resp_sendstr_chunk(req, CONFIG_MID1);
    httpd_resp_sendstr_chunk(req, ecl);
    httpd_resp_sendstr_chunk(req, CONFIG_MID2);
    httpd_resp_sendstr_chunk(req, ebl);
    httpd_resp_sendstr_chunk(req, CONFIG_TAIL);
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t config_post_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    int total = req->content_len;
    if (total <= 0 || total > 2048) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad length"); return ESP_FAIL; }
    char *body = malloc(total + 1);
    if (!body) { httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom"); return ESP_FAIL; }
    int got = 0;
    while (got < total) {
        int r = httpd_req_recv(req, body + got, total - got);
        if (r <= 0) { free(body); return ESP_FAIL; }
        got += r;
    }
    body[got] = 0;

    char tmp[256];
    if (form_field(body, "sta_ssid", tmp, sizeof(tmp)))           strlcpy(g_sta_ssid,   tmp, sizeof(g_sta_ssid));
    if (form_field(body, "sta_pass", tmp, sizeof(tmp)) && tmp[0]) strlcpy(g_sta_pass,   tmp, sizeof(g_sta_pass));
    if (form_field(body, "adm_pass", tmp, sizeof(tmp)) && tmp[0]) strlcpy(g_admin_pass, tmp, sizeof(g_admin_pass));
    if (form_field(body, "clone_mac", tmp, sizeof(tmp))) {
        char *q = tmp; while (*q == ' ') q++;
        strlcpy(g_clone_mac, q, sizeof(g_clone_mac));
    }
    char bl[512];
    if (form_field(body, "blocklist", bl, sizeof(bl))) { strlcpy(g_blocklist, bl, sizeof(g_blocklist)); blocklist_parse(); }
    free(body);

    config_save();
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr(req, "<meta http-equiv=\"refresh\" content=\"6;url=/\"><body style=\"font-family:sans-serif;background:#0d1117;color:#e6edf3;padding:40px\">Saved. Rebooting - returning to the dashboard in a few seconds.</body>");
    vTaskDelay(pdMS_TO_TICKS(800));
    esp_restart();
    return ESP_OK;
}

static httpd_handle_t start_webserver(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8192;
    config.lru_purge_enable = true;
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t root = { .uri = "/",            .method = HTTP_GET,  .handler = root_get_handler };
        httpd_uri_t st   = { .uri = "/api/status",  .method = HTTP_GET,  .handler = status_get_handler };
        httpd_uri_t fav  = { .uri = "/favicon.ico", .method = HTTP_GET,  .handler = favicon_get_handler };
        httpd_uri_t cfg  = { .uri = "/config",      .method = HTTP_GET,  .handler = config_get_handler };
        httpd_uri_t cfgp = { .uri = "/config",      .method = HTTP_POST, .handler = config_post_handler };
        httpd_register_uri_handler(server, &root);
        httpd_register_uri_handler(server, &st);
        httpd_register_uri_handler(server, &fav);
        httpd_register_uri_handler(server, &cfg);
        httpd_register_uri_handler(server, &cfgp);
        ESP_LOGI(TAG, "web UI at http://192.168.4.1/  (login: %s)", g_admin_user);
    } else {
        ESP_LOGE(TAG, "failed to start web server");
    }
    return server;
}

/* =============================== APP MAIN =================================*/
void app_main(void) {
    esp_err_t nv = nvs_flash_init();
    if (nv == ESP_ERR_NVS_NO_FREE_PAGES || nv == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    ESP_LOGI(TAG, "Pocket WiFi Filter (ESP-IDF core + dashboard) starting");

    config_load();
    g_recent_mtx = xSemaphoreCreateMutex();

    wifi_init_apsta();
    xTaskCreate(dns_filter_task, "dns_filter", ENABLE_DOH ? 20480 : 4096, NULL, 5, NULL);
    xTaskCreate(portal_task,     "portal",     4096, NULL, 4, NULL);
    start_webserver();
#if ENABLE_MONITORS
    monitors_start();
#endif

    ESP_LOGI(TAG, "core up: NAPT, DNS%s filter, web UI+auth, NVS, portal, MAC-clone, monitors=%d.", ENABLE_DOH ? "-over-HTTPS" : "", ENABLE_MONITORS);
}
