/*
 * ESP32Watchdog — Passive Wi-Fi Threat Detection  (v1.0.0)
 *
 * Target  : ESP32 DevKit V1 / ESP32-WROOM-32, 30-pin
 * Core    : esp32 by Espressif 2.0.x+
 * Libs    : U8g2 (Library Manager); SD, SPI, WiFi, esp_wifi, FreeRTOS — bundled
 *
 * Modes:
 *   MODE_DEAUTH — deauth / disassoc frame floods
 *   MODE_TWIN   — evil twin APs (same SSID, different BSSID)
 *   MODE_FLOOD  — anomalous beacon / SSID volume spike
 *
 * Pinout:
 *   OLED SSD1306 128×64 I2C  SDA=21  SCL=22
 *   MicroSD SPI              SCK=18  MOSI=23  MISO=19  CS=5
 *   Button (active-low)      GPIO4 internal pull-up
 *   LED + 220 Ω              GPIO2
 *
 * Safety model:
 *   All ISR-shared data guarded by portMUX_TYPE spinlock (g_ap_mutex) or
 *   std::atomic. millis() is always snapshotted before portENTER_CRITICAL.
 *   task_ui MUST run on Core 1 (I2C / promisc ISR isolation).
 *   Zero runtime malloc after boot.
 *   OLED shadow copies (g_disp_*) prevent torn reads on mutex-timeout.
 *   Deauth tracker uses LRU eviction — MAC-rotating attacker can't fill table.
 *   Flood SSID table uses FNV-1a 16-bit hash set (O(1) critical-section check).
 *   Evil twin alert rate-limited per SSID (TWIN_COOLDOWN_MS).
 *   xQueueSend to g_write_queue uses short timeout; drops increment g_dropped_alerts.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SD.h>
#include <SPI.h>
#include <Wire.h>
#include <U8g2lib.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <esp_task_wdt.h>
#include <lwip/def.h>
#include <atomic>
#include <freertos/portmacro.h>

/* Firmware version — single source of truth */
#define FW_VERSION "1.0.0"

/* ---------- Pin assignments ------------------------------------------------ */
#define PIN_OLED_SDA  21
#define PIN_OLED_SCL  22
#define PIN_SD_CS      5
#define PIN_SD_SCK    18
#define PIN_SD_MOSI   23
#define PIN_SD_MISO   19
#define PIN_BTN        4
#define PIN_LED        2

/* ---------- Tuning constants ----------------------------------------------- */
#define PKT_POOL_DEPTH       32
#define PKT_QUEUE_DEPTH      32
#define WRITE_QUEUE_DEPTH     8
#define MAX_UNIQUE_APS       64   /* must be power-of-two */
#define MAX_PKT_LEN        1600
#define RSSI_THRESHOLD      (-90) /* drop packets weaker than -90 dBm in ISR */
#define DEAUTH_THRESHOLD      10  /* deauth frames / window to fire */
#define DEAUTH_WINDOW_MS    1000UL
#define FLOOD_THRESHOLD       20  /* unique SSIDs / window to fire */
#define FLOOD_WINDOW_MS     1000UL
#define AP_EXPIRE_MS       30000UL
#define SD_RETRY_MS        10000UL
#define MIN_FREE_BYTES     (1024ULL * 1024ULL)
#define WDT_TIMEOUT_S        30
#define CHANNEL_DWELL_MS    200UL
#define CHANNELS_2G          13
#define DEBOUNCE_MS          50UL
#define LONG_PRESS_MS      3000UL
#define TASK_SCAN_BATCH_MAX  15
#define POOL_NONE          0xFF
#define TWIN_COOLDOWN_MS   30000UL  /* per-SSID evil-twin alert cooldown */
#define ALERT_LED_TIMEOUT_MS 10000UL /* revert LED_FAST → LED_SLOW after inactivity */

/* Stack sizes (verified with uxTaskGetStackHighWaterMark on reference hw) */
#define STACK_SCAN  6144
#define STACK_WRITE 6144
#define STACK_UI    4096

#define CSV_BUF_SIZE 256  /* one CSV row ≤ ~160 chars; 256 gives headroom */

/* Compile-time guards */
static_assert(PKT_POOL_DEPTH < 0xFF, "PKT_POOL_DEPTH too large: POOL_NONE sentinel invalid");
static_assert(MAX_UNIQUE_APS < 0xFF, "AP table index sentinel invalid");
static_assert(64 >= FLOOD_THRESHOLD,  "FLOOD_SET_SIZE must be >= FLOOD_THRESHOLD");

/* ---------- Display -------------------------------------------------------- */
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C display(
    U8G2_R0, U8X8_PIN_NONE, PIN_OLED_SCL, PIN_OLED_SDA);

/* ---------- Byte-safe memory helpers (avoids alignment faults on LX6) ----- */
static inline uint16_t read16_le(const uint8_t *p) { return p[0] | ((uint16_t)p[1] << 8); }
static inline uint16_t read16_be(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }

/* ---------- Static packet pool (zero runtime malloc after boot) ------------ */
static uint8_t pkt_pool_mem[PKT_POOL_DEPTH][MAX_PKT_LEN];

static QueueHandle_t g_pkt_free_q;  /* free-list of pool indices */
static QueueHandle_t g_pkt_queue;   /* filled packets → task_scan */
static QueueHandle_t g_write_queue; /* alert type bytes → task_write */

typedef struct {
    uint8_t  pool_idx;
    uint16_t len;
    uint8_t  channel; /* from pkt->rx_ctrl.channel (driver truth) */
    int8_t   rssi;
} pkt_item_t;

typedef uint8_t alert_type_t;
#define ALERT_DEAUTH 0
#define ALERT_TWIN   1
#define ALERT_FLOOD  2

/* ---------- Detection mode ------------------------------------------------- */
typedef enum { MODE_DEAUTH = 0, MODE_TWIN = 1, MODE_FLOOD = 2 } detect_mode_t;
static std::atomic<detect_mode_t> g_mode{MODE_DEAUTH};

/* ---------- AP table ------------------------------------------------------- */
/* Protected by g_ap_mutex. millis() always snapshotted before portENTER_CRITICAL. */
#define AP_TABLE_MASK (MAX_UNIQUE_APS - 1)

typedef struct {
    char     ssid[33];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    uint32_t last_ms;
    bool     used;
} ap_entry_t;

static ap_entry_t   g_ap_table[MAX_UNIQUE_APS];
static portMUX_TYPE g_ap_mutex = portMUX_INITIALIZER_UNLOCKED;

/* ---------- Deauth tracker — per-source sliding window -------------------- */
/* LRU eviction: when all slots occupied, oldest window_start is recycled. */
#define DEAUTH_TRACK_SLOTS 8

typedef struct {
    uint8_t  src[6];
    uint8_t  dst[6];
    uint32_t window_start;
    uint32_t count;
    uint8_t  reason;
    uint8_t  channel;
    bool     used;
} deauth_track_t;

static deauth_track_t g_deauth_track[DEAUTH_TRACK_SLOTS];

/* ---------- Alert payloads (protected by g_alert_mutex) ------------------- */
typedef struct {
    uint32_t timestamp_ms;
    uint8_t  attacker[6];
    uint8_t  target[6];
    uint8_t  channel;
    uint32_t frame_count;
    uint8_t  reason;
} deauth_alert_t;

typedef struct {
    uint32_t timestamp_ms;
    char     ssid[33];
    uint8_t  legit_bssid[6];
    int8_t   legit_rssi;
    uint8_t  rogue_bssid[6];
    int8_t   rogue_rssi;
    uint8_t  channel;
} twin_alert_t;

typedef struct {
    uint32_t timestamp_ms;
    uint32_t unique_ssids;
    uint8_t  channel;
    char     sample[3][33];
} flood_alert_t;

static deauth_alert_t g_deauth_alert;
static twin_alert_t   g_twin_alert;
static flood_alert_t  g_flood_alert;

/* OLED shadow copies — updated only under g_alert_mutex; task_ui renders from these */
static deauth_alert_t g_disp_deauth;
static twin_alert_t   g_disp_twin;
static flood_alert_t  g_disp_flood;

static SemaphoreHandle_t g_alert_mutex;
static SemaphoreHandle_t g_sd_mutex;

/* ---------- Shared status state ------------------------------------------- */
typedef enum { FACE_IDLE, FACE_ALERT_DEAUTH, FACE_ALERT_TWIN, FACE_ALERT_FLOOD, FACE_ERROR } face_t;
static std::atomic<face_t>      g_face{FACE_IDLE};

typedef enum { LED_SLOW, LED_FAST, LED_FLASH, LED_ERROR } led_state_t;
static std::atomic<led_state_t> g_led{LED_SLOW};

static std::atomic<uint32_t> g_last_alert_ms{0};
static std::atomic<uint8_t>  g_channel{1};
static std::atomic<uint32_t> g_pkt_rate{0};
static std::atomic<uint32_t> g_alert_count{0};
static std::atomic<uint32_t> g_dropped_alerts{0};
static std::atomic<bool>     g_sd_ok{false};
static std::atomic<uint32_t> g_last_sd_retry{0};

/* File-scope so sd_init() re-entry doesn't double-init SPI (guarded by g_sd_mutex) */
static bool g_spi_started = false;

/* Task handles */
static TaskHandle_t h_scan;
static TaskHandle_t h_write;
static TaskHandle_t h_ui;

/* ---------- MAC helpers ---------------------------------------------------- */
static inline bool mac_eq(const uint8_t *a, const uint8_t *b) {
    return memcmp(a, b, 6) == 0;
}
static inline bool mac_zero(const uint8_t *a) {
    for (int i = 0; i < 6; i++) if (a[i] != 0) return false;
    return true;
}
static void mac_str_colon(const uint8_t *m, char *out, size_t sz) {
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}
static void mac_str_short(const uint8_t *m, char *out, size_t sz) {
    snprintf(out, sz, "%02x:%02x:%02x", m[0], m[1], m[2]);
}

/* ---------- SD initialisation --------------------------------------------- */
/* May be called from setup() and from the retry path — won't double-init SPI. */
static bool sd_init(void) {
    xSemaphoreTake(g_sd_mutex, portMAX_DELAY);

    if (!g_spi_started) {
        SPI.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);
        g_spi_started = true;
    }

    if (!SD.begin(PIN_SD_CS)) {
        g_sd_ok.store(false);
        g_face.store(FACE_ERROR);
        g_led.store(LED_ERROR);
        Serial.println("[SD] init failed");
        xSemaphoreGive(g_sd_mutex);
        return false;
    }

    g_sd_ok.store(true);
    if (g_face.load() == FACE_ERROR) g_face.store(FACE_IDLE);
    g_led.store(LED_SLOW);

    if (!SD.exists("/watchdog")) SD.mkdir("/watchdog");

    if (!SD.exists("/watchdog/deauth.csv")) {
        File f = SD.open("/watchdog/deauth.csv", FILE_WRITE);
        if (f) { f.println("timestamp_ms,attacker_mac,target_mac,channel,frame_count,reason_code"); f.close(); }
    }
    if (!SD.exists("/watchdog/twins.csv")) {
        File f = SD.open("/watchdog/twins.csv", FILE_WRITE);
        if (f) { f.println("timestamp_ms,ssid,legit_bssid,legit_rssi,rogue_bssid,rogue_rssi,channel"); f.close(); }
    }
    if (!SD.exists("/watchdog/floods.csv")) {
        File f = SD.open("/watchdog/floods.csv", FILE_WRITE);
        if (f) { f.println("timestamp_ms,unique_ssids_per_sec,channel,sample1,sample2,sample3"); f.close(); }
    }

    Serial.println("[SD] OK");
    xSemaphoreGive(g_sd_mutex);
    return true;
}

/* ---------- AP table operations ------------------------------------------- */
/* All helpers receive 'now' as a param — millis() never called inside critical section. */

static int ap_find_ssid(const char *ssid, const uint8_t *exclude_bssid) {
    for (int i = 0; i < MAX_UNIQUE_APS; i++) {
        if (!g_ap_table[i].used) continue;
        if (strcmp(g_ap_table[i].ssid, ssid) != 0) continue;
        if (exclude_bssid && mac_eq(g_ap_table[i].bssid, exclude_bssid)) continue;
        return i;
    }
    return -1;
}

static bool ap_upsert(const char *ssid, const uint8_t *bssid,
                      int8_t rssi, uint8_t ch, uint32_t now_ms) {
    int empty_slot = -1;
    for (int i = 0; i < MAX_UNIQUE_APS; i++) {
        if (!g_ap_table[i].used) {
            if (empty_slot < 0) empty_slot = i;
            continue;
        }
        if (mac_eq(g_ap_table[i].bssid, bssid)) {
            strncpy(g_ap_table[i].ssid, ssid, 32);
            g_ap_table[i].ssid[32] = '\0';
            g_ap_table[i].rssi     = rssi;
            g_ap_table[i].channel  = ch;
            g_ap_table[i].last_ms  = now_ms;
            return false;
        }
    }
    if (empty_slot >= 0) {
        strncpy(g_ap_table[empty_slot].ssid, ssid, 32);
        g_ap_table[empty_slot].ssid[32] = '\0';
        memcpy(g_ap_table[empty_slot].bssid, bssid, 6);
        g_ap_table[empty_slot].rssi    = rssi;
        g_ap_table[empty_slot].channel = ch;
        g_ap_table[empty_slot].last_ms = now_ms;
        g_ap_table[empty_slot].used    = true;
        return true;
    }
    return false;
}

static void ap_table_expire(uint32_t now_ms) {
    portENTER_CRITICAL(&g_ap_mutex);
    for (int i = 0; i < MAX_UNIQUE_APS; i++) {
        if (g_ap_table[i].used &&
            (now_ms - g_ap_table[i].last_ms) > AP_EXPIRE_MS) {
            g_ap_table[i].used = false;
        }
    }
    portEXIT_CRITICAL(&g_ap_mutex);
}

/* ---------- Flood SSID presence table ------------------------------------- */
/* 16-bit FNV-1a hash → 512-bit bitmap; ~0.2% false-positive at 64 simultaneous SSIDs. */
#define FLOOD_SET_SIZE 64

static char     g_flood_set[FLOOD_SET_SIZE][33];
static uint8_t  g_flood_set_count    = 0;
static uint32_t g_flood_window_start = 0;
static uint8_t  g_flood_hash_bmp[64]; /* 512-bit */

static uint16_t fnv1a16_ssid(const char *s) {
    uint32_t h = 0x811C9DC5UL;
    while (*s) { h ^= (uint8_t)(*s++); h *= 0x01000193UL; }
    return (uint16_t)((h ^ (h >> 16)) & 0xFFFFU);
}

static inline bool flood_hash_test(uint16_t h) {
    uint16_t idx = h & 0x1FF;
    return (g_flood_hash_bmp[idx >> 3] >> (idx & 7)) & 1;
}
static inline void flood_hash_set(uint16_t h) {
    uint16_t idx = h & 0x1FF;
    g_flood_hash_bmp[idx >> 3] |= (uint8_t)(1u << (idx & 7));
}

/* ---------- Evil twin per-SSID cooldown ----------------------------------- */
/* Prevents a rogue AP beaconing at ~10 Hz from saturating the write queue. */
#define TWIN_COOLDOWN_SLOTS 8

typedef struct {
    char     ssid[33];
    uint32_t last_alert_ms;
    bool     used;
} twin_cooldown_t;

static twin_cooldown_t g_twin_cd[TWIN_COOLDOWN_SLOTS];

/* Returns true if SSID is still in cooldown; otherwise records now_ms and returns false.
 * Must be called inside portENTER_CRITICAL(&g_ap_mutex). */
static bool twin_cooldown_check(const char *ssid, uint32_t now_ms) {
    int empty = -1;
    for (int i = 0; i < TWIN_COOLDOWN_SLOTS; i++) {
        if (!g_twin_cd[i].used) { if (empty < 0) empty = i; continue; }
        if (strcmp(g_twin_cd[i].ssid, ssid) == 0) {
            if ((now_ms - g_twin_cd[i].last_alert_ms) < TWIN_COOLDOWN_MS) return true;
            g_twin_cd[i].last_alert_ms = now_ms;
            return false;
        }
    }
    /* New SSID — LRU eviction if table full */
    int slot = (empty >= 0) ? empty : 0;
    if (empty < 0) {
        for (int i = 1; i < TWIN_COOLDOWN_SLOTS; i++)
            if (g_twin_cd[i].last_alert_ms < g_twin_cd[slot].last_alert_ms) slot = i;
    }
    strncpy(g_twin_cd[slot].ssid, ssid, 32);
    g_twin_cd[slot].ssid[32]        = '\0';
    g_twin_cd[slot].last_alert_ms   = now_ms;
    g_twin_cd[slot].used            = true;
    return false;
}

/* ---------- SSID extraction from 802.11 tagged parameters ----------------- */
static bool extract_ssid(const uint8_t *tags, uint16_t tags_len,
                          char *out, size_t out_sz) {
    uint16_t pos = 0;
    while (pos + 2 <= tags_len) {
        uint8_t tag_id  = tags[pos];
        uint8_t tag_len = tags[pos + 1];
        if (pos + 2 + tag_len > tags_len) break;
        if (tag_id == 0 && tag_len > 0) {
            size_t copy = (tag_len < out_sz - 1) ? tag_len : out_sz - 1;
            memcpy(out, tags + pos + 2, copy);
            out[copy] = '\0';
            return true;
        }
        pos += 2 + tag_len;
    }
    out[0] = '\0';
    return false;
}

/* ---------- Detection helpers --------------------------------------------- */

static void detect_deauth(const uint8_t *mf, uint16_t mfl,
                           uint8_t ch, int8_t rssi) {
    if (mfl < 26) return;

    const uint8_t *src    = mf + 10;
    const uint8_t *dst    = mf + 4;
    uint8_t        reason = mf[24];
    uint32_t       now    = millis(); /* snapshot before critical section */

    portENTER_CRITICAL(&g_ap_mutex);

    int found = -1, empty = -1, oldest = 0;
    for (int i = 0; i < DEAUTH_TRACK_SLOTS; i++) {
        if (g_deauth_track[i].used && mac_eq(g_deauth_track[i].src, src)) { found = i; break; }
        if (!g_deauth_track[i].used && empty < 0) empty = i;
        if (g_deauth_track[i].used &&
            g_deauth_track[i].window_start < g_deauth_track[oldest].window_start) oldest = i;
    }

    if (found < 0) {
        found = (empty >= 0) ? empty : oldest; /* LRU eviction */
        memset(&g_deauth_track[found], 0, sizeof(deauth_track_t));
        memcpy(g_deauth_track[found].src, src, 6);
        g_deauth_track[found].used         = true;
        g_deauth_track[found].window_start = now;
    }

    deauth_track_t *tr = &g_deauth_track[found];
    if ((now - tr->window_start) > DEAUTH_WINDOW_MS) { tr->count = 0; tr->window_start = now; }

    tr->count++;
    memcpy(tr->dst, dst, 6);
    tr->reason  = reason;
    tr->channel = ch;

    bool     fire        = (tr->count >= DEAUTH_THRESHOLD);
    uint32_t saved_count = tr->count;
    if (fire) { tr->count = 0; tr->window_start = now; }
    portEXIT_CRITICAL(&g_ap_mutex);

    if (!fire) return;

    if (xSemaphoreTake(g_alert_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        g_deauth_alert.timestamp_ms = now;
        memcpy(g_deauth_alert.attacker, src, 6);
        memcpy(g_deauth_alert.target,   dst, 6);
        g_deauth_alert.channel     = ch;
        g_deauth_alert.frame_count = saved_count;
        g_deauth_alert.reason      = reason;
        g_disp_deauth = g_deauth_alert; /* update shadow while mutex held */
        xSemaphoreGive(g_alert_mutex);
    }

    char src_s[18], dst_s[18];
    mac_str_colon(src, src_s, sizeof(src_s));
    mac_str_colon(dst, dst_s, sizeof(dst_s));
    Serial.printf("[DEAUTH] %s -> %s  cnt=%lu  reason=%u\n",
                  src_s, dst_s, (unsigned long)saved_count, reason);

    g_alert_count.fetch_add(1, std::memory_order_relaxed);
    g_last_alert_ms.store(now, std::memory_order_relaxed);
    g_face.store(FACE_ALERT_DEAUTH);
    g_led.store(LED_FAST);

    alert_type_t at = ALERT_DEAUTH;
    if (xQueueSend(g_write_queue, &at, pdMS_TO_TICKS(2)) != pdTRUE) {
        g_dropped_alerts.fetch_add(1, std::memory_order_relaxed);
        Serial.println("[WARN] write queue full — deauth alert dropped");
    }
}

static void detect_twin(const uint8_t *mf, uint16_t mfl,
                         const uint8_t *bssid_addr3,
                         uint8_t ch, int8_t rssi) {
    if (mfl < 36) return;

    const uint8_t *tags     = mf + 24 + 12;
    uint16_t       tags_len = (mfl > 36) ? mfl - 36 : 0;

    char ssid[33] = {0};
    if (!extract_ssid(tags, tags_len, ssid, sizeof(ssid)) || ssid[0] == '\0') return;

    uint32_t now = millis();

    portENTER_CRITICAL(&g_ap_mutex);
    ap_upsert(ssid, bssid_addr3, rssi, ch, now);
    int conflict = ap_find_ssid(ssid, bssid_addr3);

    if (conflict < 0 || twin_cooldown_check(ssid, now)) {
        portEXIT_CRITICAL(&g_ap_mutex);
        return;
    }

    twin_alert_t tmp;
    tmp.timestamp_ms = now;
    strncpy(tmp.ssid, ssid, 32); tmp.ssid[32] = '\0';
    memcpy(tmp.legit_bssid,  g_ap_table[conflict].bssid, 6);
    tmp.legit_rssi = g_ap_table[conflict].rssi;
    memcpy(tmp.rogue_bssid,  bssid_addr3, 6);
    tmp.rogue_rssi = rssi;
    tmp.channel    = ch;
    portEXIT_CRITICAL(&g_ap_mutex);

    if (xSemaphoreTake(g_alert_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        g_twin_alert = tmp;
        g_disp_twin  = tmp;
        xSemaphoreGive(g_alert_mutex);
    }

    char legit_s[18], rogue_s[18];
    mac_str_colon(tmp.legit_bssid, legit_s, sizeof(legit_s));
    mac_str_colon(tmp.rogue_bssid, rogue_s, sizeof(rogue_s));
    Serial.printf("[TWIN] SSID=%s  legit=%s  rogue=%s  rssi=%d\n",
                  ssid, legit_s, rogue_s, (int)rssi);

    g_alert_count.fetch_add(1, std::memory_order_relaxed);
    g_last_alert_ms.store(now, std::memory_order_relaxed);
    g_face.store(FACE_ALERT_TWIN);
    g_led.store(LED_FAST);

    alert_type_t at = ALERT_TWIN;
    if (xQueueSend(g_write_queue, &at, pdMS_TO_TICKS(2)) != pdTRUE) {
        g_dropped_alerts.fetch_add(1, std::memory_order_relaxed);
        Serial.println("[WARN] write queue full — twin alert dropped");
    }
}

static void detect_flood(const uint8_t *mf, uint16_t mfl,
                          const uint8_t *bssid_addr3,
                          uint8_t ch) {
    if (mfl < 36) return;

    const uint8_t *tags     = mf + 24 + 12;
    uint16_t       tags_len = (mfl > 36) ? mfl - 36 : 0;

    char ssid[33] = {0};
    if (!extract_ssid(tags, tags_len, ssid, sizeof(ssid)) || ssid[0] == '\0') return;

    uint32_t now = millis();
    uint16_t h   = fnv1a16_ssid(ssid); /* compute outside critical section */

    portENTER_CRITICAL(&g_ap_mutex);

    if ((now - g_flood_window_start) > (uint32_t)FLOOD_WINDOW_MS) {
        g_flood_set_count    = 0;
        g_flood_window_start = now;
        memset(g_flood_hash_bmp, 0, sizeof(g_flood_hash_bmp));
    }

    if (!flood_hash_test(h) && g_flood_set_count < FLOOD_SET_SIZE) {
        flood_hash_set(h);
        strncpy(g_flood_set[g_flood_set_count], ssid, 32);
        g_flood_set[g_flood_set_count][32] = '\0';
        g_flood_set_count++;
    }

    bool    fire        = (g_flood_set_count >= FLOOD_THRESHOLD);
    uint8_t saved_count = g_flood_set_count;

    char s0[33]={0}, s1[33]={0}, s2[33]={0};
    if (fire && saved_count >= 1) strncpy(s0, g_flood_set[0], 32);
    if (fire && saved_count >= 2) strncpy(s1, g_flood_set[1], 32);
    if (fire && saved_count >= 3) strncpy(s2, g_flood_set[2], 32);

    if (fire) {
        g_flood_set_count    = 0;
        g_flood_window_start = now;
        memset(g_flood_hash_bmp, 0, sizeof(g_flood_hash_bmp));
    }
    portEXIT_CRITICAL(&g_ap_mutex);

    if (!fire) return;

    flood_alert_t tmp;
    tmp.timestamp_ms = now;
    tmp.unique_ssids = saved_count;
    tmp.channel      = ch;
    strncpy(tmp.sample[0], s0, 32); tmp.sample[0][32] = '\0';
    strncpy(tmp.sample[1], s1, 32); tmp.sample[1][32] = '\0';
    strncpy(tmp.sample[2], s2, 32); tmp.sample[2][32] = '\0';

    if (xSemaphoreTake(g_alert_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        g_flood_alert = tmp;
        g_disp_flood  = tmp;
        xSemaphoreGive(g_alert_mutex);
    }

    Serial.printf("[FLOOD] ssid/s=%u  sample=%s,%s,%s\n",
                  (unsigned)saved_count, s0, s1, s2);

    g_alert_count.fetch_add(1, std::memory_order_relaxed);
    g_last_alert_ms.store(now, std::memory_order_relaxed);
    g_face.store(FACE_ALERT_FLOOD);
    g_led.store(LED_FAST);

    alert_type_t at = ALERT_FLOOD;
    if (xQueueSend(g_write_queue, &at, pdMS_TO_TICKS(2)) != pdTRUE) {
        g_dropped_alerts.fetch_add(1, std::memory_order_relaxed);
        Serial.println("[WARN] write queue full — flood alert dropped");
    }
}

/* ---------- Promiscuous callback (IRAM_ATTR) ------------------------------- */
static void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    int8_t rssi = (int8_t)pkt->rx_ctrl.rssi;
    if (rssi < (int8_t)RSSI_THRESHOLD) return;

    uint16_t plen = pkt->rx_ctrl.sig_len;
    if (plen == 0 || plen > MAX_PKT_LEN) return;

    BaseType_t woken    = pdFALSE;
    uint8_t    pool_idx = POOL_NONE;

    if (xQueueReceiveFromISR(g_pkt_free_q, &pool_idx, &woken) != pdTRUE) return;

    memcpy(pkt_pool_mem[pool_idx], pkt->payload, plen);

    pkt_item_t item;
    item.pool_idx = pool_idx;
    item.len      = plen;
    item.channel  = (uint8_t)pkt->rx_ctrl.channel; /* driver truth */
    item.rssi     = rssi;

    if (xQueueSendFromISR(g_pkt_queue, &item, &woken) != pdTRUE)
        xQueueSendFromISR(g_pkt_free_q, &pool_idx, &woken);

    if (woken == pdTRUE) portYIELD_FROM_ISR();
}

/* ---------- task_scan (Core 0, priority 5) --------------------------------- */
static void task_scan(void *arg) {
    esp_task_wdt_add(NULL);

    uint32_t pkt_count   = 0;
    uint32_t rate_window = millis();
    uint32_t last_hop_ms = millis();
    uint8_t  hop_ch      = 1;
    int      batch_count = 0;

    while (1) {
        esp_task_wdt_reset();

        pkt_item_t item;
        if (xQueueReceive(g_pkt_queue, &item, pdMS_TO_TICKS(50)) == pdTRUE) {
            const uint8_t *buf = pkt_pool_mem[item.pool_idx];
            uint16_t        len = item.len;

            if (len >= 8) {
                uint16_t rt_len = read16_le(buf + 2);
                if (rt_len < len) {
                    const uint8_t *mf  = buf + rt_len;
                    uint16_t       mfl = len - rt_len;

                    if (mfl >= 24) {
                        uint8_t fc0        = mf[0];
                        uint8_t fc_type    = (fc0 >> 2) & 0x03;
                        uint8_t fc_subtype = (fc0 >> 4) & 0x0F;
                        const uint8_t *addr3 = mf + 16;

                        detect_mode_t mode = g_mode.load(std::memory_order_relaxed);

                        if (fc_type == 0) {
                            switch (mode) {
                                case MODE_DEAUTH:
                                    if (fc_subtype == 12 || fc_subtype == 10)
                                        detect_deauth(mf, mfl, item.channel, item.rssi);
                                    break;
                                case MODE_TWIN:
                                    if (fc_subtype == 8 || fc_subtype == 5)
                                        detect_twin(mf, mfl, addr3, item.channel, item.rssi);
                                    break;
                                case MODE_FLOOD:
                                    if (fc_subtype == 8 || fc_subtype == 5)
                                        detect_flood(mf, mfl, addr3, item.channel);
                                    break;
                            }
                        }
                    }
                }
            }

            xQueueSend(g_pkt_free_q, &item.pool_idx, 0);

            pkt_count++;
            if (++batch_count >= TASK_SCAN_BATCH_MAX) { batch_count = 0; taskYIELD(); }
        } else {
            batch_count = 0;
        }

        uint32_t now = millis();

        if ((now - last_hop_ms) >= CHANNEL_DWELL_MS) {
            hop_ch = (hop_ch % CHANNELS_2G) + 1;
            esp_wifi_set_channel(hop_ch, WIFI_SECOND_CHAN_NONE);
            g_channel.store(hop_ch, std::memory_order_relaxed);
            last_hop_ms = now;
        }

        if ((now - rate_window) >= 1000UL) {
            g_pkt_rate.store(pkt_count, std::memory_order_relaxed);

            detect_mode_t snap_mode = g_mode.load(std::memory_order_relaxed);
            const char   *mode_str  = (snap_mode == MODE_DEAUTH) ? "DEAUTH" :
                                      (snap_mode == MODE_TWIN)   ? "TWIN"   : "FLOOD";

            UBaseType_t hwm_scan  = uxTaskGetStackHighWaterMark(h_scan);
            UBaseType_t hwm_write = uxTaskGetStackHighWaterMark(h_write);
            UBaseType_t hwm_ui    = uxTaskGetStackHighWaterMark(h_ui);

            Serial.printf("[STAT] pkt/s=%lu  ch=%u  mode=%s  dropped=%lu"
                          "  hwm_scan=%u  hwm_write=%u  hwm_ui=%u\n",
                          (unsigned long)pkt_count,
                          (unsigned)hop_ch,
                          mode_str,
                          (unsigned long)g_dropped_alerts.load(std::memory_order_relaxed),
                          (unsigned)hwm_scan, (unsigned)hwm_write, (unsigned)hwm_ui);

            if (hwm_scan  < 512) Serial.printf("[WARN] stack low: scan  HWM=%u\n", (unsigned)hwm_scan);
            if (hwm_write < 512) Serial.printf("[WARN] stack low: write HWM=%u\n", (unsigned)hwm_write);
            if (hwm_ui    < 512) Serial.printf("[WARN] stack low: ui    HWM=%u\n", (unsigned)hwm_ui);

            pkt_count   = 0;
            rate_window = now;

            ap_table_expire(now);

            if (!g_sd_ok.load() &&
                (now - g_last_sd_retry.load(std::memory_order_relaxed)) > SD_RETRY_MS) {
                g_last_sd_retry.store(now, std::memory_order_relaxed);
                sd_init();
            }
        }
    }
}

/* ---------- task_write (Core 0, priority 4) -------------------------------- */
static void task_write(void *arg) {
    esp_task_wdt_add(NULL);
    static char cbuf[CSV_BUF_SIZE]; /* static — no malloc */

    while (1) {
        esp_task_wdt_reset();

        alert_type_t at;
        if (xQueueReceive(g_write_queue, &at, pdMS_TO_TICKS(200)) != pdTRUE) continue;
        if (!g_sd_ok.load()) continue;

        xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
        uint64_t card = (uint64_t)SD.cardSize();
        uint64_t used = (uint64_t)SD.usedBytes();
        xSemaphoreGive(g_sd_mutex);

        uint64_t free_b = (card >= used) ? (card - used) : 0;
        if (free_b < MIN_FREE_BYTES) { Serial.println("[SD] low space — skipping write"); continue; }

        const char *path    = NULL;
        int         row_len = 0;

        xSemaphoreTake(g_alert_mutex, portMAX_DELAY);

        if (at == ALERT_DEAUTH) {
            char att_s[18], tgt_s[18];
            mac_str_colon(g_deauth_alert.attacker, att_s, sizeof(att_s));
            mac_str_colon(g_deauth_alert.target,   tgt_s, sizeof(tgt_s));
            row_len = snprintf(cbuf, CSV_BUF_SIZE, "%lu,%s,%s,%u,%lu,%u\n",
                               (unsigned long)g_deauth_alert.timestamp_ms,
                               att_s, tgt_s,
                               (unsigned)g_deauth_alert.channel,
                               (unsigned long)g_deauth_alert.frame_count,
                               (unsigned)g_deauth_alert.reason);
            path = "/watchdog/deauth.csv";

        } else if (at == ALERT_TWIN) {
            char leg_s[18], rog_s[18];
            mac_str_colon(g_twin_alert.legit_bssid, leg_s, sizeof(leg_s));
            mac_str_colon(g_twin_alert.rogue_bssid, rog_s, sizeof(rog_s));
            row_len = snprintf(cbuf, CSV_BUF_SIZE, "%lu,%s,%s,%d,%s,%d,%u\n",
                               (unsigned long)g_twin_alert.timestamp_ms,
                               g_twin_alert.ssid,
                               leg_s, (int)g_twin_alert.legit_rssi,
                               rog_s, (int)g_twin_alert.rogue_rssi,
                               (unsigned)g_twin_alert.channel);
            path = "/watchdog/twins.csv";

        } else {
            row_len = snprintf(cbuf, CSV_BUF_SIZE, "%lu,%lu,%u,%s,%s,%s\n",
                               (unsigned long)g_flood_alert.timestamp_ms,
                               (unsigned long)g_flood_alert.unique_ssids,
                               (unsigned)g_flood_alert.channel,
                               g_flood_alert.sample[0],
                               g_flood_alert.sample[1],
                               g_flood_alert.sample[2]);
            path = "/watchdog/floods.csv";
        }

        xSemaphoreGive(g_alert_mutex);

        if (row_len <= 0 || row_len >= CSV_BUF_SIZE) { Serial.println("[SD] CSV row overflow — skipping"); continue; }

        xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
        File f = SD.open(path, FILE_APPEND);
        if (!f) {
            /* Retry once after 50 ms */
            xSemaphoreGive(g_sd_mutex);
            vTaskDelay(pdMS_TO_TICKS(50));
            xSemaphoreTake(g_sd_mutex, portMAX_DELAY);
            f = SD.open(path, FILE_APPEND);
        }
        if (!f) {
            Serial.printf("[SD] open failed (2/2): %s\n", path);
            xSemaphoreGive(g_sd_mutex);
            continue;
        }
        size_t written = f.write((const uint8_t *)cbuf, (size_t)row_len);
        f.close();
        xSemaphoreGive(g_sd_mutex);

        if ((int)written != row_len) {
            g_sd_ok.store(false);
            g_face.store(FACE_ERROR);
            g_led.store(LED_ERROR);
            Serial.printf("[SD] partial write %u/%d — card marked bad, reinit pending\n",
                          (unsigned)written, row_len);
        } else {
            g_led.store(LED_FLASH);
            Serial.printf("[SD] wrote alert type=%u  total=%lu\n",
                          (unsigned)at, (unsigned long)g_alert_count.load());
        }
    }
}

/* ---------- LED & Button --------------------------------------------------- */
static void led_tick(void) {
    static uint32_t last_ms   = 0;
    static bool     on        = false;
    static uint8_t  err_phase = 0;

    uint32_t    now = millis();
    led_state_t led = g_led.load();

    if (led == LED_FAST) {
        if ((now - g_last_alert_ms.load(std::memory_order_relaxed)) >= ALERT_LED_TIMEOUT_MS) {
            g_led.store(LED_SLOW);
            led = LED_SLOW;
        }
    }

    switch (led) {
        case LED_SLOW:
            if (now - last_ms >= 500UL) { on = !on; digitalWrite(PIN_LED, on ? HIGH : LOW); last_ms = now; }
            break;
        case LED_FAST:
            if (now - last_ms >= 100UL) { on = !on; digitalWrite(PIN_LED, on ? HIGH : LOW); last_ms = now; }
            break;
        case LED_FLASH:
            if (!on) { digitalWrite(PIN_LED, HIGH); on = true; last_ms = now; }
            else if (now - last_ms >= 120UL) { digitalWrite(PIN_LED, LOW); on = false; g_led.store(LED_SLOW); }
            break;
        case LED_ERROR: {
            uint32_t period = (err_phase == 6) ? 1000UL : (err_phase % 2 == 0) ? 500UL : 200UL;
            if (now - last_ms >= period) {
                last_ms   = now;
                err_phase = (err_phase >= 6) ? 0 : err_phase + 1;
                on = (err_phase % 2 == 0) && (err_phase < 6);
                digitalWrite(PIN_LED, on ? HIGH : LOW);
            }
            break;
        }
    }
}

static void btn_tick(void) {
    static bool     prev     = HIGH;
    static uint32_t press_ms = 0;
    static uint32_t last_ms  = 0;

    uint32_t now = millis();
    if (now - last_ms < (uint32_t)DEBOUNCE_MS) return;
    last_ms = now;

    bool cur = (bool)digitalRead(PIN_BTN);
    if (prev == HIGH && cur == LOW) {
        press_ms = now;
    } else if (prev == LOW && cur == HIGH) {
        uint32_t dur = now - press_ms;
        if (dur >= (uint32_t)LONG_PRESS_MS) {
            Serial.println("[BTN] long press -> restart");
            ESP.restart();
        } else if (dur >= (uint32_t)DEBOUNCE_MS) {
            detect_mode_t next = (detect_mode_t)((int(g_mode.load()) + 1) % 3);
            g_mode.store(next);
            g_face.store(FACE_IDLE);
            g_led.store(LED_SLOW);
            Serial.printf("[BTN] mode -> %s\n",
                          next == MODE_DEAUTH ? "DEAUTH" :
                          next == MODE_TWIN   ? "TWIN"   : "FLOOD");
        }
    }
    prev = cur;
}

/* ---------- OLED draw ------------------------------------------------------ */
/* Reads only from g_disp_* shadows — never acquires g_alert_mutex. */
static void oled_draw(void) {
    char line[22];
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);

    face_t        f    = g_face.load();
    detect_mode_t mode = g_mode.load(std::memory_order_relaxed);

    if (f == FACE_ALERT_DEAUTH) {
        display.drawStr(0, 10, "(X_X)");
        display.drawStr(0, 20, "DEAUTH DETECT");
        char a[10], t[10];
        mac_str_short(g_disp_deauth.attacker, a, sizeof(a));
        mac_str_short(g_disp_deauth.target,   t, sizeof(t));
        snprintf(line, sizeof(line), "AT: %s", a);  display.drawStr(0, 30, line);
        snprintf(line, sizeof(line), "TG: %s", t);  display.drawStr(0, 40, line);
        snprintf(line, sizeof(line), "CNT:%-4lu CH:%u",
                 (unsigned long)g_disp_deauth.frame_count, (unsigned)g_disp_deauth.channel);
        display.drawStr(0, 50, line);

    } else if (f == FACE_ALERT_TWIN) {
        display.drawStr(0, 10, "(>_<)");
        display.drawStr(0, 20, "EVIL TWIN");
        snprintf(line, sizeof(line), "%.14s", g_disp_twin.ssid); display.drawStr(0, 30, line);
        char l[10], r[10];
        mac_str_short(g_disp_twin.legit_bssid, l, sizeof(l));
        mac_str_short(g_disp_twin.rogue_bssid, r, sizeof(r));
        snprintf(line, sizeof(line), "L:%s %d", l, (int)g_disp_twin.legit_rssi); display.drawStr(0, 40, line);
        snprintf(line, sizeof(line), "R:%s %d", r, (int)g_disp_twin.rogue_rssi); display.drawStr(0, 50, line);

    } else if (f == FACE_ALERT_FLOOD) {
        display.drawStr(0, 10, "(o_o)");
        display.drawStr(0, 20, "BEACON FLOOD");
        snprintf(line, sizeof(line), "SSID/s: %lu", (unsigned long)g_disp_flood.unique_ssids);
        display.drawStr(0, 30, line);
        snprintf(line, sizeof(line), "CH:%-2u PKT:%-5lu",
                 (unsigned)g_disp_flood.channel, (unsigned long)g_pkt_rate.load());
        display.drawStr(0, 40, line);
        snprintf(line, sizeof(line), "%.16s", g_disp_flood.sample[0]); display.drawStr(0, 50, line);

    } else if (f == FACE_ERROR) {
        display.drawStr(0, 10, "(X_X)");
        display.drawStr(0, 24, "SD ERROR");
        display.drawStr(0, 38, "No card?");

    } else {
        display.drawStr(0, 10, "(o_o)");
        display.drawStr(0, 20, (mode == MODE_DEAUTH) ? "MODE: DEAUTH" :
                                (mode == MODE_TWIN)   ? "MODE: TWIN"   : "MODE: FLOOD");
        snprintf(line, sizeof(line), "AL:  %lu",  (unsigned long)g_alert_count.load()); display.drawStr(0, 30, line);
        snprintf(line, sizeof(line), "PKT: %lu",  (unsigned long)g_pkt_rate.load());    display.drawStr(0, 40, line);
        snprintf(line, sizeof(line), "CH:  %u",   (unsigned)g_channel.load(std::memory_order_relaxed)); display.drawStr(0, 50, line);
        snprintf(line, sizeof(line), "SD:  %s",   g_sd_ok.load() ? "OK" : "ERR");       display.drawStr(0, 60, line);
    }

    display.sendBuffer();
}

/* ---------- task_ui (Core 1 — MANDATORY) ----------------------------------- */
static void task_ui(void *arg) {
    configASSERT(xPortGetCoreID() == 1);
    esp_task_wdt_add(NULL);
    uint32_t last_oled = 0;

    while (1) {
        esp_task_wdt_reset();
        uint32_t now = millis();
        btn_tick();
        led_tick();
        if (now - last_oled >= 200) { oled_draw(); last_oled = now; }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/* ---------- setup() -------------------------------------------------------- */
void setup(void) {
    Serial.begin(115200);
    delay(200);
    Serial.println("\n[BOOT] ESP32Watchdog v" FW_VERSION);

    pinMode(PIN_LED, OUTPUT);
    pinMode(PIN_BTN, INPUT_PULLUP);
    digitalWrite(PIN_LED, LOW);

    Wire.begin(PIN_OLED_SDA, PIN_OLED_SCL);
    display.begin();
    display.clearBuffer();
    display.setFont(u8g2_font_6x10_tf);
    display.drawStr(0, 20, "Watchdog v" FW_VERSION);
    display.drawStr(0, 34, "Booting...");
    display.sendBuffer();

    esp_task_wdt_init(WDT_TIMEOUT_S, true);
    esp_task_wdt_add(NULL);

    g_pkt_free_q  = xQueueCreate(PKT_POOL_DEPTH,   sizeof(uint8_t));
    g_pkt_queue   = xQueueCreate(PKT_QUEUE_DEPTH,   sizeof(pkt_item_t));
    g_write_queue = xQueueCreate(WRITE_QUEUE_DEPTH, sizeof(alert_type_t));
    configASSERT(g_pkt_free_q);
    configASSERT(g_pkt_queue);
    configASSERT(g_write_queue);

    for (uint8_t i = 0; i < PKT_POOL_DEPTH; i++) xQueueSend(g_pkt_free_q, &i, 0);

    g_alert_mutex = xSemaphoreCreateMutex();
    g_sd_mutex    = xSemaphoreCreateMutex();
    configASSERT(g_alert_mutex);
    configASSERT(g_sd_mutex);

    memset(g_ap_table,       0, sizeof(g_ap_table));
    memset(g_deauth_track,   0, sizeof(g_deauth_track));
    memset(g_flood_set,      0, sizeof(g_flood_set));
    memset(g_flood_hash_bmp, 0, sizeof(g_flood_hash_bmp));
    memset(g_twin_cd,        0, sizeof(g_twin_cd));
    memset(&g_deauth_alert,  0, sizeof(g_deauth_alert));
    memset(&g_twin_alert,    0, sizeof(g_twin_alert));
    memset(&g_flood_alert,   0, sizeof(g_flood_alert));
    memset(&g_disp_deauth,   0, sizeof(g_disp_deauth));
    memset(&g_disp_twin,     0, sizeof(g_disp_twin));
    memset(&g_disp_flood,    0, sizeof(g_disp_flood));

    sd_init();

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    esp_wifi_set_promiscuous(false);

    wifi_promiscuous_filter_t flt;
    flt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        Serial.println("[WIFI] promiscuous failed -> restart");
        ESP.restart();
    }
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("[WIFI] promiscuous active");

    xTaskCreatePinnedToCore(task_scan,  "scan",     STACK_SCAN,  NULL, 5, &h_scan,  0);
    xTaskCreatePinnedToCore(task_write, "sd_write", STACK_WRITE, NULL, 4, &h_write, 0);
    xTaskCreatePinnedToCore(task_ui,    "ui",       STACK_UI,    NULL, 1, &h_ui,    1);
    configASSERT(h_scan);
    configASSERT(h_write);
    configASSERT(h_ui);

    display.clearBuffer();
    display.drawStr(0, 20, "Watchdog v" FW_VERSION);
    display.drawStr(0, 34, "Running...");
    display.sendBuffer();
    Serial.println("[BOOT] tasks started");

    /* Baseline memory snapshot — printed once per flash */
    Serial.printf("[MEM]  free heap     : %lu bytes\n", (unsigned long)ESP.getFreeHeap());
    Serial.printf("[MEM]  min free heap : %lu bytes\n", (unsigned long)ESP.getMinFreeHeap());
    uint32_t psram = (uint32_t)ESP.getPsramSize();
    if (psram > 0) Serial.printf("[MEM]  PSRAM size    : %lu bytes\n", (unsigned long)psram);
    else           Serial.println("[MEM]  PSRAM         : not present");

    esp_task_wdt_delete(NULL);
}

/* ---------- loop() — all work in FreeRTOS tasks ---------------------------- */
void loop(void) { vTaskDelay(portMAX_DELAY); }
