# ESP32Watchdog

[![Platform](https://img.shields.io/badge/Platform-ESP32--WROOM--32-blue)](https://www.espressif.com/en/products/socs/esp32)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/Build-Arduino_IDE_2.x-orange)](https://www.arduino.cc/)
[![Author](https://img.shields.io/badge/Author-tworjaga-lightgrey)](https://github.com/tworjaga)

> Passive Wi-Fi threat detection device for the ESP32.  
> Detects deauth floods, evil twin APs, and beacon floods — no transmission, no configuration, logs everything to microSD.

---

## Overview

ESP32Watchdog is a self-contained passive 802.11 threat monitor inspired by the Gotchi project family. It runs on the same ~10 EUR hardware stack as ESP32Gotchi, requires no host computer, and logs all detections as CSV files directly to a microSD card. All operation is autonomous from power-on.

The firmware uses three FreeRTOS tasks, a promiscuous-mode Wi-Fi callback with RSSI pre-filtering, and a dedicated SD write task so logging never stalls packet processing. A single button cycles through three independent detection modes. The device transmits nothing — it is entirely passive.

---

## Detection Modes

### Mode 0 — DEAUTH
Monitors for deauthentication and disassociation frame floods. If the same source MAC sends ≥ 10 deauth/disassoc frames within a 1-second window, an alert fires. This is the primary indicator of a deauth-based denial-of-service or forced re-association attack.

### Mode 1 — TWIN
Monitors beacon and probe-response frames for evil twin APs: two different BSSIDs advertising the same SSID. The device maintains a table of known SSID→BSSID mappings and alerts immediately when a conflicting BSSID is seen.

### Mode 2 — FLOOD
Counts unique SSIDs seen per second from beacons and probe responses. If the count exceeds 20 unique SSIDs within a 1-second window, a beacon flood is detected. This pattern is characteristic of management-frame flood tools and certain Wi-Fi scanner exploits.

---

## Hardware

### Bill of Materials

| Component | Specification | Approx. Cost |
|-----------|--------------|-------------|
| MCU | ESP32 DevKit V1, 30-pin, ESP32-WROOM-32 | ~5 EUR |
| Display | 0.96" SSD1306 OLED, 128×64, I2C (4-pin) | ~3 EUR |
| Storage | MicroSD SPI module, 3.3V compatible | ~1 EUR |
| Button | Tactile push button, through-hole | ~0.10 EUR |
| LED | 3mm or 5mm, any colour + 220 Ω resistor | ~0.15 EUR |
| MicroSD card | FAT32 formatted, 2 GB minimum | ~2 EUR |

**Total: ~11 EUR**

See [hardware/BOM.md](hardware/BOM.md) for full component details and sourcing notes.

### Wiring

**OLED — I2C**
```
ESP32 GPIO21  ->  SDA
ESP32 GPIO22  ->  SCL
ESP32 3.3V    ->  VCC
ESP32 GND     ->  GND
```

**MicroSD — SPI**
```
ESP32 GPIO18  ->  SCK
ESP32 GPIO23  ->  MOSI
ESP32 GPIO19  ->  MISO
ESP32 GPIO5   ->  CS
ESP32 3.3V    ->  VCC
ESP32 GND     ->  GND
```

> **GPIO5 note:** GPIO5 is the SDIO-slave timing strapping pin, but this has no effect in SPI mode. Safe to use on DevKit V1.

**Button — active-low on GPIO4**
```
ESP32 GPIO4   ->  Button  ->  GND
(internal pull-up enabled in firmware)
```

> **GPIO4 not GPIO0:** GPIO0 is the ESP32 boot-mode strapping pin. A button on GPIO0 that is held during reset sends the device into Download Mode — black screen, looks like a brick. GPIO4 has no strapping function.

**LED (optional)**
```
ESP32 GPIO2   ->  220 Ω resistor  ->  LED anode
LED cathode   ->  GND
```

### Block Diagram

```
ESP32-WROOM-32
 |-- OLED SSD1306      (I2C: GPIO21/22)
 |-- MicroSD module    (SPI: GPIO18/19/23/5)
 |-- Tactile button    (GPIO4, active-low)
 |-- Status LED        (GPIO2, optional)
 └-- LiPo + TP4056     (optional, portable)
```

---

## Firmware

### Architecture

Three FreeRTOS tasks with explicit core pinning:

| Task | Core | Priority | Stack | Function |
|------|------|----------|-------|----------|
| `task_scan` | 0 | 5 | 6 KB | Promiscuous packet intake, 802.11 parsing, detection logic, channel hopping |
| `task_write` | 0 | 4 | 6 KB | Reads alert indices from queue, writes CSV rows to SD |
| `task_ui` | **1** | 1 | 4 KB | OLED draw (200 ms), LED patterns, button debounce (10 ms poll) |

`task_ui` is pinned to Core 1. The U8g2 I2C bus hold (~2 ms per frame) conflicts with the promiscuous ISR on Core 0 and causes a LoadProhibited cache-miss panic if they share a core. A `configASSERT(xPortGetCoreID() == 1)` at task entry catches any future accidental migration.

Channel hopping is integrated into `task_scan` — after each packet batch, the scan task advances to the next channel (1–13, 200 ms dwell). No separate hop task is needed.

### Memory Layout

All packet storage is statically allocated at boot. No `malloc()` or `free()` at runtime.

| Region | Size | Purpose |
|--------|------|---------|
| `pkt_pool_mem[32][1600]` | 51 200 B | In-flight packet pool, claimed by `promisc_cb`, released by `task_scan` |
| `g_ap_table[64]` | ~3 KB | AP/SSID table for evil twin and flood detection |
| `g_deauth_track[8]` | ~400 B | Per-source deauth sliding-window counters |
| Alert structs (×3) | ~200 B | Deauth / twin / flood payloads, protected by `g_alert_mutex` |
| **Total user static** | **~55 KB** | Well within the ~200 KB available after the Wi-Fi stack |

### Synchronisation

| Object | Type | Protects |
|--------|------|----------|
| `g_ap_mutex` | `portMUX_TYPE` spinlock | `g_ap_table`, `g_deauth_track`, `g_flood_set` — ISR-safe |
| `g_alert_mutex` | Standard mutex | Alert payload structs |
| `g_sd_mutex` | Standard mutex | SD file access |
| `g_mode`, `g_channel`, `g_led`, `g_face`, counters | `std::atomic<T>` | All cross-core shared scalars |

### RSSI Pre-filter

`promisc_cb` drops packets weaker than -90 dBm before claiming a pool block. This is the first gate — no memcpy, no queue touch, zero pool cost for noise-floor packets. Threshold is configurable via `RSSI_THRESHOLD`.

### Detection Logic

**DEAUTH:** Maintains a per-source sliding window. On each deauth/disassoc frame (subtypes 12 and 10), the source MAC is looked up in `g_deauth_track[8]`. If the count reaches `DEAUTH_THRESHOLD` (10) within `DEAUTH_WINDOW_MS` (1000 ms), an alert fires and the window resets. The table covers the 8 most recently active sources — real floods have one dominant attacker.

**TWIN:** On each beacon or probe-response, the SSID is extracted from tagged parameters and looked up in `g_ap_table`. If the SSID is found with a different BSSID, an evil twin alert fires immediately. Both BSSIDs and their RSSI values are included in the alert.

**FLOOD:** Counts unique SSIDs per window using a 64-entry presence table. When the unique count exceeds `FLOOD_THRESHOLD` (20) within `FLOOD_WINDOW_MS` (1000 ms), an alert fires. The table resets and the window restarts. Three sample SSIDs are captured for logging.

### OLED Display

**Idle screen (no alert):**
```
(o_o)
MODE: DEAUTH
AL:  0
PKT: 128
CH:  6
SD:  OK
```

**Deauth alert:**
```
(X_X)
DEAUTH DETECT
AT: aa:bb:cc
TG: dd:ee:ff
CNT: 42  CH: 6
```

**Evil twin alert:**
```
(>_<)
EVIL TWIN
TargetNetwork
L:aa:bb:cc -45
R:dd:ee:ff -62
```

**Beacon flood alert:**
```
(o_o)
BEACON FLOOD
SSID/s: 47
CH: 1  PKT: 312
FreeWifi
```

### LED Patterns

| Pattern | Meaning |
|---------|---------|
| Slow blink (1 Hz) | Scanning, no alert |
| Fast blink (5 Hz) | Alert active |
| Single 120 ms flash | Alert saved to SD |
| 3 × long flash, repeat | SD error |

### Button Behaviour

| Press duration | Action |
|---------------|--------|
| Short (50 ms – 3 s) | Cycle mode: DEAUTH → TWIN → FLOOD → DEAUTH. Resets face and LED to idle. |
| Long (> 3 s) | `ESP.restart()` |

---

## SD Card and Logs

Format: FAT32. Minimum recommended size: 2 GB.

The firmware creates `/watchdog/` on first boot and writes CSV headers if the files do not exist. Three log files accumulate across sessions:

**`/watchdog/deauth.csv`**
```
timestamp_ms,attacker_mac,target_mac,channel,frame_count,reason_code
1712345678,aa:bb:cc:dd:ee:ff,ff:ff:ff:ff:ff:ff,6,14,7
```

**`/watchdog/twins.csv`**
```
timestamp_ms,ssid,legit_bssid,legit_rssi,rogue_bssid,rogue_rssi,channel
1712345901,HomeNetwork,aa:bb:cc:dd:ee:ff,-45,11:22:33:44:55:66,-62,11
```

**`/watchdog/floods.csv`**
```
timestamp_ms,unique_ssids_per_sec,channel,sample1,sample2,sample3
1712346100,34,1,FreeWifi,OpenNet,Guest
```

If the SD card is absent or fails, the device retries initialisation every 10 seconds and displays `SD: ERR`. Detections continue in memory during the outage.

A minimum free space check of 1 MB runs before each write. If space is below threshold, the row is skipped and a serial warning is printed.

---

## Build & Flash

### Requirements

- Arduino IDE 2.x or PlatformIO
- ESP32 board package by Espressif, version 2.0.x or later
- U8g2 library (install via Arduino Library Manager)
- SD, SPI, WiFi, esp_wifi, FreeRTOS — all bundled with the ESP32 core

### Arduino IDE

1. Add board package URL: `File → Preferences → Additional Boards Manager URLs`  
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`

2. Install U8g2: `Tools → Manage Libraries → search "U8g2"`

3. Board settings:
   ```
   Board            : ESP32 Dev Module
   Partition scheme : Default 4MB with spiffs
   CPU Frequency    : 240 MHz
   Flash mode       : QIO
   Upload speed     : 921600
   ```

4. Open `ESP32Watchdog.ino`, compile, and flash.

### PlatformIO

```ini
[env:esp32dev]
platform  = espressif32
board     = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps  = olikraus/U8g2
board_build.partitions = default.csv
```

---

## Serial Debug Output

Connect at 115200 baud. Example output:

```
[BOOT] ESP32Watchdog v1.0.0
[SD] OK
[WIFI] promiscuous active
[BOOT] tasks started
[MEM]  free heap: 148320 bytes
[STAT] pkt/s=89  ch=6  mode=DEAUTH
[DEAUTH] aa:bb:cc:dd:ee:ff -> ff:ff:ff:ff:ff:ff  cnt=14  reason=7
[TWIN] SSID=HomeNetwork  legit=aa:bb:cc  rogue=11:22:33  rssi=-68
[FLOOD] ssid/s=34  sample=FreeWifi,OpenNet,Guest
[SD] wrote alert type=0  total=1
```

---

## Technical Specifications

| Parameter | Value |
|-----------|-------|
| MCU | Xtensa LX6 dual-core, 240 MHz |
| RAM | 520 KB SRAM |
| Wi-Fi | 802.11 b/g/n, 2.4 GHz, passive only |
| Channels scanned | 1–13 |
| Channel dwell time | 200 ms |
| Packet queue depth | 32 items |
| Packet pool | 32 × 1 600 B static |
| RSSI drop threshold | -90 dBm |
| Deauth alert threshold | 10 frames / 1 s |
| Evil twin detection | Immediate (first conflicting beacon) |
| Beacon flood threshold | 20 unique SSIDs / 1 s |
| AP table capacity | 64 entries, 30 s expiry |
| Deauth tracker slots | 8 source MACs |
| Watchdog timeout | 30 s |
| Min SD free space | 1 MB |
| Runtime heap allocations | 0 (CSV row buffer is a static array) |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `SD: ERR` on boot | SD not inserted, wrong wiring, not FAT32 | Check SPI wiring; reformat card to FAT32 |
| OLED blank | I2C address mismatch or wiring fault | Verify SDA=21 / SCL=22; scan with I2C scanner sketch to confirm 0x3C |
| No alerts in any mode | RSSI threshold too strict, or no attacks nearby | Lower `RSSI_THRESHOLD` to -95; use a test tool in a controlled environment |
| Device reboots repeatedly | Watchdog trigger — task stall | Check serial for last log line; likely SD write hang on a worn card |
| CSV rows missing | SD low space or partial write | Check free space; replace card if worn |
| Button puts device in Download Mode | Button wired to GPIO0 | Move button wire to GPIO4 |
| Evil twin false positive | Two legitimate APs with same SSID (e.g. mesh network) | Expected — a mesh with identical SSIDs on different BSSIDs will trigger MODE_TWIN |

---

## Repository Structure

```
ESP32Watchdog/
 |-- ESP32Watchdog.ino       # Full firmware — single file
 |-- README.md
 |-- LICENSE
 |-- hardware/
 |    └── BOM.md             # Full bill of materials with sourcing notes
 └── docs/
      └── csv_analysis.md    # Guide to reading and analysing log files
```

---

## Relationship to ESP32Gotchi

ESP32Watchdog is a sibling project to ESP32Gotchi (WPA/WPA2 handshake sniffer). They share the same hardware platform, wiring, FreeRTOS architecture, memory pool design, ISR safety model, and coding conventions. The firmware fix annotations (`W1`–`W-W2`) follow the same scheme as the Gotchi fixes (`F1`–`F13`). Either firmware can be flashed to the same physical device with no hardware changes.

---

## Legal Notice

This tool is intended for **authorised security research and educational use only.**  
Monitoring Wi-Fi traffic on networks you do not own or have explicit written permission to test is illegal in most jurisdictions.  
The author assumes no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Contact

Author: [@tworjaga](https://github.com/tworjaga)  
Telegram: [@al7exy](https://t.me/al7exy)  
Issues: [github.com/tworjaga/ESP32Watchdog/issues](https://github.com/tworjaga/ESP32Watchdog/issues)
