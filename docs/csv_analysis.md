# CSV Log Analysis Guide

This document covers how to open, inspect, and interpret the `.csv` files produced by ESP32Watchdog.

---

## File Location

Files are written to `/watchdog/` on the microSD card. Three files are created on first boot and appended to across sessions:

```
/watchdog/deauth.csv
/watchdog/twins.csv
/watchdog/floods.csv
```

Remove the SD card from the device and mount it on your computer to access them. All three are standard UTF-8 CSV files; they open directly in Excel, LibreOffice Calc, or any text editor.

---

## deauth.csv — Deauth / Disassociation Floods

### Format

```
timestamp_ms,attacker_mac,target_mac,channel,frame_count,reason_code
```

### Example rows

```
1712345678000,aa:bb:cc:dd:ee:ff,ff:ff:ff:ff:ff:ff,6,14,7
1712345689000,aa:bb:cc:dd:ee:ff,11:22:33:44:55:66,6,22,1
```

### Field reference

| Field | Type | Description |
|-------|------|-------------|
| `timestamp_ms` | uint32 | `millis()` value at alert time (ms since boot) |
| `attacker_mac` | string | Source MAC of the deauth/disassoc frames (addr2) |
| `target_mac` | string | Destination MAC — `ff:ff:ff:ff:ff:ff` = broadcast (all clients), unicast = targeted |
| `channel` | uint8 | Wi-Fi channel the frames were observed on |
| `frame_count` | uint32 | Number of frames from this source in the detection window |
| `reason_code` | uint8 | 802.11 deauth reason code from the most recent frame |

### 802.11 Reason Codes (common)

| Code | Meaning |
|------|---------|
| 1 | Unspecified |
| 2 | Previous authentication no longer valid |
| 3 | Deauthenticated — station leaving |
| 4 | Disassociated — inactivity timer |
| 6 | Class 2 frame received from non-authenticated station |
| 7 | Class 3 frame received from non-associated station |

> **Reason code 7 at high volume** is the most common signature of an automated deauth tool. Legitimate deauths from a real AP are typically a single frame with codes 3 or 4.

### Distinguishing attacks from legitimate traffic

- **Broadcast target (`ff:ff:ff:ff:ff:ff`)** — a real AP never broadcasts deauth to all clients simultaneously. This is always an attack.
- **High frame_count** — values above 20–50 in a 1-second window are never organic.
- **Attacker MAC is not a known AP BSSID** — an attacker will often spoof the AP's MAC. Cross-reference `attacker_mac` with your known AP list.

### Analysis in Python (pandas)

```python
import pandas as pd

df = pd.read_csv('/path/to/deauth.csv')
print(df.groupby('attacker_mac')['frame_count'].sum().sort_values(ascending=False))
```

---

## twins.csv — Evil Twin APs

### Format

```
timestamp_ms,ssid,legit_bssid,legit_rssi,rogue_bssid,rogue_rssi,channel
```

### Example rows

```
1712345901000,HomeNetwork,aa:bb:cc:dd:ee:ff,-45,11:22:33:44:55:66,-62,11
1712346005000,CoffeeShop_WiFi,de:ad:be:ef:01:02,-51,c0:ff:ee:ba:be:00,-78,6
```

### Field reference

| Field | Type | Description |
|-------|------|-------------|
| `timestamp_ms` | uint32 | `millis()` at alert time |
| `ssid` | string | The SSID shared by both APs |
| `legit_bssid` | string | BSSID of the first-seen AP (treated as the reference) |
| `legit_rssi` | int8 | RSSI of the legit AP (dBm) |
| `rogue_bssid` | string | BSSID of the conflicting AP |
| `rogue_rssi` | int8 | RSSI of the rogue AP (dBm) |
| `channel` | uint8 | Channel the rogue beacon was observed on |

### Interpreting the RSSI values

A rogue AP deployed nearby to intercept clients will typically have a **stronger** signal than the legitimate AP (`rogue_rssi > legit_rssi`). A rogue detected at much weaker signal than the legitimate AP may be a distant neighbour network with a coincidentally identical SSID — check whether the SSID is a common default name (e.g. `linksys`, `NETGEAR`, `dlink`).

### Known false-positive scenario

**Mesh / multi-AP networks** (e.g. Eero, Orbi, Unifi) intentionally use the same SSID across multiple BSSIDs. If you are monitoring your own network, add known mesh nodes to a whitelist in your post-processing. The firmware cannot distinguish between a mesh and an evil twin — that judgment requires context about the environment.

### Verifying a suspected rogue

1. Note `rogue_bssid` and check the OUI (first 3 octets) against the [Wireshark OUI database](https://www.wireshark.org/tools/oui-lookup.html).
2. Check `rogue_rssi` — a strong signal (-50 dBm or stronger) indicates the rogue is physically close.
3. Cross-check whether the `rogue_bssid` appears in any other alert file.

### Analysis in Python

```python
import pandas as pd

df = pd.read_csv('/path/to/twins.csv')
# Show SSIDs with most twin detections
print(df.groupby('ssid').size().sort_values(ascending=False))
# Show cases where rogue was stronger than legit
suspicious = df[df['rogue_rssi'] > df['legit_rssi']]
print(suspicious[['ssid','legit_bssid','rogue_bssid','rogue_rssi','legit_rssi']])
```

---

## floods.csv — Beacon / SSID Floods

### Format

```
timestamp_ms,unique_ssids_per_sec,channel,sample1,sample2,sample3
```

### Example rows

```
1712346100000,34,1,FreeWifi,OpenNet,Guest_5G
1712346101000,41,6,xfinitywifi,ATT123,SpectrumSetup
```

### Field reference

| Field | Type | Description |
|-------|------|-------------|
| `timestamp_ms` | uint32 | `millis()` at alert time |
| `unique_ssids_per_sec` | uint32 | Number of distinct SSIDs seen in the detection window |
| `channel` | uint8 | Channel the device was tuned to when the threshold was crossed |
| `sample1/2/3` | string | Up to three example SSIDs from the window |

### Interpreting flood alerts

A beacon flood is the signature of management-frame flood tools (e.g. `mdk3`, `mdk4`, `wifijammer`). These tools create hundreds of fake APs per second to exhaust client scan tables and cause denial-of-service. A value of 20–50 unique SSIDs per second is suspicious in a normal environment; anything above 100 is almost certainly a tool.

> **Dense urban environments** may have 15–25 legitimate SSIDs visible simultaneously during scanning — if false positives occur, raise `FLOOD_THRESHOLD` in the firmware to 30 or 40 and recompile.

### Analysis in Python

```python
import pandas as pd

df = pd.read_csv('/path/to/floods.csv')
print(df[['timestamp_ms','unique_ssids_per_sec','channel']].describe())
# Plot SSID rate over time
df.plot(x='timestamp_ms', y='unique_ssids_per_sec', kind='line')
```

---

## Correlating Across All Three Files

Attacks often combine techniques. A deauth attack is frequently followed immediately by a beacon flood or an evil twin, since the attacker is forcing clients to reconnect. To correlate events across files:

```python
import pandas as pd

deauth = pd.read_csv('/path/to/deauth.csv')
twins  = pd.read_csv('/path/to/twins.csv')
floods = pd.read_csv('/path/to/floods.csv')

# Tag each file and merge on time proximity
deauth['type'] = 'deauth'
twins['type']  = 'twin'
floods['type'] = 'flood'

# Normalise column set for concat
combined = pd.concat([
    deauth[['timestamp_ms', 'type', 'channel']],
    twins[['timestamp_ms',  'type', 'channel']],
    floods[['timestamp_ms', 'type', 'channel']]
]).sort_values('timestamp_ms').reset_index(drop=True)

print(combined)
```

Events within a few seconds of each other on the same channel are likely part of a coordinated sequence.

---

## Tools Reference

| Tool | Purpose | Link |
|------|---------|-------|
| LibreOffice Calc / Excel | Quick spreadsheet view | — |
| pandas (Python) | Scripted analysis and correlation | [pandas.pydata.org](https://pandas.pydata.org/) |
| Wireshark | Cross-reference with raw packet captures | [wireshark.org](https://www.wireshark.org/) |
| Kismet | Passive Wi-Fi monitoring with alert overlay | [kismetwireless.net](https://www.kismetwireless.net/) |

---

## timestamp_ms and Wall Time

The firmware uses `millis()` — milliseconds since boot — not a real-time clock. To reconstruct wall time, record the device boot time and add the offset:

```
wall_time = boot_time + (timestamp_ms / 1000)
```

If you need timestamped logs tied to real time, attach a DS3231 RTC module and modify `sd_init()` to read the epoch at boot, then use `(millis() - boot_millis + epoch_at_boot * 1000)` as the timestamp.

---

## Legal Notice

Only analyse captures from networks you own or have explicit written authorisation to monitor.
