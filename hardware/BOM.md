# Bill of Materials

Complete component list for ESP32Watchdog.

---

## Core Components

| # | Component | Specification | Qty | Approx. Cost |
|---|-----------|--------------|-----|-------------|
| 1 | MCU | ESP32 DevKit V1, 30-pin, ESP32-WROOM-32 | 1 | ~5 EUR |
| 2 | Display | 0.96" SSD1306 OLED, 128×64, I2C, 4-pin (VCC/GND/SDA/SCL) | 1 | ~3 EUR |
| 3 | Storage | MicroSD SPI module, 3.3V compatible, level-shifted | 1 | ~1 EUR |
| 4 | Button | Tactile push button, through-hole, 6×6 mm or 12×12 mm | 1 | ~0.10 EUR |
| 5 | Resistor | 220 Ω, 1/4 W (current-limit for LED) | 1 | ~0.05 EUR |
| 6 | LED | 3 mm or 5 mm, any colour | 1 | ~0.10 EUR |
| 7 | MicroSD card | Class 4 or better, FAT32, 2 GB minimum | 1 | ~2 EUR |

**Core total: ~11 EUR**

---

## Optional — Portable Operation

| # | Component | Specification | Qty | Approx. Cost |
|---|-----------|--------------|-----|-------------|
| 8 | Battery | LiPo 3.7 V, 1000 mAh or larger, JST-PH 2.0 connector | 1 | ~4 EUR |
| 9 | Charger | TP4056 module, USB-C, with DW01 over-discharge protection | 1 | ~1 EUR |
| 10 | Power switch | SPDT slide switch or mini toggle, rated ≥ 500 mA | 1 | ~0.50 EUR |

> **TP4056 note:** Buy the version with the DW01 protection IC (two chips on the board, not one). The single-chip version lacks over-discharge and over-current protection.

**Portable add-on total: ~5.50 EUR**

---

## Pin Assignments (reference)

| Signal | ESP32 GPIO | Notes |
|--------|-----------|-------|
| OLED SDA | GPIO21 | I2C data |
| OLED SCL | GPIO22 | I2C clock |
| SD SCK | GPIO18 | SPI clock |
| SD MOSI | GPIO23 | SPI data out |
| SD MISO | GPIO19 | SPI data in |
| SD CS | GPIO5 | SPI chip select |
| Button | GPIO4 | Active-low, internal pull-up |
| LED | GPIO2 | Via 220 Ω series resistor |

**Do not use GPIO0 for the button.** GPIO0 is the ESP32 boot-mode strapping pin; a button press held across a reset sends the device into Download Mode.

---

## MicroSD Module Notes

Buy a module with a **3.3 V level shifter** on-board (SPI lines and CS). Unshifted 5 V modules work unreliably at 3.3 V and cause intermittent write errors. The module should expose: VCC, GND, SCK, MOSI, MISO, CS — six pins.

Confirm your module before soldering:
- 6-pin module with "SD" or "TF" label — almost always 3.3 V compatible
- 5-pin module — may be bare card socket with no level shifting; check datasheet

---

## Tools Required

- Soldering iron and solder
- Jumper wires (for breadboard prototyping) or PCB
- USB-A to Micro-USB cable (for flashing)
- Computer with Arduino IDE 2.x or PlatformIO

---

## Sourcing

Components are widely available from:

| Supplier | Notes |
|----------|-------|
| AliExpress | Lowest unit cost; 2–4 week shipping from CN |
| LCSC Electronics | Good component quality; reasonable international shipping |
| Mouser / Digi-Key | Fast shipping; higher per-unit cost; useful for resistors and LEDs in bulk |
| Local electronics shops | Useful for same-day prototyping needs |

Search terms:
- `ESP32 DevKit V1 30pin`
- `SSD1306 0.96 OLED I2C 4pin`
- `Micro SD SPI module 3.3V level shift`
- `TP4056 USB-C protection DW01`
- `LiPo 3.7V 1000mAh JST PH`
