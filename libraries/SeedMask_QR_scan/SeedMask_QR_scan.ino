#include <Arduino.h>
#include <Wire.h>
#include <Arduino_GFX_Library.h>
#include "esp_camera.h"

extern "C" {
  #include "quirc.h"
}

// =====================
// I2C / Expander
// =====================
#define I2C_SDA 8
#define I2C_SCL 7

#define TCA9554_ADDR 0x20
#define TCA_REG_OUTPUT    0x01
#define TCA_REG_CONFIG    0x03
#define TCA_REG_POLARITY  0x02

// EXIO bits (your working bring-up)
#define EXIO_CAM_PWDN 0   // P0
#define EXIO_LCD_RST  1   // P1

// =====================
// LCD QSPI (YOUR WORKING PINS)
// =====================
#define LCD_QSPI_CS   12
#define LCD_QSPI_CLK  5
#define LCD_QSPI_D0   1
#define LCD_QSPI_D1   2
#define LCD_QSPI_D2   3
#define LCD_QSPI_D3   4

// IMPORTANT: use ONLY GPIO6 for BL (GPIO45 is camera D0)
#define LCD_BL 6

#define BLACK 0x0000
#define WHITE 0xFFFF

// =====================
// Camera pins (YOUR WORKING PINS)
// =====================
#define CAM_XCLK  38
#define CAM_PCLK  41
#define CAM_VSYNC 17
#define CAM_HREF  18

#define CAM_SIOD  I2C_SDA
#define CAM_SIOC  I2C_SCL

#define CAM_D0 45
#define CAM_D1 47
#define CAM_D2 48
#define CAM_D3 46
#define CAM_D4 42
#define CAM_D5 40
#define CAM_D6 39
#define CAM_D7 21

// =====================
// TCA9554 helpers
// =====================
static uint8_t tca_out = 0xFF;

static bool tcaWrite(uint8_t reg, uint8_t val) {
  Wire.beginTransmission(TCA9554_ADDR);
  Wire.write(reg);
  Wire.write(val);
  return Wire.endTransmission() == 0;
}

static bool tcaInit() {
  if (!tcaWrite(TCA_REG_CONFIG, 0x00)) return false;  // all outputs
  tcaWrite(TCA_REG_POLARITY, 0x00);
  tca_out = 0xFF;
  return tcaWrite(TCA_REG_OUTPUT, tca_out);
}

static void tcaSetBit(uint8_t bit, bool high) {
  if (high) tca_out |= (1 << bit);
  else      tca_out &= ~(1 << bit);
  tcaWrite(TCA_REG_OUTPUT, tca_out);
}

static void lcdResetViaTCA() {
  tcaSetBit(EXIO_LCD_RST, false);
  delay(30);
  tcaSetBit(EXIO_LCD_RST, true);
  delay(120);
}

// =====================
// LCD init (WORKING STYLE)
// =====================
Arduino_DataBus *bus = new Arduino_ESP32QSPI(
  LCD_QSPI_CS,
  LCD_QSPI_CLK,
  LCD_QSPI_D0,
  LCD_QSPI_D1,
  LCD_QSPI_D2,
  LCD_QSPI_D3
);

Arduino_GFX *panel = new Arduino_AXS15231B(
  bus,
  -1,          // RST via TCA
  0,           // rotation
  false,
  320, 480
);

Arduino_Canvas *gfx = new Arduino_Canvas(320, 480, panel);

static void lcdStatus(const char *a, const char *b = "") {
  gfx->fillScreen(BLACK);
  gfx->setCursor(16, 28);
  gfx->setTextColor(WHITE);
  gfx->setTextSize(2);
  gfx->println(a);
  gfx->setTextSize(1);
  gfx->println();
  gfx->println(b);
  gfx->flush();
}

static void lcdPreview(const char *title, const char *preview) {
  gfx->fillScreen(BLACK);
  gfx->setCursor(16, 20);
  gfx->setTextColor(WHITE);
  gfx->setTextSize(2);
  gfx->println(title);
  gfx->setTextSize(1);
  gfx->println();

  int col = 0;
  for (size_t i = 0; preview[i] != 0; i++) {
    char c = preview[i];
    gfx->print(c);
    col++;
    if (c == '\n') col = 0;
    if (col > 45) { gfx->println(); col = 0; }
  }
  gfx->flush();
}

// =====================
// Camera init (GRAYSCALE VGA)
// =====================
static const int SNAP_W = 640;
static const int SNAP_H = 480;
static const int SNAP_BYTES = SNAP_W * SNAP_H;

static bool cameraInitGrayscaleVGA() {
  camera_config_t c{};
  c.ledc_channel = LEDC_CHANNEL_0;
  c.ledc_timer   = LEDC_TIMER_0;

  c.pin_d0 = CAM_D0; c.pin_d1 = CAM_D1; c.pin_d2 = CAM_D2; c.pin_d3 = CAM_D3;
  c.pin_d4 = CAM_D4; c.pin_d5 = CAM_D5; c.pin_d6 = CAM_D6; c.pin_d7 = CAM_D7;

  c.pin_xclk  = CAM_XCLK;
  c.pin_pclk  = CAM_PCLK;
  c.pin_vsync = CAM_VSYNC;
  c.pin_href  = CAM_HREF;

  c.pin_sccb_sda = CAM_SIOD;
  c.pin_sccb_scl = CAM_SIOC;

  c.pin_pwdn  = -1; // via TCA
  c.pin_reset = -1;

  c.xclk_freq_hz = 20000000;

  c.pixel_format = PIXFORMAT_GRAYSCALE;
  c.frame_size   = FRAMESIZE_VGA;        // 640x480
  c.fb_count     = 2;                    // helps overflow
  c.grab_mode    = CAMERA_GRAB_LATEST;
  c.fb_location  = CAMERA_FB_IN_PSRAM;

  esp_err_t err = esp_camera_init(&c);
  if (err != ESP_OK) {
    Serial.printf("esp_camera_init failed: 0x%x\n", (int)err);
    return false;
  }

  sensor_t *s = esp_camera_sensor_get();
  if (s) {
    // IMPORTANT: keep VGA (do NOT set QVGA here)
    s->set_framesize(s, FRAMESIZE_VGA);
    s->set_contrast(s, 2);
    s->set_brightness(s, 1);
    s->set_saturation(s, 0);
    // Optional tweaks if needed:
    // s->set_gainceiling(s, GAINCEILING_16X);
    // s->set_whitebal(s, 1);
  }

  return true;
}

// =====================
// QUIRC
// =====================
static struct quirc *qr = nullptr;

// =====================
// Shared decode state (task -> loop)
// =====================
static uint8_t *snap = nullptr;                 // VGA grayscale snapshot (PSRAM)
static SemaphoreHandle_t snapMutex;

static volatile bool snapReady = false;

static volatile bool qrFoundFlag = false;
static int qrPayloadLen = 0;
static char qrPreview[400];                     // what we show on LCD (safe small)
static uint8_t qrFirstBytes[64];                // for debug
static int qrFirstBytesLen = 0;

static void makePreview(const uint8_t *payload, int payload_len, char *out, size_t outSize) {
  size_t n = 0;
  int limit = payload_len;
  if (limit > 350) limit = 350;

  for (int i = 0; i < limit && (n + 1) < outSize; i++) {
    uint8_t c = payload[i];
    if (c == '\n' || (c >= 32 && c <= 126)) out[n++] = (char)c;
    else out[n++] = '.';
  }
  out[n] = 0;
}

static bool quircEnsureSize(int w, int h) {
  if (!qr) {
    qr = quirc_new();
    if (!qr) return false;
  }
  return quirc_resize(qr, w, h) >= 0;
}

static bool decodeFromSnap() {
  if (!quircEnsureSize(SNAP_W, SNAP_H)) return false;

  int qw = 0, qh = 0;
  uint8_t *img = quirc_begin(qr, &qw, &qh);
  if (!img || qw != SNAP_W || qh != SNAP_H) {
    quirc_end(qr);
    return false;
  }

  memcpy(img, snap, SNAP_BYTES);
  quirc_end(qr);

  int cnt = quirc_count(qr);
  if (cnt <= 0) return false;

  struct quirc_code code;
  struct quirc_data data;
  quirc_decode_error_t err;

  quirc_extract(qr, 0, &code);
  err = quirc_decode(&code, &data);

  if (err) {
    quirc_flip(&code);
    err = quirc_decode(&code, &data);
    if (err) {
      Serial.printf("QUIRC decode error: %s\n", quirc_strerror(err));
      return false;
    }
  }

  // Save results to globals (small + safe)
  qrPayloadLen = (int)data.payload_len;
  makePreview(data.payload, (int)data.payload_len, qrPreview, sizeof(qrPreview));

  qrFirstBytesLen = (qrPayloadLen < (int)sizeof(qrFirstBytes)) ? qrPayloadLen : (int)sizeof(qrFirstBytes);
  for (int i = 0; i < qrFirstBytesLen; i++) qrFirstBytes[i] = data.payload[i];

  qrFoundFlag = true;
  return true;
}

// =====================
// Decode task (runs on CORE 0)
// =====================
static void decodeTask(void *param) {
  (void)param;
  Serial.println("Decode task started (core0).");

  while (true) {
    if (!snapReady) {
      vTaskDelay(pdMS_TO_TICKS(15));
      continue;
    }

    // Consume snapshot
    xSemaphoreTake(snapMutex, portMAX_DELAY);
    snapReady = false;
    xSemaphoreGive(snapMutex);

    // Decode
    if (decodeFromSnap()) {
      Serial.println("=== QR DETECTED ===");
      Serial.printf("payload_len=%d\n", qrPayloadLen);
      Serial.print("first bytes: ");
      for (int i = 0; i < qrFirstBytesLen; i++) Serial.write(qrFirstBytes[i]);
      Serial.println();
      // Don’t spam decode repeatedly once we found one
      vTaskDelay(pdMS_TO_TICKS(500));
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

// =====================
// Setup / Loop
// =====================
static uint32_t lastBeat = 0;

void setup() {
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.println("=== SeedMask LCD + OV5640 + QUIRC (SAFE + VGA) ===");

  // Backlight
  pinMode(LCD_BL, OUTPUT);
  digitalWrite(LCD_BL, HIGH);

  // I2C
  Wire.begin(I2C_SDA, I2C_SCL);
  Wire.setClock(400000);

  // Expander
  if (!tcaInit()) Serial.println("TCA9554 init FAILED.");
  else Serial.println("TCA9554 OK.");

  tcaSetBit(EXIO_LCD_RST, true);
  tcaSetBit(EXIO_CAM_PWDN, false); // enable camera

  // LCD
  lcdResetViaTCA();
  gfx->begin();
  lcdStatus("LCD OK", "Init camera...");

  // Snapshot buffer
  snap = (uint8_t*)ps_malloc(SNAP_BYTES);
  if (!snap) {
    lcdStatus("PSRAM FAIL", "snap buffer");
    while (1) delay(1000);
  }
  memset(snap, 0, SNAP_BYTES);

  // Camera
  if (!cameraInitGrayscaleVGA()) {
    lcdStatus("CAMERA FAIL", "Check pins/PWDN");
    while (1) delay(1000);
  }

  // QUIRC
  qr = quirc_new();
  if (!qr) {
    lcdStatus("QUIRC FAIL", "quirc_new()");
    while (1) delay(1000);
  }
  if (!quircEnsureSize(SNAP_W, SNAP_H)) {
    lcdStatus("QUIRC FAIL", "resize()");
    while (1) delay(1000);
  }

  snapMutex = xSemaphoreCreateMutex();

  // Start decode task on CORE 0 (keep Arduino loopTask on CORE 1)
  xTaskCreatePinnedToCore(
    decodeTask,
    "decodeTask",
    32768,     // 32KB stack
    nullptr,
    1,
    nullptr,
    0          // CORE 0
  );

  lcdStatus("CAMERA OK", "Scanning for QR...");
  Serial.println("Camera OK. Scanning for QR...");
}

void loop() {
  // Grab frame
  camera_fb_t *fb = esp_camera_fb_get();
  if (!fb) {
    delay(5);
    return;
  }

  // Copy VGA grayscale frame into snap (only if decoder is ready for next frame)
  if (fb->width == SNAP_W && fb->height == SNAP_H && fb->format == PIXFORMAT_GRAYSCALE) {
    bool canWrite = false;

    xSemaphoreTake(snapMutex, portMAX_DELAY);
    canWrite = !snapReady; // if decode hasn't consumed previous yet
    xSemaphoreGive(snapMutex);

    if (canWrite) {
      // fb->len should be w*h, but don’t hard-fail if it’s slightly different
      int copyLen = fb->len;
      if (copyLen > SNAP_BYTES) copyLen = SNAP_BYTES;

      memcpy(snap, fb->buf, copyLen);

      xSemaphoreTake(snapMutex, portMAX_DELAY);
      snapReady = true;
      xSemaphoreGive(snapMutex);
    }
  }

  esp_camera_fb_return(fb);

  // LCD updates ONLY here (thread-safe)
  if (qrFoundFlag) {
    qrFoundFlag = false;
    char line2[64];
    snprintf(line2, sizeof(line2), "len=%d (VGA)", qrPayloadLen);
    lcdPreview("QR FOUND", qrPreview);
    delay(1200);
    lcdStatus("CAMERA OK", "Scanning for QR...");
  }

  if (millis() - lastBeat > 2000) {
    lastBeat = millis();
    Serial.println("scan...");
  }

  delay(15);
}