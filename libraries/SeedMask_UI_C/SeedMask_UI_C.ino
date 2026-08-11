#include <Arduino.h>
#include <Wire.h>
#include <Arduino_GFX_Library.h>
#include <LittleFS.h>

// =======================
// Types FIRST (ordering-proof)
// =======================
struct Rect { int16_t x, y, w, h; };

static bool hit(const Rect& r, int16_t px, int16_t py) {
  return (px >= r.x && px < (r.x + r.w) &&
          py >= r.y && py < (r.y + r.h));
}

// =======================
// UI Screens
// =======================
enum class UIScreen : uint8_t {
  HOME = 0,
  CREATE_MENU,
  SEED_ENTRY_12,
  WORD_PICKER,
};

// Forward declarations
static void show(UIScreen s);
static void drawHome();
static void drawCreateMenu();
static void drawSeedEntry12();
static void drawWordPicker();

// =======================
// BOARD CONFIG (your working pins)
// =======================
#define LCD_QSPI_CS   12
#define LCD_QSPI_CLK  5
#define LCD_QSPI_D0   1
#define LCD_QSPI_D1   2
#define LCD_QSPI_D2   3
#define LCD_QSPI_D3   4

#define GFX_BL        6
#define I2C_SDA       8
#define I2C_SCL       7

#define TCA9554_ADDR  0x20
#define TCA_REG_OUTPUT    0x01
#define TCA_REG_CONFIG    0x03
#define TCA_REG_POLARITY  0x02

#define EXIO_CAM_PWDN 0
#define EXIO_LCD_RST  1

#define TOUCH_ADDR    0x3B

#define LCD_W 320
#define LCD_H 480
#define ROTATION 0

// =======================
// TOUCH CALIBRATION (your tuned values)
// =======================
static const int RAW_X_MIN = 12;
static const int RAW_X_MAX = 310;
static const int RAW_Y_MIN = 14;
static const int RAW_Y_MAX = 461;

// =======================
// LCD Objects (your working init)
// =======================
Arduino_DataBus *bus = new Arduino_ESP32QSPI(
  LCD_QSPI_CS, LCD_QSPI_CLK,
  LCD_QSPI_D0, LCD_QSPI_D1,
  LCD_QSPI_D2, LCD_QSPI_D3
);

Arduino_GFX *panel = new Arduino_AXS15231B(
  bus, -1, 0, false, LCD_W, LCD_H
);

Arduino_Canvas *gfx = new Arduino_Canvas(LCD_W, LCD_H, panel, 0, 0, ROTATION);

// =======================
// TCA9554 helpers
// =======================
static uint8_t tca_out = 0xFF;

static bool tcaWrite(uint8_t reg, uint8_t val) {
  Wire.beginTransmission(TCA9554_ADDR);
  Wire.write(reg);
  Wire.write(val);
  return Wire.endTransmission() == 0;
}

static bool tcaInit() {
  if (!tcaWrite(TCA_REG_CONFIG, 0x00)) return false;
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

// =======================
// Touch read (your working method)
// =======================
static void mapTouch(uint16_t rx, uint16_t ry, uint16_t &sx, uint16_t &sy) {
  rx = constrain(rx, RAW_X_MIN, RAW_X_MAX);
  ry = constrain(ry, RAW_Y_MIN, RAW_Y_MAX);
  sx = map(rx, RAW_X_MIN, RAW_X_MAX, 0, LCD_W - 1);
  sy = map(ry, RAW_Y_MIN, RAW_Y_MAX, 0, LCD_H - 1);
}

static bool readTouchRaw(uint16_t &x, uint16_t &y) {
  uint8_t cmd[8] = {0xB5,0xAB,0xA5,0x5A,0,0,0,0x08};
  uint8_t data[8];

  Wire.beginTransmission(TOUCH_ADDR);
  Wire.write(cmd, 8);
  if (Wire.endTransmission(false) != 0) return false;

  if (Wire.requestFrom((uint8_t)TOUCH_ADDR, (uint8_t)8) != 8) return false;
  for (int i = 0; i < 8; i++) data[i] = Wire.read();

  if (data[1] == 0) return false;

  x = ((data[2] & 0x0F) << 8) | data[3];
  y = ((data[4] & 0x0F) << 8) | data[5];

  // Filter junk spikes (you saw nonsense like 2136)
  if (x > 1000 || y > 1000) return false;

  return true;
}

static bool readTouchScreen(uint16_t &sx, uint16_t &sy) {
  uint16_t rx, ry;
  if (!readTouchRaw(rx, ry)) return false;
  mapTouch(rx, ry, sx, sy);
  return true;
}

// =======================
// Simple UI helpers
// =======================
static void clearScreen() { gfx->fillScreen(RGB565_BLACK); }

static void titleBar(const char* title) {
  gfx->fillRect(0, 0, LCD_W, 44, RGB565_NAVY);
  gfx->setTextColor(RGB565_WHITE);
  gfx->setTextSize(2);
  gfx->setCursor(12, 12);
  gfx->print(title);
}

static void drawBtn(const Rect& r, const char* label) {
  gfx->fillRoundRect(r.x, r.y, r.w, r.h, 14, RGB565_DARKGREY);
  gfx->drawRoundRect(r.x, r.y, r.w, r.h, 14, RGB565_WHITE);
  gfx->setTextColor(RGB565_WHITE);
  gfx->setTextSize(2);
  gfx->setCursor(r.x + 16, r.y + (r.h/2) - 10);
  gfx->print(label);
}

static void drawSmallBtn(const Rect& r, const char* label) {
  gfx->fillRoundRect(r.x, r.y, r.w, r.h, 10, RGB565_DARKGREY);
  gfx->drawRoundRect(r.x, r.y, r.w, r.h, 10, RGB565_WHITE);
  gfx->setTextColor(RGB565_WHITE);
  gfx->setTextSize(1);
  gfx->setCursor(r.x + 10, r.y + (r.h/2) - 4);
  gfx->print(label);
}

// =======================
// State
// =======================
static UIScreen g_screen = UIScreen::HOME;

// HOME
static Rect BTN_CREATE  = { 40, 170, 240, 80 };
static Rect BTN_RESTORE = { 40, 280, 240, 80 }; // not used yet

// CREATE MENU
static Rect BTN_ENTER_SEED12 = { 40, 120, 240, 70 };
static Rect BTN_BACK_HOME    = { 12,  400, 140, 60 };

// SEED ENTRY
static Rect BTN_DONE_SEED    = { 168, 400, 140, 60 };
static Rect BTN_BACK_CREATE  = { 12,  400, 140, 60 };
static Rect WORD_BOXES[12];

// WORD PICKER
static Rect BTN_WP_BACK      = { 12,  400, 140, 60 };
static Rect BTN_WP_CLEAR     = { 168, 400, 140, 60 };
static Rect LETTER_BTNS[26];        // A-Z grid
static Rect CAND_BTNS[6];           // 6 candidates shown

static String seedWords[12];
static int activeWordIndex = 0;

// Word picker state
static String wpPrefix;
static String wpCandidates[6];
static int wpCandidateCount = 0;

// =======================
// BIP39 wordlist access via LittleFS
// =======================
static bool bip39FileOk() {
  return LittleFS.exists("/english.txt");
}

static bool startsWithIgnoreCase(const String& s, const String& prefix) {
  if (prefix.length() == 0) return true;
  if (s.length() < prefix.length()) return false;
  for (int i = 0; i < (int)prefix.length(); i++) {
    char a = tolower((unsigned char)s[i]);
    char b = tolower((unsigned char)prefix[i]);
    if (a != b) return false;
  }
  return true;
}

// Fill wpCandidates[] by scanning english.txt and taking first matches.
// (Fast enough for 2048 lines.)
static void bip39FindCandidates(const String& prefix) {
  wpCandidateCount = 0;
  for (int i = 0; i < 6; i++) wpCandidates[i] = "";

  if (!bip39FileOk()) return;

  File f = LittleFS.open("/english.txt", "r");
  if (!f) return;

  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    if (startsWithIgnoreCase(line, prefix)) {
      wpCandidates[wpCandidateCount++] = line;
      if (wpCandidateCount >= 6) break;
    }
  }
  f.close();
}

// =======================
// Drawing
// =======================
static void drawHome() {
  clearScreen();
  titleBar("SeedMask");
  drawBtn(BTN_CREATE,  "CREATE");
  drawBtn(BTN_RESTORE, "RESTORE");

  gfx->setTextColor(RGB565_WHITE);
  gfx->setTextSize(1);
  gfx->setCursor(12, 460);
  gfx->print("Touch enabled");
  gfx->flush();
}

static void drawCreateMenu() {
  clearScreen();
  titleBar("CREATE");

  drawBtn(BTN_ENTER_SEED12, "Enter Seed (12)");
  drawSmallBtn(BTN_BACK_HOME, "Back");

  gfx->setTextColor(RGB565_WHITE);
  gfx->setTextSize(1);
  gfx->setCursor(12, 210);
  gfx->print("No QWERTY needed. Pick words from BIP39 list.");
  gfx->setCursor(12, 230);
  gfx->print("BIP39 file: /english.txt (LittleFS)");
  if (!bip39FileOk()) {
    gfx->setCursor(12, 255);
    gfx->setTextColor(RGB565_RED);
    gfx->print("Missing english.txt (upload to LittleFS)");
  }

  gfx->flush();
}

static void drawSeedEntry12() {
  clearScreen();
  titleBar("Enter Seed (12)");

  // Build 12 boxes in 2 columns x 6 rows
  int x1 = 12, x2 = 166;
  int y = 60;
  int w = 142, h = 48;
  int gap = 8;

  for (int i = 0; i < 12; i++) {
    int col = (i < 6) ? 0 : 1;
    int row = (i < 6) ? i : (i - 6);
    int bx = (col == 0) ? x1 : x2;
    int by = y + row * (h + gap);

    WORD_BOXES[i] = { (int16_t)bx, (int16_t)by, (int16_t)w, (int16_t)h };

    uint16_t fill = (i == activeWordIndex) ? RGB565_DARKGREEN : RGB565_DARKGREY;
    gfx->fillRoundRect(bx, by, w, h, 10, fill);
    gfx->drawRoundRect(bx, by, w, h, 10, RGB565_WHITE);

    gfx->setTextColor(RGB565_WHITE);
    gfx->setTextSize(1);
    gfx->setCursor(bx + 8, by + 6);
    gfx->printf("%d.", i + 1);

    gfx->setCursor(bx + 28, by + 6);
    String wtxt = seedWords[i];
    if (wtxt.length() == 0) wtxt = "tap to set";
    gfx->print(wtxt);
  }

  drawSmallBtn(BTN_BACK_CREATE, "Back");
  drawSmallBtn(BTN_DONE_SEED,   "DONE");

  gfx->setTextColor(RGB565_WHITE);
  gfx->setTextSize(1);
  gfx->setCursor(12, 372);
  gfx->print("Tap a word slot to pick a BIP39 word.");
  gfx->flush();
}

static void drawWordPicker() {
  clearScreen();
  titleBar("Pick Word");

  // Show which slot we are editing
  gfx->setTextColor(RGB565_WHITE);
  gfx->setTextSize(1);
  gfx->setCursor(12, 50);
  gfx->printf("Word %d/12  Prefix: %s", activeWordIndex + 1, wpPrefix.c_str());

  // Candidates area
  int cy = 70;
  for (int i = 0; i < 6; i++) {
    CAND_BTNS[i] = { 12, (int16_t)(cy + i * 46), 296, 40 };
    uint16_t fill = (i < wpCandidateCount) ? RGB565_DARKGREY : RGB565_BLACK;
    gfx->fillRoundRect(CAND_BTNS[i].x, CAND_BTNS[i].y, CAND_BTNS[i].w, CAND_BTNS[i].h, 10, fill);
    gfx->drawRoundRect(CAND_BTNS[i].x, CAND_BTNS[i].y, CAND_BTNS[i].w, CAND_BTNS[i].h, 10, RGB565_WHITE);

    gfx->setTextColor(RGB565_WHITE);
    gfx->setTextSize(2);
    gfx->setCursor(CAND_BTNS[i].x + 12, CAND_BTNS[i].y + 10);
    if (i < wpCandidateCount) gfx->print(wpCandidates[i]);
    else gfx->print("-");
  }

  // Letter grid A-Z (not QWERTY)
  // 7 columns x 4 rows = 28 slots, we use 26
  int gx = 12, gy = 360;
  int bw = 40, bh = 36, ggap = 4;

  int idx = 0;
  for (int r = 0; r < 4; r++) {
    for (int c = 0; c < 7; c++) {
      if (idx >= 26) break;
      int bx = gx + c * (bw + ggap);
      int by = gy + r * (bh + ggap);
      LETTER_BTNS[idx] = { (int16_t)bx, (int16_t)by, (int16_t)bw, (int16_t)bh };

      gfx->fillRoundRect(bx, by, bw, bh, 8, RGB565_DARKGREY);
      gfx->drawRoundRect(bx, by, bw, bh, 8, RGB565_WHITE);
      gfx->setTextColor(RGB565_WHITE);
      gfx->setTextSize(2);
      gfx->setCursor(bx + 12, by + 10);
      gfx->print((char)('A' + idx));
      idx++;
    }
  }

  drawSmallBtn(BTN_WP_BACK,  "Back");
  drawSmallBtn(BTN_WP_CLEAR, "Clear");

  if (!bip39FileOk()) {
    gfx->setTextColor(RGB565_RED);
    gfx->setTextSize(1);
    gfx->setCursor(12, 330);
    gfx->print("Missing /english.txt - upload LittleFS data.");
  }

  gfx->flush();
}

static void show(UIScreen s) {
  g_screen = s;
  if (s == UIScreen::HOME) drawHome();
  else if (s == UIScreen::CREATE_MENU) drawCreateMenu();
  else if (s == UIScreen::SEED_ENTRY_12) drawSeedEntry12();
  else if (s == UIScreen::WORD_PICKER) drawWordPicker();
}

// =======================
// Touch dispatch (debounced)
// =======================
static uint32_t lastTapMs = 0;

static bool getTap(uint16_t &x, uint16_t &y) {
  static bool lastPressed = false;

  uint16_t sx, sy;
  bool pressed = readTouchScreen(sx, sy);

  bool tap = false;
  if (pressed && !lastPressed) {
    uint32_t now = millis();
    if (now - lastTapMs > 140) { // debounce
      lastTapMs = now;
      x = sx; y = sy;
      tap = true;
    }
  }
  lastPressed = pressed;
  return tap;
}

// =======================
// Setup / Loop
// =======================
void setup() {
  Serial.begin(115200);
  delay(200);

  Serial.println("=== SeedMask UI (C) ===");

  Wire.begin(I2C_SDA, I2C_SCL);
  Wire.setClock(400000);

  if (tcaInit()) Serial.println("TCA9554 OK.");
  else Serial.println("TCA9554 init FAILED.");

  tcaSetBit(EXIO_CAM_PWDN, false);
  tcaSetBit(EXIO_LCD_RST, true);

  pinMode(GFX_BL, OUTPUT);
  digitalWrite(GFX_BL, HIGH);

  lcdResetViaTCA();

  if (!gfx->begin()) {
    Serial.println("gfx->begin failed");
    while (1) delay(1000);
  }

  // LittleFS
  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS begin failed");
  } else {
    Serial.println("LittleFS OK");
    Serial.printf("english.txt exists? %d\n", (int)bip39FileOk());
  }

  // Start at HOME
  show(UIScreen::HOME);
}

void loop() {
  uint16_t x, y;
  if (!getTap(x, y)) {
    delay(10);
    return;
  }

  Serial.printf("TAP %u %u\n", x, y);

  // Visual tap dot
  gfx->fillCircle(x, y, 3, RGB565_RED);
  gfx->flush();

  if (g_screen == UIScreen::HOME) {
    if (hit(BTN_CREATE, x, y)) {
      show(UIScreen::CREATE_MENU);
    } else if (hit(BTN_RESTORE, x, y)) {
      // later
      Serial.println("RESTORE (not built yet)");
    }
    return;
  }

  if (g_screen == UIScreen::CREATE_MENU) {
    if (hit(BTN_ENTER_SEED12, x, y)) {
      // reset seed
      for (int i = 0; i < 12; i++) seedWords[i] = "";
      activeWordIndex = 0;
      show(UIScreen::SEED_ENTRY_12);
    } else if (hit(BTN_BACK_HOME, x, y)) {
      show(UIScreen::HOME);
    }
    return;
  }

  if (g_screen == UIScreen::SEED_ENTRY_12) {
    if (hit(BTN_BACK_CREATE, x, y)) {
      show(UIScreen::CREATE_MENU);
      return;
    }
    if (hit(BTN_DONE_SEED, x, y)) {
      // For now: just print the words
      Serial.println("SEED (12):");
      for (int i = 0; i < 12; i++) {
        Serial.printf("%2d: %s\n", i+1, seedWords[i].c_str());
      }
      // Next step: validate checksum etc.
      // We’ll do that in Step D.
      return;
    }

    // Tap a word slot
    for (int i = 0; i < 12; i++) {
      if (hit(WORD_BOXES[i], x, y)) {
        activeWordIndex = i;
        wpPrefix = "";
        bip39FindCandidates(wpPrefix);
        show(UIScreen::WORD_PICKER);
        return;
      }
    }
    return;
  }

  if (g_screen == UIScreen::WORD_PICKER) {
    if (hit(BTN_WP_BACK, x, y)) {
      show(UIScreen::SEED_ENTRY_12);
      return;
    }
    if (hit(BTN_WP_CLEAR, x, y)) {
      wpPrefix = "";
      bip39FindCandidates(wpPrefix);
      drawWordPicker();
      return;
    }

    // Candidate pick
    for (int i = 0; i < 6; i++) {
      if (i < wpCandidateCount && hit(CAND_BTNS[i], x, y)) {
        seedWords[activeWordIndex] = wpCandidates[i];
        show(UIScreen::SEED_ENTRY_12);
        return;
      }
    }

    // Letter press
    for (int i = 0; i < 26; i++) {
      if (hit(LETTER_BTNS[i], x, y)) {
        wpPrefix += (char)('a' + i);
        bip39FindCandidates(wpPrefix);
        drawWordPicker();
        return;
      }
    }

    return;
  }
}