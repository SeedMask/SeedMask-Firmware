#include "qrcodegen.h"
#include <string.h>
#include "seedmask_psram_attr.h"

namespace qrcodegen {

// -------- Bit helpers --------
bool QrCode::getBit(int index) const {
  return (modules[index >> 3] >> (index & 7)) & 1;
}
void QrCode::setBit(int index, bool val) {
  uint8_t &b = modules[index >> 3];
  uint8_t m = (uint8_t)(1u << (index & 7));
  if (val) b |= m;
  else     b &= (uint8_t)~m;
}
void QrCode::setModule(int x, int y, bool dark) {
  setBit(y * size + x, dark);
}
bool QrCode::getModule(int x, int y) const {
  if (x < 0 || y < 0 || x >= size || y >= size) return false;
  return getBit(y * size + x);
}

// -------- Spec tables --------

// Total codewords (data + ECC) per version (ISO 18004 Table 1; v16 = 733)
static const uint16_t TOTAL_CODEWORDS[17] = {
  0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655, 733
};

// User-data capacity in byte-mode (for version selection only)
static const uint16_t CAP_L[17] = {0,17,32,53,78,106,134,154,192,230,271,321,367,425,458,520,586};
static const uint16_t CAP_M[17] = {0,14,26,42,62,84,106,122,152,180,213,251,287,331,362,412,453};
static const uint16_t CAP_Q[17] = {0,11,20,32,46,60,74,86,108,130,151,177,203,241,258,292,335};
static const uint16_t CAP_H[17] = {0, 7,14,24,34,44,58,64, 84, 98,119,137,155,177,194,220,253};

// Max numeric-mode characters per version (ISO/IEC 18004) — used for Standard SeedQR sizing.
static const uint16_t NUM_CAP_L[17] = {0,41,77,127,187,255,322,370,461,552,652,772,883,1022,1101,1200,1340};
static const uint16_t NUM_CAP_M[17] = {0,34,63,101,149,202,255,293,365,432,513,604,691,796,871,991,1088};
static const uint16_t NUM_CAP_Q[17] = {0,27,48,77,111,144,178,207,259,312,364,427,489,580,621,703,775};
static const uint16_t NUM_CAP_H[17] = {0,17,34,58,82,106,139,154,202,235,288,331,374,434,461,513,560};

static const uint8_t ECC_PER_BLOCK_L[17] = {0,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24};
static const uint8_t ECC_PER_BLOCK_M[17] = {0,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28};
static const uint8_t ECC_PER_BLOCK_Q[17] = {0,13,22,18,26,18,24,18,22,20,24,28,26,24,28,24,24};
static const uint8_t ECC_PER_BLOCK_H[17] = {0,17,28,22,16,22,28,26,26,24,28,24,28,22,24,30,30};

static const uint8_t NUM_BLOCKS_L[17] = {0,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6};
static const uint8_t NUM_BLOCKS_M[17] = {0,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10};
static const uint8_t NUM_BLOCKS_Q[17] = {0,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17};
static const uint8_t NUM_BLOCKS_H[17] = {0,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16};

// Alignment pattern center coordinates per version (terminated by 0)
static const uint8_t ALIGN_POS[17][7] = {
  {0},               // v0 unused
  {0},               // v1: none
  {6, 18, 0},        // v2
  {6, 22, 0},        // v3
  {6, 26, 0},        // v4
  {6, 30, 0},        // v5
  {6, 34, 0},        // v6
  {6, 22, 38, 0},    // v7
  {6, 24, 42, 0},    // v8
  {6, 26, 46, 0},    // v9
  {6, 28, 50, 0},    // v10
  {6, 30, 54, 0},    // v11
  {6, 32, 58, 0},    // v12
  {6, 34, 62, 0},    // v13
  {6, 26, 46, 66, 0},// v14
  {6, 26, 48, 70, 0},// v15
  {6, 26, 50, 74, 0},// v16
};

// -------- Function-module bitmap (static, reused per encode) --------
static const int QR_MAX_SIDE = 81;  // 17 + 4*16  (must match MAX_VERSION in header)
SEEDMASK_PSRAM_BSS static uint8_t funcMods[(QR_MAX_SIDE * QR_MAX_SIDE + 7) / 8];

static inline void markFunc(int x, int y, int s) {
  int idx = y * s + x;
  funcMods[idx >> 3] |= (uint8_t)(1u << (idx & 7));
}
static inline bool isFuncMod(int x, int y, int s) {
  int idx = y * s + x;
  return (funcMods[idx >> 3] >> (idx & 7)) & 1;
}

// -------- Capacity helpers --------
int QrCode::getDataCapacityBytes(int version, Ecc ecl) {
  switch (ecl) {
  case Ecc::ECC_LOW:      return CAP_L[version];
  case Ecc::ECC_MEDIUM:   return CAP_M[version];
  case Ecc::ECC_QUARTILE: return CAP_Q[version];
  default:                return CAP_H[version];
}
}
int QrCode::getEccCodewordsPerBlock(int version, Ecc ecl) {
  switch (ecl) {
    case Ecc::ECC_LOW:      return ECC_PER_BLOCK_L[version];
    case Ecc::ECC_MEDIUM:   return ECC_PER_BLOCK_M[version];
    case Ecc::ECC_QUARTILE: return ECC_PER_BLOCK_Q[version];
    default:                return ECC_PER_BLOCK_H[version];
  }
}
int QrCode::getNumBlocks(int version, Ecc ecl) {
  switch (ecl) {
    case Ecc::ECC_LOW:      return NUM_BLOCKS_L[version];
    case Ecc::ECC_MEDIUM:   return NUM_BLOCKS_M[version];
    case Ecc::ECC_QUARTILE: return NUM_BLOCKS_Q[version];
    default:                return NUM_BLOCKS_H[version];
  }
}
int QrCode::chooseVersion(size_t dataLen, Ecc ecl) {
  for (int v = 1; v <= MAX_VERSION; v++) {
    if ((int)dataLen <= getDataCapacityBytes(v, ecl)) return v;
  }
  return MAX_VERSION;
}

static int numCharCountBitsNumeric(int version) {
  if (version <= 9) return 10;
  if (version <= 26) return 12;
  return 14;
}

static int getNumericCapacity(int version, QrCode::Ecc ecl) {
  switch (ecl) {
    case QrCode::Ecc::ECC_LOW:      return (int)NUM_CAP_L[version];
    case QrCode::Ecc::ECC_MEDIUM:   return (int)NUM_CAP_M[version];
    case QrCode::Ecc::ECC_QUARTILE: return (int)NUM_CAP_Q[version];
    default:                        return (int)NUM_CAP_H[version];
  }
}

static int chooseVersionNumeric(size_t nDigits, QrCode::Ecc ecl) {
  const int vMax = 16;  // QrCode::MAX_VERSION (private)
  for (int v = 1; v <= vMax; v++) {
    if ((int)nDigits <= getNumericCapacity(v, ecl)) return v;
  }
  return vMax;
}

// -------- Bitstream building (byte mode) --------
void QrCode::appendBits(uint8_t *bb, int &bitLen, uint32_t val, int len) {
  for (int i = len - 1; i >= 0; i--) {
    if ((val >> i) & 1)
      bb[bitLen >> 3] |= (uint8_t)(1u << (7 - (bitLen & 7)));
    bitLen++;
  }
}
void QrCode::appendByte(uint8_t *bb, int &bitLen, uint8_t b) {
  appendBits(bb, bitLen, b, 8);
}
void QrCode::addModeAndLength(uint8_t *bb, int &bitLen, int version, size_t dataLen) {
  appendBits(bb, bitLen, 0x4, 4);  // byte mode
  appendBits(bb, bitLen, (uint32_t)dataLen, (version <= 9) ? 8 : 16);
}
void QrCode::addTerminatorAndPad(uint8_t *data, int dataBytes, int &bitLen) {
  int cap = dataBytes * 8;
  int rem = cap - bitLen;
  if (rem > 0) appendBits(data, bitLen, 0, (rem >= 4 ? 4 : rem));
  while (bitLen & 7) appendBits(data, bitLen, 0, 1);
  int byteLen = bitLen / 8;
  bool t = false;
  while (byteLen < dataBytes) {
    data[byteLen++] = t ? 0x11 : 0xEC;
    t = !t;
  }
}

// -------- Reed-Solomon GF(256) with poly 0x11D --------
static uint8_t gf_mul(uint8_t x, uint8_t y) {
  uint16_t r = 0;
  for (int i = 0; i < 8; i++) {
    if (y & 1) r ^= x;
    bool hi = x & 0x80;
    x <<= 1;
    if (hi) x ^= 0x1D;
    y >>= 1;
  }
  return (uint8_t)r;
}

void QrCode::reedSolomonCompute(const uint8_t *data, int dataLen, uint8_t *ecc, int eccLen) {
  memset(ecc, 0, eccLen);
  static uint8_t gen[64];
  memset(gen, 0, sizeof(gen));
  gen[0] = 1;
  int gLen = 1;
  for (int i = 0; i < eccLen; i++) {
    uint8_t a = 1;
    for (int j = 0; j < i; j++) a = gf_mul(a, 2);
    static uint8_t next[64];
    memset(next, 0, sizeof(next));
    for (int j = 0; j < gLen; j++) {
      next[j]   ^= gf_mul(gen[j], a);
      next[j+1] ^= gen[j];
    }
    gLen++;
    memcpy(gen, next, gLen);
  }
  for (int i = 0; i < dataLen; i++) {
    uint8_t factor = data[i] ^ ecc[0];
    memmove(ecc, ecc + 1, eccLen - 1);
    ecc[eccLen - 1] = 0;
    for (int j = 0; j < eccLen; j++)
      ecc[j] ^= gf_mul(gen[eccLen - 1 - j], factor);
  }
}

// -------- Drawing function patterns --------

void QrCode::drawFunctionPatterns(QrCode &qr) {
  int s = qr.size;
  int version = (s - 17) / 4;

  memset(funcMods, 0, (s * s + 7) / 8);

  // Helper: set module value AND mark it as a function module
  auto setF = [&](int x, int y, bool dark) {
    if (x >= 0 && y >= 0 && x < s && y < s) {
      qr.setModule(x, y, dark);
      markFunc(x, y, s);
    }
  };

  // --- Finder patterns (7x7) + separators (1-module white ring) ---
  auto drawFinder = [&](int ox, int oy) {
    for (int dy = -1; dy <= 7; dy++) {
      for (int dx = -1; dx <= 7; dx++) {
        int x = ox + dx, y = oy + dy;
        if (x < 0 || y < 0 || x >= s || y >= s) continue;
        bool dark = (dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6) &&
                    (dx == 0 || dx == 6 || dy == 0 || dy == 6 ||
                     (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4));
        if (dx == -1 || dx == 7 || dy == -1 || dy == 7) dark = false;
        setF(x, y, dark);
      }
    }
  };
  drawFinder(0, 0);
  drawFinder(s - 7, 0);
  drawFinder(0, s - 7);

  // --- Timing patterns ---
  for (int i = 8; i < s - 8; i++) {
    setF(i, 6, (i & 1) == 0);
    setF(6, i, (i & 1) == 0);
  }

  // --- Alignment patterns ---
  if (version >= 2) {
    const uint8_t *pos = ALIGN_POS[version];
    int np = 0;
    while (np < 7 && pos[np] != 0) np++;
    for (int i = 0; i < np; i++) {
      for (int j = 0; j < np; j++) {
        if ((i == 0 && j == 0) ||
            (i == 0 && j == np - 1) ||
            (i == np - 1 && j == 0))
          continue;
        int cx = pos[j], cy = pos[i];
        for (int dy = -2; dy <= 2; dy++) {
          for (int dx = -2; dx <= 2; dx++) {
            int adx = dx < 0 ? -dx : dx;
            int ady = dy < 0 ? -dy : dy;
            bool dark = (adx == 2 || ady == 2 || (dx == 0 && dy == 0));
            setF(cx + dx, cy + dy, dark);
          }
        }
      }
    }
  }

  // --- Dark module ---
  setF(8, s - 8, true);

  // --- Reserve format-info areas (written later, but must be marked as function) ---
  for (int i = 0; i < 6; i++) markFunc(8, i, s);
  markFunc(8, 7, s);
  markFunc(8, 8, s);
  markFunc(7, 8, s);
  for (int i = 9; i < 15; i++) markFunc(14 - i, 8, s);
  for (int i = 0; i < 8; i++) markFunc(s - 1 - i, 8, s);
  for (int i = 8; i < 15; i++) markFunc(8, s - 15 + i, s);

  // --- Version info (v >= 7): 18-bit BCH code ---
  if (version >= 7) {
    int data = version << 12;
    for (int i = 17; i >= 12; i--)
      if (data & (1 << i))
        data ^= 0x1F25 << (i - 12);
    int bits = (version << 12) | data;
    for (int i = 0; i < 18; i++) {
      bool dark = ((bits >> i) & 1) != 0;
      int r = i / 3, c = s - 11 + (i % 3);
      setF(r, c, dark);
      setF(c, r, dark);
    }
  }
}

// Format info: 5 data bits + 10 BCH error correction, XOR mask 0x5412
int QrCode::getFormatBits(Ecc ecl, int mask) {
  int e = 0;
  switch (ecl) {
    case Ecc::ECC_MEDIUM:   e = 0; break;
    case Ecc::ECC_LOW:      e = 1; break;
    case Ecc::ECC_HIGH:     e = 2; break;
    case Ecc::ECC_QUARTILE: e = 3; break;
  }
  int data = (e << 3) | (mask & 7);
  int rem = data << 10;
  for (int i = 14; i >= 10; i--)
    if (rem & (1 << i)) rem ^= 0x537 << (i - 10);
  return ((data << 10) | rem) ^ 0x5412;
}

void QrCode::drawFormatBits(QrCode &qr, Ecc ecl, int mask) {
  int bits = getFormatBits(ecl, mask);
  int s = qr.size;
  // Around top-left finder
  for (int i = 0; i <= 5; i++) qr.setModule(8, i, ((bits >> i) & 1));
  qr.setModule(8, 7, ((bits >> 6) & 1));
  qr.setModule(8, 8, ((bits >> 7) & 1));
  qr.setModule(7, 8, ((bits >> 8) & 1));
  for (int i = 9; i < 15; i++) qr.setModule(14 - i, 8, ((bits >> i) & 1));
  // Top-right + bottom-left
  for (int i = 0; i < 8; i++) qr.setModule(s - 1 - i, 8, ((bits >> i) & 1));
  for (int i = 8; i < 15; i++) qr.setModule(8, s - 15 + i, ((bits >> i) & 1));
}

// -------- Mask patterns (all 8 from the spec) --------
bool QrCode::mask(int m, int x, int y) {
  switch (m) {
    case 0: return ((x + y) & 1) == 0;
    case 1: return (y & 1) == 0;
    case 2: return (x % 3) == 0;
    case 3: return ((x + y) % 3) == 0;
    case 4: return (((y >> 1) + (x / 3)) & 1) == 0;
    case 5: return ((x * y) % 2 + (x * y) % 3) == 0;
    case 6: return (((x * y) % 2 + (x * y) % 3) & 1) == 0;
    case 7: return (((x + y) % 2 + (x * y) % 3) & 1) == 0;
    default: return false;
  }
}

// -------- Codeword placement (zig-zag) --------
void QrCode::drawCodewords(QrCode &qr, const uint8_t *all, int totalBytes, int maskId) {
  int s = qr.size;
  int bitIdx = 0;
  int totalBits = totalBytes * 8;

  for (int right = s - 1; right >= 1; right -= 2) {
    if (right == 6) right = 5;            // skip timing column
    for (int vert = 0; vert < s; vert++) {
        for (int dx = 0; dx < 2; dx++) {
        int x = right - dx;
        bool upward = ((right + 1) & 2) == 0;  // direction alternates per column-pair
        int y = upward ? (s - 1 - vert) : vert;
        if (isFuncMod(x, y, s)) continue;       // skip function modules

        bool dark = false;
        if (bitIdx < totalBits) {
          dark = ((all[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1) != 0;
          bitIdx++;
        }
        if (mask(maskId, x, y)) dark = !dark;
        qr.setModule(x, y, dark);
      }
    }
  }
}

// -------- Penalty scoring (simplified but effective) --------
static long computePenalty(QrCode &qr) {
  int s = qr.getSize();
  long penalty = 0;

  // Rule 1: runs of same color in rows and columns
  for (int y = 0; y < s; y++) {
    int runLen = 1;
    bool last = qr.getModule(0, y);
    for (int x = 1; x < s; x++) {
      bool cur = qr.getModule(x, y);
      if (cur == last) { runLen++; }
      else { if (runLen >= 5) penalty += runLen - 2; runLen = 1; last = cur; }
    }
    if (runLen >= 5) penalty += runLen - 2;
  }
  for (int x = 0; x < s; x++) {
    int runLen = 1;
    bool last = qr.getModule(x, 0);
    for (int y = 1; y < s; y++) {
      bool cur = qr.getModule(x, y);
      if (cur == last) { runLen++; }
      else { if (runLen >= 5) penalty += runLen - 2; runLen = 1; last = cur; }
    }
    if (runLen >= 5) penalty += runLen - 2;
  }

  // Rule 2: 2x2 blocks of same color
  for (int y = 0; y < s - 1; y++) {
    for (int x = 0; x < s - 1; x++) {
      bool c = qr.getModule(x, y);
      if (c == qr.getModule(x+1, y) && c == qr.getModule(x, y+1) && c == qr.getModule(x+1, y+1))
        penalty += 3;
    }
  }

  // Rule 4: proportion of dark modules
  int dark = 0;
  for (int y = 0; y < s; y++)
    for (int x = 0; x < s; x++)
      if (qr.getModule(x, y)) dark++;
  int total = s * s;
  int pct = (dark * 200 + total) / (total * 2);  // percentage 0-100
  int dev = pct - 50;
  if (dev < 0) dev = -dev;
  penalty += (dev / 5) * 10;

  return penalty;
}

// -------- Main encode --------
// Use static result to avoid ~750-byte QrCode on stack (prevents stack overflow on ESP32).
const QrCode& QrCode::encodeBinary(const uint8_t *data, size_t len, Ecc ecl) {
  SEEDMASK_PSRAM_BSS static QrCode qr;
  if (!data) data = (const uint8_t *)"";
  if (len > (size_t)(MAX_BYTES - 4)) len = (size_t)(MAX_BYTES - 4);

  int version = chooseVersion(len, ecl);
  qr.size = 17 + 4 * version;
  memset(qr.modules, 0, sizeof(qr.modules));

  drawFunctionPatterns(qr);

  int eccPerBlock = getEccCodewordsPerBlock(version, ecl);
  int numBlocks   = getNumBlocks(version, ecl);
  int totalCW     = TOTAL_CODEWORDS[version];
  int totalDataCW = totalCW - eccPerBlock * numBlocks;

  SEEDMASK_PSRAM_BSS static uint8_t rawData[MAX_BYTES];
  memset(rawData, 0, sizeof(rawData));

  int bitLen = 0;
  addModeAndLength(rawData, bitLen, version, len);
  for (size_t i = 0; i < len; i++) appendByte(rawData, bitLen, data[i]);
  addTerminatorAndPad(rawData, totalDataCW, bitLen);

  int pos = 0;
  SEEDMASK_PSRAM_BSS static uint8_t interleaved[MAX_BYTES];
  SEEDMASK_PSRAM_BSS static uint8_t blockEcc[20][64];
  static const uint8_t *blockData[20];
  static int blockDataLen[20];

  int shortBlockLen = totalDataCW / numBlocks;
  int numLongBlocks = totalDataCW % numBlocks;
  int numShortBlocks = numBlocks - numLongBlocks;
  int offset = 0;
  for (int b = 0; b < numBlocks; b++) {
    int bLen = shortBlockLen + (b >= numShortBlocks ? 1 : 0);
    blockData[b] = rawData + offset;
    blockDataLen[b] = bLen;
    offset += bLen;
  }
  for (int b = 0; b < numBlocks; b++) {
    reedSolomonCompute(blockData[b], blockDataLen[b], blockEcc[b], eccPerBlock);
  }
  int longBlockLen = shortBlockLen + (numLongBlocks > 0 ? 1 : 0);
  for (int col = 0; col < longBlockLen; col++) {
    for (int b = 0; b < numBlocks; b++) {
      if (col < blockDataLen[b]) interleaved[pos++] = blockData[b][col];
    }
  }
  for (int col = 0; col < eccPerBlock; col++) {
    for (int b = 0; b < numBlocks; b++) interleaved[pos++] = blockEcc[b][col];
  }

  SEEDMASK_PSRAM_BSS static uint8_t savedModules[(MAX_MODULES * MAX_MODULES + 7) / 8];
  memcpy(savedModules, qr.modules, sizeof(qr.modules));
  long bestPenalty = 0x7FFFFFFF;
  int bestMask = 0;
  for (int m = 0; m < 8; m++) {
    memcpy(qr.modules, savedModules, sizeof(qr.modules));
    drawCodewords(qr, interleaved, pos, m);
    drawFormatBits(qr, ecl, m);
    long p = computePenalty(qr);
    if (p < bestPenalty) { bestPenalty = p; bestMask = m; }
  }
  memcpy(qr.modules, savedModules, sizeof(qr.modules));
  drawCodewords(qr, interleaved, pos, bestMask);
  drawFormatBits(qr, ecl, bestMask);
  return qr;
}

const QrCode& QrCode::encodeText(const char *text, Ecc ecl) {
  SEEDMASK_PSRAM_BSS static QrCode qr;
  if (!text) text = "";
  size_t len = strlen(text);

  int version = chooseVersion(len, ecl);
  qr.size = 17 + 4 * version;
  memset(qr.modules, 0, sizeof(qr.modules));

  drawFunctionPatterns(qr);

  // --- Encode data bitstream ---
  int eccPerBlock = getEccCodewordsPerBlock(version, ecl);
  int numBlocks   = getNumBlocks(version, ecl);
  int totalCW     = TOTAL_CODEWORDS[version];
  int totalDataCW = totalCW - eccPerBlock * numBlocks;

  SEEDMASK_PSRAM_BSS static uint8_t rawData[MAX_BYTES];
  memset(rawData, 0, sizeof(rawData));

  int bitLen = 0;
  addModeAndLength(rawData, bitLen, version, len);
  for (size_t i = 0; i < len; i++) appendByte(rawData, bitLen, (uint8_t)text[i]);
  addTerminatorAndPad(rawData, totalDataCW, bitLen);

  // --- Split into blocks, compute RS per block, interleave ---
  int shortBlockLen = totalDataCW / numBlocks;
  int numLongBlocks = totalDataCW % numBlocks;
  int numShortBlocks = numBlocks - numLongBlocks;

  // Pointers into rawData for each block's data
  static const uint8_t *blockData[20];
  static int            blockDataLen[20];
  SEEDMASK_PSRAM_BSS static uint8_t        blockEcc[20][64];

  int offset = 0;
  for (int b = 0; b < numBlocks; b++) {
    int bLen = shortBlockLen + (b >= numShortBlocks ? 1 : 0);
    blockData[b] = rawData + offset;
    blockDataLen[b] = bLen;
    offset += bLen;
  }

  for (int b = 0; b < numBlocks; b++) {
    reedSolomonCompute(blockData[b], blockDataLen[b], blockEcc[b], eccPerBlock);
  }

  // Interleave data codewords
  SEEDMASK_PSRAM_BSS static uint8_t interleaved[MAX_BYTES];
  int pos = 0;

  int longBlockLen = shortBlockLen + (numLongBlocks > 0 ? 1 : 0);
  for (int col = 0; col < longBlockLen; col++) {
    for (int b = 0; b < numBlocks; b++) {
      if (col < blockDataLen[b])
        interleaved[pos++] = blockData[b][col];
    }
  }

  // Interleave ECC codewords
  for (int col = 0; col < eccPerBlock; col++) {
    for (int b = 0; b < numBlocks; b++) {
      interleaved[pos++] = blockEcc[b][col];
    }
  }

  // --- Try all 8 masks, pick lowest penalty ---
  // Save a copy of the QR before codeword placement (function patterns only)
  SEEDMASK_PSRAM_BSS static uint8_t savedModules[(MAX_MODULES * MAX_MODULES + 7) / 8];
  memcpy(savedModules, qr.modules, sizeof(qr.modules));

  int bestMask = 0;
  long bestPenalty = 0x7FFFFFFF;

  for (int m = 0; m < 8; m++) {
    memcpy(qr.modules, savedModules, sizeof(qr.modules));
    drawCodewords(qr, interleaved, pos, m);
    drawFormatBits(qr, ecl, m);
    long p = computePenalty(qr);
    if (p < bestPenalty) {
      bestPenalty = p;
      bestMask = m;
    }
  }

  // Apply best mask
  memcpy(qr.modules, savedModules, sizeof(qr.modules));
  drawCodewords(qr, interleaved, pos, bestMask);
  drawFormatBits(qr, ecl, bestMask);

  return qr;
}

const QrCode& QrCode::encodeNumericDigits(const char *digits, Ecc ecl) {
  SEEDMASK_PSRAM_BSS static QrCode qr;
  if (!digits) digits = "";
  size_t len = strlen(digits);
  for (size_t i = 0; i < len; i++) {
    if (digits[i] < '0' || digits[i] > '9') {
      return encodeText(digits, ecl);
    }
  }
  if (len == 0) {
    return encodeText("", ecl);
  }

  int version = chooseVersionNumeric(len, ecl);
  qr.size = 17 + 4 * version;
  memset(qr.modules, 0, sizeof(qr.modules));

  drawFunctionPatterns(qr);

  int eccPerBlock = getEccCodewordsPerBlock(version, ecl);
  int numBlocks = getNumBlocks(version, ecl);
  int totalCW = TOTAL_CODEWORDS[version];
  int totalDataCW = totalCW - eccPerBlock * numBlocks;

  SEEDMASK_PSRAM_BSS static uint8_t rawData[MAX_BYTES];
  memset(rawData, 0, sizeof(rawData));

  int bitLen = 0;
  appendBits(rawData, bitLen, 0x1, 4);  // numeric mode
  appendBits(rawData, bitLen, (uint32_t)len, numCharCountBitsNumeric(version));
  {
    size_t i = 0;
    while (i + 3 <= len) {
      uint32_t val = (uint32_t)(digits[i] - '0') * 100u + (uint32_t)(digits[i + 1] - '0') * 10u
                   + (uint32_t)(digits[i + 2] - '0');
      appendBits(rawData, bitLen, val, 10);
      i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
      appendBits(rawData, bitLen, (uint32_t)(digits[i] - '0'), 4);
    } else if (rem == 2) {
      uint32_t val = (uint32_t)(digits[i] - '0') * 10u + (uint32_t)(digits[i + 1] - '0');
      appendBits(rawData, bitLen, val, 7);
    }
  }
  addTerminatorAndPad(rawData, totalDataCW, bitLen);

  static const uint8_t *blockData[20];
  static int blockDataLen[20];
  SEEDMASK_PSRAM_BSS static uint8_t blockEcc[20][64];

  int shortBlockLen = totalDataCW / numBlocks;
  int numLongBlocks = totalDataCW % numBlocks;
  int numShortBlocks = numBlocks - numLongBlocks;
  int offset = 0;
  for (int b = 0; b < numBlocks; b++) {
    int bLen = shortBlockLen + (b >= numShortBlocks ? 1 : 0);
    blockData[b] = rawData + offset;
    blockDataLen[b] = bLen;
    offset += bLen;
  }

  for (int b = 0; b < numBlocks; b++) {
    reedSolomonCompute(blockData[b], blockDataLen[b], blockEcc[b], eccPerBlock);
  }

  SEEDMASK_PSRAM_BSS static uint8_t interleaved[MAX_BYTES];
  int pos = 0;

  int longBlockLen = shortBlockLen + (numLongBlocks > 0 ? 1 : 0);
  for (int col = 0; col < longBlockLen; col++) {
    for (int b = 0; b < numBlocks; b++) {
      if (col < blockDataLen[b])
        interleaved[pos++] = blockData[b][col];
    }
  }

  for (int col = 0; col < eccPerBlock; col++) {
    for (int b = 0; b < numBlocks; b++) {
      interleaved[pos++] = blockEcc[b][col];
    }
  }

  SEEDMASK_PSRAM_BSS static uint8_t savedModules[(MAX_MODULES * MAX_MODULES + 7) / 8];
  memcpy(savedModules, qr.modules, sizeof(qr.modules));

  int bestMask = 0;
  long bestPenalty = 0x7FFFFFFF;

  for (int m = 0; m < 8; m++) {
    memcpy(qr.modules, savedModules, sizeof(qr.modules));
    drawCodewords(qr, interleaved, pos, m);
    drawFormatBits(qr, ecl, m);
    long p = computePenalty(qr);
    if (p < bestPenalty) {
      bestPenalty = p;
      bestMask = m;
    }
  }

  memcpy(qr.modules, savedModules, sizeof(qr.modules));
  drawCodewords(qr, interleaved, pos, bestMask);
  drawFormatBits(qr, ecl, bestMask);

  return qr;
}

} // namespace qrcodegen
