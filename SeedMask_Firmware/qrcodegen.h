#pragma once
#include <stdint.h>
#include <stddef.h>

namespace qrcodegen {

class QrCode final {

public:
  enum class Ecc : uint8_t { ECC_LOW=0, ECC_MEDIUM=1, ECC_QUARTILE=2, ECC_HIGH=3 };

  static const QrCode& encodeText(const char *text, Ecc ecl);
  /** Standard SeedQR: digits 0–9 only; uses ISO numeric mode (smaller symbol than byte mode). */
  static const QrCode& encodeNumericDigits(const char *digits, Ecc ecl);
  static const QrCode& encodeBinary(const uint8_t *data, size_t len, Ecc ecl);

  int getSize() const { return size; }
  bool getModule(int x, int y) const;

private:
  // v15 max ~520 bytes (byte mode, ECC-L); ur:crypto-psbt single-part often needs v16 (~586 B).
  static const int MAX_VERSION = 16;
  static const int MAX_MODULES = 17 + 4 * MAX_VERSION;
  static const int MAX_BYTES   = 2953;          // enough for version 15-L (raw)

  int size = 0;
  uint8_t modules[(MAX_MODULES * MAX_MODULES + 7) / 8] = {0};

  void setModule(int x, int y, bool dark);
  bool getBit(int index) const;
  void setBit(int index, bool val);

  // internal
  static void drawFunctionPatterns(QrCode &qr);
  static void drawFormatBits(QrCode &qr, Ecc ecl, int mask);
  static int  getFormatBits(Ecc ecl, int mask);

  static int  chooseVersion(size_t dataLen, Ecc ecl);
  static int  getDataCapacityBytes(int version, Ecc ecl);
  static int  getEccCodewordsPerBlock(int version, Ecc ecl);
  static int  getNumBlocks(int version, Ecc ecl);

  static void addModeAndLength(uint8_t *bb, int &bitLen, int version, size_t dataLen);
  static void appendBits(uint8_t *bb, int &bitLen, uint32_t val, int len);
  static void appendByte(uint8_t *bb, int &bitLen, uint8_t b);

  static void addTerminatorAndPad(uint8_t *data, int dataBytes, int &bitLen);
  static void reedSolomonCompute(const uint8_t *data, int dataLen, uint8_t *ecc, int eccLen);

  static void drawCodewords(QrCode &qr, const uint8_t *all, int totalBytes, int mask);
  static bool mask(int mask, int x, int y);
};

}  // namespace qrcodegen