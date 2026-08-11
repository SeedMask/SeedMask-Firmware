#pragma once
#include <Arduino.h>

// Returns true if it was our SeedMask wrapped QR (SPQR1:...)
// If false, id/blob are untouched and you should treat the original QR text as "blob".
bool seedmask_parse_qr_payload(const String &qrText, String &outId, String &outBlob);