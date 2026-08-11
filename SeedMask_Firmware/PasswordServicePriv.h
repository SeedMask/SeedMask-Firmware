/**
 * PasswordService private I/O — include ONLY from Vault.cpp.
 * Keeps plaintext serialize/deserialize off the public PasswordService API.
 */
#pragma once

#include <Arduino.h>

bool pwSvc_deserializePlain(const char* str, size_t len);
String pwSvc_serializePlain();
