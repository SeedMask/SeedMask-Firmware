#include "SecureMem.h"

#include <cstring>
#include "mbedtls/platform_util.h"

void secure_memzero(void* p, size_t n) {
  if (!p || n == 0) return;
#if defined(MBEDTLS_PLATFORM_ZEROIZE_ALT) || defined(MBEDTLS_PLATFORM_C)
  mbedtls_platform_zeroize(p, n);
#else
  volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
  while (n--) *v++ = 0;
#endif
}
