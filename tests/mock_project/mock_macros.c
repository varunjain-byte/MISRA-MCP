/* mock_macros.c — testing preprocessor features */

#include "utils.h"

#define PI 3.14159
#define SQUARE(x) ((x) * (x))

int calculate_area(int radius) { return (int)(PI * SQUARE(radius)); }

#ifdef DEBUG_ENABLED
void log_debug(const char *msg) {
  // This block should be active if DEBUG_ENABLED is defined
}
#else
void log_production(const char *msg) {
  // This block is active if DEBUG_ENABLED is NOT defined
}
#endif

#if 0
    void dead_code(void) {
        // This block should be inactive
        int x = 1 / 0; 
    }
#endif

#define GREETING "Hello"
#define FULL_GREETING GREETING ", World!"

const char *get_greeting(void) { return FULL_GREETING; }
