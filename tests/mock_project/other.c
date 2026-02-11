/* other.c — another TU for cross-file tests */

#include "utils.h"

/* Rule 8.5 test: duplicate extern declaration (also in main.c) */
extern int shared_var;

/* Calls add_numbers from a second TU — verifies call graph */
int helper_calc(void) { return add_numbers(10, 20); }
