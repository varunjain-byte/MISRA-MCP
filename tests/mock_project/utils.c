/* utils.c — utility function definitions */

#include "utils.h"

/* Rule 8.3: matches header exactly */
int add_numbers(int a, int b) { return a + b; }

/* Rule 8.3: param names differ from header (x,y vs a,b) */
int multiply_values(int a, int b) { return a * b; }

/* Rule 8.4: has prior declaration in utils.h */
void process_data(const char *data, int length) {
  int i;
  for (i = 0; i < length; i++) {
    /* process each byte */
  }
}

/* Rule 8.13: values is never written through — should be const */
int compute_sum(int *values, int count) {
  int sum = 0;
  int i;
  for (i = 0; i < count; i++) {
    sum += values[i];
  }
  return sum;
}

/* Rule 8.8: declared in header, so it's public */
void public_function(void) { /* intentionally empty */ }

/* Rule 8.8: NOT in any header — should be static */
void internal_helper(void) { /* only used in this file */ }

/* Rule 8.6: only defined here (no duplicate) */
int global_counter = 0;
