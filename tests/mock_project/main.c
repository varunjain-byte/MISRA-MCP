/* main.c — main entry point calling utils */

#include "utils.h"

/* Rule 8.5 test: duplicate extern (also declared extern in other.c) */
extern int shared_var;

/* Rule 8.6 test: another definition of global_counter (violates ODR) */
int global_counter = 0;

/* Rule 8.11 test: extern array without explicit size */
extern int lookup_table[];

int main(void) {
  int result;
  int data[5] = {1, 2, 3, 4, 5};

  /* Call add_numbers — creates call graph entry */
  result = add_numbers(3, 4);

  /* Call multiply_values — creates call graph entry */
  result = multiply_values(5, 6);

  /* Call process_data — creates call graph entry */
  process_data("hello", 5);

  /* Call compute_sum — creates call graph entry for 8.13 impact */
  result = compute_sum(data, 5);

  /* Call public_function — proves it has external callers */
  public_function();

  return result;
}
