#include "some_header.h"
#include <stdio.h>
#include <stdlib.h>

// --- Violation 1: Rule 8.3 (Decl/Def mismatch) ---
// Declaration says int x
void myFunction(int x);

// Definition has int x, int y
void myFunction(int x, int y) { // Line 12
  printf("Value: %d\n", x + y);
}

// --- Violation 2: Rule 5.1 (Identifier length/uniqueness) ---
// Identifiers too similar in first 31 chars
int very_long_identifier_name_that_is_not_unique_A = 10;
int very_long_identifier_name_that_is_not_unique_B = 20; // Line 20

// --- Violation 3: Rule 11.4 (Pointer to Integer cast) ---
void ptrTest() {
  int *ptr = (int *)0xDEADBEEF;
  int addr = (int)ptr; // Line 28 - Violation
}

// --- Violation 4: Rule 17.7 (Unused return value) ---
int returnSomething() { return 42; }

void callTest() {
  returnSomething(); // Line 35 - Violation (ignoring return)
}

// --- Violation 5: Dir 4.14 (External input check) ---
void inputTest() {
  int val;
  scanf("%d", &val);
  // Line 42 - Violation: val used without range check
  printf("Val: %d", 100 / val);
}

// --- Deviation Case: Rule 21.3 (Dynamic Memory) ---
void memoryTest() {
  // Line 50 - Suppressed violation
  int *arr = (int *)malloc(10 * sizeof(int));
  free(arr);
}

int main() {
  myFunction(1, 2);
  ptrTest();
  callTest();
  inputTest();
  memoryTest();
  return 0;
}
