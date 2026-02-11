/* ==========================================================
 * MISRA C:2012 Rule 10.x — Essential Type Model (Edge Cases)
 * Rules: 10.1–10.8
 * ========================================================== */

#include <stdbool.h>
#include <stdio.h>

/* ---- Rule 10.1: Operands not of inappropriate essential type ---- */

/* Edge: boolean used in arithmetic */
void rule_10_1_bool_arith(void) {
  _Bool flag = 1;
  int x = flag + 1; /* Line 14: boolean in addition — inappropriate */
  printf("%d\n", x);
}

/* Edge: enum used as bitwise operand */
enum Color { RED, GREEN, BLUE };

void rule_10_1_enum_bitwise(void) {
  enum Color c = RED;
  int mask = c & 0x01; /* Line 22: enum in bitwise & — inappropriate */
  printf("%d\n", mask);
}

/* Edge: signed used as shift operand */
void rule_10_1_signed_shift(void) {
  int val = -1;
  int result = val << 2; /* Line 29: signed left-shift — UB territory */
  printf("%d\n", result);
}

/* Edge: char used in relational with int */
void rule_10_1_char_cmp(void) {
  char ch = 'A';
  if (ch > 100) { /* Line 35: char compared to int literal */
    printf("big\n");
  }
}

/* ---- Rule 10.2: Character type not in addition/subtraction ---- */

/* Edge: character subtracted from character (common idiom, but non-compliant)
 */
int rule_10_2_char_sub(char a, char b) {
  return a - b; /* Line 44: char subtraction — non-compliant */
}

/* Edge: character used in addition with integer (not '0'-based) */
char rule_10_2_char_add(char c) {
  return c + 5; /* Line 49: char + int literal */
}

/* Edge: string index computed from char arithmetic */
void rule_10_2_index(const char *str) {
  char offset = 'A';
  char idx = str[0] - offset; /* Line 54: character arithmetic for index */
  printf("index: %d\n", idx);
}

/* ---- Rule 10.3: Assignment to narrower essential type ---- */

/* Edge: uint32_t assigned to uint16_t without cast */
void rule_10_3_narrow(void) {
  unsigned int wide = 70000U;
  unsigned short narrow = wide; /* Line 62: 32-bit → 16-bit truncation */
  printf("%u\n", narrow);
}

/* Edge: signed to unsigned assignment losing sign */
void rule_10_3_sign_loss(void) {
  int negative = -42;
  unsigned int positive = negative; /* Line 68: sign loss */
  printf("%u\n", positive);
}

/* Edge: float to int — fractional loss */
void rule_10_3_float_int(void) {
  float pi = 3.14159f;
  int truncated = pi; /* Line 74: float → int truncation */
  printf("%d\n", truncated);
}

/* ---- Rule 10.4: Both operands same essential type category ---- */

/* Edge: mixed signed/unsigned comparison */
void rule_10_4_mixed_cmp(void) {
  int s = -1;
  unsigned int u = 1U;
  if (s < u) { /* Line 83: signed vs unsigned comparison */
    printf("tricky\n");
  }
}

/* Edge: enum mixed with plain int in ternary */
void rule_10_4_enum_ternary(int cond) {
  enum Color c1 = RED;
  int fallback = 99;
  int result = cond ? c1 : fallback; /* Line 91: enum vs int in ternary */
  printf("%d\n", result);
}

/* ---- Rule 10.5: Cast to inappropriate essential type ---- */

/* Edge: signed cast to boolean */
void rule_10_5_signed_bool(int x) {
  _Bool b = (_Bool)x; /* Line 98: int → bool cast — loses info */
  printf("%d\n", b);
}

/* Edge: pointer cast to boolean (common but non-compliant) */
void rule_10_5_ptr_bool(void *ptr) {
  _Bool valid = (_Bool)ptr; /* Line 103: pointer → bool */
  printf("%d\n", valid);
}

/* Edge: unsigned to enum cast */
void rule_10_5_uint_enum(unsigned int val) {
  enum Color c = (enum Color)val; /* Line 108: uint → enum */
  printf("%d\n", c);
}

/* ---- Rule 10.6: Composite expression → wider type assignment ---- */

/* Edge: two uint16_t multiplied, result assigned to uint32_t without cast */
void rule_10_6_composite_widen(void) {
  unsigned short a = 40000U;
  unsigned short b = 40000U;
  unsigned int result =
      a * b; /* Line 117: u16*u16 → u32 — type of a*b is still u16 */
  printf("%u\n", result);
}

/* Edge: two uint8_t added, stored in uint16_t */
void rule_10_6_byte_add(void) {
  unsigned char x = 200;
  unsigned char y = 200;
  unsigned short sum = x + y; /* Line 124: u8+u8 → u16 */
  printf("%u\n", sum);
}

/* ---- Rule 10.7: Composite with operator — other operand same type ---- */

/* Edge: small-type composite op used alongside wider type */
void rule_10_7_composite_op(void) {
  unsigned short a = 100;
  unsigned short b = 200;
  unsigned int c = 50U;
  unsigned int total = (a + b) + c; /* Line 134: (u16+u16) + u32 — mismatch */
  printf("%u\n", total);
}

/* Edge: char composite mixed with int */
void rule_10_7_char_composite(char x, char y) {
  int z = 10;
  int result = (x + y) * z; /* Line 140: (char+char) * int */
  printf("%d\n", result);
}

/* ---- Rule 10.8: Composite expression cast to different essential type ---- */

/* Edge: unsigned composite cast to signed */
void rule_10_8_cast_sign(void) {
  unsigned short a = 30000U;
  unsigned short b = 30000U;
  int signed_val = (int)(a + b); /* Line 149: u16 composite → signed int */
  printf("%d\n", signed_val);
}

/* Edge: integer composite cast to float */
void rule_10_8_cast_float(void) {
  int x = 1000;
  int y = 3;
  float ratio = (float)(x / y); /* Line 156: int composite → float (integer div
                                   already done) */
  printf("%f\n", ratio);
}

/* Edge: signed composite cast to unsigned */
void rule_10_8_signed_to_unsigned(void) {
  int a = -100;
  int b = 50;
  unsigned int val =
      (unsigned int)(a + b); /* Line 163: signed composite → unsigned */
  printf("%u\n", val);
}
