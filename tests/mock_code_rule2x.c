/* ==========================================================
 * MISRA C:2012 Rule 2.x — Unused Code (Edge Cases)
 * All rules: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7
 * ========================================================== */

#include <stdio.h>
#include <stdlib.h>

/* ---- Rule 2.1: Unreachable code ---- */

/* Edge: code after return inside nested if-else chain */
int rule_2_1_edge_nested(int a) {
  if (a > 0) {
    return 1;
  } else {
    return -1;
  }
  a = a + 1; /* Line 18: UNREACHABLE — both branches return */
}

/* Edge: code after infinite loop with no break */
void rule_2_1_edge_infinite(void) {
  for (;;) {
    /* spin forever */
  }
  printf("never reached\n"); /* Line 26: UNREACHABLE */
}

/* Edge: switch where every case returns */
int rule_2_1_edge_switch(int x) {
  switch (x) {
  case 0:
    return 0;
  case 1:
    return 1;
  default:
    return -1;
  }
  return 99; /* Line 35: UNREACHABLE — all paths return */
}

/* ---- Rule 2.2: Dead code (no side‐effect) ---- */

/* Edge: expression result computed but never stored/used */
void rule_2_2_edge_unused_expr(int a, int b) {
  int c = a + b;
  a *b; /* Line 43: DEAD CODE — multiplication result discarded */
  (void)(c);
}

/* Edge: post-increment with value unused */
void rule_2_2_edge_postinc(void) {
  int x = 5;
  x++; /* Line 49: actually used (modifies x) — but... */
       /* x is never read again — entire modification is dead */
}

/* Edge: assignment to variable that is immediately overwritten */
void rule_2_2_edge_overwrite(int input) {
  int result = input * 2; /* Line 55: DEAD — overwritten below */
  result = input * 3;
  printf("%d\n", result);
}

/* ---- Rule 2.3: Unused type declaration ---- */

/* Edge: typedef inside function scope, never used */
void rule_2_3_edge(void) {
  typedef struct { /* Line 63: UNUSED type */
    int x;
    int y;
  } UnusedLocalPoint;
}

/* Edge: typedef at file scope never referenced anywhere */
typedef unsigned long long UnusedFileType; /* Line 69: UNUSED */

/* ---- Rule 2.4: Unused tag declaration ---- */

/* Edge: struct tag declared but only pointer-to-void used */
struct UnusedTag { /* Line 74: UNUSED tag */
  float value;
  char name[32];
};

/* Edge: enum tag with values that ARE used via #define, but tag itself is not
 */
enum UnusedColorTag { /* Line 80: UNUSED tag */
                      RED_VAL = 0xFF0000,
                      GREEN_VAL = 0x00FF00,
                      BLUE_VAL = 0x0000FF
};

/* ---- Rule 2.5: Unused macro declaration ---- */

#define UNUSED_MACRO_BUFFER_SIZE 1024 /* Line 88: UNUSED macro */

/* Edge: macro defined just before a #undef — never actually expanded */
#define TEMP_MACRO 42 /* Line 91: UNUSED — undef'd immediately */
#undef TEMP_MACRO

/* ---- Rule 2.6: Unused label declaration ---- */

/* Edge: label exists for a goto that was later refactored out */
void rule_2_6_edge(int x) {
  if (x > 0) {
    printf("positive\n");
  }
cleanup: /* Line 100: UNUSED label */
  return;
}

/* Edge: multiple labels, only one used */
void rule_2_6_edge_multi(int mode) {
  if (mode == 1)
    goto used_label;
unused_label: /* Line 107: UNUSED label */
  printf("dead path\n");
used_label:
  printf("alive\n");
}

/* ---- Rule 2.7: Unused function parameter ---- */

/* Edge: callback signature forces extra params */
int rule_2_7_edge_callback(int used, int unused_a, int unused_b) {
  /* Line 115: unused_a, unused_b never referenced */
  return used * 2;
}

/* Edge: variadic-like pattern where only first param matters */
void rule_2_7_edge_variadic(int count, int a, int b, int c) {
  /* Line 121: a, b, c are never touched */
  printf("count = %d\n", count);
}
