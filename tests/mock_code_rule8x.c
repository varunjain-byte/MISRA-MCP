/* ==========================================================
 * MISRA C:2012 Rule 8.x — Declarations & Definitions (Edge Cases)
 * Rules: 8.1–8.14
 * ========================================================== */

#include <stdio.h>
#include <string.h>

/* ---- Rule 8.1: Types shall be explicitly specified ---- */

/* Edge: implicit int return in K&R style declaration */
rule_8_1_implicit() /* Line 11: Missing return type — illegal C99+ but common
                       legacy */
{
  return 0;
}

/* Edge: parameter with no type in old-style definition */
void rule_8_1_param(x) /* Line 17: x has no type specifier */
    int x;
{
  printf("%d\n", x);
}

/* ---- Rule 8.2: Function types in prototype form with named parameters ---- */

/* Edge: prototype missing parameter names */
int rule_8_2_proto(int, int); /* Line 26: param names missing */

int rule_8_2_proto(int a, int b) { return a + b; }

/* Edge: empty parentheses (means unspecified params in C, not void) */
int rule_8_2_empty_parens(); /* Line 33: () ≠ (void) */

/* ---- Rule 8.3: All declarations use same names and type qualifiers ---- */

/* Edge: const mismatch between declaration and definition */
void rule_8_3_const(const int *p);       /* Line 38: const int* */
void rule_8_3_const(int *p) { (void)p; } /* Line 39: int* — MISMATCH */

/* Edge: parameter name differs */
int rule_8_3_names(int width, int height); /* Line 42: width, height */
int rule_8_3_names(int w, int h) {
  return w * h;
} /* Line 43: w, h — MISMATCH */

/* ---- Rule 8.4: Compatible declaration visible at definition ---- */

/* Edge: function defined with external linkage but no prior declaration */
int rule_8_4_no_decl(int x) { /* Line 48: no prior prototype visible */
  return x * x;
}

/* ---- Rule 8.5: External object/function declared once in one file ---- */

/* Edge: extern declared in .c file instead of header */
extern int global_counter; /* Line 55: extern in .c — should be in .h */
extern int global_counter; /* Line 56: DUPLICATE extern declaration */

/* ---- Rule 8.6: Identifier with external linkage — exactly one definition ----
 */

/* Edge: tentative definition that may create duplicates across TUs */
int rule_8_6_tentative; /* Line 61: tentative definition */
int rule_8_6_tentative; /* Line 62: SECOND tentative — ambiguous */

/* ---- Rule 8.7: No block-scope definitions for external linkage objects ----
 */

void rule_8_7_blockscope(void) {
  extern int block_extern; /* Line 67: extern inside block scope */
  printf("%d\n", block_extern);
}

/* ---- Rule 8.8: static for internal linkage ---- */

/* Edge: function used only in this TU but missing static */
void rule_8_8_internal_only(void) { /* Line 73: should be static */
  printf("internal\n");
}

/* ---- Rule 8.9: Object at block scope if accessed from single function ---- */

/* Edge: file-scope variable only used inside main() */
static int single_use_var = 42; /* Line 80: should be local to main */

int use_single(void) { return single_use_var + 1; }

/* ---- Rule 8.10: Inline function must be static ---- */

/* Edge: inline without static at file scope */
inline int rule_8_10_inline(int x) { /* Line 88: inline without static */
  return x + 1;
}

/* ---- Rule 8.11: Array with external linkage — size explicit ---- */

/* Edge: extern array with unspecified size */
extern int rule_8_11_array[]; /* Line 95: size not specified */

/* ---- Rule 8.12: Implicit enum constant value must be unique ---- */

/* Edge: implicit values collide with explicit ones */
enum rule_8_12_bad {
  A_VAL = 0,
  B_VAL,     /* 1 — implicit */
  C_VAL = 1, /* Line 103: DUPLICATE value 1 */
  D_VAL      /* 2 */
};

/* ---- Rule 8.13: Pointer to const where possible ---- */

/* Edge: function reads through pointer but doesn't modify — should be const */
int rule_8_13_nomod(int *data,
                    int len) { /* Line 110: data should be const int* */
  int sum = 0;
  for (int i = 0; i < len; i++) {
    sum += data[i]; /* read-only access */
  }
  return sum;
}

/* Edge: struct pointer only inspected, not mutated */
typedef struct {
  int x;
  int y;
} Point;

int rule_8_13_struct(Point *p) { /* Line 120: p should be const Point* */
  return p->x + p->y;
}

/* ---- Rule 8.14: restrict type qualifier shall not be used ---- */

/* Edge: restrict on both overlapping pointers */
void rule_8_14_restrict(int *restrict a, int *restrict b,
                        int n) { /* Line 127: restrict */
  for (int i = 0; i < n; i++) {
    a[i] = b[i] * 2;
  }
}
