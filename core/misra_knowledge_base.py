"""
MISRA C:2012 Rule Knowledge Base

Structured data for rules 2.x (Unused Code), 8.x (Declarations & Definitions),
and 10.x (Essential Type Model).  Each entry provides the official title, category,
rationale, compliant / non-compliant examples, and human-readable fix strategy.

Fix generation is handled by the AST-aware fix engine (fix_engine.py + c_analyzer.py).
"""

from typing import Dict, Optional, List
from dataclasses import dataclass, field


@dataclass
class MisraRule:
    rule_id: str
    title: str
    category: str                          # "Mandatory" | "Required" | "Advisory"
    rationale: str
    non_compliant: str                     # code example
    compliant: str                         # fixed code example
    fix_strategy: str                      # human-readable guidance
    cross_references: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
#  Knowledge Base — all 29 rules
# ═══════════════════════════════════════════════════════════════════════

_RULES: Dict[str, MisraRule] = {}

def _add(rule: MisraRule):
    _RULES[rule.rule_id] = rule

# ───────────────────────────────────────────────────────────────────────
#  Rule 2.x — Unused Code
# ───────────────────────────────────────────────────────────────────────

_add(MisraRule(
    rule_id="MisraC2012-2.1",
    title="Unreachable code",
    category="Required",
    rationale=(
        "Unreachable code is often a symptom of a logic error.  "
        "It wastes space, confuses maintainers, and may mask defects.  "
        "The compiler may silently discard it, hiding the bug."
    ),
    non_compliant="""\
int foo(int x) {
    if (x > 0) return 1;
    else        return -1;
    x = x + 1;  /* unreachable */
}""",
    compliant="""\
int foo(int x) {
    if (x > 0) return 1;
    else        return -1;
    /* removed dead statement */
}""",
    fix_strategy=(
        "Delete the unreachable statement(s).  If the code was intentional "
        "(e.g. a defensive default), restructure the control flow so every "
        "path is reachable, or add a deviation comment explaining why."
    ),
    cross_references=["MisraC2012-2.2"],
))

_add(MisraRule(
    rule_id="MisraC2012-2.2",
    title="Dead code",
    category="Required",
    rationale=(
        "Code whose removal has no effect on program behaviour is 'dead'.  "
        "It indicates a logic oversight, wastes review effort, and may "
        "mislead readers about the program's actual semantics."
    ),
    non_compliant="""\
void f(int a, int b) {
    int c = a + b;
    a * b;          /* result discarded — dead */
    (void)(c);
}""",
    compliant="""\
void f(int a, int b) {
    int c = a + b;
    /* removed dead expression 'a * b' */
    (void)(c);
}""",
    fix_strategy=(
        "If the expression was meant to have a side-effect, assign or use "
        "its result.  Otherwise delete the statement.  For dead assignments "
        "(value overwritten before read), remove the first assignment."
    ),
    cross_references=["MisraC2012-2.1"],
))

_add(MisraRule(
    rule_id="MisraC2012-2.3",
    title="Unused type declaration",
    category="Advisory",
    rationale=(
        "An unused typedef or struct definition clutters the namespace and "
        "may mislead developers into thinking it is part of the interface."
    ),
    non_compliant="""\
void f(void) {
    typedef struct { int x; int y; } Point;
    /* Point is never used */
}""",
    compliant="""\
void f(void) {
    /* removed unused typedef 'Point' */
}""",
    fix_strategy=(
        "Delete the unused type declaration.  If it is reserved for future "
        "use, move it to a separate header guarded by a version macro, or "
        "add a deviation comment."
    ),
    cross_references=["MisraC2012-2.4", "MisraC2012-2.5"],
))

_add(MisraRule(
    rule_id="MisraC2012-2.4",
    title="Unused tag declaration",
    category="Advisory",
    rationale=(
        "An unused struct/enum/union tag wastes namespace and signals "
        "incomplete refactoring."
    ),
    non_compliant="""\
struct OldConfig {   /* tag never used */
    int mode;
    int timeout;
};""",
    compliant="""\
/* removed unused struct tag 'OldConfig' */""",
    fix_strategy=(
        "Remove the entire struct/enum/union definition if no variable "
        "of that tag type is ever declared.  If only the anonymous body "
        "is needed, use a typedef without a tag."
    ),
    cross_references=["MisraC2012-2.3"],
))

_add(MisraRule(
    rule_id="MisraC2012-2.5",
    title="Unused macro declaration",
    category="Advisory",
    rationale=(
        "Unused macros pollute the preprocessor namespace and can cause "
        "unexpected substitutions if a future identifier matches."
    ),
    non_compliant="""\
#define BUFFER_SIZE 1024   /* never expanded */""",
    compliant="""\
/* removed unused macro BUFFER_SIZE */""",
    fix_strategy=(
        "Delete the #define.  If the macro is part of a configuration "
        "header intended for multiple translation units, ensure each TU "
        "that includes it actually uses it, or guard it with #ifdef."
    ),
    cross_references=["MisraC2012-2.3"],
))

_add(MisraRule(
    rule_id="MisraC2012-2.6",
    title="Unused label declaration",
    category="Advisory",
    rationale=(
        "A label with no corresponding goto is a leftover from refactoring.  "
        "It misleads reviewers and may mask missing error-handling paths."
    ),
    non_compliant="""\
void f(int x) {
    if (x > 0) printf("ok");
cleanup:           /* no goto targets this label */
    return;
}""",
    compliant="""\
void f(int x) {
    if (x > 0) printf("ok");
    /* removed unused label 'cleanup' */
    return;
}""",
    fix_strategy=(
        "Delete the label.  If a goto was removed during refactoring, "
        "verify that the cleanup logic is still reachable via structured "
        "control flow."
    ),
    cross_references=[],
))

_add(MisraRule(
    rule_id="MisraC2012-2.7",
    title="Unused function parameter",
    category="Advisory",
    rationale=(
        "An unused parameter may indicate that the implementation is "
        "incomplete or that the API has changed but callers were not "
        "updated.  It also triggers compiler warnings."
    ),
    non_compliant="""\
int callback(int used, int unused_a, int unused_b) {
    return used * 2;
}""",
    compliant="""\
int callback(int used, int unused_a, int unused_b) {
    (void)unused_a;
    (void)unused_b;
    return used * 2;
}""",
    fix_strategy=(
        "Cast each unused parameter to (void) at the start of the function "
        "body.  This silences warnings and documents that the omission is "
        "intentional.  If the parameter is truly unnecessary, consider "
        "changing the API (but beware breaking callers / function-pointer "
        "compatibility)."
    ),
    cross_references=[],
))

# ───────────────────────────────────────────────────────────────────────
#  Rule 8.x — Declarations & Definitions
# ───────────────────────────────────────────────────────────────────────

_add(MisraRule(
    rule_id="MisraC2012-8.1",
    title="Types shall be explicitly specified",
    category="Required",
    rationale=(
        "Implicit int (allowed in C89) is error-prone and prohibited in "
        "C99+.  Every function return type and parameter must have an "
        "explicit type specifier."
    ),
    non_compliant="""\
foo() { return 0; }           /* implicit int return */
void bar(x) int x; { }       /* K&R param style */""",
    compliant="""\
int foo(void) { return 0; }
void bar(int x) { (void)x; }""",
    fix_strategy=(
        "Add the missing type specifier.  For implicit-int returns, add "
        "'int' (or the correct return type).  For K&R-style parameters, "
        "convert to prototype form with explicit types."
    ),
    cross_references=["MisraC2012-8.2"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.2",
    title="Function types shall be in prototype form with named parameters",
    category="Required",
    rationale=(
        "In C, empty parentheses mean 'unspecified parameters' — not 'no "
        "parameters'.  Using (void) or named parameters makes the intent "
        "explicit and enables compiler type-checking."
    ),
    non_compliant="""\
int proto(int, int);    /* unnamed params */
int noparam();          /* () ≠ (void)   */""",
    compliant="""\
int proto(int a, int b);
int noparam(void);""",
    fix_strategy=(
        "For unnamed parameters, add descriptive names.  "
        "For empty parentheses, replace () with (void)."
    ),
    cross_references=["MisraC2012-8.1"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.3",
    title="Consistent declarations — same names and type qualifiers",
    category="Required",
    rationale=(
        "All declarations of an object or function shall use the same names "
        "and type qualifiers.  Mismatches between a declaration and definition "
        "(different param names, missing const/volatile) indicate copy-paste "
        "errors and may cause subtle type-safety bugs.  The checker examines "
        "declarations across all translation units.\n"
        "Exceptions: (1) compatible versions of the same basic type (signed, "
        "int, signed int) are interchangeable.  (2) unnamed function parameters "
        "do not violate the rule (e.g., void foo(int a) and void foo(int) are "
        "considered consistent)."
    ),
    non_compliant="""\
/* header.h */
void func(const int *ptr, int count);   /* declaration */

/* source.c — param names and const differ */
void func(int *p, int n) { (void)p; (void)n; }

/* Another common violation: type qualifier mismatch */
int compute(int x, int y);              /* declaration */
int compute(int a, int b) { return a+b;} /* param names differ */""",
    compliant="""\
/* header.h */
void func(const int *ptr, int count);

/* source.c — matches declaration exactly */
void func(const int *ptr, int count) { (void)ptr; (void)count; }

/* Consistent names throughout */
int compute(int x, int y);
int compute(int x, int y) { return x + y; }""",
    fix_strategy=(
        "Ensure the definition exactly matches the declaration: same "
        "parameter names, same const/volatile qualifiers, same types.  "
        "Update ALL declarations in headers to be consistent.  "
        "Note: unnamed params (void foo(int)) match named (void foo(int a)) — "
        "if a param is intentionally unnamed in the prototype, adding the name "
        "in the definition is compliant."
    ),
    cross_references=["MisraC2012-8.4"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.4",
    title="Compatible declaration visible at definition",
    category="Required",
    rationale=(
        "A compatible declaration shall be visible when an object or function "
        "with external linkage is defined.  If the definition has no visible "
        "prior declaration, the compiler cannot verify that callers pass the "
        "correct argument types.\n"
        "This rule, combined with 8.5, enforces declaring objects/functions "
        "in a header file and #including that header wherever the identifier "
        "is defined or used.  Tentative definitions (variables declared "
        "without extern and not explicitly defined) are also flagged — either "
        "declare the variable static or use extern followed by a definition."
    ),
    non_compliant="""\
/* module.c — no prior declaration visible */
int compute(int x) { return x * x; }

/* Also noncompliant: tentative definition without extern */
int global_var;   /* tentative — no prior declaration */""",
    compliant="""\
/* compute.h */
int compute(int x);  /* declaration in header */

/* module.c */
#include "compute.h"  /* prior declaration now visible */
int compute(int x) { return x * x; }

/* For variables: use extern + definition */
extern int global_var;       /* in header */
int global_var = 0;          /* in one .c file */""",
    fix_strategy=(
        "Add a function prototype in the appropriate header file, and "
        "#include that header from the .c file containing the definition.  "
        "If the function is only used internally, make it static instead.  "
        "For tentative variable definitions, add an extern declaration in a "
        "header or add the static specifier."
    ),
    cross_references=["MisraC2012-8.3", "MisraC2012-8.5", "MisraC2012-8.8"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.5",
    title="External declaration in one and only one file",
    category="Required",
    rationale=(
        "An external object or function shall be declared once in one and only "
        "one file.  Declaring in a header enables inclusion in any TU where the "
        "identifier is defined or used, maintaining consistency.\n"
        "Violations include: (1) extern declared in a .c file instead of a "
        "header, (2) declared in a header AND a .c file, and (3) implicit "
        "declarations arising from calling a function without including its "
        "header — the compiler creates an implicit declaration, violating "
        "the one-file rule."
    ),
    non_compliant="""\
/* module.c — extern in .c file, NOT in a header */
#include "header.h"
extern void func2(void);     /* Noncompliant — should be in header */

/* Also noncompliant: implicit declaration */
/* module2.c — calls func() without #include "header.h" */
void bar(void) { func(); }   /* implicit decl created by compiler */""",
    compliant="""\
/* header.h — single location for all external declarations */
extern int var;
extern void func1(void);
extern void func2(void);

/* module.c */
#include "header.h"    /* single declaration, included everywhere */""",
    fix_strategy=(
        "Move the extern declaration to a single header file and "
        "#include that header wherever needed.  Delete duplicate extern "
        "declarations from .c files.  For implicit declarations, add the "
        "correct #include to make the prototype visible."
    ),
    cross_references=["MisraC2012-8.4", "MisraC2012-8.6"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.6",
    title="Exactly one external definition",
    category="Required",
    rationale=(
        "An identifier with external linkage shall have exactly one external "
        "definition.  Multiple definitions in different files are UB even if "
        "the definitions are identical.  Note: tentative definitions "
        "(e.g., 'int val;' followed by 'int val = 1;' in the SAME file) are "
        "NOT treated as multiple definitions.  This rule flags only "
        "definitions in DIFFERENT files."
    ),
    non_compliant="""\
/* file1.c */
extern int var = 1;     /* definition in file1 */

/* file2.c */
int var = 0;            /* another definition — Noncompliant */

/* Also applies to functions: */
/* file1.c */  int func(int p) { return p + 1; }
/* file2.c */  int func(int p) { return p - 1; }  /* Noncompliant */""",
    compliant="""\
/* header.h */
extern int var;         /* declaration only */

/* file1.c */
#include "header.h"
int var = 0;            /* single definition */

/* file2.c */
#include "header.h"     /* uses extern declaration — no redefinition */""",
    fix_strategy=(
        "Keep exactly one definition (with an initializer) in one .c file.  "
        "Use 'extern' in headers for declarations.  Remove all duplicate "
        "definitions from other files.  For functions defined in multiple "
        "files, mark one as static if it's internal, or consolidate."
    ),
    cross_references=["MisraC2012-8.5"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.7",
    title="No block-scope extern declarations",
    category="Advisory",
    rationale=(
        "An extern declaration inside a function body is hidden from other "
        "functions and makes the linkage relationship hard to audit."
    ),
    non_compliant="""\
void f(void) {
    extern int global;  /* block-scope extern */
    printf("%d", global);
}""",
    compliant="""\
extern int global;  /* file-scope extern */
void f(void) {
    printf("%d", global);
}""",
    fix_strategy=(
        "Move the extern declaration to file scope (ideally into a header).  "
        "This makes the external dependency visible at a glance."
    ),
    cross_references=["MisraC2012-8.5"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.8",
    title="Static for objects and functions with internal linkage",
    category="Required",
    rationale=(
        "The static storage class specifier shall be used in ALL declarations "
        "of objects and functions that have internal linkage.  If static is "
        "not used consistently, you might declare the same object with both "
        "external and internal linkage, leading to C99 §6.2.2 ambiguity.\n"
        "Violations include: (1) function used only in one TU without static, "
        "(2) mixed storage class specifiers on the same identifier (e.g., "
        "'static int foo; extern int foo;' or 'static int fee(void); "
        "int fee(void) { ... }')."
    ),
    non_compliant="""\
/* Violation 1: function only used in this file, no static */
void helper(void) { printf("internal"); }

/* Violation 2: linkage conflict — static then non-static */
static int fee(void);        /* internal linkage */
int fee(void) { return 1; }  /* missing static — linkage conflict */

/* Violation 3: variable linkage conflict */
static int foo = 0;
extern int foo;              /* conflicts with static */""",
    compliant="""\
static void helper(void) { printf("internal"); }

static int fee(void);          /* consistently static */
static int fee(void) { return 1; }

static int foo = 0;
static int foo;                /* consistent internal linkage */""",
    fix_strategy=(
        "Add the 'static' storage-class specifier to the declaration and "
        "definition.  Verify that the function/object is not referenced in "
        "any other translation unit before making this change.  For linkage "
        "conflicts, ensure ALL declarations use the same storage class: "
        "use static consistently for internal, extern for external."
    ),
    cross_references=["MisraC2012-8.4", "MisraC2012-8.5"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.9",
    title="Object at block scope if used in single function",
    category="Advisory",
    rationale=(
        "File-scope variables that are only accessed from one function "
        "should be local to that function.  This reduces coupling and "
        "makes the data flow easier to understand."
    ),
    non_compliant="""\
static int config = 42;  /* file-scope */
int get_config(void) { return config + 1; }""",
    compliant="""\
int get_config(void) {
    static int config = 42;  /* block-scope */
    return config + 1;
}""",
    fix_strategy=(
        "Move the variable declaration inside the only function that "
        "uses it, adding 'static' if persistent state is needed.  "
        "Verify no other function reads or writes the variable."
    ),
    cross_references=[],
))

_add(MisraRule(
    rule_id="MisraC2012-8.10",
    title="Inline function shall be declared static",
    category="Required",
    rationale=(
        "An inline function without static at file scope has external "
        "linkage.  The C standard requires exactly one external definition, "
        "making non-static inline fragile across translation units."
    ),
    non_compliant="""\
inline int square(int x) { return x * x; }""",
    compliant="""\
static inline int square(int x) { return x * x; }""",
    fix_strategy="Add 'static' before 'inline'.",
    cross_references=["MisraC2012-8.8"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.11",
    title="Extern array shall have explicit size",
    category="Advisory",
    rationale=(
        "An extern array without a size (e.g., extern int a[];) prevents "
        "the compiler from detecting out-of-bounds accesses."
    ),
    non_compliant="""\
extern int lookup_table[];   /* no size */""",
    compliant="""\
extern int lookup_table[256];""",
    fix_strategy=(
        "Add an explicit size to the extern array declaration.  Use a "
        "macro or enum constant for the size to keep it synchronized "
        "with the definition."
    ),
    cross_references=[],
))

_add(MisraRule(
    rule_id="MisraC2012-8.12",
    title="Implicit enum values shall be unique",
    category="Required",
    rationale=(
        "When an enumerator list mixes explicit and implicit values, an "
        "implicit value may silently collide with an explicit one, causing "
        "logic errors in switch statements."
    ),
    non_compliant="""\
enum Status {
    OK = 0,
    WARN,      /* implicit 1 */
    ERR = 1,   /* collision with WARN! */
};""",
    compliant="""\
enum Status {
    OK   = 0,
    WARN = 1,
    ERR  = 2,
};""",
    fix_strategy=(
        "Assign explicit values to all enumerators, or ensure that "
        "implicit values do not collide with any explicit ones.  "
        "Review all switch/case blocks that use this enum."
    ),
    cross_references=[],
))

_add(MisraRule(
    rule_id="MisraC2012-8.13",
    title="Pointer should point to const when possible",
    category="Advisory",
    rationale=(
        "A pointer should point to a const-qualified type whenever possible.  "
        "This ensures you do not inadvertently use pointers to modify objects.  "
        "The rule applies to function parameters that are pointers or arrays: "
        "if the function never writes through the pointer, add const.\n"
        "Also covers: (1) 'char * const s' where the pointer itself is const "
        "but the pointed-to type is not — if no modification occurs, the "
        "pointed-to type also needs const.  (2) Array parameters (int a[5]) "
        "where elements are never modified.\n"
        "Exception: Polyspace does not flag if the pointed data is modified "
        "through a COPY of the pointer."
    ),
    non_compliant="""\
/* Pointer param never writes — should be const */
uint16_t ptr_ex(uint16_t *p) { return *p; }

/* Pointer is const but pointed-to type is not */
char last_char(char * const s) { return s[strlen(s) - 1u]; }

/* Array param never modifies elements */
uint16_t first(uint16_t a[5]) { return a[0]; }""",
    compliant="""\
uint16_t ptr_ex(const uint16_t *p) { return *p; }
char last_char(const char * const s) { return s[strlen(s) - 1u]; }
uint16_t first(const uint16_t a[5]) { return a[0]; }""",
    fix_strategy=(
        "Add 'const' to the pointer parameter type.  Verify that the "
        "function never modifies data through the pointer (including via "
        "copies of the pointer).  Update the corresponding prototype in "
        "the header file.  For array parameters, add const to the element "
        "type (e.g., const int a[N])."
    ),
    cross_references=["MisraC2012-8.3"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.14",
    title="The restrict qualifier shall not be used",
    category="Required",
    rationale=(
        "The 'restrict' qualifier is difficult to use correctly.  If the "
        "aliasing promise is violated, the behaviour is undefined — and "
        "the error is nearly impossible to detect through testing."
    ),
    non_compliant="""\
void copy(int *restrict dst, const int *restrict src, int n) {
    for (int i = 0; i < n; i++) dst[i] = src[i];
}""",
    compliant="""\
void copy(int *dst, const int *src, int n) {
    for (int i = 0; i < n; i++) dst[i] = src[i];
}""",
    fix_strategy="Remove the 'restrict' qualifier from all pointer parameters.",
    cross_references=[],
))

# ───────────────────────────────────────────────────────────────────────
#  Rule 10.x — Essential Type Model
# ───────────────────────────────────────────────────────────────────────

_add(MisraRule(
    rule_id="MisraC2012-10.1",
    title="Operands of inappropriate essential type",
    category="Required",
    rationale=(
        "Using a boolean in arithmetic, an enum in bitwise operations, or "
        "a signed value in a shift is semantically meaningless and often "
        "signals a logic error."
    ),
    non_compliant="""\
_Bool flag = 1;
int x = flag + 1;    /* bool in arithmetic */

enum Color c = RED;
int m = c & 0x01;    /* enum in bitwise */

int v = -1;
int r = v << 2;      /* signed left-shift */""",
    compliant="""\
_Bool flag = 1;
int x = (flag ? 1 : 0) + 1;

unsigned int raw_c = (unsigned int)RED;
int m = raw_c & 0x01u;

unsigned int v = 1u;
unsigned int r = v << 2u;""",
    fix_strategy=(
        "Convert booleans to int via ternary before arithmetic.  "
        "Cast enums to an unsigned integer type before bitwise ops.  "
        "Use unsigned types for shift operands."
    ),
    cross_references=["MisraC2012-10.4", "MisraC2012-10.5"],
))

_add(MisraRule(
    rule_id="MisraC2012-10.2",
    title="Character type in inappropriate addition/subtraction",
    category="Required",
    rationale=(
        "Character types are intended for text processing.  Arbitrary "
        "arithmetic on characters (beyond 'c - \'0\'' style conversions) "
        "obscures intent and may produce nonsensical results."
    ),
    non_compliant="""\
char a = 'X', b = 'A';
int diff = a - b;      /* char subtraction */
char c2 = a + 5;       /* char + int */""",
    compliant="""\
char a = 'X', b = 'A';
int diff = (int)a - (int)b;
char c2 = (char)((int)a + 5);""",
    fix_strategy=(
        "Cast character operands to int before performing arithmetic.  "
        "Cast the result back to char if storing in a char variable.  "
        "Document the intent of the character arithmetic."
    ),
    cross_references=["MisraC2012-10.1"],
))

_add(MisraRule(
    rule_id="MisraC2012-10.3",
    title="Assignment to narrower or different essential type",
    category="Required",
    rationale=(
        "The value of an expression shall not be assigned to an object with a "
        "narrower essential type or of a different essential type category.  "
        "Implicit conversions can cause loss of value (truncation), loss of "
        "sign, or loss of precision (float → int).\n"
        "Essential type categories: essentially Boolean, essentially char, "
        "essentially enum, essentially signed, essentially unsigned, "
        "essentially floating.  Mixing categories is prohibited."
    ),
    non_compliant="""\
unsigned int wide = 70000U;
unsigned short narrow = wide;     /* truncation — narrower type */

int neg = -42;
unsigned int pos = neg;           /* different category: signed → unsigned */

float pi = 3.14f;
int trunc = pi;                   /* different category: float → int */

/* Also: enum assigned to int without cast */
enum Color { RED, GREEN, BLUE };
int c = RED;                      /* enum → signed */""",
    compliant="""\
unsigned int wide = 70000U;
unsigned short narrow = (unsigned short)wide;  /* explicit cast */

float pi = 3.14f;
int trunc = (int)pi;              /* explicit cast */""",
    fix_strategy=(
        "Add an explicit cast to document the intentional narrowing.  "
        "Better yet, validate the source value is within the target "
        "type's range before assigning.  For signed→unsigned, add a "
        "range check."
    ),
    cross_references=["MisraC2012-10.4", "MisraC2012-10.8"],
))

_add(MisraRule(
    rule_id="MisraC2012-10.4",
    title="Both operands shall have same essential type category",
    category="Required",
    rationale=(
        "Mixing signed and unsigned operands in arithmetic or comparison "
        "triggers implicit conversions that may change sign or magnitude.  "
        "Mixing enum and int in a ternary operator loses type safety."
    ),
    non_compliant="""\
int s = -1;
unsigned int u = 1U;
if (s < u) { }          /* signed vs unsigned comparison */

enum Color c = RED;
int val = cond ? c : 99; /* enum vs int in ternary */""",
    compliant="""\
int s = -1;
int u_as_signed = (int)1U;   /* or use same type */
if (s < u_as_signed) { }

enum Color c = RED;
int val = cond ? (int)c : 99;""",
    fix_strategy=(
        "Ensure both operands have the same essential type category.  "
        "Cast one operand to match the other, preferring the wider or "
        "signed type.  For enum/int mixing, cast the enum to int."
    ),
    cross_references=["MisraC2012-10.1", "MisraC2012-10.3"],
))

_add(MisraRule(
    rule_id="MisraC2012-10.5",
    title="Cast to inappropriate essential type",
    category="Advisory",
    rationale=(
        "Casting an integer to _Bool loses all but the least-significant "
        "bit.  Casting a pointer to _Bool compiles but is semantically "
        "wrong — use explicit comparison against NULL.  Casting an "
        "unsigned to enum may produce an invalid enumerator."
    ),
    non_compliant="""\
_Bool b = (_Bool)some_int;     /* int → bool */
_Bool v = (_Bool)ptr;          /* pointer → bool */
enum Color c = (enum Color)u;  /* uint → enum */""",
    compliant="""\
_Bool b = (some_int != 0);
_Bool v = (ptr != NULL);
/* validate 'u' is within enum range before cast */
enum Color c = (u <= BLUE) ? (enum Color)u : RED;""",
    fix_strategy=(
        "Replace int→bool casts with explicit '!= 0' comparison.  "
        "Replace pointer→bool casts with '!= NULL'.  "
        "For uint→enum, validate the value before casting."
    ),
    cross_references=["MisraC2012-10.1", "MisraC2012-10.3"],
))

_add(MisraRule(
    rule_id="MisraC2012-10.6",
    title="Composite expression assigned to wider type",
    category="Required",
    rationale=(
        "When two uint16_t values are multiplied, the result is still "
        "uint16_t even if assigned to uint32_t.  Overflow occurs in the "
        "narrower type *before* the widening assignment."
    ),
    non_compliant="""\
unsigned short a = 40000U, b = 40000U;
unsigned int result = a * b;  /* u16 * u16 overflows before widening */""",
    compliant="""\
unsigned short a = 40000U, b = 40000U;
unsigned int result = (unsigned int)a * b;  /* widen BEFORE multiply */""",
    fix_strategy=(
        "Cast at least one operand to the wider target type BEFORE "
        "performing the operation.  This ensures the arithmetic happens "
        "at the wider width."
    ),
    cross_references=["MisraC2012-10.7"],
))

_add(MisraRule(
    rule_id="MisraC2012-10.7",
    title="Composite expression operand with wider type",
    category="Required",
    rationale=(
        "If a composite expression like (u16 + u16) is combined with a "
        "u32 operand, the addition may overflow before the implicit widening."
    ),
    non_compliant="""\
unsigned short a = 100, b = 200;
unsigned int c = 50U;
unsigned int total = (a + b) + c;  /* (u16+u16) may overflow */""",
    compliant="""\
unsigned short a = 100, b = 200;
unsigned int c = 50U;
unsigned int total = (unsigned int)a + (unsigned int)b + c;""",
    fix_strategy=(
        "Cast the narrower operands to the wider type before combining "
        "them with the wider operand.  This prevents intermediate overflow "
        "in the narrower type."
    ),
    cross_references=["MisraC2012-10.6"],
))

_add(MisraRule(
    rule_id="MisraC2012-10.8",
    title="Composite expression cast to different essential type category",
    category="Required",
    rationale=(
        "Casting a composite expression to a different type category "
        "(e.g., unsigned→signed, int→float) may mask intermediate "
        "overflow or precision loss."
    ),
    non_compliant="""\
unsigned short a = 30000U, b = 30000U;
int val = (int)(a + b);       /* unsigned composite → signed */

int x = 1000, y = 3;
float ratio = (float)(x / y); /* integer div already truncated */""",
    compliant="""\
unsigned short a = 30000U, b = 30000U;
int val = (int)((unsigned int)a + (unsigned int)b);

int x = 1000, y = 3;
float ratio = (float)x / (float)y;  /* float div preserves fraction */""",
    fix_strategy=(
        "For unsigned→signed casts: widen operands first, then cast.  "
        "For int→float: cast operands to float BEFORE division to "
        "preserve the fractional result."
    ),
    cross_references=["MisraC2012-10.3", "MisraC2012-10.6"],
))


# ═══════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════

def get_rule(rule_id: str) -> Optional[MisraRule]:
    """Look up a single MISRA rule by its ID (e.g. 'MisraC2012-8.13')."""
    return _RULES.get(rule_id)


def get_all_rules() -> Dict[str, MisraRule]:
    """Return the entire knowledge base dictionary."""
    return dict(_RULES)


def get_rules_by_group(group: str) -> Dict[str, MisraRule]:
    """Return rules whose IDs start with 'MisraC2012-{group}.'."""
    prefix = f"MisraC2012-{group}."
    return {k: v for k, v in _RULES.items() if k.startswith(prefix)}


def format_rule_explanation(rule_id: str) -> str:
    """Return a rich, human-readable explanation of a rule."""
    rule = get_rule(rule_id)
    if rule is None:
        return f"Unknown rule: {rule_id}"

    explanation = f"""## {rule.rule_id} — {rule.title}
**Category**: {rule.category}

### Rationale
{rule.rationale}

### Non-Compliant Example
```c
{rule.non_compliant}
```

### Compliant Example
```c
{rule.compliant}
```

### How to Fix
{rule.fix_strategy}"""

    if rule.cross_references:
        explanation += f"\n\n### Related Rules\n{', '.join(rule.cross_references)}"

    return explanation
