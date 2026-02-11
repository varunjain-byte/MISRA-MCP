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
        "Mismatches between a function's declaration and definition (e.g., "
        "different parameter names or missing const) indicate copy-paste "
        "errors and may cause subtle type-safety bugs."
    ),
    non_compliant="""\
void func(const int *p);         /* declaration */
void func(int *p) { (void)p; }  /* definition — const missing */""",
    compliant="""\
void func(const int *p);
void func(const int *p) { (void)p; }""",
    fix_strategy=(
        "Ensure the definition exactly matches the declaration: same "
        "parameter names, same const/volatile qualifiers, same types.  "
        "Update ALL declarations in headers to be consistent."
    ),
    cross_references=["MisraC2012-8.4"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.4",
    title="Compatible declaration visible at definition",
    category="Required",
    rationale=(
        "If a function with external linkage is defined without a prior "
        "declaration (prototype), the compiler cannot verify that callers "
        "pass the correct argument types."
    ),
    non_compliant="""\
/* no prior declaration */
int compute(int x) { return x * x; }""",
    compliant="""\
int compute(int x);  /* declaration in header */
int compute(int x) { return x * x; }""",
    fix_strategy=(
        "Add a function prototype in the appropriate header file, or add "
        "a forward declaration before the definition in the same file.  "
        "If the function is only used internally, make it static instead."
    ),
    cross_references=["MisraC2012-8.3", "MisraC2012-8.8"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.5",
    title="External declaration in one and only one file",
    category="Required",
    rationale=(
        "Duplicate extern declarations in .c files create maintenance risk: "
        "if one copy is updated and the other is not, the linker may "
        "silently accept incompatible types."
    ),
    non_compliant="""\
extern int counter;   /* first extern in .c */
extern int counter;   /* duplicate */""",
    compliant="""\
/* extern declaration belongs in counter.h only */
#include "counter.h"  /* single declaration */""",
    fix_strategy=(
        "Move the extern declaration to a single header file and "
        "#include that header wherever needed.  Delete duplicate extern "
        "declarations from .c files."
    ),
    cross_references=["MisraC2012-8.6"],
))

_add(MisraRule(
    rule_id="MisraC2012-8.6",
    title="Exactly one external definition",
    category="Required",
    rationale=(
        "Multiple tentative definitions of the same variable across "
        "translation units leads to undefined behaviour per the C standard."
    ),
    non_compliant="""\
int shared_var;   /* tentative definition 1 */
int shared_var;   /* tentative definition 2 */""",
    compliant="""\
int shared_var = 0;  /* single real definition */""",
    fix_strategy=(
        "Keep exactly one definition (with an initializer) in one .c file.  "
        "Use 'extern' in headers for declarations.  Remove all duplicate "
        "tentative definitions."
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
        "A function or object used only within one translation unit should "
        "be declared static.  This prevents accidental name collisions and "
        "makes the scope explicit."
    ),
    non_compliant="""\
void helper(void) {   /* used only in this file */
    printf("internal");
}""",
    compliant="""\
static void helper(void) {
    printf("internal");
}""",
    fix_strategy=(
        "Add the 'static' storage-class specifier to the declaration.  "
        "Verify that the function/object is not referenced in any other "
        "translation unit before making this change."
    ),
    cross_references=["MisraC2012-8.4"],
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
        "If a function only reads through a pointer (never writes), "
        "declaring the parameter as pointer-to-const documents that "
        "contract and allows the compiler to catch accidental writes."
    ),
    non_compliant="""\
int sum(int *data, int len) {
    int s = 0;
    for (int i = 0; i < len; i++) s += data[i];
    return s;
}""",
    compliant="""\
int sum(const int *data, int len) {
    int s = 0;
    for (int i = 0; i < len; i++) s += data[i];
    return s;
}""",
    fix_strategy=(
        "Add 'const' to the pointer parameter type.  Verify that the "
        "function never modifies data through the pointer.  Update "
        "the corresponding prototype in the header file."
    ),
    cross_references=[],
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
        "Assigning a wider type to a narrower type (e.g., uint32_t to "
        "uint16_t) silently truncates.  Assigning a signed to unsigned "
        "loses sign.  Float to int loses the fractional part."
    ),
    non_compliant="""\
unsigned int wide = 70000U;
unsigned short narrow = wide;     /* truncation */

int neg = -42;
unsigned int pos = neg;           /* sign loss */

float pi = 3.14f;
int trunc = pi;                   /* fractional loss */""",
    compliant="""\
unsigned int wide = 70000U;
unsigned short narrow = (unsigned short)wide;  /* explicit cast */

int neg = -42;
unsigned int pos = (neg >= 0) ? (unsigned int)neg : 0U;

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
