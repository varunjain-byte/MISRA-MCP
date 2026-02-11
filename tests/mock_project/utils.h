/* utils.h — header declaring utility functions */

#ifndef UTILS_H
#define UTILS_H

/* Rule 8.3 test: declaration matches definition */
int add_numbers(int a, int b);

/* Rule 8.3 test: declaration does NOT match definition (param names differ) */
int multiply_values(int x, int y);

/* Rule 8.4 test: prototype provided */
void process_data(const char *data, int length);

/* Rule 8.13 test: pointer param could be const */
int compute_sum(int *values, int count);

/* Rule 8.8 test: declared in header = has external linkage */
void public_function(void);

/* Macro for testing */
#define MAX_BUFFER_SIZE 1024

/* Typedef for testing */
typedef unsigned int uint32_t_custom;

/* Struct tag for testing */
struct DataPoint {
    int x;
    int y;
};

#endif /* UTILS_H */
