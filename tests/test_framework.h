#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

extern int g_tests_run;
extern int g_tests_failed;
extern int g_assertions;
extern jmp_buf g_test_jmp;

#define ASSERT(cond, msg) do { \
    g_assertions++; \
    if (!(cond)) { \
        fprintf(stderr, "    ASSERT FAILED (line %d): %s\n", __LINE__, msg); \
        longjmp(g_test_jmp, 1); \
    } \
} while (0)

#define ASSERT_EQ(a, b, msg) do { \
    g_assertions++; \
    if ((a) != (b)) { \
        fprintf(stderr, "    ASSERT FAILED (line %d): %s - expected %ld, got %ld\n", \
                __LINE__, msg, (long)(b), (long)(a)); \
        longjmp(g_test_jmp, 1); \
    } \
} while (0)

#define ASSERT_STR_EQ(a, b, msg) do { \
    g_assertions++; \
    if (strcmp(a, b) != 0) { \
        fprintf(stderr, "    ASSERT FAILED (line %d): %s - expected \"%s\", got \"%s\"\n", \
                __LINE__, msg, b, a); \
        longjmp(g_test_jmp, 1); \
    } \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
    g_assertions++; \
    if (memcmp(a, b, len) != 0) { \
        fprintf(stderr, "    ASSERT FAILED (line %d): %s\n", __LINE__, msg); \
        longjmp(g_test_jmp, 1); \
    } \
} while (0)

#define TEST(name) static void test_##name(void); static void test_##name(void)
#define RUN_TEST(name) do { \
    g_tests_run++; \
    printf("  %-45s ", #name); \
    fflush(stdout); \
    if (setjmp(g_test_jmp) == 0) { \
        test_##name(); \
        printf("OK\n"); \
    } else { \
        printf("FAIL\n"); \
        g_tests_failed++; \
    } \
} while (0)

#endif
