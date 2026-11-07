/* Diagnostic public fixtures only. This is not linked into Spiral or TLS. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

extern void xor_cancel_control(const uint8_t *, uint8_t *, size_t);
extern void xor_clear_control(const uint8_t *, uint8_t *, size_t);

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "cancel") && strcmp(argv[1], "clear"))) {
        fprintf(stderr, "usage: xor_control cancel|clear\n");
        return 2;
    }
    const int clear = strcmp(argv[1], "clear") == 0;
    unsigned int reports = 0;
    for (unsigned int trial = 0; trial < 1000; trial++) {
        uint8_t fixture[48], out[48];
        for (unsigned int i = 0; i < 48; i++)
            fixture[i] = (uint8_t)(i * 71u + trial * 13u);
        memset(out, 0xa5, sizeof out);
        VALGRIND_MAKE_MEM_UNDEFINED(fixture, sizeof fixture);
        if (clear)
            xor_clear_control(fixture, out, 16);
        else
            xor_cancel_control(fixture, out, 16);
        uintptr_t bad = VALGRIND_CHECK_MEM_IS_DEFINED(out, sizeof out);
        reports += bad != 0;
        /* Record definedness first; then compare only public fixture bytes.
           Never apply this declassification to protocol buffers or secrets. */
        VALGRIND_MAKE_MEM_DEFINED(out, sizeof out);
        VALGRIND_MAKE_MEM_DEFINED(fixture, sizeof fixture);
        for (unsigned int i = 0; i < 48; i++) {
            if (out[i] != 0) {
                fprintf(stderr, "nonzero output at trial %u, byte %u\n", trial, i);
                return 3;
            }
        }
    }
    printf("{\"mode\":\"%s\",\"zero_output_checks\":1000,"
           "\"definedness_reports\":%u,\"running_on_valgrind\":%u}\n",
           clear ? "direct-clear" : "copy-branch-cancel", reports,
           (unsigned int)RUNNING_ON_VALGRIND);
    return 0;
}
