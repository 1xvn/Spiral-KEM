#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <valgrind/memcheck.h>
extern void xor_cancel_control(const uint8_t *, uint8_t *, size_t);
extern void xor_clear_control(const uint8_t *, uint8_t *, size_t);
int main(int argc,char **argv) {
  const int clear=argc==2 && strcmp(argv[1],"clear")==0;
  unsigned int reports=0;
  for (unsigned int trial=0;trial<1000;trial++) {
    uint8_t fixture[48],out[48];
    for (unsigned int i=0;i<48;i++) fixture[i]=(uint8_t)(i*71u+trial*13u);
    memset(out,0xa5,sizeof out);
    VALGRIND_MAKE_MEM_UNDEFINED(fixture,sizeof fixture);
    if (clear) xor_clear_control(fixture,out,16); else xor_cancel_control(fixture,out,16);
    uintptr_t bad=VALGRIND_CHECK_MEM_IS_DEFINED(out,sizeof out);
    reports+=(bad!=0);
    /* Public fixture output only, after recording its definedness, for the
       independent value check. This does not change the actual zero bytes. */
    VALGRIND_MAKE_MEM_DEFINED(out,sizeof out);
    VALGRIND_MAKE_MEM_DEFINED(fixture,sizeof fixture);
    for (unsigned int i=0;i<48;i++) assert(out[i]==0);
  }
  printf("{\"mode\":\"%s\",\"zero_output_checks\":1000,\"definedness_reports\":%u}\n",clear?"direct-clear":"copy-branch-cancel",reports);
  return 0;
}
