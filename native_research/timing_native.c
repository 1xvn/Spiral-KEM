/* Random-order two-class local timing assessment, not the dudect package. */
#define _GNU_SOURCE
#define SPIRAL_TESTING
#include "spiral_native.c"
#include <assert.h>
#include <math.h>
#include <sched.h>
#include <stdio.h>
#include <time.h>

static uint64_t ticks(void) {
    struct timespec value;
    assert(clock_gettime(CLOCK_MONOTONIC_RAW, &value) == 0);
    return (uint64_t)value.tv_sec*1000000000u+(uint64_t)value.tv_nsec;
}

typedef struct { size_t n; double mean, m2; } statistics;
static void update(statistics *s, double value) {
    ++s->n;
    double delta = value-s->mean;
    s->mean += delta/s->n;
    s->m2 += delta*(value-s->mean);
}
static double t_value(const statistics a, const statistics b) {
    double variance = a.m2/(a.n-1)/a.n + b.m2/(b.n-1)/b.n;
    return variance > 0 ? (a.mean-b.mean)/sqrt(variance) : 0;
}

static uint32_t random_word(uint32_t *state) {
    *state ^= *state << 13; *state ^= *state >> 17; *state ^= *state << 5;
    return *state;
}

int main(int argc, char **argv) {
    size_t samples = 6000;
    if (argc == 2) samples = (size_t)strtoul(argv[1], NULL, 10);
    if (samples < 100 || samples > 1000000 || samples%2) return 2;
    cpu_set_t available, chosen;
    CPU_ZERO(&available); CPU_ZERO(&chosen);
    int cpu = -1;
    if (sched_getaffinity(0, sizeof available, &available) == 0) {
        for (int i = 0; i < CPU_SETSIZE; ++i) if (CPU_ISSET(i,&available)) { cpu=i; break; }
        if (cpu >= 0) { CPU_SET(cpu,&chosen); (void)sched_setaffinity(0,sizeof chosen,&chosen); }
    }
    uint8_t *classes = malloc(samples);
    assert(classes != NULL);
    for (size_t i=0;i<samples;++i) classes[i]=(uint8_t)(i%2);
    uint32_t rng=20261106u;
    for (size_t i=samples-1;i>0;--i) {
        size_t j=random_word(&rng)%(i+1);
        uint8_t tmp=classes[i];classes[i]=classes[j];classes[j]=tmp;
    }
    statistics positive[2]={{0}}, assessment[2]={{0}}, control[2]={{0}};
    volatile uint32_t sink=0;
    uint8_t fixed[96], varying[96], pk[808], out[32], zero_ct[1160]={0};
    memset(fixed,0x91,sizeof fixed);
    memcpy(zero_ct,CT_PREFIX,8); zero_ct[8]=1;
    for (size_t i=0;i<samples;++i) {
        uint8_t label=classes[i];
        uint64_t start=ticks();
        /* Known leaky positive control. This branch is intentionally public. */
        for (size_t k=0;k<(label ? 10000u : 32u);++k) sink += (uint32_t)k;
        update(&positive[label],(double)(ticks()-start));
    }
    for (size_t i=0;i<samples;++i) {
        uint8_t label=classes[i];
        memcpy(varying,fixed,sizeof varying);
        if (label) for (size_t j=32;j<96;++j) varying[j]=(uint8_t)random_word(&rng);
        sp_key *key=NULL;
        assert(keygen_seeded(varying,pk,&key)==SP_OK);
        uint64_t start=ticks();
        int status=sp_decaps_once(key,zero_ct,sizeof zero_ct,out);
        uint64_t elapsed=ticks()-start;
        assert(status==SP_OK && sp_test_cleared(key));
        update(&assessment[label],(double)elapsed);
        sp_key_destroy(&key);
        /* Sham classes have exactly the same key and ciphertext input. */
        assert(keygen_seeded(fixed,pk,&key)==SP_OK);
        start=ticks();
        status=sp_decaps_once(key,zero_ct,sizeof zero_ct,out);
        elapsed=ticks()-start;
        assert(status==SP_OK);
        update(&control[label],(double)elapsed);
        sp_key_destroy(&key);
    }
    printf("{\"samples\":%zu,\"cpu\":%d,\"positive_t\":%.8f,\"secret_class_t\":%.8f,\"sham_t\":%.8f,"
           "\"class0_mean_ns\":%.3f,\"class1_mean_ns\":%.3f,\"clock\":\"CLOCK_MONOTONIC_RAW\"}\n",
           samples,cpu,t_value(positive[0],positive[1]),t_value(assessment[0],assessment[1]),
           t_value(control[0],control[1]),assessment[0].mean,assessment[1].mean);
    free(classes);
    return sink==0xdeadbeefu ? 3 : 0;
}
