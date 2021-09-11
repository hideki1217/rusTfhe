#include "spqlios-fft.h"
#include <cassert>
#include <cmath>

using namespace std;

FFT_Processor_Spqlios::FFT_Processor_Spqlios(const int32_t N) : _2N(2 * N), N(N), Ns2(N / 2) {
    tables_direct = new_fft_table(N);
    tables_reverse = new_ifft_table(N);
    real_inout_direct = fft_table_get_buffer(tables_direct);
    imag_inout_direct = real_inout_direct + Ns2;
    real_inout_rev = fft_table_get_buffer(tables_reverse);
    imag_inout_rev = real_inout_rev + Ns2;
}

void FFT_Processor_Spqlios::execute_reverse(double *res,const double *a){
    //for (int32_t i=0; i<N; i++) real_inout_rev[i]=a[i];
    {
        double *dst = real_inout_rev;
        const double *ait = a;
        const double *aend = a + N;
        __asm__ __volatile__ (
        "0:\n"
                "vmovupd (%1),%%ymm0\n"
                "vmovapd %%ymm0,(%0)\n"
                "addq $32,%1\n"
                "addq $32,%0\n"
                "cmpq %2,%1\n"
                "jb 0b\n"
        : "=r"(dst), "=r"(ait), "=r"(aend)
        : "0"(dst), "1"(ait), "2"(aend)
        : "%ymm0", "memory"
        );
    }
    ifft(tables_reverse, real_inout_rev);
    //for (int32_t i=0; i<N; i++) res[i]=real_inout_rev[i];
    {
        double *dst = res;
        double *sit = real_inout_rev;
        double *send = real_inout_rev + N;
        __asm__ __volatile__ (
        "1:\n"
                "vmovapd (%1),%%ymm0\n"
                "vmovupd %%ymm0,(%0)\n"
                "addq $32,%1\n"
                "addq $32,%0\n"
                "cmpq %2,%1\n"
                "jb 1b\n"
                "vzeroall\n"
        : "=r"(dst), "=r"(sit), "=r"(send)
        : "0"(dst), "1"(sit), "2"(send)
        : "%ymm0", "memory"
        );
    }
}


void FFT_Processor_Spqlios::execute_reverse_int(double *res, const int32_t *a) {
    //for (int32_t i=0; i<N; i++) real_inout_rev[i]=(double)a[i];
    {
        double *dst = real_inout_rev;
        const int32_t *ait = a;
        const int32_t *aend = a + N;
        __asm__ __volatile__ (
        "0:\n"
                "vmovupd (%1),%%xmm0\n"
                "vcvtdq2pd %%xmm0,%%ymm1\n"
                "vmovapd %%ymm1,(%0)\n"
                "addq $16,%1\n"
                "addq $32,%0\n"
                "cmpq %2,%1\n"
                "jb 0b\n"
        : "=r"(dst), "=r"(ait), "=r"(aend)
        : "0"(dst), "1"(ait), "2"(aend)
        : "%xmm0", "%ymm1", "memory"
        );
    }
    ifft(tables_reverse, real_inout_rev);
    //for (int32_t i=0; i<N; i++) res[i]=real_inout_rev[i];
    {
        double *dst = res;
        double *sit = real_inout_rev;
        double *send = real_inout_rev + N;
        __asm__ __volatile__ (
        "1:\n"
                "vmovapd (%1),%%ymm0\n"
                "vmovupd %%ymm0,(%0)\n"
                "addq $32,%1\n"
                "addq $32,%0\n"
                "cmpq %2,%1\n"
                "jb 1b\n"
                "vzeroall\n"
        : "=r"(dst), "=r"(sit), "=r"(send)
        : "0"(dst), "1"(sit), "2"(send)
        : "%ymm0", "memory"
        );
    }
}

void FFT_Processor_Spqlios::execute_reverse_torus32(double *res, const Torus32 *a) {
    int32_t *aa = (int32_t *) a;
    //for (int32_t i=0; i<N; i++) real_inout_rev[i]=aa[i]; //we do not rescale
    //ifft(tables_reverse,real_inout_rev);
    //for (int32_t i=0; i<N; i++) res[i]=real_inout_rev[i];
    execute_reverse_int(res, aa);
}

void FFT_Processor_Spqlios::execute_direct(double *res,const double *a){
    //TODO: parallelization
    static const double _2sN = double(2) / double(N);
    //for (int32_t i=0; i<N; i++) real_inout_direct[i]=a[i]*_2sn;
    {
        double *dst = real_inout_direct;
        const double *sit = a;
        const double *send = a + N;
        //double __2sN = 2./N;
        const double *bla = &_2sN;
        __asm__ __volatile__ (
        "vbroadcastsd (%3),%%ymm2\n"
                "1:\n"
                "vmovupd (%1),%%ymm0\n"
                "vmulpd	%%ymm2,%%ymm0,%%ymm0\n"
                "vmovapd %%ymm0,(%0)\n"
                "addq $32,%1\n"
                "addq $32,%0\n"
                "cmpq %2,%1\n"
                "jb 1b\n"
        : "=r"(dst), "=r"(sit), "=r"(send), "=r"(bla)
        : "0"(dst), "1"(sit), "2"(send), "3"(bla)
        : "%ymm0", "%ymm2", "memory"
        );
    }
    fft(tables_direct, real_inout_direct);
    for (int32_t i = 0; i < N; i++) res[i] = real_inout_direct[i];
    {
        double *dst = res;
        double *sit = real_inout_direct;
        double *send = real_inout_direct + N;
        __asm__ __volatile__ (
        "1:\n"
                "vmovapd (%1),%%ymm0\n"
                "vmovupd %%ymm0,(%0)\n"
                "addq $32,%1\n"
                "addq $32,%0\n"
                "cmpq %2,%1\n"
                "jb 1b\n"
                "vzeroall\n"
        : "=r"(dst), "=r"(sit), "=r"(send)
        : "0"(dst), "1"(sit), "2"(send)
        : "%ymm0", "memory"
        );
    }
}


void FFT_Processor_Spqlios::execute_direct_torus32(Torus32 *res, const double *a) {
    //TODO: parallelization
    static const double _2sN = double(2) / double(N);
    //for (int32_t i=0; i<N; i++) real_inout_direct[i]=a[i]*_2sn;
    {
        double *dst = real_inout_direct;
        const double *sit = a;
        const double *send = a + N;
        //double __2sN = 2./N;
        const double *bla = &_2sN;
        __asm__ __volatile__ (
        "vbroadcastsd (%3),%%ymm2\n"
                "1:\n"
                "vmovupd (%1),%%ymm0\n"
                "vmulpd	%%ymm2,%%ymm0,%%ymm0\n"
                "vmovapd %%ymm0,(%0)\n"
                "addq $32,%1\n"
                "addq $32,%0\n"
                "cmpq %2,%1\n"
                "jb 1b\n"
        : "=r"(dst), "=r"(sit), "=r"(send), "=r"(bla)
        : "0"(dst), "1"(sit), "2"(send), "3"(bla)
        : "%ymm0", "%ymm2", "memory"
        );
    }
    fft(tables_direct, real_inout_direct);
    for (int32_t i = 0; i < N; i++) res[i] = Torus32(int64_t(real_inout_direct[i]));
}

FFT_Processor_Spqlios::~FFT_Processor_Spqlios() {
    delete (tables_direct);
    delete (tables_reverse);
}

