#include "spqlios-fft.h"
#include <array>

extern "C" {
    typedef struct {
       FFT_Processor_Spqlios impl;
    } SpqliosImpl;

    SpqliosImpl* Spqlios_new(const int32_t N) {
        FFT_Processor_Spqlios *spqlios = new FFT_Processor_Spqlios(N);
        return (SpqliosImpl *)spqlios;
    }

    void Spqlios_destructor(SpqliosImpl *si) {
        si->impl.~FFT_Processor_Spqlios();
    }

    void Spqlios_ifft(SpqliosImpl *si, double *res, const double *src){
        si->impl.execute_reverse(res,src);
    }

    void Spqlios_ifft_u32(SpqliosImpl *si, double *res, const uint32_t *src) {
        si->impl.execute_reverse_torus32(res, src);
    }

    void Spqlios_ifft_i32(SpqliosImpl *si, double *res, const int32_t *src){
        si->impl.execute_reverse_int(res,src);
    }

    void Spqlios_fft(SpqliosImpl *si, double *res, const double *src){
        si->impl.execute_direct(res,src);
    }

    void Spqlios_fft_u32(SpqliosImpl *si, uint32_t *res, const double *src) {
        si->impl.execute_direct_torus32(res, src);
    }

    void Spqlios_poly_mul(SpqliosImpl *si, uint32_t *res, const uint32_t *src_a, const uint32_t *src_b) {
        double tmp_a[si->impl.N];
        double tmp_b[si->impl.N];
        Spqlios_ifft_u32(si, tmp_a, src_a);
        Spqlios_ifft_u32(si, tmp_b, src_b);

        const int Ns2 = si->impl.Ns2;
        for (int i=0;i<Ns2;i++){
            double aimbim = tmp_a[i + Ns2] * tmp_b[i + Ns2];
            double arebim = tmp_a[i] * tmp_b[i + Ns2];
            tmp_a[i] = tmp_a[i] * tmp_b[i] - aimbim;
            tmp_a[i + Ns2] = tmp_a[i + Ns2] * tmp_b[i] + arebim;
        }

        Spqlios_fft_u32(si, res, tmp_a);
    }
}