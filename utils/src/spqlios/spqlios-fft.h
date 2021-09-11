#pragma once
#include <stdint.h>

extern "C" {

void *new_fft_table(int32_t nn);
double *fft_table_get_buffer(const void *tables);
void *new_ifft_table(int32_t nn);
double *ifft_table_get_buffer(const void *tables);
void fft_model(const void *tables);
void ifft_model(void *tables);
void fft(const void *tables, double *data);
void ifft(const void *tables, double *data);
}

typedef uint32_t Torus32;

class FFT_Processor_Spqlios {
 public:
  const int32_t _2N;
  const int32_t N;
  const int32_t Ns2;

 private:
  double *real_inout_direct;
  double *imag_inout_direct;
  double *real_inout_rev;
  double *imag_inout_rev;
  void *tables_direct;
  void *tables_reverse;

 public:

  FFT_Processor_Spqlios(const int32_t N);

  void execute_reverse(double *res,const double *a);

  void execute_reverse_int(double *res, const int32_t *a);

  void execute_reverse_torus32(double *res, const Torus32 *a);

  void execute_direct(double *res,const double *a);

  void execute_direct_torus32(Torus32 *res, const double *a);

  ~FFT_Processor_Spqlios();
};
