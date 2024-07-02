#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef int fixed;

/*Fixed-point real number operation*/
/*Implemented according to the pintos document*/
/*Using macro definitions, which is faster than function*/

/*Decimals*/
#define frac 14

/*int to fixed-point*/
#define itf(n) ((n) << frac)
/*fixed-point to int*/
#define fti(x) ((x) / (1 << frac))
/*fixed-point to int and round*/
#define ftiround(x) (((x) + (1 << (frac - 1)) - ((x) < 0)) >> frac)

/*Operations of fixed-point */
#define fixed_add(x, y) ((x) + (y))
#define fixed_sub(x, y) ((x) - (y))
#define fixed_mul(x, y) ((int)(((long long int)(x)) * (y) / (1 << frac)))
#define fixed_div(x, y) ((int)((((long long int)(x)) << frac) / (y)))

/*Operations of fixed-point and int*/
#define fixed_int_add(x, n) ((x) + itf((n)))
#define fixed_int_sub(x, n) ((x) - itf((n)))
#define fixed_int_mul(x, n) ((x) * (n))
#define fixed_int_div(x, n) ((x) / (n))

#endif /**< threads/fixed-point.h */
