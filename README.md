# Bignum headerfile
## bignum.h
Simple headerfile for bignum. Decimals not supported.

example.c provided to show sample multiplication operation.

## Current functions
### Init functions
 * initBn(struct bignum* bn, uint number[], int highestWord, int sign);
 * initBnUll(struct bignum* bn, ullong number, int sign);
 * initBnHex(struct bignum* bn, char hex[], int sign);

### Print functions
 * printBits(size_t const size, void const* const ptr, bool blocks);
 * printBn(struct bignum bn, bool blocks);

### Compare functions
 * compareBn(struct bignum a, struct bignum b);
 * compareBnIgnoreSize(struct bignum a, struct bignum b);

### Simple bit manipulation functions
 * flipBitBn(struct bignum a, int bitIndex, struct bignum *out);
 * shiftBn(struct bignum a, int shift, struct bignum* out);
 * bitShiftBn(struct bignum a, int shift, struct bignum* out);

### Logic bit manipulation functions
 * orBnBn(struct bignum a, struct bignum b, struct bignum* out);
 * andBnBn(struct bignum a, struct bignum b, struct bignum* out);
 * xorBnBn(struct bignum a, struct bignum b, struct bignum* out);

### Arithmetic functions
 * addBnBn(struct bignum a, struct bignum b, struct bignum* out);
 * subBnBn(struct bignum a, struct bignum b, struct bignum* out);
 * mulBnBn(struct bignum a, struct bignum b, struct bignum* out);
 * divBnBn(struct bignum a, struct bignum b, struct bignum* out, struct bignum* remainder);

### Complex math functions
 * modBnBn(struct bignum a, struct bignum b, struct bignum* out);
 * gcdBn(struct bignum a, struct bignum b, struct bignum* d, struct bignum* x, struct bignum* y);
 * modExponentiation(struct bignum base, struct bignum exponent, struct bignum modulus, struct bignum* out);