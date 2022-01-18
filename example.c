#include "bignum.h"

int main() {
    struct bignum a;
    initBnHex(&a, "987af893e98def9c87ca098b09f80e9d09c24", 1);
    struct bignum b;
    initBnHex(&b, "98f72e93c090bad09c98eb213b4987ebd98c09a00d0be0f", 1);
    struct bignum out;

    mulBnBn(a, b, &out);

    printBn(out, false);
}