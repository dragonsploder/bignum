#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <stdbool.h>

/* This assert must succeed for this code to work */
//#include <assert.h>
//assert(sizeof(unsigned int) == sizeof(unsigned long long)/2);

typedef unsigned int uint;
typedef unsigned long long ullong;

#define BN_MAX_WORDS 512 
#define BN_FIRST_BIT_OF_HIGH_WORD (ullong) 0b100000000000000000000000000000000
#define BN_WORD_SIZE (sizeof(uint) * 8)

#define BN_LOWER_WORD(l) (l & UINT_MAX)
#define BN_UPPER_WORD(l) (l >> BN_WORD_SIZE)

#define BN_INDEX_OF_HIGHEST_BIT_WORD(x) (BN_WORD_SIZE - __builtin_clz(x))
#define BN_INDEX_OF_HIGHEST_BIT(x) (BN_INDEX_OF_HIGHEST_BIT_WORD(x.number[x.highestWord]) + x.highestWord * BN_WORD_SIZE)

#define BN_IS_ZERO(x) (x.number[0] == 0 && x.highestWord == 0)
#define BN_IS_ONE(x) (x.number[0] == 1 && x.highestWord == 0)

/*********************************************************************************************************\
 *  Each bignum represents a number by encoding it as an array of base 2^32 (uint) digits called words.  *
 *  number[0] is the first, or lowest word, and number[highestWord] is the last, or highest word.        *
 *  sign can be either 1 or -1 to denote positive or negative numbers respectively.                      *
\*********************************************************************************************************/
struct bignum {
    uint number[BN_MAX_WORDS];
    int highestWord;
    int sign;
};

/* Useful pre-initalized bignums */
struct bignum emptyBn = {{0}, 0, 1};
struct bignum oneBn = {{1}, 0, 1};


/*********************************************************************************************************\
 * All functions follow the pattern of value args: inputs & reference args: outputs                      *
\*********************************************************************************************************/

/* Bignum initialization functions */
extern void initBn(struct bignum* bn, uint number[], int highestWord, int sign);
extern void initBnUll(struct bignum* bn, ullong number, int sign);
extern void initBnHex(struct bignum* bn, char hex[], int sign);

/* Print functions */
extern void printBits(size_t const size, void const* const ptr, bool blocks);
extern void printBn(struct bignum bn, bool blocks);

/* Compare functions */
extern int  compareBn(struct bignum a, struct bignum b);
extern bool compareBnIgnoreSize(struct bignum a, struct bignum b);

/* Simple bit manipulation functions */
extern void flipBitBn(struct bignum a, int bitIndex, struct bignum *out);
extern void shiftBn(struct bignum a, int shift, struct bignum* out);
extern void bitShiftBn(struct bignum a, int shift, struct bignum* out);

/* Logic bit manipulation functions */
extern void orBnBn(struct bignum a, struct bignum b, struct bignum* out);
extern void andBnBn(struct bignum a, struct bignum b, struct bignum* out);
extern void xorBnBn(struct bignum a, struct bignum b, struct bignum* out);

/* Arithmetic functions which ignore sign of bignum (not typically used by user) */
extern void addBnBnNS(struct bignum a, struct bignum b, struct bignum* out);
extern void subBnBnNS(struct bignum a, struct bignum b, struct bignum* out);
extern void mulBnBnNS(struct bignum a, struct bignum b, struct bignum* out);
extern void divBnBnNS(struct bignum a, struct bignum b, struct bignum* out, struct bignum* remainder);

/* Arithmetic functions */
extern void addBnBn(struct bignum a, struct bignum b, struct bignum* out);
extern void subBnBn(struct bignum a, struct bignum b, struct bignum* out);
extern void mulBnBn(struct bignum a, struct bignum b, struct bignum* out);
extern void divBnBn(struct bignum a, struct bignum b, struct bignum* out, struct bignum* remainder);

/* Complex math functions */
extern void modBnBn(struct bignum a, struct bignum b, struct bignum* out);
extern void gcdBn(struct bignum a, struct bignum b, struct bignum* d, struct bignum* x, struct bignum* y);
extern void modExponentiation(struct bignum base, struct bignum exponent, struct bignum modulus, struct bignum* out);


/*********************************************************************************************************\
 * initBn initializes a bignum with an array of words.                                                   *
\*********************************************************************************************************/
void initBn(struct bignum* bn, uint number[], int highestWord, int sign) {
    (*bn) = emptyBn;

    for (int i = 0; i < (highestWord + 1); i++) {
        bn->number[i] = number[i];
    }

    bn->highestWord = highestWord;
    bn->sign = sign;
};

/*********************************************************************************************************\
 * initBnUll initializes a bignum with an unsigned long long (ullong).                                   *
\*********************************************************************************************************/
void initBnUll(struct bignum* bn, ullong number, int sign) {
    (*bn) = emptyBn;
    bn->number[0] = (uint) BN_LOWER_WORD(number);
    bn->number[1] = (uint) BN_UPPER_WORD(number);

    if (BN_UPPER_WORD(number) == 0) {
        bn->highestWord = 0;
    } else {
        bn->highestWord = 1;
    }

    bn->sign = sign;
}   

/*********************************************************************************************************\
 * initBnHex initializes a bignum with a hex string ("0x" not included).                                 *
\*********************************************************************************************************/
void initBnHex(struct bignum* bn, char hex[], int sign) {
    (*bn) = emptyBn;
    int stringLen = strlen(hex);
    int wordLen = (stringLen / 8);
    if (wordLen % stringLen != 0 || stringLen < 8) {
        wordLen++;
    }

    for (int i = 0; i < wordLen; i++) {
        char hexSection[9];
        if (i == wordLen - 1) {
            strncpy(hexSection, hex, stringLen % 8);
            hexSection[stringLen % 8] = '\0';
        } else {
            strncpy(hexSection, &hex[stringLen - ((i + 1) * 8)], 8);
        }
        bn->number[i] = (uint) strtoul(hexSection, NULL, 16);
    }

    bn->highestWord = (wordLen - 1);
    bn->sign = sign;
}

/*********************************************************************************************************\
 * printBits is a helper function to print variable in binary.                                           *
\*********************************************************************************************************/
void printBits(size_t const size, void const* const ptr, bool blocks) {
    unsigned char *bytes = (unsigned char*) ptr;
    unsigned char byte;
    
    for (int i = (size - 1); i >= 0; i--) {
        for (int j = 7; j >= 0; j--) {
            byte = (bytes[i] >> j) & 1;
            printf("%u", byte);
        }
    }

    if (blocks) {
        printf(" ");
    }
}

/*********************************************************************************************************\
 * printBn prints a bignum in binary. If blocks is true, words will be seperated by spaces.              *
\*********************************************************************************************************/
void printBn(struct bignum bn, bool blocks) {
    if (bn.sign == -1) {
        printf("-");
    }
    for (int i = bn.highestWord; i >=0; i--) {
        printBits(sizeof(bn.number[i]), &bn.number[i], blocks);
    }
    printf("\n\n");
}


/*********************************************************************************************************\
 *  compareBn compares the size of two bignums.                                                          *
 *  Returns:                                                                                             *
 *      0: a == b                                                                                        *
 *      1: a >  b                                                                                        *
 *     -1: a <  b                                                                                        *
 *  Note: Sign of bignum is ignored                                                                      *
\*********************************************************************************************************/
int compareBn(struct bignum a, struct bignum b) {
    if (a.highestWord > b.highestWord) {
        return 1;
    } else if (a.highestWord < b.highestWord) {
        return -1;
    } else {
        if (a.number[a.highestWord] > b.number[b.highestWord]) {
            return 1; 
        } else if (a.number[a.highestWord] < b.number[b.highestWord]) {
            return -1;
        } else if (a.highestWord == 0) {
            return 0;
        } else {
            a.highestWord--;
            b.highestWord--;
            return compareBn(a, b);
        }
    }
}

/*********************************************************************************************************\
 *  compareBnIgnoreSize functions the same as compareBn, but ignores the value of highestWord in each.   *
 *  Returns:                                                                                             *
 *      true:  a == b                                                                                    *
 *      false: a != b                                                                                    *
 *  Note: Helper function not intended for use by user.                                                  *
\*********************************************************************************************************/
bool compareBnIgnoreSize(struct bignum a, struct bignum b) {
    uint highestWord = fmax(a.highestWord, b.highestWord);
    for (int i = 0; i < (highestWord + 1); i++) {
        if (a.number[i] != b.number[i]) {
            return false;
        }
    }
    return true;
}

/*********************************************************************************************************\
 *  flipBitBn flips the bit of a bignum at a specifed location.                                          *
\*********************************************************************************************************/
void flipBitBn(struct bignum a, int bitIndex, struct bignum *out) {
    (*out) = a;
    int wordBitIndex = (bitIndex / BN_WORD_SIZE);
    int wordBitIndexFine = (bitIndex % BN_WORD_SIZE);
    out->number[wordBitIndex] ^= (1 << wordBitIndexFine);

    if (out->highestWord < wordBitIndex) {
        out->highestWord = wordBitIndex;
    }
}

/*********************************************************************************************************\
 *  shiftBn shifts the words in a bignum by a specified amount.                                          *
 *  Note: shift can by positive or negative for a right or left shift respectively.                      *
\*********************************************************************************************************/
void shiftBn(struct bignum a, int shift, struct bignum *out) {
    if (shift > 0) {
        for (int i = 0; i < (a.highestWord + 1); i++) {
            a.number[(shift + a.highestWord) - i] = a.number[a.highestWord - i];
            a.number[a.highestWord - i] = 0;
        }
    } else if (shift < 0) {
        for (int i = 0; i < (a.highestWord + 1); i++) {
            a.number[i] = a.number[i + shift];
            a.number[i + shift] = 0;
        }
    }

    a.highestWord += shift;
    (*out) = a;
}

/*********************************************************************************************************\
 *  bitShiftBn shifts the bits in a bignum by a specified amount.                                        *
 *  Note: shift can by positive or negative for a right or left shift respectively.                      *
\*********************************************************************************************************/
void bitShiftBn(struct bignum a, int shift, struct bignum* out) {
    if (shift > 0) {
        (*out) = emptyBn;

        int wordShift = (shift / BN_WORD_SIZE);
        int wordShiftFine = (shift % BN_WORD_SIZE);

        for (int i = a.highestWord; i >= 0; i--) {
            ullong tmp = ((ullong) a.number[i]) << wordShiftFine;

            out->number[wordShift + i + 1] += (uint) BN_UPPER_WORD(tmp); 
            out->number[wordShift + i] += (uint) BN_LOWER_WORD(tmp);
        }

        if (out->number[wordShift + a.highestWord + 1] == 0) {
            out->highestWord = wordShift + a.highestWord;
        } else {
            out->highestWord = wordShift + a.highestWord + 1;
        }
    } else if (shift < 0) {
        (*out) = emptyBn;
        shift *= -1;

        int wordShift = (shift / BN_WORD_SIZE);
        int wordShiftFine = (shift % BN_WORD_SIZE);

        for (int i = 0; i < (a.highestWord + 1); i++) {
            ullong tmp = ((ullong) a.number[i]) << (BN_WORD_SIZE - wordShiftFine);

            if (i != 0) {
                out->number[(i - wordShift) - 1] += (uint) BN_LOWER_WORD(tmp); 
            }
            out->number[(i - wordShift)] += (uint) BN_UPPER_WORD(tmp);
        }

        if (out->number[a.highestWord - wordShift] == 0) {
            out->highestWord = a.highestWord - wordShift - 1;
        } else {
            out->highestWord = a.highestWord - wordShift;
        }
    } else {
        (*out) = a;
    }
}

/*********************************************************************************************************\
 *  orBnBn performs a logical or on the bits of a and b.                                                 *
 *  a | b = out                                                                                          *
\*********************************************************************************************************/
void orBnBn(struct bignum a, struct bignum b, struct bignum* out) {
    int highestWord = fmax(a.highestWord, b.highestWord);

    for (int i = 0; i < (highestWord + 1); i++) {
        out->number[i] = a.number[i] | b.number[i];
    }

    out->highestWord = highestWord;
}

/*********************************************************************************************************\
 *  andBnBn performs a logical and on the bits of a and b.                                               *
 *  a & b = out                                                                                          *
\*********************************************************************************************************/
void andBnBn(struct bignum a, struct bignum b, struct bignum* out) {
    int highestWord = fmax(a.highestWord, b.highestWord);

    for (int i = 0; i < (highestWord + 1); i++) {
        out->number[i] = a.number[i] & b.number[i];
    }

    out->highestWord = highestWord;
}

/*********************************************************************************************************\
 *  xorBnBn performs a logical xor on the bits of a and b.                                               *
 *  a ^ b = out                                                                                          *
\*********************************************************************************************************/
void xorBnBn(struct bignum a, struct bignum b, struct bignum* out) {
    int highestWord = fmax(a.highestWord, b.highestWord);

    for (int i = 0; i < (highestWord + 1); i++) {
        out->number[i] = a.number[i] ^ b.number[i];
    }

    out->highestWord = highestWord;
}

/*********************************************************************************************************\
 *  addBnBnNS adds a and b but ignores their sign.                                                       *
 *  Note: Helper function not intended for use by user.                                                  *
\*********************************************************************************************************/
void addBnBnNS(struct bignum a, struct bignum b, struct bignum* out) {
    (*out) = emptyBn;
    int highestWord = fmax(a.highestWord, b.highestWord);

    for (int i = 0; i < (highestWord + 1); i++) {
        ullong sum = ((ullong) a.number[i]) + ((ullong) b.number[i]) + ((ullong) out->number[i]);

        out->number[i] = BN_LOWER_WORD(sum); 
        out->number[i + 1] = BN_UPPER_WORD(sum);
    }

    if (out->number[highestWord + 1] != 0) {
        out->highestWord = highestWord + 1;
    } else {
        out->highestWord = highestWord;
    }
}

/*********************************************************************************************************\
 *  subBnBnNS subtracts b by a but ignores their sign.                                                   *
 *  Note: Helper function not intended for use by user.                                                  *
\*********************************************************************************************************/
void subBnBnNS(struct bignum a, struct bignum b, struct bignum* out) {
    (*out) = emptyBn;

    switch (compareBn(a, b)) {
        case 1: {
            break; 
        }
        case 0: {
            return;
        } 
        case -1: {
            struct bignum tmp = a;
            a = b;
            b = tmp;
            out->sign = -1;
            break;
        }
    }

    int highestWord = a.highestWord;

    ullong sub = 0;
    ullong carry = 0;

    for (int i = 0; i < (highestWord + 1); i++) {
        if (i > b.highestWord) {
            b.number[i] = 0;
        }

        if (((ullong) a.number[i]) >= (((ullong) b.number[i]) + carry)) {
            sub = ((ullong) a.number[i]) - ((ullong) b.number[i]) - carry;
            carry = 0;
        } else {
            sub = (((ullong) a.number[i]) ^ BN_FIRST_BIT_OF_HIGH_WORD) - ((ullong) b.number[i]) - carry;
            carry = 1;
        }

        out->number[i] = BN_LOWER_WORD(sub); 
    }

    for (int i = highestWord; i > 0; i--) {
        if (out->number[i] != 0) {
            out->highestWord = i;
            break;
        }
    }
}

/*********************************************************************************************************\
 *  mulBnBnNS multiplies a and b but ignores their sign.                                                 *
 *  Note: Helper function not intended for use by user.                                                  *
\*********************************************************************************************************/
void mulBnBnNS(struct bignum a, struct bignum b, struct bignum* out) {
    (*out) = emptyBn;

    for (int i = 0; i < (a.highestWord + 1); i++) {
        struct bignum section = {0};
        for (int j = 0; j < (b.highestWord + 1); j++) {
            ullong prod = (ullong) a.number[i] * (ullong) b.number[j];

            struct bignum prodShift;
            struct bignum prodBn;
            initBnUll(&prodBn, prod, 1);
            shiftBn(prodBn, j, &prodShift);

            struct bignum sectionTmp;
            addBnBn(section, prodShift, &sectionTmp);
            section = sectionTmp;
        }
        struct bignum sectionShift;
        shiftBn(section, i, &sectionShift);

        struct bignum outTmp = emptyBn;
        addBnBn(*out, sectionShift, &outTmp);
        (*out) = outTmp;
    }
}

/*********************************************************************************************************\
 *  divBnBnNS divides a by b but ignores their sign and assumes a >= b.                                  *
 *  Note: Helper function not intended for use by user.                                                  *
\*********************************************************************************************************/
void divBnBnNS(struct bignum a, struct bignum b, struct bignum* out, struct bignum* remainder) {
    (*out) = emptyBn;

    if (BN_IS_ZERO(a) || BN_IS_ZERO(b)) {
        return;
    }

    struct bignum tmp;

    int highestBitOfDivisor = (b.highestWord * BN_WORD_SIZE) + BN_INDEX_OF_HIGHEST_BIT_WORD(b.number[b.highestWord]);
    int highestBitOfDividend;

    do {
        highestBitOfDividend = (a.highestWord * BN_WORD_SIZE) + BN_INDEX_OF_HIGHEST_BIT_WORD(a.number[a.highestWord]);

        struct bignum part;
        bitShiftBn(b, highestBitOfDividend - highestBitOfDivisor, &part);

        int extraShift = 0;
        switch (compareBn(a, part)) {
            case 1: {
                subBnBn(a, part, &tmp);
                a = tmp;
                break;
            }
            case 0: {
                a = emptyBn;
                break;
            }
            case -1: {
                bitShiftBn(part, -1, &tmp);
                part = tmp;
                subBnBn(a, part, &tmp);
                a = tmp;
                extraShift = 1;
                break;
            }
        }

        tmp = (*out);
        flipBitBn(tmp, (highestBitOfDividend - highestBitOfDivisor) - extraShift, out);
    } while (compareBn(a, b) != -1);

    (*remainder) = a;
}


/*********************************************************************************************************\
 *  addBnBn adds a and b.                                                                                *
\*********************************************************************************************************/
void addBnBn(struct bignum a, struct bignum b, struct bignum* out) {
    if (a.sign == 1) {
        if (b.sign == 1) {
            addBnBnNS(a, b, out);
        } else {
            subBnBnNS(a, b, out);
        }
    } else {
        if (b.sign == 1) {
            subBnBnNS(b, a, out);
        } else {
            a.sign = 1;
            b.sign = 1;
            addBnBnNS(a, b, out);
            out->sign = -1;
        }
    }
}

/*********************************************************************************************************\
 *  subBnBn subtracts a by b.                                                                            *
\*********************************************************************************************************/
void subBnBn(struct bignum a, struct bignum b, struct bignum* out) {
    if (a.sign == 1) {
        if (b.sign == 1) {
            subBnBnNS(a, b, out);
        } else {
            addBnBnNS(a, b, out);
        }
    } else {
        if (b.sign == 1) {
            addBnBnNS(a, b, out);
            out->sign = -1;
        } else {
            subBnBnNS(b, a, out);
        }
    }
}

/*********************************************************************************************************\
 *  mulBnBn multiples a and b.                                                                           *
\*********************************************************************************************************/
void mulBnBn(struct bignum a, struct bignum b, struct bignum* out) {
    if (a.sign == 1) {
        if (b.sign == 1) {
            mulBnBnNS(a, b, out);
        } else {
            mulBnBnNS(a, b, out);
            out->sign = -1;
        }
    } else {
        if (b.sign == 1) {
            mulBnBnNS(a, b, out);
            out->sign = -1;
        } else {
            mulBnBnNS(b, a, out);
        }
    }
}

/*********************************************************************************************************\
 *  divBnBn divides a by b.                                                                              *
\*********************************************************************************************************/
void divBnBn(struct bignum a, struct bignum b, struct bignum* out, struct bignum* remainder) {
    if (compareBn(a, b) == -1) {
        *out = emptyBn;
        *remainder = a;
        return;
    }
    if (a.sign == 1) {
        if (b.sign == 1) {
            divBnBnNS(a, b, out, remainder);
        } else {
            divBnBnNS(a, b, out, remainder);
            out->sign = -1;
        }
    } else {
        if (b.sign == 1) {
            divBnBnNS(a, b, out, remainder);
            out->sign = -1;
        } else {
            divBnBnNS(b, a, out, remainder);
        }
    }
}

/*********************************************************************************************************\
 *  modBnBn mods a by b (a % b).                                                                         *
 *  Note: Currently ignores sign.                                                                        *
\*********************************************************************************************************/
void modBnBn(struct bignum a, struct bignum b, struct bignum* out) {
    struct bignum tmp;
    switch (compareBn(a, b)) {
        case 1: {
            divBnBnNS(a, b, &tmp, out);
            break;
        }
        case 0: {
            (*out) = emptyBn;
        }
        case -1: {
            (*out) = a;
        }
    }
}

/*********************************************************************************************************\
 *  gcdBn perforems the extended Euclidean algorithem.                                                   *
 *  gcd(a, b) = d = a*x + b*y                                                                            *
\*********************************************************************************************************/
void gcdBn(struct bignum a, struct bignum b, struct bignum* d, struct bignum* x, struct bignum* y) {
	struct bignum remander = b;
	struct bignum oldRemander = a;

	struct bignum s;
	initBnUll(&s, (ullong) 0, 1);
	struct bignum oldS;
	initBnUll(&oldS, (ullong) 1, 1);
	struct bignum t;
	initBnUll(&t, (ullong) 1, 1);
	struct bignum oldT;
	initBnUll(&oldT, (ullong) 0, 1);

	struct bignum tmp;
	struct bignum save;
	struct bignum div;
	struct bignum placeholder;
    
	do {
		divBnBn(oldRemander, remander, &div, &placeholder);
		// Euclidean Algorithem
		save = remander;
		mulBnBn(div, remander, &tmp);
		subBnBn(oldRemander, tmp, &remander);
		oldRemander = save;

		// Extended Euclidean Algorithem
		save = s;
		mulBnBn(div, s, &tmp);
		subBnBn(oldS, tmp, &s);
		oldS = save;

		save = t;
		mulBnBn(div, t, &tmp);
		subBnBn(oldT, tmp, &t);
		oldT = save;

	} while (compareBn(remander, emptyBn) == 1);
	
	*d = oldRemander;
	*x = oldS;
	*y = oldT;
}

/*********************************************************************************************************\
 *  modExponentiation computes base ^ exponent % modulus = ans.                                          *
\*********************************************************************************************************/
void modExponentiation(struct bignum base, struct bignum exponent, struct bignum modulus, struct bignum* out) {
	struct bignum answer = oneBn;
	struct bignum tmp = emptyBn;
	struct bignum tmp2 = emptyBn;
    
	while (!compareBnIgnoreSize(exponent, emptyBn)) {
		andBnBn(exponent, oneBn, &tmp);

		if (compareBnIgnoreSize(tmp, oneBn)) {
			mulBnBn(answer, base, &tmp);
			modBnBn(tmp, modulus, &answer);

			tmp = exponent;
			xorBnBn(tmp, oneBn, &exponent);
		}

		tmp2 = base;
		mulBnBn(base, tmp2, &tmp);
		modBnBn(tmp, modulus, &base);

		tmp = exponent;
		bitShiftBn(tmp, -1, &exponent);
	}

	modBnBn(answer, modulus, out);
}