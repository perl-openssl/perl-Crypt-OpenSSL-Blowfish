#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/blowfish.h>

//=======================================================
// 
// hexdump.xs:
// https://gist.github.com/mcnewton/14322391d50240ec9ebf
//
// Matthew Newton @mcnewton 
// See hexdump.xs for LICENSE information
//=======================================================

//#define INCLUDE_HEXDUMP
#ifdef INCLUDE_HEXDUMP
#include "hexdump.xs"
#endif

//================================================
// 
// Macro to swap from little endian to big endian
//
// Calling it twice will undo the swap
//
//================================================
# undef n2l
# define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24L, \
                         l|=((unsigned long)(*((c)++)))<<16L, \
                         l|=((unsigned long)(*((c)++)))<< 8L, \
                         l|=((unsigned long)(*((c)++))))

//================================================
// 
// Macro to swap from big endian to little endian
// 
//================================================
# undef l2n
# define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                         *((c)++)=(unsigned char)(((l)     )&0xff))

//===========================================
// 
// ensure_hv(SV *sv, const char *identifier)
// 
// Helper function Taken from p5-Git-Raw
// to ensure that a value is a hash.  It is 
// used to verify that the 'options' passed
// in the constructor is valid
//
//===========================================
STATIC HV *ensure_hv(SV *sv, const char *identifier) {
    if (!SvROK(sv) || SvTYPE(SvRV(sv)) != SVt_PVHV)
    croak("Invalid type for '%s', expected a hash", identifier);

    return (HV *) SvRV(sv);
}

//======================================================================
// 
// swap_endian(const unsigned char *in, unsigned char *out, STRLEN len)
// 
// Swap the endianness of the block of data in 'in'.  This is only
// required for compatability with the original version of
// Crypt::OpenSSL::Blowfish.  Which calls BF_encrypt and BF_decrypt
// without switching to big endian first.  This function is called if
// Crypt::OpenSSL::Blowfish is created without any options (other than
// the key).
//
//========================================================================
void * swap_endian(const unsigned char *in, unsigned char *out, STRLEN len)
{

    BF_LONG l, d[2];

    n2l(in, l);
    d[0] = l;
    n2l(in, l);
    d[1] = l;
    if(sizeof(out) >= sizeof(d))
        memcpy(out, d, sizeof(d));
    l = d[0] = d[1] = 0;
}

static const MGVTBL ks_magic = { NULL, NULL, NULL, NULL, NULL };

MODULE = Crypt::OpenSSL::Blowfish PACKAGE = Crypt::OpenSSL::Blowfish PREFIX = blowfish_
PROTOTYPES: DISABLE

#=============================================
# 
# blowfish_new(class, key_sv, ...)
# 
# Instantiate the BF_KEY and add it to the 
# object
#
#=============================================
SV *
blowfish_new(class, key_sv, ...)
    const char * class
    SV *  key_sv
PREINIT:
        SV *ks = newSV(0);
        IV mod = 1;
        STRLEN keysize;
        unsigned char * key;
        BF_KEY *bf_ks;
        HV * options = NULL;
        HV * attributes;
        SV *modern = newSV(0);
        //SV **svp;
        //SV * cipher;
CODE:
    {
        HV * options = newHV();
        if (items > 2)
            options = ensure_hv(ST(2), "options");

        if (!SvPOK (key_sv))
            croak("Key must be a scalar");

        key     = (unsigned char *) SvPVbyte_nolen(key_sv);
        keysize = SvCUR(key_sv);

        if (keysize != 8 && keysize !=16 && keysize != 24 && keysize != 32)
            croak ("The key must be 64, 128, 192 or 256 bits long");

        // Allocate memory to hold the Blowfish BF_KEY object
        Newx(bf_ks, 1, BF_KEY);

        BF_set_key(bf_ks, keysize, key);

        //hexdump(stdout, (unsigned char *) bf_ks, sizeof(BF_KEY), 16, 8);

        //printf("New pointer: %p\n", bf_ks);
        //printf("New INT of pointer %lu\n", (unsigned long) PTR2IV(bf_ks));

        attributes = newHV();
        SV *const self = newRV( (SV *)attributes );

        sv_magicext(ks, NULL, PERL_MAGIC_ext,
            &ks_magic, (const char *) bf_ks, 0);

        if((hv_store(attributes, "ks", 2, ks, 0)) == NULL)
            croak("unable to store the BF_KEY");

        if (items > 2) {
            sv_magicext(modern, NULL, PERL_MAGIC_ext,
                &ks_magic, (const char *) mod, 0);

            if((hv_store(attributes, "modern", 6, modern, 0)) == NULL)
                croak("unable to store the modern");
        }

        RETVAL = sv_bless( self, gv_stashpv( class, 0 ) );
    }
OUTPUT:
    RETVAL

#=============================================
# 
# blowfish_crypt(self, data_sv, dir)
# 
# Crypt/Decrypt the data depending on the dir
#
#=============================================
SV * blowfish_crypt(self, data_sv, dir)
    HV * self
    SV * data_sv
    int dir
    PREINIT:
        STRLEN data_len;
        STRLEN key_len;
        unsigned char * data;
        unsigned char out[BF_BLOCK];
        MAGIC* mg;
        SV **svp;
        int *modern = 0;
        BF_KEY *bf_ks = NULL;
    CODE:
    {
        if (hv_exists(self, "modern", strlen("modern"))) {
            svp = hv_fetch(self, "modern", strlen("modern"), 0);
            if (!SvMAGICAL(*svp) || (mg = mg_findext(*svp, PERL_MAGIC_ext, &ks_magic)) == NULL)
                croak("STORE is invalid");
            modern = (int *) mg->mg_ptr;
        }

        data = (unsigned char *) SvPVbyte(data_sv,data_len);
        if (!modern)
            swap_endian(data, data, data_len);
        //hexdump(stdout, data, data_len, 16, 8);

        if (!hv_exists(self, "ks", strlen("ks")))
            croak("ks not found in self!\n");

        svp = hv_fetch(self, "ks", strlen("ks"), 0);

        if (!SvMAGICAL(*svp) || (mg = mg_findext(*svp, PERL_MAGIC_ext, &ks_magic)) == NULL)
            croak("STORE is invalid");

        bf_ks = (BF_KEY *) mg->mg_ptr;

        //printf("Crypt pointer: %p\n", bf_ks);
        //printf("Crypt INT of pointer %lu\n", (unsigned long) PTR2IV(bf_ks));

        //hexdump(stdout, bf_ks, sizeof(BF_KEY), 16, 8);
        if (data_len != BF_BLOCK) {
            croak("data must be 8 bytes long");
        }

        //ecb_encrypt(data, out, bf_ks, dir);
        BF_ecb_encrypt(data, out, bf_ks, dir);
        if (!modern)
            swap_endian(out, out, data_len);

        //hexdump(stdout, out, sizeof(char)*8, 16, 8);

        RETVAL = newSV (data_len);
        SvPOK_only (RETVAL);
        SvCUR_set (RETVAL, data_len);
        sv_setpvn(RETVAL, out, data_len);

    }
    OUTPUT:
        RETVAL

#===========================================
# 
# blowfish_DESTROY(self)
# 
# Free the BF_KEY as the module is unloaded
#
#===========================================
void
blowfish_DESTROY(self)
    HV *self
PREINIT:
    SV **svp;
    BF_KEY *bf_ks = NULL;
    MAGIC* mg;
CODE:
    if (!hv_exists(self, "ks", strlen("ks")))
        croak("ks not found in self!\n");

    svp = hv_fetch(self, "ks", strlen("ks"), 0);

    if (!SvMAGICAL(*svp) || (mg = mg_findext(*svp, PERL_MAGIC_ext, &ks_magic)) == NULL)
        croak("STORE is invalid");

    bf_ks = (BF_KEY *) mg->mg_ptr;
    //printf("Crypt pointer: %p\n", bf_ks);
    //printf("Crypt INT of pointer %lu\n", (unsigned long) PTR2IV(bf_ks));

    Safefree(bf_ks);
