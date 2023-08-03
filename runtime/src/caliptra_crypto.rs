// Licensed under the Apache-2.0 license

use caliptra_drivers::{Csrng, KeyId, Sha384, Sha384Ctx};
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg};
use core::num::NonZeroUsize;
use crypto::{AlgLen, Crypto, CryptoError, Digest, EcdsaPub, EcdsaSig, HmacSig};

pub struct CaliptraCrypto<'a> {
    sha384: &'a mut Sha384,
}

impl<'a> CaliptraCrypto<'a> {
    pub fn new(sha384: &'a mut Sha384) -> Self {
        Self { sha384 }
    }
}

impl<'a> Crypto for CaliptraCrypto<'a> {
    type Cdi = KeyId;
    type HashCtx = Sha384Ctx;
    type PrivKey = KeyId;

    fn rand_bytes(&mut self, dst: &mut [u8]) -> Result<(), CryptoError> {
        let csrng_reg = unsafe { CsrngReg::new() };
        let entropy_src_reg = unsafe { EntropySrcReg::new() };

        let mut csrng = Csrng::new(csrng_reg, entropy_src_reg).unwrap();
        let num_words = NonZeroUsize::new(dst.len() / 4).unwrap();

        let mut i = 0;
        for src in csrng.generate(num_words).unwrap() {
            dst[i] = (src & 0xFF) as u8;
            dst[i + 1] = ((src >> 8) & 0xFF) as u8;
            dst[i + 2] = ((src >> 16) & 0xFF) as u8;
            dst[i + 3] = ((src >> 24) & 0xFF) as u8;
            i += 4;
        }
        Ok(())
    }

    fn hash_initialize(&mut self, algs: AlgLen) -> Result<Self::HashCtx, CryptoError> {
        match algs {
            AlgLen::Bit256 => Err(CryptoError::Size),
            AlgLen::Bit384 => Ok(Sha384Ctx::new()),
        }
    }

    fn hash_update(&mut self, ctx: &mut Sha384Ctx, bytes: &[u8]) -> Result<(), CryptoError> {
        self.sha384
            .update_ctx(ctx, bytes)
            .map_err(|_| CryptoError::HashError)?;
        Ok(())
    }

    fn hash_finish(&mut self, ctx: &mut Self::HashCtx) -> Result<Digest, CryptoError> {
        let digest = self
            .sha384
            .finalize_ctx(ctx)
            .map_err(|_| CryptoError::HashError)?;
        Digest::new(
            <[u8; AlgLen::Bit384.size()]>::from(digest).as_ref(),
            AlgLen::Bit384,
        )
    }

    fn derive_cdi(
        &mut self,
        _algs: AlgLen,
        _measurement: &Digest,
        _info: &[u8],
    ) -> Result<Self::Cdi, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_private_key(
        &mut self,
        _algs: AlgLen,
        _cdi: &Self::Cdi,
        _label: &[u8],
        _info: &[u8],
    ) -> Result<Self::PrivKey, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn derive_ecdsa_pub(
        &mut self,
        _algs: AlgLen,
        _priv_key: &Self::PrivKey,
    ) -> Result<EcdsaPub, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn ecdsa_sign_with_alias(
        &mut self,
        _algs: AlgLen,
        _digest: &Digest,
    ) -> Result<EcdsaSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn ecdsa_sign_with_derived(
        &mut self,
        _algs: AlgLen,
        _digest: &Digest,
        _priv_key: &Self::PrivKey,
    ) -> Result<EcdsaSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn get_ecdsa_alias_serial(
        &mut self,
        _algs: AlgLen,
        _serial: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn hmac_sign_with_derived(
        &mut self,
        _algs: AlgLen,
        _cdi: &Self::Cdi,
        _label: &[u8],
        _info: &[u8],
        _digest: &Digest,
    ) -> Result<HmacSig, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}
