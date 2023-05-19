use crate::RuntimeErr;
use caliptra_drivers::{CaliptraResult, DataVault};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, FmcAliasCertTbs, LocalDevIdCertTbs};

extern "C" {
    static mut LDEVID_TBS_ORG: u8;
    static mut FMCALIAS_TBS_ORG: u8;
}

enum CertType {
    LDevId,
    FmcAlias,
}

/// Copy LDevID certificate produced by ROM to `cert` buffer
///
/// Returns the number of bytes written to `cert`
pub fn copy_ldevid_cert(cert: &mut [u8]) -> CaliptraResult<usize> {
    cert_from_dccm(cert, CertType::LDevId)
}

/// Copy FMC Alias certificate produced by ROM to `cert` buffer
///
/// Returns the number of bytes written to `cert`
pub fn copy_fmc_alias_cert(cert: &mut [u8]) -> CaliptraResult<usize> {
    cert_from_dccm(cert, CertType::FmcAlias)
}

/// Copy a certificate from `dccm_offset`, append signature, and write the
/// output to `cert`.
fn cert_from_dccm(cert: &mut [u8], cert_type: CertType) -> CaliptraResult<usize> {
    let data_vault = DataVault::default();
    let (tbs, sig) = match cert_type {
        CertType::LDevId => {
            let tbs = unsafe {
                let ptr = &mut LDEVID_TBS_ORG as *mut u8;
                core::slice::from_raw_parts_mut(ptr, LocalDevIdCertTbs::TBS_TEMPLATE_LEN)
            };

            (tbs, data_vault.ldev_dice_signature())
        }
        CertType::FmcAlias => {
            let tbs = unsafe {
                let ptr = &mut FMCALIAS_TBS_ORG as *mut u8;
                core::slice::from_raw_parts_mut(ptr, FmcAliasCertTbs::TBS_TEMPLATE_LEN)
            };

            (tbs, data_vault.fmc_dice_signature())
        }
    };

    // DataVault returns a different type than CertBuilder accepts
    let bldr_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };
    let Some(builder) = Ecdsa384CertBuilder::new(tbs, &bldr_sig) else {
        return Err(RuntimeErr::InsufficientMemory.into());
    };

    let Some(size) = builder.build(cert) else {
        return Err(RuntimeErr::InsufficientMemory.into());
    };

    Ok(size)
}
