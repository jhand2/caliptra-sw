// Licensed under the Apache-2.0 license

//! Send DICE certificates over the mailbox

#![no_main]
#![no_std]

use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_runtime::{dice, mailbox::Mailbox};
use caliptra_test_harness::{runtime_handlers, test_suite};

fn mbox_responder() {
    let soc_ifc = caliptra_registers::soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_flow_status().write(|w| w.ready_for_fw(true));
    let mbox = caliptra_registers::mbox::RegisterBlock::mbox_csr();

    loop {
        while !mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            // Wait for a request from the SoC.
        }
        let cmd = mbox.cmd().read();

        match cmd {
            // Send LDevID Cert
            0x1000_0000 => {
                let mut ldev = [0u8; 1024];
                dice::copy_ldevid_cert(&mut ldev).unwrap();
                Mailbox::write_response(&ldev).unwrap();
                Mailbox::set_status(MboxStatusE::DataReady);
            }
            // Send FMC Alias Cert
            0x2000_0000 => {
                let mut fmc = [0u8; 1024];
                dice::copy_fmc_alias_cert(&mut fmc).unwrap();
                Mailbox::write_response(&fmc).unwrap();
                Mailbox::set_status(MboxStatusE::DataReady);
            }
            _ => {
                mbox.status().write(|w| w.status(|w| w.cmd_failure()));
            }
        }
    }
}

test_suite! {
    mbox_responder,
}
