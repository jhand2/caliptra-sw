// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{self, APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::{
    mailbox_api::{CommandId, MailboxReq, MailboxReqHeader, StashMeasurementReq},
    RomBootStatus,
};
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_runtime::RtBootStatus;
use zerocopy::AsBytes;

use crate::common::run_rt_test;

#[test]
fn test_standard() {
    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None, None, None);

    model
        .step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();
}

#[test]
fn test_boot() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::BOOT), None, None);

    model.step_until_exit_success().unwrap();
}

#[test]
fn test_fw_version() {
    let mut model = run_rt_test(None, None, None);
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let fw_rev = model.soc_ifc().cptra_fw_rev_id().read();
    assert_eq!(fw_rev[0], 0xaaaaaaaa);
    assert_eq!(fw_rev[1], 0xbbbbbbbb);
}

#[test]
fn test_update() {
    let image_options = ImageOptions {
        app_version: 0xaabbccdd,
        ..Default::default()
    };
    // Make image to update to. On the FPGA this needs to be done before executing the test,
    // otherwise the test will fail because processor is too busy building to be able to respond to
    // the TRNG call during the initial boot.
    let image =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap()
            .to_bytes()
            .unwrap();

    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();

    model
        .step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();

    let fw_rev = model.soc_ifc().cptra_fw_rev_id().read();
    assert_eq!(fw_rev[0], 0xaaaaaaaa);
    assert_eq!(fw_rev[1], 0xaabbccdd);
}

#[test]
fn test_boot_tci_data() {
    let mut model = run_rt_test(Some(&firmware::runtime_tests::MBOX), None, None);

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

    // hash expected DPE measurements in order
    let measurements_to_be_hashed = [rt_journey_pcr, valid_pauser_hash].concat();
    let expected_measurement_hash = model
        .mailbox_execute(0x4000_0000, measurements_to_be_hashed.as_bytes())
        .unwrap()
        .unwrap();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash, dpe_measurement_hash);
}

#[test]
fn test_measurement_in_measurement_log_added_to_dpe() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions::default(),
    )
    .unwrap();

    // Upload measurement to measurement log
    let measurement: [u8; 48] = [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap();
    let mut measurement_log_entry = MailboxReq::StashMeasurement(StashMeasurementReq {
        measurement,
        hdr: MailboxReqHeader { chksum: 0 },
        metadata: [0xAB; 4],
        context: [0xCD; 48],
        svn: 0xEF01,
    });
    measurement_log_entry.populate_chksum().unwrap();

    model
        .upload_measurement(measurement_log_entry.as_bytes().unwrap())
        .unwrap();

    model
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    model.step_until_boot_status(u32::from(RomBootStatus::ColdResetComplete), true);

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

    // hash expected DPE measurements in order
    let measurements_to_be_hashed = [rt_journey_pcr, valid_pauser_hash, measurement].concat();
    let expected_measurement_hash = model
        .mailbox_execute(0x4000_0000, measurements_to_be_hashed.as_bytes())
        .unwrap()
        .unwrap();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash, dpe_measurement_hash);
}
