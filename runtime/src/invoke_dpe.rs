// Licensed under the Apache-2.0 license

use crate::{CaliptraCrypto, CaliptraEnv, CaliptraPlatform, Drivers, InvokeDpeCmd, InvokeDpeResp};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

const INVOKE_DPE_LOCALITY: u32 = 0x30020004;

/// Handle the `INVOKE_DPE_COMMAND` mailbox command
pub(crate) fn handle_invoke_dpe_command<'a>(
    drivers: &mut Drivers,
    cmd_args: &[u8],
) -> CaliptraResult<InvokeDpeResp> {
    if let Some(cmd) = InvokeDpeCmd::read_from(cmd_args) {
        let mut response_buf = [0u8; 4096];
        let mut env = CaliptraEnv {
            crypto: CaliptraCrypto::new(&mut drivers.sha384),
            platform: CaliptraPlatform,
        };
        match drivers
            .dpe
            .execute_serialized_command(&mut env, INVOKE_DPE_LOCALITY, &cmd.data)
        {
            Ok(resp) => {
                let serialized_resp = resp.as_bytes();
                response_buf.copy_from_slice(&serialized_resp);
                Ok(InvokeDpeResp {
                    chksum: cmd.chksum,
                    size: serialized_resp.len() as u32,
                    data: response_buf,
                })
            }
            _ => Err(CaliptraError::RUNTIME_INVOKE_DPE_FAILED),
        }
    } else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }
}
