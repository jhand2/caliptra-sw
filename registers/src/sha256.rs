// Licensed under the Apache-2.0 license.
//
// generated by caliptra_registers_generator with rtl-caliptra repo at 30c7b76fffbc3f0a0b0c124b2c08b2bcfc263253
//
#![allow(clippy::erasing_op)]
#![allow(clippy::identity_op)]
#[derive(Clone, Copy)]
pub struct RegisterBlock(*mut u32);
impl RegisterBlock {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    pub unsafe fn new(ptr: *mut u32) -> Self {
        Self(ptr)
    }
    pub fn sha256_reg() -> Self {
        unsafe { Self::new(0x10028000 as *mut u32) }
    }
    /// Two 32-bit read-only registers repereseting of the name
    /// of SHA256 component. These registers are located at
    /// SHA256_base_address + 0x0000_0000 and 0x0000_0004 addresses.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn name(&self) -> ureg::Array<2, ureg::RegRef<crate::sha256::meta::Name>> {
        unsafe { ureg::Array::new(self.0.wrapping_add(0 / core::mem::size_of::<u32>())) }
    }
    /// Two 32-bit read-only registers repereseting of the version
    /// of SHA256 component. These registers are located at
    /// SHA256_base_address + 0x0000_0008 and 0x0000_000C addresses.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn version(&self) -> ureg::Array<2, ureg::RegRef<crate::sha256::meta::Version>> {
        unsafe { ureg::Array::new(self.0.wrapping_add(8 / core::mem::size_of::<u32>())) }
    }
    /// One 3-bit register including the following flags:
    /// bit #0: INIT : Trigs the SHA256 core to start the
    ///                processing for the first padded message block.
    /// bit #1: NEXT: ​Trigs the SHA256 core to start the
    ///                processing for the remining padded message block.
    /// bit #2: MODE : Indicates the SHA256 core to set dynamically
    ///                 the type of hashing algorithm. This can be:
    ///                 0 for SHA256/224
    ///                 1 for SHA256
    /// This register is located at SHA256_base_address + 0x0000_0010
    /// After each software write, hardware will erase the register.
    ///
    /// Read value: [`sha256::regs::CtrlReadVal`]; Write value: [`sha256::regs::CtrlWriteVal`]
    pub fn ctrl(&self) -> ureg::RegRef<crate::sha256::meta::Ctrl> {
        unsafe { ureg::RegRef::new(self.0.wrapping_add(0x10 / core::mem::size_of::<u32>())) }
    }
    /// One 2-bit register including the following flags:
    /// bit #0: READY : ​Indicates if the core is ready to take
    ///                a control command and process the block.  
    /// bit #1: Valid: ​Indicates if the process is done and the
    ///                hash value stored in DIGEST registers is valid.
    /// This register is located at SHA256_base_address + 0x0000_0018.
    ///
    /// Read value: [`sha256::regs::StatusReadVal`]; Write value: [`sha256::regs::StatusWriteVal`]
    pub fn status(&self) -> ureg::RegRef<crate::sha256::meta::Status> {
        unsafe { ureg::RegRef::new(self.0.wrapping_add(0x18 / core::mem::size_of::<u32>())) }
    }
    /// 16 32-bit registers storing the 512-bit padded input.
    /// These registers are located at SHA256_base_address +
    /// 0x0000_0080 to 0x0000_00BC in big-endian representation.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn block(&self) -> ureg::Array<16, ureg::RegRef<crate::sha256::meta::Block>> {
        unsafe { ureg::Array::new(self.0.wrapping_add(0x80 / core::mem::size_of::<u32>())) }
    }
    /// 8 32-bit registers storing the 256-bit digest output.
    /// These registers are located at SHA256_base_address +
    /// 0x0000_0100 to 0x0000_011C in big-endian representation.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn digest(&self) -> ureg::Array<8, ureg::RegRef<crate::sha256::meta::Digest>> {
        unsafe { ureg::Array::new(self.0.wrapping_add(0x100 / core::mem::size_of::<u32>())) }
    }
}
pub mod regs {
    //! Types that represent the values held by registers.
    #[derive(Clone, Copy)]
    pub struct CtrlWriteVal(u32);
    impl CtrlWriteVal {
        /// Control init command bit
        #[inline(always)]
        pub fn init(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
        /// Control next command bit
        #[inline(always)]
        pub fn next(self, val: bool) -> Self {
            Self((self.0 & !(1 << 1)) | (u32::from(val) << 1))
        }
        /// Control mode command bits
        #[inline(always)]
        pub fn mode(self, val: bool) -> Self {
            Self((self.0 & !(1 << 2)) | (u32::from(val) << 2))
        }
    }
    impl From<u32> for CtrlWriteVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<CtrlWriteVal> for u32 {
        fn from(val: CtrlWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct StatusReadVal(u32);
    impl StatusReadVal {
        /// Status ready bit
        #[inline(always)]
        pub fn ready(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Status valid bit
        #[inline(always)]
        pub fn valid(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
        }
    }
    impl From<u32> for StatusReadVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<StatusReadVal> for u32 {
        fn from(val: StatusReadVal) -> u32 {
            val.0
        }
    }
}
pub mod enums {
    //! Enumerations used by some register fields.
    pub mod selector {}
}
pub mod meta {
    //! Additional metadata needed by ureg.
    #[derive(Clone, Copy)]
    pub struct Name();
    impl ureg::RegType for Name {
        type Raw = u32;
    }
    impl ureg::ReadableReg for Name {
        type ReadVal = u32;
    }
    #[derive(Clone, Copy)]
    pub struct Version();
    impl ureg::RegType for Version {
        type Raw = u32;
    }
    impl ureg::ReadableReg for Version {
        type ReadVal = u32;
    }
    #[derive(Clone, Copy)]
    pub struct Ctrl();
    impl ureg::RegType for Ctrl {
        type Raw = u32;
    }
    impl ureg::WritableReg for Ctrl {
        type WriteVal = crate::sha256::regs::CtrlWriteVal;
    }
    impl ureg::ResettableReg for Ctrl {
        const RESET_VAL: Self::Raw = 0;
    }
    #[derive(Clone, Copy)]
    pub struct Status();
    impl ureg::RegType for Status {
        type Raw = u32;
    }
    impl ureg::ReadableReg for Status {
        type ReadVal = crate::sha256::regs::StatusReadVal;
    }
    #[derive(Clone, Copy)]
    pub struct Block();
    impl ureg::RegType for Block {
        type Raw = u32;
    }
    impl ureg::WritableReg for Block {
        type WriteVal = u32;
    }
    impl ureg::ResettableReg for Block {
        const RESET_VAL: Self::Raw = 0;
    }
    #[derive(Clone, Copy)]
    pub struct Digest();
    impl ureg::RegType for Digest {
        type Raw = u32;
    }
    impl ureg::ReadableReg for Digest {
        type ReadVal = u32;
    }
}
