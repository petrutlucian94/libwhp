// Copyright 2018-2019 CrowdStrike, Inc.
// Copyright 2018 Cloudbase Solutions Srl
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

pub use win_hv_platform_defs::*;
pub use win_hv_platform_defs_internal::*;
pub use x86_64::XsaveArea;

use vmm_vcpu::x86_64::{FpuState, SegmentRegister, DescriptorTable};
//use vmm_vcpu::vcpu::Result as VcpuResult;

///
/// Enumerate the index at which each register will be stored within the
/// WinStandardRegisters
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WinStandardRegIndex {
    Rax = 0x00,
    Rcx = 0x01,
    Rdx = 0x02,
    Rbx = 0x03,
    Rsp = 0x04,
    Rbp = 0x05,
    Rsi = 0x06,
    Rdi = 0x07,
    R8 = 0x08,
    R9 = 0x09,
    R10 = 0x0A,
    R11 = 0x0B,
    R12 = 0x0C,
    R13 = 0x0D,
    R14 = 0x0E,
    R15 = 0x0F,
    Rip = 0x10,
    Rflags = 0x11,
}

///
/// Create a structure to hold the corresponding arrays of the WHV_REGISTER_NAMEs
/// and WHV_REGISTER_VALUEs that comprise the StandardRegisters, with
/// WHV_REGISTER_NAMEs prepopulated on default initialization, and both arrays
/// accessible via the WinStandardRegIndex enum defined above
///
#[derive(Copy, Clone)]
pub struct WinStandardRegisters {
    pub names: [WHV_REGISTER_NAME; 18],
    pub values: [WHV_REGISTER_VALUE; 18],
}

impl Default for WinStandardRegisters {
    fn default() -> Self {
        //unsafe { ::std::mem::zeroed() }
        let mut mapping = WinStandardRegisters {
            names: Default::default(),
            values: Default::default(),
        };

        mapping.names[WinStandardRegIndex::Rax as usize] = WHV_REGISTER_NAME::WHvX64RegisterRax;
        mapping.names[WinStandardRegIndex::Rcx as usize] = WHV_REGISTER_NAME::WHvX64RegisterRcx;
        mapping.names[WinStandardRegIndex::Rdx as usize] = WHV_REGISTER_NAME::WHvX64RegisterRdx;
        mapping.names[WinStandardRegIndex::Rbx as usize] = WHV_REGISTER_NAME::WHvX64RegisterRbx;
        mapping.names[WinStandardRegIndex::Rsp as usize] = WHV_REGISTER_NAME::WHvX64RegisterRsp;
        mapping.names[WinStandardRegIndex::Rbp as usize] = WHV_REGISTER_NAME::WHvX64RegisterRbp;
        mapping.names[WinStandardRegIndex::Rsi as usize] = WHV_REGISTER_NAME::WHvX64RegisterRsi;
        mapping.names[WinStandardRegIndex::Rdi as usize] = WHV_REGISTER_NAME::WHvX64RegisterRdi;
        mapping.names[WinStandardRegIndex::R8 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR8;
        mapping.names[WinStandardRegIndex::R9 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR9;
        mapping.names[WinStandardRegIndex::R10 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR10;
        mapping.names[WinStandardRegIndex::R11 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR11;
        mapping.names[WinStandardRegIndex::R12 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR12;
        mapping.names[WinStandardRegIndex::R13 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR13;
        mapping.names[WinStandardRegIndex::R14 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR14;
        mapping.names[WinStandardRegIndex::R15 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR15;
        mapping.names[WinStandardRegIndex::Rip as usize] = WHV_REGISTER_NAME::WHvX64RegisterRip;
        mapping.names[WinStandardRegIndex::Rflags as usize] = WHV_REGISTER_NAME::WHvX64RegisterRflags;

        mapping
    }
}

///
/// Enumerate the index at which each register will be stored within the
/// WinSpecialRegisters
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WinSpecialRegIndex {
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    Ss,
    Tr,
    Ldt,
    Gdt,
    Idt,
    Cr0,
    Cr2,
    Cr3,
    Cr4,
    Cr8,
    Efer,
    ApicBase,
}

///
/// Create a structure to hold the corresponding arrays of the WHV_REGISTER_NAMEs
/// and WHV_REGISTER_VALUEs that comprise the SpecialRegisters, with
/// WHV_REGISTER_NAMEs prepopulated on default initialization, and both arrays
/// accessible via the WinSpecialRegIndex enum defined above
///
#[derive(Copy, Clone)]
pub struct WinSpecialRegisters {
    pub names: [WHV_REGISTER_NAME; 17],
    pub values: [WHV_REGISTER_VALUE; 17],
}

impl Default for WinSpecialRegisters {
    fn default() -> Self {
        //unsafe { ::std::mem::zeroed() }
        let mut mapping = WinSpecialRegisters {
            names: Default::default(),
            values: Default::default(),
        };

        mapping.names[WinSpecialRegIndex::Cs as usize] = WHV_REGISTER_NAME::WHvX64RegisterCs;
        mapping.names[WinSpecialRegIndex::Ds as usize] = WHV_REGISTER_NAME::WHvX64RegisterDs;
        mapping.names[WinSpecialRegIndex::Es as usize] = WHV_REGISTER_NAME::WHvX64RegisterEs;
        mapping.names[WinSpecialRegIndex::Fs as usize] = WHV_REGISTER_NAME::WHvX64RegisterFs;
        mapping.names[WinSpecialRegIndex::Gs as usize] = WHV_REGISTER_NAME::WHvX64RegisterGs;
        mapping.names[WinSpecialRegIndex::Ss as usize] = WHV_REGISTER_NAME::WHvX64RegisterSs;

        mapping.names[WinSpecialRegIndex::Tr as usize] = WHV_REGISTER_NAME::WHvX64RegisterTr;
        mapping.names[WinSpecialRegIndex::Ldt as usize] = WHV_REGISTER_NAME::WHvX64RegisterLdtr;
        mapping.names[WinSpecialRegIndex::Gdt as usize] = WHV_REGISTER_NAME::WHvX64RegisterGdtr;
        mapping.names[WinSpecialRegIndex::Idt as usize] = WHV_REGISTER_NAME::WHvX64RegisterIdtr;

        mapping.names[WinSpecialRegIndex::Cr0 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr0;
        mapping.names[WinSpecialRegIndex::Cr2 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr2;
        mapping.names[WinSpecialRegIndex::Cr3 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr3;
        mapping.names[WinSpecialRegIndex::Cr4 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr4;
        mapping.names[WinSpecialRegIndex::Cr8 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr8;

        mapping.names[WinSpecialRegIndex::Efer as usize] = WHV_REGISTER_NAME::WHvX64RegisterEfer;
        mapping.names[WinSpecialRegIndex::ApicBase as usize] = WHV_REGISTER_NAME::WHvX64RegisterApicBase;

        mapping
    }
}

///
/// Enumerate the index at which each register will be stored within the
/// WinFpuRegisters
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WinFpRegIndex {
    Xmm0 = 0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
    FpMmx0 = 16,
    FpMmx1,
    FpMmx2,
    FpMmx3,
    FpMmx4,
    FpMmx5,
    FpMmx6,
    FpMmx7,
    Fcs = 24,
    Xcs = 25,
}

///
/// Create a structure to hold the corresponding arrays of the WHV_REGISTER_NAMEs
/// and WHV_REGISTER_VALUEs that comprise the FpuRegisters, with
/// WHV_REGISTER_NAMEs prepopulated on default initialization, and both arrays
/// accessible via the WinFpuRegIndex enum defined above
///
#[derive(Copy, Clone)]
pub struct WinFpuRegisters {
    pub names: [WHV_REGISTER_NAME; 26],
    pub values: [WHV_REGISTER_VALUE; 26],
}

impl Default for WinFpuRegisters {
    fn default() -> Self {
        //unsafe { ::std::mem::zeroed() }
        let mut mapping = WinFpuRegisters {
            names: Default::default(),
            values: Default::default(),
        };

        mapping.names[WinFpRegIndex::Xmm0 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm0;
        mapping.names[WinFpRegIndex::Xmm1 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm1;
        mapping.names[WinFpRegIndex::Xmm2 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm2;
        mapping.names[WinFpRegIndex::Xmm3 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm3;
        mapping.names[WinFpRegIndex::Xmm4 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm4;
        mapping.names[WinFpRegIndex::Xmm5 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm5;
        mapping.names[WinFpRegIndex::Xmm6 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm6;
        mapping.names[WinFpRegIndex::Xmm7 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm7;
        mapping.names[WinFpRegIndex::Xmm8 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm8;
        mapping.names[WinFpRegIndex::Xmm9 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm9;
        mapping.names[WinFpRegIndex::Xmm10 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm10;
        mapping.names[WinFpRegIndex::Xmm11 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm11;
        mapping.names[WinFpRegIndex::Xmm12 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm12;
        mapping.names[WinFpRegIndex::Xmm13 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm13;
        mapping.names[WinFpRegIndex::Xmm14 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm14;
        mapping.names[WinFpRegIndex::Xmm15 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm15;

        // Loop over the Floating Point MMX registers
        mapping.names[WinFpRegIndex::FpMmx0 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx0;
        mapping.names[WinFpRegIndex::FpMmx1 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx1;
        mapping.names[WinFpRegIndex::FpMmx2 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx2;
        mapping.names[WinFpRegIndex::FpMmx3 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx3;
        mapping.names[WinFpRegIndex::FpMmx4 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx4;
        mapping.names[WinFpRegIndex::FpMmx5 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx5;
        mapping.names[WinFpRegIndex::FpMmx6 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx6;
        mapping.names[WinFpRegIndex::FpMmx7 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx7;

        // Fill in the remaining two control registers
        mapping.names[WinFpRegIndex::Fcs as usize] =
            WHV_REGISTER_NAME::WHvX64RegisterFpControlStatus;
        mapping.names[WinFpRegIndex::Xcs as usize] =
            WHV_REGISTER_NAME::WHvX64RegisterXmmControlStatus;

        mapping
    }
}

///
/// Trait to convert between a FpControlStatusRegister and the FpuState
/// structure
/// 
pub trait ConvertFpControlStatusRegister {
    fn add_fields_to_state(&self, fpu_state: &mut FpuState);
    fn extract_fields_from_state(&mut self, from: &FpuState);
}

impl ConvertFpControlStatusRegister for WHV_X64_FP_CONTROL_STATUS_REGISTER {
    //
    // Take an existing FpuState as input and add the fields of the 
    // FP ControlStatusRegister. x64 only.
    //
    fn add_fields_to_state(&self, fpu_state: &mut FpuState) {
        unsafe {
            fpu_state.fcw = self.anon_struct.FpControl;
            fpu_state.fsw = self.anon_struct.FpStatus;
            fpu_state.ftwx = self.anon_struct.FpTag;
            fpu_state.last_opcode = self.anon_struct.LastFpOp;
            fpu_state.last_ip = self.anon_struct.anon_union.LastFpRip;
        };
    }

    fn extract_fields_from_state(&mut self, fpu_state: &FpuState) {
        unsafe {
            self.anon_struct.FpControl = fpu_state.fcw;
            self.anon_struct.FpStatus = fpu_state.fsw;
            self.anon_struct.FpTag = fpu_state.ftwx;
            self.anon_struct.LastFpOp = fpu_state.last_opcode;
            self.anon_struct.anon_union.LastFpRip = fpu_state.last_ip;
        };
    }
}

///
/// Trait to convert between an Xmm pControlStatusRegister and the FpuState
/// structure
/// 
pub trait ConvertXmmControlStatusRegister {
    fn add_fields_to_state(&self, fpu_state: &mut FpuState);
    fn extract_fields_from_state(&mut self, from: &FpuState);
}

impl ConvertXmmControlStatusRegister for WHV_X64_XMM_CONTROL_STATUS_REGISTER {
    //
    // Take an existing FpuState as input and add the fields of the 
    // XMM ControlStatusRegister. x64 only.
    //
    fn add_fields_to_state(&self, fpu_state: &mut FpuState) {
        unsafe {
            fpu_state.last_dp = self.anon_struct.anon_union.LastFpRdp;
            fpu_state.mxcsr = self.anon_struct.XmmStatusControl;
        };
    }

    fn extract_fields_from_state(&mut self, fpu_state: &FpuState) {
        unsafe {
            self.anon_struct.anon_union.LastFpRdp = fpu_state.last_dp;
            self.anon_struct.XmmStatusControl = fpu_state.mxcsr;
        };
    }
}

pub trait ConvertSegmentRegister {
    fn to_portable(&self) -> SegmentRegister;
    fn from_portable(from: &SegmentRegister) -> Self;
}

impl ConvertSegmentRegister for WHV_X64_SEGMENT_REGISTER {
    fn to_portable(&self) -> SegmentRegister {
        SegmentRegister {
            base: self.Base,
            limit: self.Limit,
            selector: self.Selector,
            type_: self.SegmentType() as u8,
            present: self.Present() as u8,
            dpl: self.DescriptorPrivilegeLevel() as u8,
            db: self.Default() as u8,
            s: !self.NonSystemSegment() as u8,
            l: self.Long() as u8,
            g: self.Granularity() as u8,
            avl: self.Available() as u8,
            unusable: 0,
            padding: 0,
        }
    }

    fn from_portable(from: &SegmentRegister) -> WHV_X64_SEGMENT_REGISTER {
        let mut segment = WHV_X64_SEGMENT_REGISTER {
            Base: from.base,
            Limit: from.limit,
            Selector: from.selector,
            Attributes: 0,
        };

        segment.set_SegmentType(from.type_ as u16);
        segment.set_NonSystemSegment(!from.s as u16);
        segment.set_Present(from.present as u16);
        segment.set_Long(from.l as u16);
        segment.set_Granularity(from.g as u16);

        segment
    }
}

pub trait ConvertDescriptorTable {
    fn to_portable(&self) -> DescriptorTable;
    fn from_portable(from: &DescriptorTable) -> Self;
}

impl ConvertDescriptorTable for WHV_X64_TABLE_REGISTER {
    fn to_portable(&self) -> DescriptorTable {
        DescriptorTable {
            base: self.Base,
            limit: self.Limit,
            padding: self.Pad,
        }
    }

    fn from_portable(from: &DescriptorTable) -> WHV_X64_TABLE_REGISTER {
        WHV_X64_TABLE_REGISTER {
            Base: from.base,
            Limit: from.limit,
            Pad: from.padding,
        }
    }
}

///
/// Trait to convert between a UINT128 and an array of UINT8s
/// 
pub trait ConvertUint128{
    fn to_u8_array(&self) -> [u8; 16usize];
    fn from_u8_array(from: &[u8; 16usize]) -> Self;
}

impl ConvertUint128 for WHV_UINT128 {
    fn to_u8_array(&self) -> [u8; 16usize] {
        let mut array: [u8; 16usize] = Default::default();

        // Store the high bytes by shifting to put the bits in the LSB position
        // idx runs from 7..0, but we'll put them in the 15..8 slots
        for idx in (0..8).rev() {
            array[idx + 8] = (self.High64 >> (idx * 8)) as u8;
        }

        // Store the low bytes by shifting to put the bits in the LSB position
        // idx runs from 7..0, and we'll put them in the 7..0 slots
        for idx in (0..8).rev() {
            array[idx] = (self.Low64 >> (idx * 8)) as u8;
        }

        array
    }

    fn from_u8_array(from: &[u8; 16usize]) -> Self {
        let mut uint128: WHV_UINT128 = Default::default();

        // Store the high bytes by ANDing with the shifted bits
        // idx runs from 7..0, but we'll take from the top 15..0 entries
        for idx in (0..8).rev() {
            uint128.High64 |= (from[idx + 8]  << (idx * 8)) as u64;
        }

        // Store the low bytes by ANDing with the shifted bits
        // idx runs from 7..0, and we'll take from the 7..0 entries
        for idx in (0..8).rev() {
            uint128.Low64 |= (from[idx]  << (idx * 8)) as u64;
        }

        uint128
    }
    // TODO: Write tests
}

