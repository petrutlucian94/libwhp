// Copyright 2018 Cloudbase Solutions Srl
// Copyright 2018-2019 CrowdStrike, Inc.
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

use common::*;
use std::io;
pub use whp_vcpu_structs::*;
pub use win_hv_platform_defs::*;
pub use win_hv_platform_defs_internal::*;
pub use x86_64::XsaveArea;

use platform::{Partition, VirtualProcessor};
use vmm_vcpu::vcpu::{Vcpu, VcpuExit};
use vmm_vcpu::x86_64::{FpuState, MsrEntries, SpecialRegisters, StandardRegisters,
                       LapicState, CpuId};
impl Vcpu for VirtualProcessor {

    type RunContextType = WHV_RUN_VP_EXIT_CONTEXT;

    fn get_run_context(&self) -> WHV_RUN_VP_EXIT_CONTEXT {
        self.last_exit_context()
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn get_regs(&self) -> Result<StandardRegisters, io::Error> {
        let mut win_regs: WinStandardRegisters = Default::default();

        self.get_registers(&win_regs.names, &mut win_regs.values)
            .map_err(|_| io::Error::last_os_error())?;

        unsafe {
            Ok(StandardRegisters {
                rax: win_regs.values[WinStandardRegIndex::Rax as usize].Reg64,
                rbx: win_regs.values[WinStandardRegIndex::Rbx as usize].Reg64,
                rcx: win_regs.values[WinStandardRegIndex::Rcx as usize].Reg64,
                rdx: win_regs.values[WinStandardRegIndex::Rdx as usize].Reg64,

                rsi: win_regs.values[WinStandardRegIndex::Rsi as usize].Reg64,
                rdi: win_regs.values[WinStandardRegIndex::Rdi as usize].Reg64,
                rsp: win_regs.values[WinStandardRegIndex::Rsp as usize].Reg64,
                rbp: win_regs.values[WinStandardRegIndex::Rbp as usize].Reg64,

                r8: win_regs.values[WinStandardRegIndex::R8 as usize].Reg64,
                r9: win_regs.values[WinStandardRegIndex::R9 as usize].Reg64,
                r10: win_regs.values[WinStandardRegIndex::R10 as usize].Reg64,
                r11: win_regs.values[WinStandardRegIndex::R11 as usize].Reg64,
                r12: win_regs.values[WinStandardRegIndex::R12 as usize].Reg64,
                r13: win_regs.values[WinStandardRegIndex::R13 as usize].Reg64,
                r14: win_regs.values[WinStandardRegIndex::R14 as usize].Reg64,
                r15: win_regs.values[WinStandardRegIndex::R15 as usize].Reg64,

                rip: win_regs.values[WinStandardRegIndex::Rip as usize].Reg64,
                rflags: win_regs.values[WinStandardRegIndex::Rflags as usize].Reg64,
            })
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn set_regs(&self, regs: &StandardRegisters) -> Result<(), io::Error> {
        let mut win_regs: WinStandardRegisters = Default::default();

        win_regs.values[WinStandardRegIndex::Rax as usize].Reg64 = regs.rax;
        win_regs.values[WinStandardRegIndex::Rbx as usize].Reg64 = regs.rbx;
        win_regs.values[WinStandardRegIndex::Rcx as usize].Reg64 = regs.rcx;
        win_regs.values[WinStandardRegIndex::Rdx as usize].Reg64 = regs.rdx;

        win_regs.values[WinStandardRegIndex::Rsi as usize].Reg64 = regs.rsi;
        win_regs.values[WinStandardRegIndex::Rdi as usize].Reg64 = regs.rdi;
        win_regs.values[WinStandardRegIndex::Rsp as usize].Reg64 = regs.rsp;
        win_regs.values[WinStandardRegIndex::Rbp as usize].Reg64 = regs.rbp;

        win_regs.values[WinStandardRegIndex::R8 as usize].Reg64 = regs.r8;
        win_regs.values[WinStandardRegIndex::R9 as usize].Reg64 = regs.r9;
        win_regs.values[WinStandardRegIndex::R10 as usize].Reg64 = regs.r10;
        win_regs.values[WinStandardRegIndex::R11 as usize].Reg64 = regs.r11;
        win_regs.values[WinStandardRegIndex::R12 as usize].Reg64 = regs.r12;
        win_regs.values[WinStandardRegIndex::R13 as usize].Reg64 = regs.r13;
        win_regs.values[WinStandardRegIndex::R14 as usize].Reg64 = regs.r14;
        win_regs.values[WinStandardRegIndex::R15 as usize].Reg64 = regs.r15;

        win_regs.values[WinStandardRegIndex::Rip as usize].Reg64 = regs.rip;
        win_regs.values[WinStandardRegIndex::Rflags as usize].Reg64 = regs.rflags;

        self.set_registers(&win_regs.names, &win_regs.values)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

    fn get_sregs(&self) -> Result<SpecialRegisters, io::Error> {
        let mut win_sregs: WinSpecialRegisters = Default::default();

        self.get_registers(&win_sregs.names, &mut win_sregs.values)
            .map_err(|_| io::Error::last_os_error())?;

        unsafe {
            Ok(SpecialRegisters {
                cs: win_sregs.values[WinSpecialRegIndex::Cs as usize].Segment.to_portable(),
                ds: win_sregs.values[WinSpecialRegIndex::Ds as usize].Segment.to_portable(),
                es: win_sregs.values[WinSpecialRegIndex::Es as usize].Segment.to_portable(),
                fs: win_sregs.values[WinSpecialRegIndex::Fs as usize].Segment.to_portable(),
                gs: win_sregs.values[WinSpecialRegIndex::Gs as usize].Segment.to_portable(),
                ss: win_sregs.values[WinSpecialRegIndex::Ss as usize].Segment.to_portable(),
                tr: win_sregs.values[WinSpecialRegIndex::Tr as usize].Segment.to_portable(),

                ldt: win_sregs.values[WinSpecialRegIndex::Ldt as usize].Segment.to_portable(),
                gdt: win_sregs.values[WinSpecialRegIndex::Gdt as usize].Table.to_portable(),
                idt: win_sregs.values[WinSpecialRegIndex::Idt as usize].Table.to_portable(),
                cr0: win_sregs.values[WinSpecialRegIndex::Cr0 as usize].Reg64,
                cr2: win_sregs.values[WinSpecialRegIndex::Cr2 as usize].Reg64,
                cr3: win_sregs.values[WinSpecialRegIndex::Cr3 as usize].Reg64,
                cr4: win_sregs.values[WinSpecialRegIndex::Cr4 as usize].Reg64,
                cr8: win_sregs.values[WinSpecialRegIndex::Cr8 as usize].Reg64,
                efer: win_sregs.values[WinSpecialRegIndex::Efer as usize].Reg64,
                apic_base: win_sregs.values[WinSpecialRegIndex::ApicBase as usize].Reg64,
                interrupt_bitmap: [
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                ],
            })
        }
    }

    fn set_sregs(&self, sregs: &SpecialRegisters) -> Result<(), io::Error> {
        let mut win_sregs: WinSpecialRegisters = Default::default();
        win_sregs.values[WinSpecialRegIndex::Cs as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.cs);

        win_sregs.values[WinSpecialRegIndex::Ds as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ds);

        win_sregs.values[WinSpecialRegIndex::Es as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.es);

        win_sregs.values[WinSpecialRegIndex::Fs as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.fs);

        win_sregs.values[WinSpecialRegIndex::Gs as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.gs);

        win_sregs.values[WinSpecialRegIndex::Ss as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ss);

        win_sregs.values[WinSpecialRegIndex::Tr as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.tr);

        win_sregs.values[WinSpecialRegIndex::Ldt as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ldt);

        win_sregs.values[WinSpecialRegIndex::Gdt as usize].Table =
            WHV_X64_TABLE_REGISTER::from_portable(&sregs.gdt);

        win_sregs.values[WinSpecialRegIndex::Idt as usize].Table =
            WHV_X64_TABLE_REGISTER::from_portable(&sregs.idt);

        win_sregs.values[WinSpecialRegIndex::Cr0 as usize].Reg64 = sregs.cr0;
        win_sregs.values[WinSpecialRegIndex::Cr2 as usize].Reg64 = sregs.cr2;
        win_sregs.values[WinSpecialRegIndex::Cr3 as usize].Reg64 = sregs.cr3;
        win_sregs.values[WinSpecialRegIndex::Cr4 as usize].Reg64 = sregs.cr4;
        win_sregs.values[WinSpecialRegIndex::Cr8 as usize].Reg64 = sregs.cr8;
        win_sregs.values[WinSpecialRegIndex::Efer as usize].Reg64 = sregs.efer;
        win_sregs.values[WinSpecialRegIndex::ApicBase as usize].Reg64 = sregs.apic_base;

        self.set_registers(&win_sregs.names, &win_sregs.values)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

    fn get_fpu(&self) -> Result<FpuState, io::Error>{
        let mut fregs: WinFpuRegisters = Default::default();

        self.get_registers(&fregs.names, &mut fregs.values)
            .map_err(|_| io::Error::last_os_error())?;

        let mut fpu: FpuState = Default::default();

        // Add the fields from the FP Control Status Register
        let fcs_reg: WHV_X64_FP_CONTROL_STATUS_REGISTER;
        unsafe {
            fcs_reg = fregs.values[WinFpRegIndex::Fcs as usize].FpControlStatus;
        };
        fcs_reg.add_fields_to_state(&mut fpu);

        // Add the fields from the XMM Control Status Register
        let xcs_reg: WHV_X64_XMM_CONTROL_STATUS_REGISTER;
        unsafe {
            xcs_reg = fregs.values[WinFpRegIndex::Xcs as usize].XmmControlStatus;
        };
        xcs_reg.add_fields_to_state(&mut fpu);

        // Add the 16 XMM Regs
        for idx in 0..16 {
            // TODO: Add these
        }
        // Add the 7 FP MMX Regs
        //gdt: win_sregs.values[WinSpecialRegIndex::Gdt as usize].Table.to_portable(),

        /*
        unsafe {
            Ok(FpuState {
                fcw: reg_values[0].Reg64 as UINT16,
                mxcsr: reg_values[1].Reg64 as UINT32,
                fpr[0]: reg_values[2].Reg
            })
        }
        */

        Ok(fpu)
    }

    fn set_fpu(&self, fpu: &FpuState) -> Result<(), io::Error> {
        let reg_names: [WHV_REGISTER_NAME; 4] = [
            WHV_REGISTER_NAME::WHvX64RegisterFpControlStatus,
            WHV_REGISTER_NAME::WHvX64RegisterXmmControlStatus,
            WHV_REGISTER_NAME::WHvX64RegisterXmm0,
            WHV_REGISTER_NAME::WHvX64RegisterFpMmx0,
        ];

        let mut reg_values: [WHV_REGISTER_VALUE; 4] = Default::default();
        reg_values[0].Reg64 = fpu.fcw as UINT64;
        reg_values[1].Reg64 = fpu.mxcsr as UINT64;
        reg_values[2].Fp = WHV_X64_FP_REGISTER {
            AsUINT128: WHV_UINT128 {
                Low64: 0,
                High64: 0,
            },
        };
        reg_values[3].Fp = WHV_X64_FP_REGISTER {
            AsUINT128: WHV_UINT128 {
                Low64: 0,
                High64: 0,
            },
        };
        println!("In WHP set_fpu");

        self.set_registers(&reg_names, &reg_values)
            .map_err(|_| io::Error::last_os_error()).unwrap();
        Ok(())
    }

    /// According to the Windows Hypervisor Top Level Functional Specification,
    /// the virtualized values of CPUID leaves are pre-determined (ie,
    /// per the specification, each leaf is either set, cleared, or passed-through
    /// from hardware) and cannot be configured.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_cpuid2(&self, _cpuid: &CpuId) -> Result<(), io::Error> {
        unimplemented!();
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msrs(&self, _msrs: &mut MsrEntries) -> Result<i32, io::Error> {
        Ok(0)
    }

    fn set_msrs(&self, _msrs: &MsrEntries) -> Result<(), io::Error> {
        // Need to create a mapping between arch_gen indices of MSRs and the
        // MSRs that WHV exposes. Each mapping will consist of a tuple of
        // the MSR index and the WHV register name. Non-supported MSRs should
        // be empty/identifiabler

        let sregs: SpecialRegisters = Default::default();
        self.set_sregs(&sregs)?;
        println!("In WHP set_msrs");
        Ok(())
    }
    fn run(&self) -> Result<VcpuExit, io::Error> {
        let exit_context: WHV_RUN_VP_EXIT_CONTEXT = self.do_run().unwrap();

        let exit_reason = 
            match exit_context.ExitReason {
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonNone => VcpuExit::Unknown,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess => VcpuExit::MemoryAccess,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess => VcpuExit::IoPortAccess,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonUnrecoverableException => {
                    VcpuExit::UnrecoverableException
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonInvalidVpRegisterValue => {
                    VcpuExit::InvalidVpRegisterValue
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonUnsupportedFeature => {
                    VcpuExit::UnsupportedFeature
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64InterruptWindow => {
                    VcpuExit::IrqWindowOpen
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Halt => VcpuExit::Hlt,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64ApicEoi => VcpuExit::IoapicEoi,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64MsrAccess => VcpuExit::MsrAccess,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Cpuid => VcpuExit::Cpuid,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonException => VcpuExit::Exception,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonCanceled => VcpuExit::Canceled,
            };

        Ok(exit_reason)
    }

    fn get_lapic(&self) -> Result<LapicState, io::Error> {
        let state: LapicState = self.get_lapic_state()
                    .map_err(|_| io::Error::last_os_error())?;
        Ok(state)
    }

    fn set_lapic(&self, klapic: &LapicState) -> Result<(), io::Error> {
        self.set_lapic_state(klapic)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_vcpu_test(p: &mut Partition) {
        let mut property: WHV_PARTITION_PROPERTY = Default::default();
        property.ProcessorCount = 1;

        p.set_property(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
            &property,
        )
        .unwrap();
        p.setup().unwrap();
    }

    #[test]
    fn test_set_get_vcpu_regs() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();

        let std_regs_in = StandardRegisters {
            rax: 0xabcd0000abcd0000,
            rbx: 0xabcd0000abcd0001,
            rcx: 0xabcd0000abcd0002,
            rdx: 0xabcd0000abcd0003,
            rsi: 0xabcd0000abcd0004,
            rdi: 0xabcd0000abcd0005,
            rsp: 0xabcd0000abcd0006,
            rbp: 0xabcd0000abcd0007,
            r8: 0xabcd0000abcd0008,
            r9: 0xabcd0000abcd0009,
            r10: 0xabcd0000abcd000a,
            r11: 0xabcd0000abcd000b,
            r12: 0xabcd0000abcd000c,
            r13: 0xabcd0000abcd000d,
            r14: 0xabcd0000abcd000e,
            r15: 0xabcd0000abcd000f,
            rip: 0xabcd0000abcd0010,
            rflags: 0xabcd0000abcd0011,
        };

        vp.set_regs(&std_regs_in).unwrap();
        let std_regs_out = vp.get_regs().unwrap();

        assert_eq!(
            std_regs_in, std_regs_out,
            "StandardRegister values set and gotten do not match"
        );
    }

    #[test]
    fn test_set_get_vcpu_sregs() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();

        // Get the initial set of special registers
        let mut sregs = vp.get_sregs().unwrap();

        // Make some modifications to them
        sregs.cs.limit = 0xffff;
        sregs.ds.limit = 0xffff;
        sregs.es.limit = 0xffff;
        sregs.fs.limit = 0xffff;
        sregs.gs.limit = 0xffff;
        sregs.ss.limit = 0xffff;
        sregs.gdt.base = 0xa000;
        sregs.gdt.limit = 0xff;
        sregs.idt.base = 0xb000;
        sregs.idt.limit = 0xff;
        sregs.apic_base = 0xa0000000;

        // Set the modified values
        vp.set_sregs(&sregs).unwrap();
        let std_regs_out = vp.get_sregs().unwrap();

        assert_eq!(
            sregs, std_regs_out,
            "SpecialRegister values set and gotten do not match"
        );
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use std;

    #[test]
    fn test_create_delete_partition() {
        println!("CreateDeletePartition");
        let p: Partition = Partition::new().unwrap();
        drop(p);
    }

    #[test]
    fn test_delete_partition_panic() {
        let result = std::panic::catch_unwind(|| {
            // Create an invalid partition
            let _p = Partition {
                partition: Rc::new(RefCell::new(PartitionHandle {
                    handle: std::ptr::null_mut(),
                })),
            };
        });
        assert!(result.is_err(), "Drop was suppoesed to panic");
    }

    #[test]
    fn test_get_capability() {
        let _capability: WHV_CAPABILITY =
            get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeHypervisorPresent).unwrap();
    }

    #[test]
    fn test_set_get_partition_property() {
        let mut p: Partition = Partition::new().unwrap();
        let property_code = WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount;
        let mut property: WHV_PARTITION_PROPERTY = Default::default();
        property.ProcessorCount = 1;

        p.set_property(property_code, &property).unwrap();
        let property_out = p.get_property(property_code).unwrap();

        unsafe {
            assert_eq!(
                property.ProcessorCount, property_out.ProcessorCount,
                "The property value is not matching"
            );
        }
    }

    #[test]
    fn test_set_get_partition_property_cpuid_exits() {
        let mut p: Partition = Partition::new().unwrap();
        let cpuids: [UINT32; 2] = [1, 2];

        // Getting this property is not supported
        assert_eq!(
            p.set_property_cpuid_exits(&cpuids).ok(),
            Some(()),
            "set_property_cpuid_exits failed"
        );
    }

    #[test]
    fn test_set_get_partition_property_cpuid_results() {
        const CPUID_EXT_HYPERVISOR: UINT32 = 1 << 31;
        let mut p: Partition = Partition::new().unwrap();
        let mut cpuid_results: Vec<WHV_X64_CPUID_RESULT> = Vec::new();
        let mut cpuid_result: WHV_X64_CPUID_RESULT = Default::default();
        cpuid_result.Function = 1;
        cpuid_result.Ecx = CPUID_EXT_HYPERVISOR;
        cpuid_results.push(cpuid_result);

        // Getting this property is not supported
        assert_eq!(
            p.set_property_cpuid_results(&cpuid_results).ok(),
            Some(()),
            "set_property_cpuid_results failed"
        );
    }

    #[test]
    fn test_setup_partition() {
        let mut p: Partition = Partition::new().unwrap();
        let mut property: WHV_PARTITION_PROPERTY = Default::default();
        property.ProcessorCount = 1;

        // Setup fails without setting at least the number of vcpus
        p.set_property(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
            &property,
        )
        .unwrap();
    }

    #[test]
    fn test_setup_partition_fail() {
        let mut p: Partition = Partition::new().unwrap();
        match p.setup() {
            Err(e) => assert_eq!(
                e.result(),
                WHV_E_INVALID_PARTITION_CONFIG,
                "Unexpected error code"
            ),
            Ok(()) => panic!("An error was expected"),
        }
    }

    fn setup_vcpu_test(p: &mut Partition) {
        let mut property: WHV_PARTITION_PROPERTY = Default::default();
        property.ProcessorCount = 1;

        p.set_property(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
            &property,
        )
        .unwrap();
        p.setup().unwrap();
    }

    #[test]
    fn test_create_delete_virtual_processor() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();
        drop(vp)
    }

    #[test]
    fn test_run_virtual_processor() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let mut vp = p.create_virtual_processor(vp_index).unwrap();
        let exit_context: WHV_RUN_VP_EXIT_CONTEXT = vp.run().unwrap();

        assert_eq!(
            exit_context.ExitReason,
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess,
            "Unexpected exit reason"
        )
    }

    #[test]
    fn test_cancel_virtual_processor() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let mut vp = p.create_virtual_processor(vp_index).unwrap();
        vp.cancel_run().unwrap();
    }

    #[test]
    #[ignore]
    fn test_set_get_virtual_processor_registers() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let mut vp = p.create_virtual_processor(vp_index).unwrap();

        const NUM_REGS: UINT32 = 1;
        const REG_VALUE: UINT64 = 11111111;
        let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
        let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();
        let mut reg_values_out: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRax;
        reg_values[0].Reg64 = REG_VALUE;

        vp.set_registers(&reg_names, &reg_values).unwrap();
        vp.get_registers(&reg_names, &mut reg_values_out).unwrap();

        unsafe {
            assert_eq!(
                reg_values_out[0].Reg64, REG_VALUE,
                "Registers values do not match"
            );
        }
    }

    #[test]
    fn test_map_gpa_range() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        const SIZE: UINT64 = 0x100000;
        let guest_address: WHV_GUEST_PHYSICAL_ADDRESS = 0;

        let mem = VirtualMemory::new(SIZE as usize).unwrap();

        let mapping = p
            .map_gpa_range(
                &mem,
                guest_address,
                SIZE,
                WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead,
            )
            .unwrap();

        assert_eq!(mapping.get_size(), SIZE);
        assert_eq!(mapping.get_source_address(), mem.as_ptr());
        assert_eq!(mapping.get_guest_address(), guest_address);
        assert_eq!(
            mapping.get_flags(),
            WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead
        );
    }

    #[test]
    fn test_translate_gva() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();

        let gva: WHV_GUEST_PHYSICAL_ADDRESS = 0;
        let (translation_result, gpa) = vp
            .translate_gva(
                gva,
                WHV_TRANSLATE_GVA_FLAGS::WHvTranslateGvaFlagValidateRead,
            )
            .unwrap();

        assert_eq!(
            translation_result.ResultCode,
            WHV_TRANSLATE_GVA_RESULT_CODE::WHvTranslateGvaResultGpaUnmapped,
            "Unexpected translation result code {:?}",
            translation_result.ResultCode
        );

        assert_eq!(gpa, 0, "Unexpected GPA value");
    }

    #[test]
    fn test_virtual_processor_index() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();

        assert_eq!(vp.index(), vp_index, "Index value not matching");
    }

    #[test]
    #[allow(unused_variables)]
    #[allow(unused_mut)]
    fn test_request_interrupt() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let mut vp = p.create_virtual_processor(vp_index).unwrap();

        let mut interrupt_control: WHV_INTERRUPT_CONTROL = Default::default();
        // TriggerMode = 0 (Edge)
        // DestinationMode = 0 (Logical)
        // InterruptType = 0x0 (Fixed)
        interrupt_control.TypeDestinationModeTriggerModeReserved = 0x000;
        interrupt_control.Destination = 0;
        interrupt_control.Vector = 0x37;
        let interrupt_control_size = std::mem::size_of::<WHV_INTERRUPT_CONTROL>() as UINT32;
        match vp.request_interrupt(&interrupt_control) {
            Err(e) => println!("Error"),
            Ok(()) => println!("Success"),
        }
    }

    #[test]
    fn test_get_set_xsave_state() {
        let mut capability_features: WHV_CAPABILITY_FEATURES;
        capability_features.AsUINT64 = 0;

        let capability: WHV_CAPABILITY =
            get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeFeatures).unwrap();
        unsafe {
            capability_features = capability.Features;
        }

        if capability_features.Xsave() != 0 {
            let mut p: Partition = Partition::new().unwrap();
            setup_vcpu_test(&mut p);

            let vp_index: UINT32 = 0;
            let vp = p.create_virtual_processor(vp_index).unwrap();

            let mut xsave_state: XsaveArea = Default::default();
            assert_eq!(xsave_state.region[7], 0);

            xsave_state = vp.get_xsave_state().unwrap();
            assert_eq!(xsave_state.region[7], 0xffff);

            vp.set_xsave_state(xsave_state).unwrap();
        }
    }

    fn initialize_apic(p: &mut Partition) -> bool {
        let capability: WHV_CAPABILITY =
            get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeFeatures).unwrap();
        let features: WHV_CAPABILITY_FEATURES = unsafe { capability.Features };
        let mut apic_enabled = false;

        if features.LocalApicEmulation() != 0 {
            let mut property: WHV_PARTITION_PROPERTY = Default::default();

            property.LocalApicEmulationMode =
                WHV_X64_LOCAL_APIC_EMULATION_MODE::WHvX64LocalApicEmulationModeXApic;

            p.set_property(
                WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeLocalApicEmulationMode,
                &property,
            )
            .unwrap();

            apic_enabled = true;
        }

        apic_enabled
    }

    use x86_64::*;
    use interrupts::*;
    #[test]
    fn test_enable_get_set_apic() {
        let mut p: Partition = Partition::new().unwrap();

        let apic_enabled = initialize_apic(&mut p);

        let mut property: WHV_PARTITION_PROPERTY = Default::default();
        property.ProcessorCount = 1;

        p.set_property(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
            &property,
        )
        .unwrap();

        p.setup().unwrap();

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();

        if apic_enabled == true {
            let state: LapicState = vp.get_lapic().unwrap();
            let icr0 = get_lapic_reg(&state, APIC_REG_OFFSET::InterruptCommand0);
            assert_eq!(icr0, 0);

            // Uses both get_lapic and set_lapic under the hood
            set_reg_in_lapic(&vp, APIC_REG_OFFSET::InterruptCommand0, 0x40);

            let state_out: LapicState = vp.get_lapic().unwrap();
            let icr0 = get_lapic_reg(&state_out, APIC_REG_OFFSET::InterruptCommand0);
            assert_eq!(icr0, 0x40);
        }
    }

    #[test]
    fn test_get_partition_counters() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;

        let mut _vp = p.create_virtual_processor(vp_index).unwrap();

        let counters: WHV_PARTITION_COUNTERS = _vp
            .get_partition_counters(WHV_PARTITION_COUNTER_SET::WHvPartitionCounterSetMemory)
            .unwrap();
        let mem_counters = unsafe { counters.MemoryCounters };

        assert_eq!(mem_counters.Mapped4KPageCount, 0);
        assert_eq!(mem_counters.Mapped2MPageCount, 0);
        assert_eq!(mem_counters.Mapped1GPageCount, 0);
    }

    #[test]
    fn test_get_processor_counters() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;

        let vp = p.create_virtual_processor(vp_index).unwrap();
        let counters: WHV_PROCESSOR_COUNTERS = vp
            .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetRuntime)
            .unwrap();
        let runtime_counters = unsafe { counters.RuntimeCounters };
        assert!(runtime_counters.TotalRuntime100ns > 0);

        let counters: WHV_PROCESSOR_COUNTERS = vp
            .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetIntercepts)
            .unwrap();
        let intercept_counters = unsafe { counters.InterceptCounters };
        assert_eq!(intercept_counters.PageInvalidations.Count, 0);

        let counters: WHV_PROCESSOR_COUNTERS = vp
            .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetEvents)
            .unwrap();
        let event_counters = unsafe { counters.EventCounters };
        assert_eq!(event_counters.PageFaultCount, 0);

        let counters: WHV_PROCESSOR_COUNTERS = vp
            .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetApic)
            .unwrap();
        let apic_counters = unsafe { counters.ApicCounters };
        assert_eq!(apic_counters.SentIpiCount, 0);
    }
}

*/