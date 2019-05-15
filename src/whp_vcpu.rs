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

use std::io;
pub use whp_vcpu_structs::*;
pub use win_hv_platform_defs::*;
pub use win_hv_platform_defs_internal::*;
pub use x86_64::XsaveArea;
pub use common::*;

use platform::VirtualProcessor;
use vmm_vcpu::vcpu::{Vcpu, VcpuExit, Result as VcpuResult};
use vmm_vcpu::x86_64::{FpuState, MsrEntries, SpecialRegisters, StandardRegisters,
                       LapicState, CpuId, MsrEntry};


impl Vcpu for VirtualProcessor {

    type RunContextType = WHV_RUN_VP_EXIT_CONTEXT;

    fn get_run_context(&self) -> WHV_RUN_VP_EXIT_CONTEXT {
        self.last_exit_context()
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn get_regs(&self) -> VcpuResult<StandardRegisters> {
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
    fn set_regs(&self, regs: &StandardRegisters) -> VcpuResult<()> {
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

    fn get_sregs(&self) -> VcpuResult<SpecialRegisters> {
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

    fn set_sregs(&self, sregs: &SpecialRegisters) -> VcpuResult<()> {
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

    fn get_fpu(&self) -> VcpuResult<FpuState>{
        let mut fregs: WinFpuRegisters = Default::default();

        // Get the registers from the vCPU
        self.get_registers(&fregs.names, &mut fregs.values)
            .map_err(|_| io::Error::last_os_error())?;

        // Perform the conversion from these fields to FpuState fields
        let fpu_state: FpuState = ConvertFpuState::to_portable(&fregs);

        Ok(fpu_state)
    }

    fn set_fpu(&self, fpu: &FpuState) -> VcpuResult<()> {
        let fregs: WinFpuRegisters = ConvertFpuState::from_portable(&fpu);

        self.set_registers(&fregs.names, &fregs.values)
            .map_err(|_| io::Error::last_os_error()).unwrap();
        Ok(())
    }

    /// x86-specific call to setup the CPUID registers.
    /// 
    /// Unimplemented in WHP because it is not possible to do this from the vCPU
    /// level.
    /// 
    /// CPUID results _can_ be set on a partition level, however, this must be
    /// done via WHvSetPartitionProperty, which itself must be called after
    /// before WHvSetupPartition. Since
    /// a vCPU cannot be created (via WHvCreateVirtualProcessor) until
    /// after WHvSetupPartition finalizes partition properties, it is impossible
    /// to call WHvSetPartitionProperty after a vCPU has been created. In other
    /// words, the mandatory order of operations is:
    /// - WHvCreatePartition
    /// - WHvSetPartitionProperty (which can optionally set the
    ///   WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeCpuidResultList 
    ///   property)
    /// - WHvSetupPartition
    /// - WHvCreateVirtualProcessor
    /// 
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_cpuid2(&self, _cpuid: &CpuId) -> VcpuResult<()> {

        unimplemented!();

        /*
        let mut cpuid_results: Vec<WHV_X64_CPUID_RESULT> = Vec::new();

        for entry in _cpuid.as_entries_slice().iter() {
            let mut cpuid_result: WHV_X64_CPUID_RESULT = Default::default();
            cpuid_result.Function = entry.function;
            cpuid_result.Eax = entry.eax;
            cpuid_result.Ebx = entry.ebx;
            cpuid_result.Ecx = entry.ecx;
            cpuid_result.Edx = entry.edx;

            cpuid_results.push(cpuid_result);
        }

        self.set_cpuid_results_on_partition(&cpuid_results).unwrap();
        */

        return Ok(())
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msrs(&self, msrs: &mut MsrEntries) -> VcpuResult<i32> {
        let mut msr_names: Vec<WHV_REGISTER_NAME> = Vec::new();
        let mut msr_values: Vec<WHV_REGISTER_VALUE> = Vec::new();

        let num_msrs = msrs.nmsrs as usize;

        // Translate each MSR index into its corresponding MSR NAME
        unsafe {
            for entry in msrs.entries.as_slice(num_msrs).iter() {
                let reg_name = WHV_REGISTER_NAME::from_portable(entry.index).unwrap();
                msr_names.push(reg_name);

                // Push a corresponding blank MSR Value to the value array
                let reg_value: WHV_REGISTER_VALUE = Default::default();
                msr_values.push(reg_value);
            }
        }

        // Get the MSR values
        self.get_registers(&msr_names, &mut msr_values)
            .map_err(|_| io::Error::last_os_error())?;
        
        // Now re-insert the returned MSR data in the original MsrEntries
        unsafe {
            for (idx, entry) in msrs.entries.as_mut_slice(num_msrs).iter_mut().enumerate() {
                entry.data = msr_values[idx].Reg64;
            }
        }

        Ok(num_msrs as i32)
    }

    fn set_msrs(&self, msrs: &MsrEntries) -> VcpuResult<()> {

        let mut msr_names: Vec<WHV_REGISTER_NAME> = Vec::new();
        let mut msr_values: Vec<WHV_REGISTER_VALUE> = Vec::new();

        unsafe {
            for entry in msrs.entries.as_slice(msrs.nmsrs as usize).iter() {
                let reg_name = WHV_REGISTER_NAME::from_portable(entry.index).unwrap();
                msr_names.push(reg_name);

                let mut reg_value: WHV_REGISTER_VALUE = Default::default();
                reg_value.Reg64 = entry.data;
                msr_values.push(reg_value);
            }
        }

        self.set_registers(&msr_names, &msr_values)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

    fn run(&self) -> VcpuResult<VcpuExit> {
        let exit_context: WHV_RUN_VP_EXIT_CONTEXT = self.do_run().unwrap();

        let exit_reason = 
            match exit_context.ExitReason {
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonNone => VcpuExit::None,
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

    fn get_lapic(&self) -> VcpuResult<LapicState> {
        let state: LapicState = self.get_lapic_state()
                    .map_err(|_| io::Error::last_os_error())?;
        Ok(state)
    }

    fn set_lapic(&self, klapic: &LapicState) -> VcpuResult<()> {
        self.set_lapic_state(klapic)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub use platform::Partition;
    use vmm_vcpu::x86_64::{CpuIdEntry2, msr_index};
    use common::*;
    pub use std::*;

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

    #[ignore]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_set_cpuid2() {
        const CPUID_EXT_HYPERVISOR: UINT32 = 1 << 31;

        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();

        // Create a VCPU array
        let mut cpuid = CpuId::new(0);
        cpuid.push(CpuIdEntry2 {
            function: 1,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: CPUID_EXT_HYPERVISOR,
            edx: 0,
            padding: [0, 0, 0]
        }).unwrap();

        vp.set_cpuid2(&cpuid).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_set_and_get_msrs() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();

        let entries = [
            MsrEntry {
                index: 0x174,
                reserved: 0,
                data: 25
            },
            MsrEntry {
                index: msr_index::MSR_IA32_SYSENTER_EIP,
                reserved: 0,
                data: 7890
            }
        ];
        let array_len = entries.len();

        // Create a vector large enough to hold the MSR entry defined above in a
        // MsrEntries structure
        let entries_bytes = array_len * mem::size_of::<MsrEntry>();
        let msrs_vec: Vec<u8> =
            Vec::with_capacity(mem::size_of::<MsrEntries>() + entries_bytes);
        let msrs: &mut MsrEntries = unsafe {
            &mut *(msrs_vec.as_ptr() as *mut MsrEntries)
        };

        // Set the number of entries
        msrs.nmsrs = array_len as u32;

        // Copy the entries into the vector
        unsafe {
            let src = &entries as *const MsrEntry as *const u8;
            let dst = msrs.entries.as_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(src, dst, entries_bytes);
        }

        unsafe {
            assert_eq!(
                msrs.entries.as_slice(array_len)[0].index,
                0x174,
                "Failure converting/copying MSR entry[0].index");
            assert_eq!(
                msrs.entries.as_slice(array_len)[0].data,
                25,
                "Failure converting/copying MSR entry[0].data");
            assert_eq!(
                msrs.entries.as_slice(array_len)[1].index,
                msr_index::MSR_IA32_SYSENTER_EIP,
                "Failure converting/copying MSR entry[1].index");
            assert_eq!(
                msrs.entries.as_slice(array_len)[1].data,
                7890,
                "Failure converting/copying MSR entry[1].data");
        }

        vp.set_msrs(msrs).unwrap();

        // Now test getting the data back
        let out_entries = [
            MsrEntry {
                index: 0x174,
                ..Default::default()
            },
            MsrEntry {
                index: msr_index::MSR_IA32_SYSENTER_EIP,
                ..Default::default()
            }
        ];

        // Create a vector large enough to hold the MSR entry defined above in a
        // MsrEntries structure
        let out_entries_bytes = out_entries.len() * mem::size_of::<MsrEntry>();
        let out_msrs_vec: Vec<u8> =
            Vec::with_capacity(mem::size_of::<MsrEntries>() + out_entries_bytes);
        let mut out_msrs: &mut MsrEntries = unsafe {
            &mut *(out_msrs_vec.as_ptr() as *mut MsrEntries)
        };

        // Set the number of entries
        out_msrs.nmsrs = out_entries.len() as u32;

        // Copy the entries into the vector
        unsafe {
            let src = &out_entries as *const MsrEntry as *const u8;
            let dst = out_msrs.entries.as_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(src, dst, out_entries_bytes);
        }

        vp.get_msrs(&mut out_msrs).unwrap();

        assert_eq!(msrs.nmsrs, out_msrs.nmsrs, "Mismatch between number of get and set MSRs");

        unsafe {
            let num_msrs = msrs.nmsrs as usize;
            for (idx, entry) in msrs.entries.as_slice(num_msrs).iter().enumerate() {
                let out_entry = out_msrs.entries.as_slice(num_msrs)[idx];
                println!("entry[{}]: {:?}", idx, entry);
                println!("out_entry[{}]: {:?}", idx, out_entry);
                assert_eq!(
                    entry.index, 
                    out_entry.index, 
                    "MSR index gotten from vCPU did not match input"
                );
                assert_eq!(
                    entry.data, 
                    out_entry.data, 
                    "MSR data gotten from vCPU did not match input"
                );
            }
        }
    }
}