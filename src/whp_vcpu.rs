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
use memory::*;
use std;
use std::cell::RefCell;
use std::rc::Rc;
use std::io;
use win_hv_platform::*;
pub use win_hv_platform_defs::*;
pub use win_hv_platform_defs_internal::*;
pub use x86_64::XsaveArea;

use vmm_vcpu::vcpu::{Vcpu, Fpu, MsrEntries, SpecialRegisters, VmmRegisters,
                     SegmentRegister, SegmentDescriptor, VcpuExit, LApicState,
                     CpuId};
use vmm_vcpu::vcpu::Result as VcpuResult;

pub struct WhpVcpu {
    ref_cell: RefCell<libwhp::VirtualProcessor>,
    exit_context: WHV_RUN_VP_EXIT_CONTEXT,
}

impl Drop for WhpVcpu{
    fn drop(&mut self) {
        check_result(unsafe {
            WHvDeleteVirtualProcessor(*self.partition.borrow_mut().handle(), self.index)
        })
        .unwrap();
    }
}

impl Vcpu for VirtualProcessor {

    type RunContextType = WHV_RUN_VP_EXIT_CONTEXT;

    fn get_run_context(&self) -> WHV_RUN_VP_EXIT_CONTEXT {
        return self.exit_context;
    }

    // TODO: These should do the full FPU registers
    fn get_fpu(&self) -> Result<Fpu, io::Error>{
        let reg_names: [WHV_REGISTER_NAME; 4] = [
            WHV_REGISTER_NAME::WHvX64RegisterFpControlStatus,
            WHV_REGISTER_NAME::WHvX64RegisterXmmControlStatus,
            WHV_REGISTER_NAME::WHvX64RegisterXmm0,
            WHV_REGISTER_NAME::WHvX64RegisterFpMmx0,
        ];

        let mut reg_values: [WHV_REGISTER_VALUE; 4] = Default::default();

        self.get_registers(&reg_names, &mut reg_values)
            .map_err(|_| io::Error::last_os_error())?;

        let mut fpu: Fpu = Default::default();

        unsafe {
            fpu.fcw = reg_values[0].Reg64 as UINT16;
            fpu.mxcsr = reg_values[1].Reg64 as UINT32;
            fpu.xmm[0][0] = 0;
        }

        /*
        unsafe {
            Ok(Fpu {
                fcw: reg_values[0].Reg64 as UINT16,
                mxcsr: reg_values[1].Reg64 as UINT32,
                fpr[0]: reg_values[2].Reg
            })
        }
        */

        Ok(fpu)
    }

    fn set_fpu(&self, fpu: &Fpu) -> Result<(), io::Error> {
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

        self.ref_cell
            .borrow_mut()
            .set_registers(&reg_names, &reg_values)
            .map_err(|_| io::Error::last_os_error());
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

    fn set_msrs(&self, _msrs: &MsrEntries) -> VcpuResult<()> {
        // Need to create a mapping between arch_gen indices of MSRs and the
        // MSRs that WHV exposes. Each mapping will consist of a tuple of
        // the MSR index and the WHV register name. Non-supported MSRs should
        // be empty/identifiabler

        let sregs: SpecialRegisters = Default::default();
        self.set_sregs(&sregs);
        println!("In WHP set_msrs");
        Ok(())
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn get_regs(&self) -> Result<VmmRegisters, io::Error> {
        let reg_names: [WHV_REGISTER_NAME; 18] = [
            WHV_REGISTER_NAME::WHvX64RegisterRax,    // 0
            WHV_REGISTER_NAME::WHvX64RegisterRbx,    // 1
            WHV_REGISTER_NAME::WHvX64RegisterRcx,    // 2
            WHV_REGISTER_NAME::WHvX64RegisterRdx,    // 3
            WHV_REGISTER_NAME::WHvX64RegisterRsi,    // 4
            WHV_REGISTER_NAME::WHvX64RegisterRdi,    // 5
            WHV_REGISTER_NAME::WHvX64RegisterRsp,    // 6
            WHV_REGISTER_NAME::WHvX64RegisterRbp,    // 7
            WHV_REGISTER_NAME::WHvX64RegisterR8,     // 8
            WHV_REGISTER_NAME::WHvX64RegisterR9,     // 9
            WHV_REGISTER_NAME::WHvX64RegisterR10,    // 10
            WHV_REGISTER_NAME::WHvX64RegisterR11,    // 11
            WHV_REGISTER_NAME::WHvX64RegisterR12,    // 12
            WHV_REGISTER_NAME::WHvX64RegisterR13,    // 13
            WHV_REGISTER_NAME::WHvX64RegisterR14,    // 14
            WHV_REGISTER_NAME::WHvX64RegisterR15,    // 15
            WHV_REGISTER_NAME::WHvX64RegisterRip,    // 16
            WHV_REGISTER_NAME::WHvX64RegisterRflags, // 17  ??
        ];
        let mut reg_values: [WHV_REGISTER_VALUE; 18] = Default::default();

        self.get_registers(&reg_names, &mut reg_values)
            .map_err(|_| io::Error::last_os_error())?;

        unsafe {
            Ok(VmmRegisters {
                rax: reg_values[0].Reg64,
                rbx: reg_values[1].Reg64,
                rcx: reg_values[2].Reg64,
                rdx: reg_values[3].Reg64,
                rsi: reg_values[4].Reg64,
                rdi: reg_values[5].Reg64,
                rsp: reg_values[6].Reg64,
                rbp: reg_values[7].Reg64,
                r8: reg_values[8].Reg64,
                r9: reg_values[9].Reg64,
                r10: reg_values[10].Reg64,
                r11: reg_values[11].Reg64,
                r12: reg_values[12].Reg64,
                r13: reg_values[13].Reg64,
                r14: reg_values[14].Reg64,
                r15: reg_values[15].Reg64,
                rip: reg_values[16].Reg64,
                rflags: reg_values[17].Reg64,
            })
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn set_regs(&self, regs: &VmmRegisters) -> Result<(), io::Error> {
        let reg_names: [WHV_REGISTER_NAME; 18] = [
            WHV_REGISTER_NAME::WHvX64RegisterRax,    // 0 rax
            WHV_REGISTER_NAME::WHvX64RegisterRbx,    // 1
            WHV_REGISTER_NAME::WHvX64RegisterRcx,    // 2
            WHV_REGISTER_NAME::WHvX64RegisterRdx,    // 3
            WHV_REGISTER_NAME::WHvX64RegisterRsi,    // 4
            WHV_REGISTER_NAME::WHvX64RegisterRdi,    // 5
            WHV_REGISTER_NAME::WHvX64RegisterRsp,    // 6
            WHV_REGISTER_NAME::WHvX64RegisterRbp,    // 7  ??
            WHV_REGISTER_NAME::WHvX64RegisterR8,     // 8  ??
            WHV_REGISTER_NAME::WHvX64RegisterR9,     // 9  ??
            WHV_REGISTER_NAME::WHvX64RegisterR10,    // 10
            WHV_REGISTER_NAME::WHvX64RegisterR11,    // 11
            WHV_REGISTER_NAME::WHvX64RegisterR12,    // 12
            WHV_REGISTER_NAME::WHvX64RegisterR13,    // 13
            WHV_REGISTER_NAME::WHvX64RegisterR14,    // 14
            WHV_REGISTER_NAME::WHvX64RegisterR15,    // 15
            WHV_REGISTER_NAME::WHvX64RegisterRip,    // 16
            WHV_REGISTER_NAME::WHvX64RegisterRflags, // 17  ??
        ];
        let reg_values: [WHV_REGISTER_VALUE; 18] = [
            WHV_REGISTER_VALUE { Reg64: regs.rax },    // 0: Rax
            WHV_REGISTER_VALUE { Reg64: regs.rbx },    // 1: Rbx
            WHV_REGISTER_VALUE { Reg64: regs.rcx },    // 2: Rcx
            WHV_REGISTER_VALUE { Reg64: regs.rdx },    // 3: Rdx
            WHV_REGISTER_VALUE { Reg64: regs.rsi },    // 4: Rsi
            WHV_REGISTER_VALUE { Reg64: regs.rdi },    // 5: Rdi
            WHV_REGISTER_VALUE { Reg64: regs.rsp },    // 6: Rsp
            WHV_REGISTER_VALUE { Reg64: regs.rbp },    // 7: Rbp
            WHV_REGISTER_VALUE { Reg64: regs.r8 },     // 8: R8
            WHV_REGISTER_VALUE { Reg64: regs.r9 },     // 9: R9
            WHV_REGISTER_VALUE { Reg64: regs.r10 },    // 10: R10
            WHV_REGISTER_VALUE { Reg64: regs.r11 },    // 11: R11
            WHV_REGISTER_VALUE { Reg64: regs.r12 },    // 12: R12
            WHV_REGISTER_VALUE { Reg64: regs.r13 },    // 13: R13
            WHV_REGISTER_VALUE { Reg64: regs.r14 },    // 14: R14
            WHV_REGISTER_VALUE { Reg64: regs.r15 },    // 15: R15
            WHV_REGISTER_VALUE { Reg64: regs.rip },    // 16: Rip
            WHV_REGISTER_VALUE { Reg64: regs.rflags }, // 17: Rflags
        ];

        self.set_registers(&reg_names, &reg_values)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

    fn set_sregs(&self, sregs: &SpecialRegisters) -> Result<(), io::Error> {
        let reg_names: [WHV_REGISTER_NAME; 17] = [
            WHV_REGISTER_NAME::WHvX64RegisterCs,   // 0
            WHV_REGISTER_NAME::WHvX64RegisterDs,   // 1
            WHV_REGISTER_NAME::WHvX64RegisterEs,   // 2
            WHV_REGISTER_NAME::WHvX64RegisterFs,   // 3
            WHV_REGISTER_NAME::WHvX64RegisterGs,   // 4
            WHV_REGISTER_NAME::WHvX64RegisterSs,   // 5
            WHV_REGISTER_NAME::WHvX64RegisterTr,   // 6
            WHV_REGISTER_NAME::WHvX64RegisterLdtr, // 7
            WHV_REGISTER_NAME::WHvX64RegisterGdtr, // 8
            WHV_REGISTER_NAME::WHvX64RegisterIdtr, // 9
            WHV_REGISTER_NAME::WHvX64RegisterCr0,  // 10
            WHV_REGISTER_NAME::WHvX64RegisterCr2,  // 11
            WHV_REGISTER_NAME::WHvX64RegisterCr3,  // 12
            WHV_REGISTER_NAME::WHvX64RegisterCr4,  // 13
            WHV_REGISTER_NAME::WHvX64RegisterCr8,  // 14
            WHV_REGISTER_NAME::WHvX64RegisterEfer, // 15
            WHV_REGISTER_NAME::WHvX64RegisterApicBase, // 16
                                                   //            WHV_REGISTER_NAME::WHvRegisterPendingInterruption, // 17
        ];
        let reg_values: [WHV_REGISTER_VALUE; 17] = [
            WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.cs),
            }, // 0: Cs
            WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ds),
            }, // 1: Ds
            WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.es),
            }, // 2: Es
            WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.fs),
            }, // 3: Fs
            WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.gs),
            }, // 4: Gs
            WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ss),
            }, // 5: Ss
            WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.tr),
            }, // 6: Tr
            WHV_REGISTER_VALUE {
                Segment: WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ldt),
            }, // 7: Ldtr
            WHV_REGISTER_VALUE {
                Table: WHV_X64_TABLE_REGISTER::from_portable(&sregs.gdt),
            }, // 8: Gdtr
            WHV_REGISTER_VALUE {
                Table: WHV_X64_TABLE_REGISTER::from_portable(&sregs.idt),
            }, // 9: Idtr
            WHV_REGISTER_VALUE { Reg64: sregs.cr0 }, // 10: Cr0
            WHV_REGISTER_VALUE { Reg64: sregs.cr2 }, // 11: Cr2
            WHV_REGISTER_VALUE { Reg64: sregs.cr3 }, // 12: Cr3
            WHV_REGISTER_VALUE { Reg64: sregs.cr4 }, // 13: Cr4
            WHV_REGISTER_VALUE { Reg64: sregs.cr8 }, // 14: Cr8
            WHV_REGISTER_VALUE { Reg64: sregs.efer }, // 15: Efer
            WHV_REGISTER_VALUE {
                Reg64: sregs.apic_base,
            }, // 16: ApicBase
                                                     //            WHV_REGISTER_VALUE { Reg64: Default::default() }, // 17: PendingInterruption
        ];

        self.set_registers(&reg_names, &reg_values)
            .map_err(|_| io::Error::last_os_error())?;

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
                    VcpuExit::InterruptWindow
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

    fn get_lapic(&self) -> Result<LApicState, io::Error> {
        let mut state: LApicState = Default::default();

        state = self.get_lapic_state()
                    .map_err(|_| io::Error::last_os_error())?;
        Ok(state)
    }

    fn set_lapic(&self, klapic: &LApicState) -> Result<(), io::Error> {
        self.set_lapic_state(klapic)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

    fn get_sregs(&self) -> Result<SpecialRegisters, io::Error> {
        let reg_names: [WHV_REGISTER_NAME; 18] = [
            WHV_REGISTER_NAME::WHvX64RegisterCs,               // 0
            WHV_REGISTER_NAME::WHvX64RegisterDs,               // 1
            WHV_REGISTER_NAME::WHvX64RegisterEs,               // 2
            WHV_REGISTER_NAME::WHvX64RegisterFs,               // 3
            WHV_REGISTER_NAME::WHvX64RegisterGs,               // 4
            WHV_REGISTER_NAME::WHvX64RegisterSs,               // 5
            WHV_REGISTER_NAME::WHvX64RegisterTr,               // 6
            WHV_REGISTER_NAME::WHvX64RegisterLdtr,             // 7  ??
            WHV_REGISTER_NAME::WHvX64RegisterGdtr,             // 8  ??
            WHV_REGISTER_NAME::WHvX64RegisterIdtr,             // 9  ??
            WHV_REGISTER_NAME::WHvX64RegisterCr0,              // 10
            WHV_REGISTER_NAME::WHvX64RegisterCr2,              // 11
            WHV_REGISTER_NAME::WHvX64RegisterCr3,              // 12
            WHV_REGISTER_NAME::WHvX64RegisterCr4,              // 13
            WHV_REGISTER_NAME::WHvX64RegisterCr8,              // 14
            WHV_REGISTER_NAME::WHvX64RegisterEfer,             // 15
            WHV_REGISTER_NAME::WHvX64RegisterApicBase,         // 16
            WHV_REGISTER_NAME::WHvRegisterPendingInterruption, // 17  ??
        ];
        let mut reg_values: [WHV_REGISTER_VALUE; 18] = Default::default();

        self.get_registers(&reg_names, &mut reg_values)
            .map_err(|_| io::Error::last_os_error())?;

        unsafe {
            Ok(SpecialRegisters {
                cs: reg_values[0].Segment.to_portable(),
                ds: reg_values[1].Segment.to_portable(),
                es: reg_values[2].Segment.to_portable(),
                fs: reg_values[3].Segment.to_portable(),
                gs: reg_values[4].Segment.to_portable(),
                ss: reg_values[5].Segment.to_portable(),
                tr: reg_values[6].Segment.to_portable(),
                ldt: reg_values[7].Segment.to_portable(),
                gdt: reg_values[8].Table.to_portable(),
                idt: reg_values[9].Table.to_portable(),
                cr0: reg_values[10].Reg64,
                cr2: reg_values[11].Reg64,
                cr3: reg_values[12].Reg64,
                cr4: reg_values[13].Reg64,
                cr8: reg_values[14].Reg64,
                efer: reg_values[15].Reg64,
                apic_base: reg_values[16].Reg64,
                interrupt_bitmap: [
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                ],
            })
        }
    }
}


impl VirtualProcessor {
    pub fn index(&self) -> UINT32 {
        return self.index;
    }

    pub fn do_run(&mut self) -> Result<WHV_RUN_VP_EXIT_CONTEXT, WHPError> {
        let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = Default::default();
        let exit_context_size = std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as UINT32;

        check_result(unsafe {
            WHvRunVirtualProcessor(
                *self.partition.borrow_mut().handle(),
                self.index,
                &mut exit_context as *mut _ as *mut VOID,
                exit_context_size,
            )
        })?;
        Ok(exit_context)
    }

    pub fn cancel_run(&mut self) -> Result<(), WHPError> {
        check_result(unsafe {
            WHvCancelRunVirtualProcessor(*self.partition.borrow_mut().handle(), self.index, 0)
        })?;
        Ok(())
    }

    pub fn set_registers(
        &mut self,
        reg_names: &[WHV_REGISTER_NAME],
        reg_values: &[WHV_REGISTER_VALUE],
    ) -> Result<(), WHPError> {
        let num_regs = reg_names.len();

        if num_regs != reg_values.len() {
            panic!("reg_names and reg_values must have the same length")
        }

        check_result(unsafe {
            WHvSetVirtualProcessorRegisters(
                *self.partition.borrow_mut().handle(),
                self.index,
                reg_names.as_ptr(),
                num_regs as UINT32,
                reg_values.as_ptr(),
            )
        })?;
        Ok(())
    }

    pub fn get_registers(
        &self,
        reg_names: &[WHV_REGISTER_NAME],
        reg_values: &mut [WHV_REGISTER_VALUE],
    ) -> Result<(), WHPError> {
        let num_regs = reg_names.len();

        if num_regs != reg_values.len() {
            panic!("reg_names and reg_values must have the same length")
        }

        check_result(unsafe {
            WHvGetVirtualProcessorRegisters(
                *self.partition.borrow().handle(),
                self.index,
                reg_names.as_ptr(),
                num_regs as UINT32,
                reg_values.as_mut_ptr(),
            )
        })?;
        Ok(())
    }

    pub fn translate_gva(
        &self,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        flags: WHV_TRANSLATE_GVA_FLAGS,
    ) -> Result<(WHV_TRANSLATE_GVA_RESULT, WHV_GUEST_PHYSICAL_ADDRESS), WHPError> {
        let mut gpa: WHV_GUEST_PHYSICAL_ADDRESS = 0;
        let mut translation_result: WHV_TRANSLATE_GVA_RESULT = Default::default();

        check_result(unsafe {
            WHvTranslateGva(
                *self.partition.borrow().handle(),
                self.index,
                gva,
                flags,
                &mut translation_result,
                &mut gpa,
            )
        })?;
        Ok((translation_result, gpa))
    }

    pub fn query_gpa_range_dirty_bitmap(
        &self,
        gva: WHV_GUEST_PHYSICAL_ADDRESS,
        range_size_in_bytes: UINT64,
        bitmap_size_in_bytes: UINT32,
    ) -> Result<(Box<[UINT64]>), WHPError> {
        let num_elem = bitmap_size_in_bytes / std::mem::size_of::<UINT64>() as UINT32;
        let mut bitmap: Box<[UINT64]> = vec![0; num_elem as usize].into_boxed_slice();

        check_result(unsafe {
            WHvQueryGpaRangeDirtyBitmap(
                *self.partition.borrow().handle(),
                gva,
                range_size_in_bytes,
                bitmap.as_mut_ptr(),
                bitmap_size_in_bytes,
            )
        })?;
        Ok(bitmap)
    }

    pub fn get_lapic_state(&self) -> Result<LApicState, WHPError> {
        let mut state: LApicState = Default::default();
        let mut written_size: UINT32 = 0;

        check_result(unsafe {
            WHvGetVirtualProcessorInterruptControllerState(
                *self.partition.borrow().handle(),
                self.index,
                &mut state as *mut _ as *mut VOID,
                std::mem::size_of::<LApicState>() as UINT32,
                &mut written_size,
            )
        })?;
        Ok(state)
    }

    pub fn set_lapic_state(&self, state: &LApicState) -> Result<(), WHPError> {
        check_result(unsafe {
            WHvSetVirtualProcessorInterruptControllerState(
                *self.partition.borrow().handle(),
                self.index,
                state as *const _ as *const VOID,
                std::mem::size_of::<LApicState>() as UINT32,
            )
        })?;
        Ok(())
    }

    pub fn request_interrupt(&self, interrupt: &WHV_INTERRUPT_CONTROL) -> Result<(), WHPError> {
        check_result(unsafe {
            WHvRequestInterrupt(
                *self.partition.borrow_mut().handle(),
                interrupt,
                std::mem::size_of::<WHV_INTERRUPT_CONTROL>() as UINT32,
            )
        })?;
        Ok(())
    }

    #[allow(unreachable_patterns)] // Future-proof against new WHV_PARTITION_COUNTER_SET values
    pub fn get_partition_counters(
        &self,
        partition_counter_set: WHV_PARTITION_COUNTER_SET,
    ) -> Result<(WHV_PARTITION_COUNTERS), WHPError> {
        let mut partition_counters: WHV_PARTITION_COUNTERS = Default::default();
        let mut bytes_written: UINT32 = 0;

        let buffer_size_in_bytes = match partition_counter_set {
            WHV_PARTITION_COUNTER_SET::WHvPartitionCounterSetMemory => {
                std::mem::size_of::<WHV_PARTITION_MEMORY_COUNTERS>() as UINT32
            }
            _ => panic!("Unknown partition counter set enum value"),
        };

        check_result(unsafe {
            WHvGetPartitionCounters(
                *self.partition.borrow().handle(),
                partition_counter_set,
                &mut partition_counters as *mut _ as *mut VOID,
                buffer_size_in_bytes as UINT32,
                &mut bytes_written,
            )
        })?;
        Ok(partition_counters)
    }

    #[allow(unreachable_patterns)] // Future-proof against new WHV_PROCESSOR_COUNTER_SET values
    pub fn get_processor_counters(
        &self,
        processor_counter_set: WHV_PROCESSOR_COUNTER_SET,
    ) -> Result<WHV_PROCESSOR_COUNTERS, WHPError> {
        let mut processor_counters: WHV_PROCESSOR_COUNTERS = Default::default();
        let mut bytes_written: UINT32 = 0;

        let buffer_size_in_bytes = match processor_counter_set {
            WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetRuntime => {
                std::mem::size_of::<WHV_PROCESSOR_RUNTIME_COUNTERS>()
            }
            WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetIntercepts => {
                std::mem::size_of::<WHV_PROCESSOR_INTERCEPT_COUNTERS>()
            }
            WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetEvents => {
                std::mem::size_of::<WHV_PROCESSOR_EVENT_COUNTERS>()
            }
            WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetApic => {
                std::mem::size_of::<WHV_PROCESSOR_APIC_COUNTERS>()
            }
            _ => panic!("Unknown processor counter set enum value"),
        };

        check_result(unsafe {
            WHvGetVirtualProcessorCounters(
                *self.partition.borrow().handle(),
                self.index,
                processor_counter_set,
                &mut processor_counters as *mut _ as *mut VOID,
                buffer_size_in_bytes as UINT32,
                &mut bytes_written,
            )
        })?;
        Ok(processor_counters)
    }

    pub fn get_xsave_state(&self) -> Result<(XsaveArea), WHPError> {
        let mut xsave_area: XsaveArea = Default::default();
        let mut bytes_written: UINT32 = 0;

        check_result(unsafe {
            WHvGetVirtualProcessorXsaveState(
                *self.partition.borrow().handle(),
                self.index,
                &mut xsave_area as *mut _ as *mut VOID,
                std::mem::size_of::<XsaveArea>() as UINT32,
                &mut bytes_written,
            )
        })?;
        Ok(xsave_area)
    }

    pub fn set_xsave_state(&self, xsave_area: XsaveArea) -> Result<(), WHPError> {
        check_result(unsafe {
            WHvSetVirtualProcessorXsaveState(
                *self.partition.borrow().handle(),
                self.index,
                &xsave_area as *const _ as *const VOID,
                std::mem::size_of::<XsaveArea>() as UINT32,
            )
        })?;
        Ok(())
    }
}

impl Drop for VirtualProcessor {
    fn drop(&mut self) {
        check_result(unsafe {
            WHvDeleteVirtualProcessor(*self.partition.borrow_mut().handle(), self.index)
        })
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;
    use arch::*;

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
    fn test_crate_arch() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp: VirtualProcessor = p.create_virtual_processor(vp_index).unwrap();
        
        // Call the arch crate with our custom VCPU
        arch::x86_64::regs::setup_fpu(&vp).unwrap();
        drop(vp)
    }

    #[test]
    fn test_crate_vmm_vcpu() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp: WhpVcpu = p.create_vcpu(vp_index).unwrap();

        // Call the arch crate with our custom VCPU
        let msrs: MsrEntries = Default::default();
        vp.set_msrs(&msrs);

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
            let state: LApicState = vp.get_lapic().unwrap();
            let icr0 = get_lapic_reg(&state, APIC_REG_OFFSET::InterruptCommand0);
            assert_eq!(icr0, 0);

            // Uses both get_lapic and set_lapic under the hood
            set_reg_in_lapic(&vp, APIC_REG_OFFSET::InterruptCommand0, 0x40);

            let state_out: LApicState = vp.get_lapic().unwrap();
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
