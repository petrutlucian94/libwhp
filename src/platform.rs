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

use common::*;
use memory::*;
use std;
use std::cell::RefCell;
use std::rc::Rc;
use win_hv_platform::*;
pub use win_hv_platform_defs::*;

pub fn get_capability(capability_code: WHV_CAPABILITY_CODE) -> Result<WHV_CAPABILITY, WHPError> {
    let mut capability: WHV_CAPABILITY;
    let mut written_size: UINT32 = 0;

    check_result(unsafe {
        capability = std::mem::zeroed();

        WHvGetCapability(
            capability_code,
            &mut capability as *mut _ as *mut VOID,
            std::mem::size_of::<WHV_CAPABILITY>() as UINT32,
            &mut written_size,
        )
    })?;
    Ok(capability)
}

struct PartitionHandle {
    handle: WHV_PARTITION_HANDLE,
}

impl PartitionHandle {
    fn handle(&self) -> &WHV_PARTITION_HANDLE {
        &self.handle
    }
}

impl Drop for PartitionHandle {
    fn drop(&mut self) {
        check_result(unsafe { WHvDeletePartition(self.handle) }).unwrap();
    }
}

pub struct Partition {
    partition: Rc<RefCell<PartitionHandle>>,
}

impl Partition {
    pub fn new() -> Result<Partition, WHPError> {
        let mut handle: WHV_PARTITION_HANDLE = std::ptr::null_mut();
        check_result(unsafe { WHvCreatePartition(&mut handle) })?;
        Ok(Partition {
            partition: Rc::new(RefCell::new(PartitionHandle { handle: handle })),
        })
    }

    pub fn set_property(
        &mut self,
        property_code: WHV_PARTITION_PROPERTY_CODE,
        property: &WHV_PARTITION_PROPERTY,
    ) -> Result<(), WHPError> {
        self.set_property_from_buffer(
            property_code,
            property as *const _ as *const VOID,
            std::mem::size_of::<WHV_PARTITION_PROPERTY>() as UINT32,
        )?;
        Ok(())
    }

    pub fn set_property_cpuid_exits(&mut self, cpuids: &[UINT32]) -> Result<(), WHPError> {
        self.set_property_from_buffer(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeCpuidExitList,
            cpuids.as_ptr() as *const VOID,
            (std::mem::size_of::<UINT32>() * cpuids.len()) as UINT32,
        )?;
        Ok(())
    }

    pub fn set_property_cpuid_results(
        &mut self,
        cpuid_results: &[WHV_X64_CPUID_RESULT],
    ) -> Result<(), WHPError> {
        self.set_property_from_buffer(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeCpuidResultList,
            cpuid_results.as_ptr() as *const VOID,
            (std::mem::size_of::<WHV_X64_CPUID_RESULT>() * cpuid_results.len()) as UINT32,
        )?;
        Ok(())
    }

    fn set_property_from_buffer(
        &mut self,
        property_code: WHV_PARTITION_PROPERTY_CODE,
        property: *const VOID,
        size: UINT32,
    ) -> Result<(), WHPError> {
        check_result(unsafe {
            WHvSetPartitionProperty(
                *self.partition.borrow_mut().handle(),
                property_code,
                property,
                size,
            )
        })?;
        Ok(())
    }

    pub fn get_property(
        &self,
        property_code: WHV_PARTITION_PROPERTY_CODE,
    ) -> Result<WHV_PARTITION_PROPERTY, WHPError> {
        let mut property: WHV_PARTITION_PROPERTY = unsafe { std::mem::zeroed() };
        self.get_property_buffer(
            property_code,
            &mut property as *mut _ as *mut VOID,
            std::mem::size_of::<WHV_PARTITION_PROPERTY>() as UINT32,
        )?;
        Ok(property)
    }

    fn get_property_buffer(
        &self,
        property_code: WHV_PARTITION_PROPERTY_CODE,
        property: *mut VOID,
        size: UINT32,
    ) -> Result<UINT32, WHPError> {
        let mut written_size: UINT32 = 0;

        check_result(unsafe {
            WHvGetPartitionProperty(
                *self.partition.borrow().handle(),
                property_code,
                property,
                size,
                &mut written_size,
            )
        })?;
        Ok(written_size)
    }

    pub fn setup(&mut self) -> Result<(), WHPError> {
        check_result(unsafe { WHvSetupPartition(*self.partition.borrow_mut().handle()) })?;
        Ok(())
    }

    pub fn create_virtual_processor(
        &mut self,
        index: UINT32,
    ) -> Result<VirtualProcessor, WHPError> {
        check_result(unsafe {
            WHvCreateVirtualProcessor(*self.partition.borrow_mut().handle(), index, 0)
        })?;
        Ok(VirtualProcessor {
            partition: Rc::clone(&self.partition),
            index: index,
        })
    }

    pub fn map_gpa_range<T: Memory>(
        &mut self,
        source_address: &T,
        guest_address: WHV_GUEST_PHYSICAL_ADDRESS,
        size: UINT64,
        flags: WHV_MAP_GPA_RANGE_FLAGS,
    ) -> Result<GPARangeMapping, WHPError> {
        check_result(unsafe {
            WHvMapGpaRange(
                *self.partition.borrow_mut().handle(),
                source_address.as_ptr(),
                guest_address,
                size,
                flags,
            )
        })?;
        Ok(GPARangeMapping {
            partition: Rc::clone(&self.partition),
            source_address: source_address.as_ptr(),
            guest_address: guest_address,
            size: size,
            flags: flags,
        })
    }
}

pub struct GPARangeMapping {
    partition: Rc<RefCell<PartitionHandle>>,
    source_address: *const VOID,
    guest_address: WHV_GUEST_PHYSICAL_ADDRESS,
    size: UINT64,
    flags: WHV_MAP_GPA_RANGE_FLAGS,
}

impl GPARangeMapping {
    pub fn get_source_address(&self) -> *const VOID {
        self.source_address
    }

    pub fn get_guest_address(&self) -> WHV_GUEST_PHYSICAL_ADDRESS {
        self.guest_address
    }

    pub fn get_size(&self) -> UINT64 {
        self.size
    }

    pub fn get_flags(&self) -> WHV_MAP_GPA_RANGE_FLAGS {
        self.flags
    }
}

impl Drop for GPARangeMapping {
    fn drop(&mut self) {
        let p = self.partition.borrow_mut();
        check_result(unsafe { WHvUnmapGpaRange(*p.handle(), self.guest_address, self.size) })
            .unwrap();
    }
}

pub struct VirtualProcessor {
    partition: Rc<RefCell<PartitionHandle>>,
    index: UINT32,
}

impl VirtualProcessor {
    pub fn index(&self) -> UINT32 {
        return self.index;
    }

    pub fn run(&mut self) -> Result<WHV_RUN_VP_EXIT_CONTEXT, WHPError> {
        let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = unsafe { std::mem::zeroed() };
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
        let mut translation_result: WHV_TRANSLATE_GVA_RESULT = unsafe { std::mem::zeroed() };

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
}

impl Drop for VirtualProcessor {
    fn drop(&mut self) {
        check_result(unsafe {
            WHvDeleteVirtualProcessor(*self.partition.borrow_mut().handle(), self.index)
        }).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    #[test]
    fn test_create_delete_partition() {
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
        let mut property: WHV_PARTITION_PROPERTY = unsafe { std::mem::zeroed() };
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
        let mut cpuid_result: WHV_X64_CPUID_RESULT = unsafe { std::mem::zeroed() };
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
        let mut property: WHV_PARTITION_PROPERTY = unsafe { std::mem::zeroed() };
        property.ProcessorCount = 1;

        // Setup fails without setting at least the number of vcpus
        p.set_property(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
            &property,
        ).unwrap();
        p.setup().unwrap();
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
        let mut property: WHV_PARTITION_PROPERTY = unsafe { std::mem::zeroed() };
        property.ProcessorCount = 1;

        p.set_property(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
            &property,
        ).unwrap();
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
    fn test_set_get_virtual_processor_registers() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let mut vp = p.create_virtual_processor(vp_index).unwrap();

        const NUM_REGS: UINT32 = 1;
        const REG_VALUE: UINT64 = 11111111;
        let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = unsafe { std::mem::zeroed() };
        let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = unsafe { std::mem::zeroed() };
        let mut reg_values_out: [WHV_REGISTER_VALUE; NUM_REGS as usize] =
            unsafe { std::mem::zeroed() };

        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRax;
        reg_values[0].Reg64 = REG_VALUE;

        vp.set_registers(&reg_names, &reg_values).unwrap();
        vp.get_registers(&reg_names, &mut reg_values_out).unwrap();

        unsafe {
            assert_eq!(
                reg_values_out[0].Reg64, REG_VALUE,
                "Registers values fo not match"
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

        let mapping = p.map_gpa_range(
            &mem,
            guest_address,
            SIZE,
            WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead,
        ).unwrap();

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
        let (translation_result, gpa) = vp.translate_gva(
            gva,
            WHV_TRANSLATE_GVA_FLAGS::WHvTranslateGvaFlagValidateRead,
        ).unwrap();

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
}
