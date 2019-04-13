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

// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::error::{self, Error as InterruptsError};
use std::fmt::{self, Display};
use std::io::Cursor;
use std::mem;
use std::result;

use vmm_vcpu::vcpu::{Vcpu, LapicState};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use common::WHPError;
use x86_64::{APIC_REG_OFFSET};

#[derive(Debug)]
pub enum Error {
    GetLapic(WHPError),
    SetLapic(WHPError),
}
pub type Result<T> = result::Result<T, Error>;

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::GetLapic(_) => "GetLapic ioctl failed",
            &Error::SetLapic(_) => "SetLapic ioctl failed",
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Interrupt Error: {}", Error::description(self))
    }
}

pub fn get_lapic_reg(lapic: &LapicState, reg_offset: APIC_REG_OFFSET) -> u32 {
    let sliceu8 = unsafe {
        // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
        // Cursors are only readable on arrays of u8, not i8(c_char).
        mem::transmute::<&[i8], &[u8]>(&lapic.regs[reg_offset as usize..])
    };
    let mut reader = Cursor::new(sliceu8);
    // read_u32 can't fail if the offsets defined above are correct.
    reader.read_u32::<LittleEndian>().unwrap()
}

pub fn set_lapic_reg(lapic: &mut LapicState, reg_offset: APIC_REG_OFFSET, value: u32) {
    let sliceu8 = unsafe {
        // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
        // Cursors are only readable on arrays of u8, not i8(c_char).
        mem::transmute::<&mut [i8], &mut [u8]>(&mut lapic.regs[reg_offset as usize..])
    };
    let mut writer = Cursor::new(sliceu8);
    // read_u32 can't fail if the offsets defined above are correct.
    writer.write_u32::<LittleEndian>(value).unwrap()
}

pub fn get_reg_from_lapic<T: Vcpu>(vcpu: &T, reg_offset: APIC_REG_OFFSET) -> u32 {
    //let lapic: LapicState = vcpu.get_lapic().map_err(Error::GetLapic).unwrap();
    let lapic: LapicState = vcpu.get_lapic().unwrap();

    get_lapic_reg(&lapic, reg_offset)
}

pub fn set_reg_in_lapic<T: Vcpu>(vcpu: &T, reg_offset: APIC_REG_OFFSET, value: u32) {
    let mut lapic: LapicState = vcpu.get_lapic().unwrap();

    set_lapic_reg(&mut lapic, reg_offset, value);

    vcpu.set_lapic(&lapic).unwrap();
}
