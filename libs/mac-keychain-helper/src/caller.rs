//! Is our parent BaseHero? Checked once, through the parent's audit token.
use core_foundation::{base::TCFType, data::CFData};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use std::os::unix::process::parent_id;

type MachPort = u32;
const TASK_AUDIT_TOKEN: i32 = 15;
const TASK_AUDIT_TOKEN_COUNT: u32 = 8;

unsafe extern "C" {
    static mach_task_self_: MachPort;
    fn task_name_for_pid(target: MachPort, pid: i32, name: *mut MachPort) -> i32;
    fn task_info(task: MachPort, flavor: i32, info: *mut u32, count: *mut u32) -> i32;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> i32;
}

/// `audit_token_t` of a live same-user process: eight words, pid at 5 and
/// pidversion at 7, so it names one process image, not a reusable pid.
fn audit_token(pid: i32) -> Option<[u32; 8]> {
    // SAFETY: reading the process's own task port, set up before main.
    let task = unsafe { mach_task_self_ };
    let mut name: MachPort = 0;
    // SAFETY: `name` is a valid out-pointer for one port right.
    if unsafe { task_name_for_pid(task, pid, &mut name) } != 0 {
        return None;
    }
    let mut token = [0u32; 8];
    let mut count = TASK_AUDIT_TOKEN_COUNT;
    // SAFETY: `token` holds TASK_AUDIT_TOKEN_COUNT words and `count` says so.
    let status = unsafe { task_info(name, TASK_AUDIT_TOKEN, token.as_mut_ptr(), &mut count) };
    // SAFETY: releases the name right obtained above, exactly once.
    unsafe { mach_port_deallocate(task, name) };
    (status == 0 && count == TASK_AUDIT_TOKEN_COUNT).then_some(token)
}

/// The parent's running code, its files on disk and its bundle resources
/// satisfy `requirement`, and it stayed our parent throughout. Re-parenting
/// only happens when the parent exits, so an unchanged parent pid afterwards
/// means the token's process lived for the whole check.
pub fn parent_satisfies(requirement: &str) -> bool {
    let parent = parent_id() as i32;
    if parent <= 1 {
        return false;
    }
    let Some(token) = audit_token(parent) else {
        return false;
    };
    if token[5] as i32 != parent {
        return false;
    }
    let Ok(requirement) = requirement.parse::<SecRequirement>() else {
        return false;
    };
    let bytes: Vec<u8> = token.iter().flat_map(|word| word.to_ne_bytes()).collect();
    let token = CFData::from_buffer(&bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token.as_concrete_TypeRef());
    let Ok(code) = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE) else {
        return false;
    };
    code.check_validity(Flags::NONE, &requirement).is_ok() && parent_id() as i32 == parent
}
