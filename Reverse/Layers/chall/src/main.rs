use std::io::{stdin, stdout, Write};
use std::arch::asm;
use std::mem;
use std::ptr;
use mmap::{MemoryMap, MapOption};

const SHELLCODE_BYTES: &[u8] = include_bytes!("shellcode.bin");

fn main() {
    let opts = [MapOption::MapWritable, MapOption::MapExecutable];
    let map = MemoryMap::new(SHELLCODE_BYTES.len(), &opts).unwrap();

    let real_shellcode = SHELLCODE_BYTES.iter().map(|x| x ^ 137).collect::<Vec<u8>>();

    unsafe {
        ptr::copy(real_shellcode.as_ptr(), map.data(), real_shellcode.len());
    }

    let exec_shellcode: extern "C" fn() = unsafe { mem::transmute(map.data() as *const _ as *const ()) };

    println!("So, what did you understand about the idol?");
    print!("> ");
    stdout().flush().unwrap();

    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    input = input.trim().to_string();

    let enc = [1014124571, 1014125115, 1014124891, 1014124739, 1014125091, 1014124563, 1014125115, 1014124891, 1014124651, 1014125091, 1014124555, 1014124891, 1014124603, 1014125099, 1014124755, 1014124731, 1014125099, 1014124595, 1014125115, 1014124739, 1014124651, 1014124891, 1014124691, 1014125115, 1014124595, 1014124595, 1014125099, 1014125067];

    unsafe {
        asm!(
            "mov rdi, {}",
            "mov rsi, {}",
            "mov rdx, {}",
            "mov rcx, {}",
            in(reg) input.as_ptr(),
            in(reg) input.len(),
            in(reg) enc.as_ptr(),
            in(reg) enc.len(),
        );
    }

    exec_shellcode();

    let mut result: i32;
    unsafe {
        asm!(
            "mov {0:e}, eax",
            out(reg) result,
        );
    }

    if result == 1 {
        println!("You suddenly feel deep inside yourself a big feeling of satisfaction... You don't know precisely how, but you've figured out what the locals wanted to tell you about their culture.");
    } else {
        println!("Absolutely nothing happens... You're probably still missing something...");
    }
}