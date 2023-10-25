use core::mem;
use memmap::Mmap;
use std::collections::HashMap;
use std::env;
use std::fs::File;

const HEADER_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

const ELF64_ADDR_SIZE: usize = mem::size_of::<u64>();
const ELF64_OFF_SIZE: usize = mem::size_of::<u64>();
const ELF64_WORD_SIZE: usize = mem::size_of::<u32>();
const ELF64_HALF_SIZE: usize = mem::size_of::<u16>();

const E_TYPE_START_BYTE: usize = 16;
const E_TYPE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_MACHINE_START_BYTE: usize = E_TYPE_START_BYTE + E_TYPE_SIZE_BYTE;
const E_MACHINE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_VERSION_START_BYTE: usize = E_MACHINE_START_BYTE + E_MACHINE_SIZE_BYTE;
const E_VERSION_SIZE_BYTE: usize = ELF64_WORD_SIZE;
const E_ENTRY_START_BYTE: usize = E_VERSION_START_BYTE + E_VERSION_SIZE_BYTE;
const E_ENTRY_SIZE_BYTE: usize = ELF64_ADDR_SIZE;
const E_PHOFF_START_BYTE: usize = E_ENTRY_START_BYTE + E_ENTRY_SIZE_BYTE;
const E_PHOFF_SIZE_BYTE: usize = ELF64_OFF_SIZE;
const E_SHOFF_START_BYTE: usize = E_PHOFF_START_BYTE + E_PHOFF_SIZE_BYTE;
const E_SHOFF_SIZE_BYTE: usize = ELF64_OFF_SIZE;
const E_FLAGS_START_BYTE: usize = E_SHOFF_START_BYTE + E_SHOFF_SIZE_BYTE;
const E_FLAGS_SIZE_BYTE: usize = ELF64_WORD_SIZE;
const E_EHSIZE_START_BYTE: usize = E_FLAGS_START_BYTE + E_FLAGS_SIZE_BYTE;
const E_EHSIZE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_PHENTSIZE_START_BYTE: usize = E_EHSIZE_START_BYTE + E_EHSIZE_SIZE_BYTE;
const E_PHENTSIZE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_PHNUM_START_BYTE: usize = E_PHENTSIZE_START_BYTE + E_PHENTSIZE_SIZE_BYTE;
const E_PHNUM_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_SHENTSIZE_START_BYTE: usize = E_PHNUM_START_BYTE + E_PHNUM_SIZE_BYTE;
const E_SHENTSIZE_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_SHNUM_START_BYTE: usize = E_SHENTSIZE_START_BYTE + E_SHENTSIZE_SIZE_BYTE;
const E_SHNUM_SIZE_BYTE: usize = ELF64_HALF_SIZE;
const E_SHSTRNDX_START_BYTE: usize = E_SHNUM_START_BYTE + E_SHNUM_SIZE_BYTE;

enum ElfMachineType {
    EmNone = 0,
    EmSparc = 2,
    Em386 = 3,
    EmSparc32PLUS = 18,
    EmArm = 40,
    EmAmd64 = 62,
    EmCuda = 190,
    EmAmdGpu = 224,
    EmRiscv = 243,
}

impl ElfMachineType {
    fn as_str(&self) -> &str {
        match *self {
            ElfMachineType::EmNone => "None",
            ElfMachineType::EmSparc => "SPARC",
            ElfMachineType::Em386 => "x86",
            ElfMachineType::EmSparc32PLUS => "SPARC 32+",
            ElfMachineType::EmArm => "ARM",
            ElfMachineType::EmAmd64 => "AMD64",
            ElfMachineType::EmCuda => "CUDA",
            ElfMachineType::EmAmdGpu => "AMD GPU",
            ElfMachineType::EmRiscv => "RISC-V",
        }
    }
}

pub struct Loader {
    file: Mmap,
}

impl Loader {
    pub fn open(path: &str) -> std::io::Result<Loader> {
        let file = File::open(path)?;
        let file = unsafe { Mmap::map(&file)? };
        Ok(Loader { file })
    }

    fn is_elf(&self) -> bool {
        self.file[0..4] == HEADER_MAGIC
    }

    fn get_ei_class(&self) -> &str {
        match self.file[4] {
            1 => "32bit architecture",
            2 => "64bit architecture",
            _ => "Invalid class",
        }
    }

    fn get_ei_data(&self) -> &str {
        match self.file[5] {
            1 => "Little endian",
            2 => "Big endian",
            _ => "Invalid data",
        }
    }

    fn get_ei_version(&self) -> u8 {
        self.file[6]
    }

    fn get_e_type(&self) -> &str {
        match (self.file[E_TYPE_START_BYTE + 1] as u16) << 8 | (self.file[E_TYPE_START_BYTE] as u16)
        {
            0 => "No file type",
            1 => "Relocatable file",
            2 => "Executable file",
            3 => "Shared object file",
            4 => "Core file",
            0xfe00 | 0xfeff => "Operating system-specific",
            0xff00 | 0xffff => "Processor-specific",
            _ => "Invalid type",
        }
    }

    fn get_e_machine(&self) -> Option<&str> {
        let machine_type = (self.file[E_MACHINE_START_BYTE + 1] as u16) << 8
            | (self.file[E_MACHINE_START_BYTE] as u16);
        match machine_type {
            0 => Some(ElfMachineType::EmNone.as_str()),
            2 => Some(ElfMachineType::EmSparc.as_str()),
            3 => Some(ElfMachineType::Em386.as_str()),
            18 => Some(ElfMachineType::EmSparc32PLUS.as_str()),
            40 => Some(ElfMachineType::EmArm.as_str()),
            62 => Some(ElfMachineType::EmAmd64.as_str()),
            190 => Some(ElfMachineType::EmCuda.as_str()),
            224 => Some(ElfMachineType::EmAmdGpu.as_str()),
            243 => Some(ElfMachineType::EmRiscv.as_str()),
            _ => None,
        }
    }

    fn get_e_version(&self) -> u64 {
        (self.file[E_VERSION_START_BYTE + 3] as u64) << 24
            | (self.file[E_VERSION_START_BYTE + 2] as u64) << 16
            | (self.file[E_VERSION_START_BYTE + 1] as u64) << 8
            | (self.file[E_VERSION_START_BYTE] as u64)
    }

    fn get_e_entry(&self) -> u64 {
        (self.file[E_ENTRY_START_BYTE + 3] as u64) << 24
            | (self.file[E_ENTRY_START_BYTE + 2] as u64) << 16
            | (self.file[E_ENTRY_START_BYTE + 1] as u64) << 8
            | (self.file[E_ENTRY_START_BYTE] as u64)
    }

    fn get_e_phoff(&self) -> u64 {
        (self.file[E_PHOFF_START_BYTE + 3] as u64) << 24
            | (self.file[E_PHOFF_START_BYTE + 2] as u64) << 16
            | (self.file[E_PHOFF_START_BYTE + 1] as u64) << 8
            | (self.file[E_PHOFF_START_BYTE] as u64)
    }

    fn get_e_shoff(&self) -> u64 {
        (self.file[E_SHOFF_START_BYTE + 3] as u64) << 24
            | (self.file[E_SHOFF_START_BYTE + 2] as u64) << 16
            | (self.file[E_SHOFF_START_BYTE + 1] as u64) << 8
            | (self.file[E_SHOFF_START_BYTE] as u64)
    }

    fn get_e_flags(&self) -> u32 {
        (self.file[E_FLAGS_START_BYTE + 3] as u32) << 24
            | (self.file[E_FLAGS_START_BYTE + 2] as u32) << 16
            | (self.file[E_FLAGS_START_BYTE + 1] as u32) << 8
            | (self.file[E_FLAGS_START_BYTE] as u32)
    }

    fn get_e_ehsize(&self) -> u32 {
        (self.file[E_EHSIZE_START_BYTE + 1] as u32) << 8 | (self.file[E_EHSIZE_START_BYTE] as u32)
    }

    fn get_e_phentsize(&self) -> u32 {
        (self.file[E_PHENTSIZE_START_BYTE + 1] as u32) << 8
            | (self.file[E_PHENTSIZE_START_BYTE] as u32)
    }

    fn get_e_phnum(&self) -> u32 {
        (self.file[E_PHNUM_START_BYTE + 1] as u32) << 8 | (self.file[E_PHNUM_START_BYTE] as u32)
    }

    fn get_e_shentsize(&self) -> u32 {
        (self.file[E_SHENTSIZE_START_BYTE + 1] as u32) << 8
            | (self.file[E_SHENTSIZE_START_BYTE] as u32)
    }

    fn get_e_shnum(&self) -> u32 {
        (self.file[E_SHNUM_START_BYTE + 1] as u32) << 8 | (self.file[E_SHNUM_START_BYTE] as u32)
    }

    fn get_e_shstrndx(&self) -> u32 {
        (self.file[E_SHSTRNDX_START_BYTE + 1] as u32) << 8
            | (self.file[E_SHSTRNDX_START_BYTE] as u32)
    }
}

fn display_elem(key: String, values: Vec<String>, hex: bool, suffix: &str) {
    print!("{:<50} = ", key);
    for (_, string) in values.iter().enumerate() {
        if hex {
            if let Ok(parsed_int) = string.parse::<i32>() {
                let hex_string = format!("{:#x}", parsed_int);
                if !suffix.is_empty() {
                    print!("{:<30}", hex_string.to_owned() + suffix);
                } else {
                    print!("{:<30}", hex_string);
                }
            } else {
                panic!("Illegal instruction");
            }
        } else if !suffix.is_empty() {
            print!("{:<30}", string.to_owned() + suffix);
        } else {
            print!("{:<30}", string);
        }
    }
    println!();
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if !args.is_empty() {
        args.remove(0);
    }
    args.retain(|arg| {
        if let Ok(loaded) = Loader::open(arg) {
            loaded.is_elf()
        } else {
            panic!("Error");
        }
    });

    for arg in env::args().skip(1) {
        if !args.contains(&arg) {
            println!("{}", arg.to_owned() + " is not an ELF file");
        }
    }

    let mut results: HashMap<String, Vec<String>> = HashMap::new();

    for arg in &args {
        let loader = match Loader::open(&arg) {
            Ok(loader) => loader,
            Err(error) => {
                panic!("There was a problem opening the file: {:?}", error)
            }
        };

        results
            .entry("EI_CLASS".to_string())
            .or_insert(Vec::new())
            .push(loader.get_ei_class().to_string());
        results
            .entry("EI_DATA".to_string())
            .or_insert(Vec::new())
            .push(loader.get_ei_data().to_string());
        results
            .entry("EI_VERSION".to_string())
            .or_insert(Vec::new())
            .push(loader.get_ei_version().to_string());
        results
            .entry("E_TYPE".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_type().to_string());

        if let Some(e_machine) = loader.get_e_machine() {
            results
                .entry("E_MACHINE".to_string())
                .or_insert(Vec::new())
                .push(e_machine.to_string());
        }

        results
            .entry("E_VERSION".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_version().to_string());
        results
            .entry("E_ENTRY".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_entry().to_string());
        results
            .entry("E_PHOFF".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_phoff().to_string());
        results
            .entry("E_SHOFF".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_shoff().to_string());
        results
            .entry("E_FLAGS".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_flags().to_string());
        results
            .entry("E_EHSIZE".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_ehsize().to_string());
        results
            .entry("E_PHENTSIZE".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_phentsize().to_string());
        results
            .entry("E_PHNUM".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_phnum().to_string());
        results
            .entry("E_SHENTSIZE".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_shentsize().to_string());
        results
            .entry("E_SHNUM".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_shnum().to_string());
        results
            .entry("E_SHSTRNDX".to_string())
            .or_insert(Vec::new())
            .push(loader.get_e_shstrndx().to_string());
    }

    print!("{:^53}", "File");
    for arg in &args{
        print!("{:^30}", arg);
    }
    println!();

    display_elem(
        "Architecture".to_string(),
        results.get("EI_CLASS").unwrap().to_vec(),
        false,
        "",
    );
    display_elem(
        "Endian".to_string(),
        results.get("EI_DATA").unwrap().to_vec(),
        false,
        "",
    );
    display_elem(
        "ELF Header Version".to_string(),
        results.get("EI_VERSION").unwrap().to_vec(),
        false,
        "",
    );
    display_elem(
        "File Type".to_string(),
        results.get("E_TYPE").unwrap().to_vec(),
        false,
        "",
    );
    display_elem(
        "Machine Type".to_string(),
        results.get("E_MACHINE").unwrap().to_vec(),
        false,
        "",
    );
    display_elem(
        "Object File Version".to_string(),
        results.get("E_VERSION").unwrap().to_vec(),
        true,
        "",
    );
    display_elem(
        "Entry Point".to_string(),
        results.get("E_ENTRY").unwrap().to_vec(),
        true,
        "",
    );
    display_elem(
        "Program Header Offset".to_string(),
        results.get("E_PHOFF").unwrap().to_vec(),
        true,
        "",
    );
    display_elem(
        "Section Header Offset".to_string(),
        results.get("E_SHOFF").unwrap().to_vec(),
        true,
        "",
    );
    display_elem(
        "Flags".to_string(),
        results.get("E_FLAGS").unwrap().to_vec(),
        false,
        "",
    );
    display_elem(
        "Header's Size".to_string(),
        results.get("E_EHSIZE").unwrap().to_vec(),
        false,
        " bytes",
    );
    display_elem(
        "Per Program Header's Size".to_string(),
        results.get("E_PHENTSIZE").unwrap().to_vec(),
        false,
        " bytes",
    );
    display_elem(
        "Program Header's Number".to_string(),
        results.get("E_PHNUM").unwrap().to_vec(),
        false,
        "",
    );
    display_elem(
        "Per Section Header's Size".to_string(),
        results.get("E_SHENTSIZE").unwrap().to_vec(),
        false,
        " bytes",
    );
    display_elem(
        "Section Header's Number".to_string(),
        results.get("E_SHNUM").unwrap().to_vec(),
        false,
        "",
    );
    display_elem(
        "Entry Index".to_string(),
        results.get("E_SHSTRNDX").unwrap().to_vec(),
        false,
        "",
    );
}
