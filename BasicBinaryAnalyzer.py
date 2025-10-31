import sys
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM, CS_ARCH_AARCH64, CS_ARCH_PPC, CS_MODE_PPC64, CS_MODE_BE, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_MIPS64

try:
    import pefile
except ImportError:
    pefile = None


# Map ELF machine types to Capstone architectures
ELF_ARCH_MAPPING = {
    'EM_X86_64': (CS_ARCH_X86, CS_MODE_64),
    'EM_386': (CS_ARCH_X86, CS_MODE_32),
    'EM_ARM': (CS_ARCH_ARM, CS_MODE_ARM),
    'EM_AARCH64': (CS_ARCH_AARCH64, CS_MODE_ARM),  # Capstone uses CS_MODE_ARM for AArch64
    'EM_PPC64': (CS_ARCH_PPC, CS_MODE_PPC64 | CS_MODE_BE),
    'EM_MIPS': (CS_ARCH_MIPS, CS_MODE_MIPS64), # Default to MIPS64, can be refined
    'EM_MIPS_RS3_LE': (CS_ARCH_MIPS, CS_MODE_MIPS32),
}

# Map PE machine types to Capstone architectures
PE_ARCH_MAPPING = {}
if pefile:
    PE_ARCH_MAPPING = {
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: (CS_ARCH_X86, CS_MODE_32),
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: (CS_ARCH_X86, CS_MODE_64),
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']: (CS_ARCH_ARM, CS_MODE_ARM),
        pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']: (CS_ARCH_AARCH64, CS_MODE_ARM),
    }

def find_strings(filepath, min_len=4):
    """
    Finds and yields printable strings from a binary file.
    Reads the file in chunks for better memory efficiency.
    """
    print("\n" + "="*20, f"Strings (min length {min_len})", "="*20)
    try:
        with open(filepath, 'rb') as f:
            result = ""
            chunk_size = 4096
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for byte in chunk:
                    # Check for printable ASCII characters (32-126)
                    if 32 <= byte <= 126:
                        result += chr(byte)
                    else:
                        if len(result) >= min_len:
                            yield result
                        result = ""
            # Yield any remaining string at the end of the file
            if len(result) >= min_len: # Check for any remaining string
                 yield result
    except IOError as e:
        print(f"[ERROR] Could not read file for strings: {e}")

def disassemble_section(section, arch, mode, functions):
    """
    Disassembles a given executable section.
    """
    print("\n" + "="*20, f"Disassembly of {section.name} section", "="*20)
    code = section.data()
    addr = section['sh_addr']
    
    # Create a quick lookup for function names by address
    func_addrs = {f['st_value']: f['name'] for f in functions}

    try:
        # Initialize Capstone disassembler
        md = Cs(arch, mode)
        md.detail = True # Enable detail to get more instruction info if needed
        
        # Disassemble and print instructions
        for instruction in md.disasm(code, addr):
            # Check if the current address is a known function start
            if instruction.address in func_addrs:
                print(f"\n--- <{func_addrs[instruction.address]}> ---")
            print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")


    except Exception as e:
        print(f"[ERROR] Disassembly failed: {e}")

def get_elf_arch_details(elf):
    """
    Gets the Capstone architecture and mode from the ELF file's machine type.
    """
    machine_arch = elf['e_machine']
    return ELF_ARCH_MAPPING.get(machine_arch)
    
def find_functions(elf):
    """
    Finds and returns a list of functions from the symbol table.
    """
    functions = []
    print("\n" + "="*20, "Function Symbols", "="*20)
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                if symbol['st_info']['type'] == 'STT_FUNC':
                    functions.append({'name': symbol.name, 'st_value': symbol['st_value']})
                    print(f"  Found function: {symbol.name} at 0x{symbol['st_value']:x}")
    if not functions:
        print("  No function symbols found in .symtab.")
    return functions


def analyze_elf(filepath, do_disasm=True, do_strings=True, do_funcs=True):
    """
    Analyzes an ELF binary file.
    """
    print(f"Analyzing file: {filepath}")
    try:
        with open(filepath, 'rb') as f:
            elf = ELFFile(f)

            # 1. Display ELF Header Information
            print("="*20, "ELF Header Information", "="*20)
            print(f"  Class: {elf['e_ident']['EI_CLASS']}")
            print(f"  Data: {elf['e_ident']['EI_DATA']}")
            print(f"  Type: {elf['e_type']}")
            print(f"  Machine: {elf['e_machine']}")

            # 2. Find functions from symbol tables
            functions = find_functions(elf) if do_funcs else []

            # 3. Disassemble executable sections
            if do_disasm:
                arch_details = get_elf_arch_details(elf)
                if arch_details:
                    arch, mode = arch_details
                    print(f"\n[INFO] Detected architecture: {elf['e_machine']}. Initializing disassembler.")
                    
                    for section in elf.iter_sections():
                        # Check if the section is executable ('SHF_EXECINSTR')
                        if isinstance(section, Section) and section['sh_flags'] & 0x4:
                            disassemble_section(section, arch, mode, functions)
                else:
                    print(f"\n[INFO] Skipping disassembly for unsupported architecture: {elf['e_machine']}")

            # 4. Find and print strings
            if do_strings:
                for s in find_strings(filepath):
                    print(s)

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
    except Exception as e:
        # ELFFile will raise an ELFError if it's not a valid ELF file
        print(f"[ERROR] An error occurred: {e}")
        print(f"'{filepath}' is likely not a valid ELF file.")


def analyze_pe(filepath, do_disasm=True, do_strings=True, do_funcs=True):
    """
    Analyzes a Windows PE binary file.
    """
    if not pefile:
        print("[ERROR] 'pefile' library is not installed. Cannot analyze PE files.")
        print("Please run: pip install pefile")
        return

    print(f"Analyzing file: {filepath}")
    try:
        pe = pefile.PE(filepath)

        # 1. Display PE Header Information
        print("="*20, "PE Header Information", "="*20)
        machine_type = pe.FILE_HEADER.Machine
        print(f"  Machine: {pefile.MACHINE_TYPE[machine_type]} ({machine_type})")
        print(f"  Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
        print(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}")

        # 2. Find exported functions
        functions = []
        if do_funcs and hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("\n" + "="*20, "Exported Functions", "="*20)
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                functions.append({'name': exp.name.decode('utf-8', 'ignore'), 'st_value': pe.OPTIONAL_HEADER.ImageBase + exp.address})
                print(f"  Found function: {exp.name.decode('utf-8', 'ignore')} at 0x{pe.OPTIONAL_HEADER.ImageBase + exp.address:x}")

        # 3. Disassemble executable sections
        if do_disasm:
            arch_details = PE_ARCH_MAPPING.get(machine_type)
            if arch_details:
                arch, mode = arch_details
                print(f"\n[INFO] Detected architecture: {pefile.MACHINE_TYPE[machine_type]}. Initializing disassembler.")
                
                for section in pe.sections:
                    # Check if the section is executable
                    if section.Characteristics & 0x20000000: # IMAGE_SCN_MEM_EXECUTE
                        # Adapt PE section to work with the generic disassembler function
                        adapted_section = type('AdaptedSection', (), {
                            'name': section.Name.decode().rstrip('\x00'),
                            'data': section.get_data,
                            'sh_addr': pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                        })
                        disassemble_section(adapted_section, arch, mode, functions)
            else:
                print(f"\n[INFO] Skipping disassembly for unsupported architecture: {pefile.MACHINE_TYPE[machine_type]}")

        # 4. Find and print strings
        if do_strings:
            for s in find_strings(filepath):
                print(s)

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
    except pefile.PEFormatError as e:
        print(f"[ERROR] Not a valid PE file: {e}")
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")


def main():
    """
    Main entry point for the script. Detects file type and calls the appropriate analyzer.
    """
    parser = argparse.ArgumentParser(
        description="A basic binary analysis tool for ELF and PE files.",
        epilog="Example: python basic_binary_analyzer.py /bin/ls (for ELF) or C:\\Windows\\System32\\kernel32.dll (for PE)"
    )
    parser.add_argument("file", help="The binary file to analyze")
    parser.add_argument("--no-disasm", action="store_true", help="Skip the disassembly phase")
    parser.add_argument("--no-strings", action="store_true", help="Skip the string search phase")
    parser.add_argument("--no-funcs", action="store_true", help="Skip the function symbol/export search phase")
    args = parser.parse_args()

    try:
        with open(args.file, 'rb') as f:
            magic_bytes = f.read(4)
            if magic_bytes.startswith(b'\x7fELF'):
                print("[INFO] ELF file detected.")
                analyze_elf(args.file, do_disasm=not args.no_disasm, do_strings=not args.no_strings, do_funcs=not args.no_funcs)
            elif magic_bytes.startswith(b'MZ'):
                print("[INFO] PE file (Windows executable) detected.")
                analyze_pe(args.file, do_disasm=not args.no_disasm, do_strings=not args.no_strings, do_funcs=not args.no_funcs)
            else:
                print("[ERROR] Unknown file type. Only ELF and PE files are supported.")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.file}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
