from unicorn import *
from unicorn.unicorn_const import *
from unicorn.riscv_const import *

def mem_hook(uc, access, address, size, value, user_data):
    print(f"Python hook at is: {hex(address)}")

    pass

def uc_load(uc):
    with open("./test_cases/simple_test", "rb") as f:
        data = f.read()
        align = 0x1000

        raw1 = data[0:0x1738]

        raw2 = data[0x1738:0x1738+ 0xfa8]
        padding = bytearray([0] * (0x1030 - 0xfa8))
        raw2 = raw2 + padding

        assert(len(raw1) == 0x1738)
        assert(len(raw2) == 0x1030)

        aligned_size1 = (align - 1 + 0x1738) & ~(align - 1);
        aligned_addr1 = (0x10000 & ~(align - 1))

        aligned_size2 = (align - 1 + 0x1030) & ~(align - 1);
        aligned_addr2 = (0x12738 & ~(align - 1))

        uc.mem_map(aligned_addr1, aligned_size1, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(aligned_addr2, aligned_size2, UC_PROT_READ | UC_PROT_WRITE)

        uc.mem_write(0x10000, raw1)
        uc.mem_write(0x12738, raw2)

        uc.reg_write(UC_RISCV_REG_PC, 0x10298)

def main():
    uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    uc_load(uc)
    uc.hook_add(UC_HOOK_MEM_WRITE, mem_hook)

    print("[+] Finished loading")

    uc.emu_start(0x10298, 0x10298 + 0x1000)

if __name__ == "__main__":
    main()
