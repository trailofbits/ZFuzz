"""
    Script to create a memory dump using gdb
    To use, enter following 2 commands in gdb while running program: "source snapshot.py" "fulldump"
"""
import gdb, json, os, select, shutil, re

# Execute a provided gdb-command and save output
def execute_output(command):
    # Create temporary file for the output
    filename = 'gdb_output_' + str(os.getpid())

    # Enable logging
    gdb.execute("set logging file " + filename)
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging redirect on")
    gdb.execute("set logging enabled")
    
    # Execute command and save output to log file
    try:
        gdb.execute(command)
    except:
        pass

    # Restore normal gdb behaviour
    gdb.execute("set logging enabled off")
    gdb.execute("set logging redirect off")

    # Read output from logged command
    outfile = open(filename, 'r')
    output = outfile.read()

    # Cleanup
    os.remove(filename)
    outfile.close()

    return output.splitlines()

# Retrieve process mappings using `info proc mappings` gdb command
def process_mappings():
    # Get process mappings
    output = execute_output('info proc mappings')
    mappings = list()

    # Parse out every emitted line
    for line in output:
        if re.compile('^\s+0x[0-9a-f]+').search(line):
            fields = re.compile('\s+').split(line)

            # Provide empty-string as objfile name if not present
            if len(fields) < 6:
                fields.append('')

            mappings.append({
                'start': int(fields[1], 16),
                'end': int(fields[2], 16),
                'size': int(fields[3], 16),
                'offset': int(fields[4], 16),
                'perms': fields[5],
                'objfile': fields[6],
                })
    return mappings

# Retrieve the in-use file-descriptors of this process and the current location of the cursor into
# the file
def in_use_fds(pid):
    # Get process mappings
    gdb.execute(f'shell lsof -p {pid} -o > gdb_tmp_output')
    files = list()

    with open("gdb_tmp_output", "rb") as f:
        data = f.readlines()[1:]
        for listing in data:
            entries = str(listing).split(' ')
            entries = list(filter(lambda x: not not x, entries))

            # This is a valid fd that we want access to
            # There is no way this check will actually always be correct, but I would have to
            # dig deeper into the fsof program to properly parse this which I want to avoid for now
            if entries[6][0] == '0' and entries[6][1] == 't':
                fd_num    = int(entries[3][:-1])
                fd_offset = int(entries[6][2:])
                fd_path   = entries[8]

                files.append({
                        'name': fd_path,
                        'cursor': fd_offset,
                        'fd':  fd_num,
                        })

        os.remove("gdb_tmp_output")

    return files

# Command to dump full memory/register state of a program running in gdb
class FullDump(gdb.Command):
    # Register class
    def __init__(self):
        super(FullDump, self).__init__("fulldump", gdb.COMMAND_DATA)

    # This method is called when command is invoked
    def invoke(self, arg, from_tty):
        dump_path = "./dump/"
        tmp = arg.split(" ")[0]
        if not tmp:
            pid = gdb.selected_inferior().pid
        else:
            pid = int(tmp)

        # Verify that the process is correctly running
        #pid = gdb.selected_inferior().pid
        if not pid or not gdb.selected_inferior().is_valid():
            print("[!]: Couldn't get pid. Make sure the process is running before generating trace")
            return False

        # Retrieve and parse open fd's
        open_fds = in_use_fds(pid)
        if not open_fds:
            print("[!]: Couldn't get file listings for process")
            return False

        # Retrieve and parse memory mappings
        vmmap = process_mappings()
        if not vmmap:
            print("[!]: Couldn't get virtual memory mappings")
            return False

        memory = list()
        for i in range(0, len(vmmap)):
            page = vmmap[i]
            start = page["start"]
            size = page["size"]
            offset = page["offset"]
            perms = page["perms"]
            name = page["objfile"]
            end = start + size

            try:
                raw = gdb.selected_inferior().read_memory(start, size).tobytes()
                memory.append({
                                "start": start, 
                                "end": end, 
                                "size": size,
                                "offset": offset, 
                                "permissions": perms,
                                "name": name,
                                "raw": raw, 
                                }
                            )
            except:
                print(f"Failed to dump: {hex(start)} - {hex(end)}")
                pass

        # Get register-names and their values
        arch = gdb.selected_frame().architecture()
        reg_groups = arch.register_groups()
        reg_map = {}
        for reg_group in reg_groups:
            # TODO
            # Some of the other more complicated memory groups (eg. regs to handle floats) are
            # emitted by gdb in various differently typed ways. For now, since the fuzzer does not
            # support them anyways, I will just ignore other register groups apart from the base set
            if str(reg_group) != "general" and str(reg_group) != "system":
                continue

            regs = arch.registers(str(reg_group))
            for reg in regs:
                value = int(gdb.parse_and_eval(f'${reg}'))
                u64 = value % 2**64
                reg_map[str(reg)] = u64

        # Prepare disk for dumping
        if os.path.exists(dump_path):
            shutil.rmtree(dump_path)
        os.makedirs(dump_path)
        os.makedirs(dump_path + "raw_memory/")
        os.makedirs(dump_path + "raw_files/")

        # Dump register maps
        with open(dump_path + "regs", "w+") as f:
            json.dump(reg_map, f, indent = 4)

        # Dump open file information
        with open(dump_path + "files", "w+") as f:
            json.dump(open_fds, f, indent = 4)

        # Dump data-backing for files if we can read it
        for file in open_fds:
            with open(file["name"][:-3], "rb") as file_backing:
                # Check if the file has any data to read
                r, _, _ = select.select([ file_backing ], [], [], 0)
                if file_backing in r:
                    backing = file_backing.read()
                    with open(dump_path + f"raw_files/raw_{file['fd']}", "wb+") as tmp:
                        tmp.write(backing)

        # Dump memory mappings and the raw-data
        for i in range(0, len(memory)):
            raw_data = memory[i]["raw"]
            memory[i].pop("raw")
            with open(dump_path + f"raw_memory/raw_{i}", "wb") as f:
                f.write(raw_data)

        with open(dump_path + "memory_maps", "w+") as f:
            json.dump(memory, f, indent = 4)

        print(f"Full dump written to {dump_path}")

        return True

# This registers our class to the gdb runtime at "source" time.
FullDump()
