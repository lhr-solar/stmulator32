# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.31

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ishdeshpa/Work/lhrs/stmulator32

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ishdeshpa/Work/lhrs/stmulator32/output

# Include any dependencies generated for this target.
include CMakeFiles/stmulator.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/stmulator.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/stmulator.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/stmulator.dir/flags.make

CMakeFiles/stmulator.dir/codegen:
.PHONY : CMakeFiles/stmulator.dir/codegen

CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o: CMakeFiles/stmulator.dir/flags.make
CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o: /home/ishdeshpa/Work/lhrs/stmulator32/src/engine/architecture.cpp
CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o: CMakeFiles/stmulator.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ishdeshpa/Work/lhrs/stmulator32/output/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o -MF CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o.d -o CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o -c /home/ishdeshpa/Work/lhrs/stmulator32/src/engine/architecture.cpp

CMakeFiles/stmulator.dir/src/engine/architecture.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/stmulator.dir/src/engine/architecture.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ishdeshpa/Work/lhrs/stmulator32/src/engine/architecture.cpp > CMakeFiles/stmulator.dir/src/engine/architecture.cpp.i

CMakeFiles/stmulator.dir/src/engine/architecture.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/stmulator.dir/src/engine/architecture.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ishdeshpa/Work/lhrs/stmulator32/src/engine/architecture.cpp -o CMakeFiles/stmulator.dir/src/engine/architecture.cpp.s

CMakeFiles/stmulator.dir/src/launcher.cpp.o: CMakeFiles/stmulator.dir/flags.make
CMakeFiles/stmulator.dir/src/launcher.cpp.o: /home/ishdeshpa/Work/lhrs/stmulator32/src/launcher.cpp
CMakeFiles/stmulator.dir/src/launcher.cpp.o: CMakeFiles/stmulator.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ishdeshpa/Work/lhrs/stmulator32/output/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/stmulator.dir/src/launcher.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/stmulator.dir/src/launcher.cpp.o -MF CMakeFiles/stmulator.dir/src/launcher.cpp.o.d -o CMakeFiles/stmulator.dir/src/launcher.cpp.o -c /home/ishdeshpa/Work/lhrs/stmulator32/src/launcher.cpp

CMakeFiles/stmulator.dir/src/launcher.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/stmulator.dir/src/launcher.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ishdeshpa/Work/lhrs/stmulator32/src/launcher.cpp > CMakeFiles/stmulator.dir/src/launcher.cpp.i

CMakeFiles/stmulator.dir/src/launcher.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/stmulator.dir/src/launcher.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ishdeshpa/Work/lhrs/stmulator32/src/launcher.cpp -o CMakeFiles/stmulator.dir/src/launcher.cpp.s

CMakeFiles/stmulator.dir/src/loader/binary.cpp.o: CMakeFiles/stmulator.dir/flags.make
CMakeFiles/stmulator.dir/src/loader/binary.cpp.o: /home/ishdeshpa/Work/lhrs/stmulator32/src/loader/binary.cpp
CMakeFiles/stmulator.dir/src/loader/binary.cpp.o: CMakeFiles/stmulator.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ishdeshpa/Work/lhrs/stmulator32/output/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/stmulator.dir/src/loader/binary.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/stmulator.dir/src/loader/binary.cpp.o -MF CMakeFiles/stmulator.dir/src/loader/binary.cpp.o.d -o CMakeFiles/stmulator.dir/src/loader/binary.cpp.o -c /home/ishdeshpa/Work/lhrs/stmulator32/src/loader/binary.cpp

CMakeFiles/stmulator.dir/src/loader/binary.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/stmulator.dir/src/loader/binary.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ishdeshpa/Work/lhrs/stmulator32/src/loader/binary.cpp > CMakeFiles/stmulator.dir/src/loader/binary.cpp.i

CMakeFiles/stmulator.dir/src/loader/binary.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/stmulator.dir/src/loader/binary.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ishdeshpa/Work/lhrs/stmulator32/src/loader/binary.cpp -o CMakeFiles/stmulator.dir/src/loader/binary.cpp.s

# Object files for target stmulator
stmulator_OBJECTS = \
"CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o" \
"CMakeFiles/stmulator.dir/src/launcher.cpp.o" \
"CMakeFiles/stmulator.dir/src/loader/binary.cpp.o"

# External object files for target stmulator
stmulator_EXTERNAL_OBJECTS = \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/cs.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/Mapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/MCInst.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/MCInstrDesc.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/MCInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/MCRegisterInfo.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/SStream.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/utils.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMBaseInfo.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMDisassemblerExtension.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64BaseInfo.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64Disassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64DisassemblerExtension.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64InstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64Mapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64Module.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Mips/MipsDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Mips/MipsInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Mips/MipsMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Mips/MipsModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/PowerPC/PPCDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/PowerPC/PPCInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/PowerPC/PPCMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/PowerPC/PPCModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/X86/X86Disassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/X86/X86DisassemblerDecoder.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/X86/X86IntelInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/X86/X86InstPrinterCommon.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/X86/X86Mapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/X86/X86Module.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/X86/X86ATTInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Sparc/SparcDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Sparc/SparcInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Sparc/SparcMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Sparc/SparcModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZDisassemblerExtension.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZMCTargetDesc.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/XCore/XCoreDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/XCore/XCoreInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/XCore/XCoreMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/XCore/XCoreModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/M68K/M68KDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/M68K/M68KInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/M68K/M68KModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/TMS320C64x/TMS320C64xDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/TMS320C64x/TMS320C64xInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/TMS320C64x/TMS320C64xMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/TMS320C64x/TMS320C64xModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/M680X/M680XDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/M680X/M680XInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/M680X/M680XModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/EVM/EVMDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/EVM/EVMInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/EVM/EVMMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/EVM/EVMModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/WASM/WASMDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/WASM/WASMInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/WASM/WASMMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/WASM/WASMModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/MOS65XX/MOS65XXModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/MOS65XX/MOS65XXDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/BPF/BPFDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/BPF/BPFInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/BPF/BPFMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/BPF/BPFModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/RISCV/RISCVDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/RISCV/RISCVInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/RISCV/RISCVMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/RISCV/RISCVModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SH/SHDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SH/SHInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/SH/SHModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/TriCore/TriCoreDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/TriCore/TriCoreInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/TriCore/TriCoreMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/TriCore/TriCoreModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Alpha/AlphaDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Alpha/AlphaInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Alpha/AlphaMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Alpha/AlphaModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/HPPA/HPPADisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/HPPA/HPPAInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/HPPA/HPPAMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/HPPA/HPPAModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchDisassemblerExtension.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchModule.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Xtensa/XtensaDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Xtensa/XtensaInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Xtensa/XtensaMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/output/capstone_build/CMakeFiles/capstone.dir/arch/Xtensa/XtensaModule.c.o"

stmulator: CMakeFiles/stmulator.dir/src/engine/architecture.cpp.o
stmulator: CMakeFiles/stmulator.dir/src/launcher.cpp.o
stmulator: CMakeFiles/stmulator.dir/src/loader/binary.cpp.o
stmulator: capstone_build/CMakeFiles/capstone.dir/cs.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/Mapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/MCInst.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/MCInstrDesc.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/MCInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/MCRegisterInfo.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/SStream.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/utils.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMBaseInfo.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMDisassemblerExtension.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64BaseInfo.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64Disassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64DisassemblerExtension.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64InstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64Mapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/AArch64/AArch64Module.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Mips/MipsDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Mips/MipsInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Mips/MipsMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Mips/MipsModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/PowerPC/PPCDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/PowerPC/PPCInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/PowerPC/PPCMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/PowerPC/PPCModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/X86/X86Disassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/X86/X86DisassemblerDecoder.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/X86/X86IntelInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/X86/X86InstPrinterCommon.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/X86/X86Mapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/X86/X86Module.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/X86/X86ATTInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Sparc/SparcDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Sparc/SparcInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Sparc/SparcMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Sparc/SparcModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZDisassemblerExtension.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SystemZ/SystemZMCTargetDesc.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/XCore/XCoreDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/XCore/XCoreInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/XCore/XCoreMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/XCore/XCoreModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/M68K/M68KDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/M68K/M68KInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/M68K/M68KModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/TMS320C64x/TMS320C64xDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/TMS320C64x/TMS320C64xInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/TMS320C64x/TMS320C64xMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/TMS320C64x/TMS320C64xModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/M680X/M680XDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/M680X/M680XInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/M680X/M680XModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/EVM/EVMDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/EVM/EVMInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/EVM/EVMMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/EVM/EVMModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/WASM/WASMDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/WASM/WASMInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/WASM/WASMMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/WASM/WASMModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/MOS65XX/MOS65XXModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/MOS65XX/MOS65XXDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/BPF/BPFDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/BPF/BPFInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/BPF/BPFMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/BPF/BPFModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/RISCV/RISCVDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/RISCV/RISCVInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/RISCV/RISCVMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/RISCV/RISCVModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SH/SHDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SH/SHInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/SH/SHModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/TriCore/TriCoreDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/TriCore/TriCoreInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/TriCore/TriCoreMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/TriCore/TriCoreModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Alpha/AlphaDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Alpha/AlphaInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Alpha/AlphaMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Alpha/AlphaModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/HPPA/HPPADisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/HPPA/HPPAInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/HPPA/HPPAMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/HPPA/HPPAModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchDisassemblerExtension.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/LoongArch/LoongArchModule.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Xtensa/XtensaDisassembler.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Xtensa/XtensaInstPrinter.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Xtensa/XtensaMapping.c.o
stmulator: capstone_build/CMakeFiles/capstone.dir/arch/Xtensa/XtensaModule.c.o
stmulator: CMakeFiles/stmulator.dir/build.make
stmulator: CMakeFiles/stmulator.dir/compiler_depend.ts
stmulator: CMakeFiles/stmulator.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/ishdeshpa/Work/lhrs/stmulator32/output/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable stmulator"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/stmulator.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/stmulator.dir/build: stmulator
.PHONY : CMakeFiles/stmulator.dir/build

CMakeFiles/stmulator.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/stmulator.dir/cmake_clean.cmake
.PHONY : CMakeFiles/stmulator.dir/clean

CMakeFiles/stmulator.dir/depend:
	cd /home/ishdeshpa/Work/lhrs/stmulator32/output && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ishdeshpa/Work/lhrs/stmulator32 /home/ishdeshpa/Work/lhrs/stmulator32 /home/ishdeshpa/Work/lhrs/stmulator32/output /home/ishdeshpa/Work/lhrs/stmulator32/output /home/ishdeshpa/Work/lhrs/stmulator32/output/CMakeFiles/stmulator.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/stmulator.dir/depend

