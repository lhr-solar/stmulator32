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
CMAKE_BINARY_DIR = /home/ishdeshpa/Work/lhrs/stmulator32/build

# Include any dependencies generated for this target.
include capstone_build/CMakeFiles/fuzz_disasm.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include capstone_build/CMakeFiles/fuzz_disasm.dir/compiler_depend.make

# Include the progress variables for this target.
include capstone_build/CMakeFiles/fuzz_disasm.dir/progress.make

# Include the compile flags for this target's objects.
include capstone_build/CMakeFiles/fuzz_disasm.dir/flags.make

capstone_build/CMakeFiles/fuzz_disasm.dir/codegen:
.PHONY : capstone_build/CMakeFiles/fuzz_disasm.dir/codegen

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o: capstone_build/CMakeFiles/fuzz_disasm.dir/flags.make
capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o: /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/onefile.c
capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o: capstone_build/CMakeFiles/fuzz_disasm.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ishdeshpa/Work/lhrs/stmulator32/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o -MF CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o.d -o CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o -c /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/onefile.c

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.i"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/onefile.c > CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.i

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.s"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/onefile.c -o CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.s

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o: capstone_build/CMakeFiles/fuzz_disasm.dir/flags.make
capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o: /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/fuzz_disasm.c
capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o: capstone_build/CMakeFiles/fuzz_disasm.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ishdeshpa/Work/lhrs/stmulator32/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o -MF CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o.d -o CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o -c /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/fuzz_disasm.c

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.i"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/fuzz_disasm.c > CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.i

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.s"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/fuzz_disasm.c -o CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.s

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o: capstone_build/CMakeFiles/fuzz_disasm.dir/flags.make
capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o: /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/platform.c
capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o: capstone_build/CMakeFiles/fuzz_disasm.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ishdeshpa/Work/lhrs/stmulator32/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o -MF CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o.d -o CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o -c /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/platform.c

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.i"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/platform.c > CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.i

capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.s"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ishdeshpa/Work/lhrs/stmulator32/capstone/suite/fuzz/platform.c -o CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.s

# Object files for target fuzz_disasm
fuzz_disasm_OBJECTS = \
"CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o" \
"CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o" \
"CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o"

# External object files for target fuzz_disasm
fuzz_disasm_EXTERNAL_OBJECTS = \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/cs.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/Mapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/MCInst.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/MCInstrDesc.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/MCInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/MCRegisterInfo.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/SStream.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/utils.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMBaseInfo.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMDisassembler.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMDisassemblerExtension.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMInstPrinter.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMMapping.c.o" \
"/home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMModule.c.o"

capstone_build/fuzz_disasm: capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/onefile.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/fuzz_disasm.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/fuzz_disasm.dir/suite/fuzz/platform.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/cs.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/Mapping.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/MCInst.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/MCInstrDesc.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/MCInstPrinter.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/MCRegisterInfo.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/SStream.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/utils.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMBaseInfo.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMDisassembler.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMDisassemblerExtension.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMInstPrinter.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMMapping.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/capstone.dir/arch/ARM/ARMModule.c.o
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/fuzz_disasm.dir/build.make
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/fuzz_disasm.dir/compiler_depend.ts
capstone_build/fuzz_disasm: capstone_build/CMakeFiles/fuzz_disasm.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/ishdeshpa/Work/lhrs/stmulator32/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable fuzz_disasm"
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/fuzz_disasm.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
capstone_build/CMakeFiles/fuzz_disasm.dir/build: capstone_build/fuzz_disasm
.PHONY : capstone_build/CMakeFiles/fuzz_disasm.dir/build

capstone_build/CMakeFiles/fuzz_disasm.dir/clean:
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build && $(CMAKE_COMMAND) -P CMakeFiles/fuzz_disasm.dir/cmake_clean.cmake
.PHONY : capstone_build/CMakeFiles/fuzz_disasm.dir/clean

capstone_build/CMakeFiles/fuzz_disasm.dir/depend:
	cd /home/ishdeshpa/Work/lhrs/stmulator32/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ishdeshpa/Work/lhrs/stmulator32 /home/ishdeshpa/Work/lhrs/stmulator32/capstone /home/ishdeshpa/Work/lhrs/stmulator32/build /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build /home/ishdeshpa/Work/lhrs/stmulator32/build/capstone_build/CMakeFiles/fuzz_disasm.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : capstone_build/CMakeFiles/fuzz_disasm.dir/depend

