# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

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
CMAKE_SOURCE_DIR = /root/stmulator32/output

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/stmulator32/output

# Include any dependencies generated for this target.
include CMakeFiles/stmulator.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/stmulator.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/stmulator.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/stmulator.dir/flags.make

CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o: CMakeFiles/stmulator.dir/flags.make
CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o: /root/stmulator32/src/launcher.cpp
CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o: CMakeFiles/stmulator.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/stmulator32/output/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o -MF CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o.d -o CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o -c /root/stmulator32/src/launcher.cpp

CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/stmulator32/src/launcher.cpp > CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.i

CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/stmulator32/src/launcher.cpp -o CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.s

CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o: CMakeFiles/stmulator.dir/flags.make
CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o: /root/stmulator32/src/loader/binary.cpp
CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o: CMakeFiles/stmulator.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/stmulator32/output/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o -MF CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o.d -o CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o -c /root/stmulator32/src/loader/binary.cpp

CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/stmulator32/src/loader/binary.cpp > CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.i

CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/stmulator32/src/loader/binary.cpp -o CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.s

# Object files for target stmulator
stmulator_OBJECTS = \
"CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o" \
"CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o"

# External object files for target stmulator
stmulator_EXTERNAL_OBJECTS =

stmulator: CMakeFiles/stmulator.dir/root/stmulator32/src/launcher.cpp.o
stmulator: CMakeFiles/stmulator.dir/root/stmulator32/src/loader/binary.cpp.o
stmulator: CMakeFiles/stmulator.dir/build.make
stmulator: CMakeFiles/stmulator.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/stmulator32/output/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable stmulator"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/stmulator.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/stmulator.dir/build: stmulator
.PHONY : CMakeFiles/stmulator.dir/build

CMakeFiles/stmulator.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/stmulator.dir/cmake_clean.cmake
.PHONY : CMakeFiles/stmulator.dir/clean

CMakeFiles/stmulator.dir/depend:
	cd /root/stmulator32/output && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/stmulator32/output /root/stmulator32/output /root/stmulator32/output /root/stmulator32/output /root/stmulator32/output/CMakeFiles/stmulator.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/stmulator.dir/depend

