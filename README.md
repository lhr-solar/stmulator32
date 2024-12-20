# stmulator32
Pronounced "Stemulator" for STM-Simulator. Being developed for e-team purposes in hopes of accurately emulating the STM32 processors used on boards.

# Timeline
- [x] Read and parse ARM assembly from raw .bin files
- [ ] Memory regions and mappings
- [ ] Instruction fetch / decode / execute from simulated memory (RISC)
- [ ] STM32x4 core register maps
- [ ] Memory-mapped IO implementations
- [ ] Peripheral support: registers and hardware emulation (FIFOs)
- [ ] Unit testing

# How to use
To build, run ``maker build``. To execute, run ``maker run``. Requirements can be installed with ``./requirements.sh``.
