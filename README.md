# mdisas

worlds best 8086 disassembler actually. dont look at the code

## why

i want to reverse engineer some dos software but none of the disassemblers ive found are any good. i want something that outputs code i can put directly into nasm, distinguishes between code and data, and does not get desynced as often as something like ndisasm

## scope

32/64 bit code will not be supported because i do not need it. it may support mz exe in the future but it is currently meant for flat binaries (com for example)

## opcodes

most 1-byte opcodes are supported. 2-byte/modrm support is in progress and going *very* slowly because i am allergic to the x86 manual
