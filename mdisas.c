// public domain single-file tracing disassembler
// TODO tracing

#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

int load_offset = 0x100;

const char* const regs[8] = {
	"ax",
	"cx",
	"dx",
	"bx",
	"sp",
	"bp",
	"si",
	"di"
};

const char* const halfregs[8] = {
	"al",
	"cl",
	"dl",
	"bl",
	"ah",
	"ch",
	"dh",
	"bh",
};

// flags: 000000pm
// p - prefix byte
// m - malloc'ed
int xdecode(char** str, uint8_t* op, uint32_t addr, uint8_t* flags) {
	
	// push+pop, inc+dec, 32 opcodes total
	if((*op & 0xF8) == 0x58) {
		*str = memcpy(malloc(7), "pop \0\0", 7);
		*((uint16_t*)(*str + 4)) = *((uint16_t*)regs[*op & 7]);
		return (*flags = 1);
	} else if((*op & 0xF8) == 0x50) {
		*str = memcpy(malloc(8), "push \0\0", 8);
		*((uint16_t*)(*str + 5)) = *((uint16_t*)regs[*op & 7]);
		return (*flags = 1);
	} else if((*op & 0xF0) == 0x40) {
		*str = memcpy(malloc(7), "inc \0\0", 7);
		if(*op & 0x8) *((uint16_t*)(*str)) = *((uint16_t*)"de");
		*((uint16_t*)(*str + 4)) = *((uint16_t*)regs[*op & 7]);
		return (*flags = 1);
	} else if((*op & 0xF8) == 0x90 && *op != 0x90) {
		*str = memcpy(malloc(12), "xchg ax, \0\0", 12);
		*((uint16_t*)(*str + 9)) = *((uint16_t*)regs[*op & 7]);
		return (*flags = 1);
	} else if((*op & 0xF8) == 0xB0) {
		*str = memcpy(malloc(12), "mov \0\0, 0x\0\0", 12);
		*((uint16_t*)(*str + 4)) = *((uint16_t*)halfregs[*op & 7]);
		sprintf(*str + 10, "%02X", *(op+1));
		return (*flags = 1) + 1;
	} else if((*op & 0xF8) == 0xB8) {
		*str = memcpy(malloc(12), "mov \0\0, 0x\0\0\0\0", 12);
		*((uint16_t*)(*str + 4)) = *((uint16_t*)regs[*op & 7]);
		sprintf(*str + 10, "%04X", *(uint16_t*)(op+1));
		return (*flags = 1) + 2;
	}


	long swpl;

#define stat1op(A, B) case A: *str = B; return !(*flags = 0); break
#define stat1pre(A, B) case A: *str = B; return !!(*flags = 2); break
#define dy2opim8(A, B) case A: *str = B; swpl = strlen(*str) + 6; *str = memcpy(malloc(swpl), B" 0x\0\0", swpl); sprintf(*str + swpl - 3, "%02X", *(op + 1)); *flags = 1; return 2; break
#define dy3opim16(A, B) case A: *str = B; swpl = strlen(*str) + 8; *str = memcpy(malloc(swpl), B" 0x\0\0\0\0", swpl); sprintf(*str + swpl - 5, "%04X", *(uint16_t*)(op + 1)); *flags = 1; return 3; break
#define dy2oprl8(A, B) case A: *str = B; swpl = strlen(*str) + 8; *str = memcpy(malloc(swpl), B" 0x\0\0\0\0", swpl); sprintf(*str + swpl - 5, "%04X", addr + 2 + (int8_t)(*(op + 1))); *flags = 1; return 2; break
	// 35 opcodes
	switch(*op) {
		dy2opim8(0x04, "add al,");
		dy3opim16(0x05, "add ax,");
		stat1op(0x06, "push es");
		stat1op(0x07, "pop es");
		dy2opim8(0x0C, "or al,");
		dy3opim16(0x0D, "or ax,");
		stat1op(0x0E, "push cs");
		stat1op(0x0F, "%%error \"pop cs\"");
		
		dy2opim8(0x14, "adc al,");
		dy3opim16(0x15, "adc ax,");
		stat1op(0x16, "push ss");
		stat1op(0x17, "pop ss");
		dy2opim8(0x1C, "sbb al,");
		dy3opim16(0x1D, "sbb ax,");
		stat1op(0x1E, "push ds");
		stat1op(0x1F, "pop ds");
		
		dy2opim8(0x24, "and al,");
		dy3opim16(0x25, "and ax,");
		stat1pre(0x26, "es");
		stat1op(0x27, "daa");
		dy2opim8(0x2C, "sub al,");
		dy3opim16(0x2D, "sub ax,");
		stat1pre(0x2E, "cs");
		stat1op(0x2F, "das");

		dy2opim8(0x34, "xor al,");
		dy3opim16(0x35, "xor ax,");
		stat1pre(0x36, "ss");
		stat1op(0x37, "aaa");
		dy2opim8(0x3C, "cmp al,");
		dy3opim16(0x3D, "cmp ax,");
		stat1pre(0x3E, "ds");
		stat1op(0x3F, "aas");
		
		// 40-5F insdec

		stat1op(0x60, "pusha");
		stat1op(0x61, "popa");
		stat1pre(0x64, "fs");
		stat1pre(0x65, "gs");
	stat1op(0x66, "db 0x66 ; data override");
	stat1op(0x67, "db 0x67 ; addr override");
		dy2opim8(0x6A, "push byte"); // sign extended :/
		stat1op(0x6C, "insb");
		stat1op(0x6D, "insw");
		stat1op(0x6E, "outsb");
		stat1op(0x6F, "outsw");
		
		dy2oprl8(0x70, "jo");
		dy2oprl8(0x71, "jno");
		dy2oprl8(0x72, "jc");
		dy2oprl8(0x73, "jnc");
		dy2oprl8(0x74, "jz");
		dy2oprl8(0x75, "jnz");
		dy2oprl8(0x76, "jna");
		dy2oprl8(0x77, "ja");
		dy2oprl8(0x78, "js");
		dy2oprl8(0x79, "jns");
		dy2oprl8(0x7A, "jpe");
		dy2oprl8(0x7B, "jpo");
		dy2oprl8(0x7C, "jl");
		dy2oprl8(0x7D, "jnl");
		dy2oprl8(0x7E, "jng");
		dy2oprl8(0x7F, "jg"); // TODO may have to be specified 'short'

		stat1op(0x90, "nop");
		stat1op(0x98, "cbw");
		stat1op(0x99, "cwd");
		stat1pre(0x9B, "wait");
		stat1op(0x9C, "pushf");
		stat1op(0x9D, "popf");
		stat1op(0x9E, "sahf");
		stat1op(0x9F, "lahf");

		stat1op(0xA6, "cmpsb");
		stat1op(0xA7, "cmpsw");
		stat1op(0xAA, "stosb");
		stat1op(0xAB, "stosw");
		stat1op(0xAC, "lodsb");
		stat1op(0xAD, "lodsw");
		stat1op(0xAE, "scasb");
		stat1op(0xAF, "scasw");
		
		stat1op(0xC3, "ret");
		stat1op(0xC9, "leave");
		stat1op(0xCB, "retf");
		stat1op(0xCC, "int3");
		dy2opim8(0xCD, "int");
		stat1op(0xCE, "into");
		stat1op(0xCF, "iret");
		
		dy2opim8(0xD4, "aam");
		dy2opim8(0xD5, "aad");
		stat1op(0xD6, "salc");
		stat1op(0xD7, "xlat");
		
		dy2oprl8(0xE3, "jcxz");
		dy2opim8(0xE4, "in al,");
		dy2opim8(0xE5, "in ax,");
		stat1op(0xEC, "in al, dx");
		stat1op(0xED, "in ax, dx");
		stat1op(0xEE, "out dx, al");
		stat1op(0xEF, "out dx, ax");

		stat1pre(0xF0, "lock");
		stat1op(0xF1, "int1");
		stat1pre(0xF2, "repnz");
		stat1pre(0xF3, "rep");
		stat1op(0xF4, "hlt");
		stat1op(0xF5, "cmc");
		stat1op(0xF8, "clc");
		stat1op(0xF9, "stc");
		stat1op(0xFA, "cli");
		stat1op(0xFB, "sti");
		stat1op(0xFC, "cld");
		stat1op(0xFD, "std");
		default:
			return -1;
			break;
	}
}

int main(int argc, char** argv) {
	if(argc != 2) err: return printf("could not open file\n");
	int fd;
	uint8_t* mem;
	struct stat s;
	if(
		(fd = open(argv[1], O_RDONLY)) < 0 ||
		fstat(fd, &s) ||
		(mem = mmap(0, s.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED
	) goto err;

	int lp = 0, cp = 0, nd = 0;
	printf("opcodes unsupported\n");
	for(long o = 0; o < 256; o++) {
		char* s;
		uint8_t m = 0;
		cp = (o+1) >> 4;
		if(xdecode(&s, &o, 0, &m) < 0) nd += !!printf("%02X ", o);
		if(lp ^ cp) putchar('\n');
		if(m & 1) free(s);
		lp = cp;
	}

	printf("\n== %i (%.02f%%) ok, %i err ==================================================\n\n", 256-nd, ((double)(256-nd))/2.56, nd);

	printf(
		"[bits 16]\n"
		"[org 0x%04X]\n"
		, load_offset
	);

	long p = 0, prefixl = 0;
	char* ins;
	uint8_t m, prefix = 0;
	while(1) {
		int l = xdecode(&ins, mem + p, p + load_offset, &m);
		if(l < 0) {
			printf("%%error \"unknown opcode at 0x%04X\"\n", p + load_offset);
			break;
		}
		if(!(m & 2)) {
			prefix = !printf("%s\t; 0x%04X\n", ins, (prefix ? prefixl : p) + load_offset);
		} else {
			if(!prefix) prefixl = p;
			prefix = printf("%s ", ins);
		}
		p += l;
		if(m & 1) free(ins);
		if(p >= s.st_size) break;
	}

}
