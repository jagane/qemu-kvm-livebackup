asm(".code16gcc");

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned u32;
typedef unsigned long long u64;

static int strlen(const char *str)
{
	int n;

	for (n = 0; *str; ++str)
		++n;
	return n;
}

static void print_serial(const char *buf)
{
	unsigned long len = strlen(buf);

	asm volatile ("addr32/rep/outsb" : "+S"(buf), "+c"(len) : "d"(0xf1));
}

static void exit(int code)
{
        asm volatile("out %0, %1" : : "a"(code), "d"((short)0xf4));
}

struct regs {
	u32 eax, ebx, ecx, edx;
	u32 esi, edi, esp, ebp;
	u32 eip, eflags;
};

static u64 gdt[] = {
	0,
	0x00cf9b000000ffffull, // flat 32-bit code segment
	0x00cf93000000ffffull, // flat 32-bit data segment
};

static struct {
	u16 limit;
	void *base;
} __attribute__((packed)) gdt_descr = {
	sizeof(gdt) - 1,
	gdt,
};

static void exec_in_big_real_mode(const struct regs *inregs,
				  struct regs *outregs,
				  const u8 *insn, int insn_len)
{
	unsigned long tmp;
	static struct regs save;
	int i;
	extern u8 test_insn[], test_insn_end[];

	for (i = 0; i < insn_len; ++i)
		test_insn[i] = insn[i];
	for (; i < test_insn_end - test_insn; ++i)
		test_insn[i] = 0x90; // nop

	save = *inregs;
	asm volatile(
		"lgdtl %[gdt_descr] \n\t"
		"mov %%cr0, %[tmp] \n\t"
		"or $1, %[tmp] \n\t"
		"mov %[tmp], %%cr0 \n\t"
		"mov %[bigseg], %%gs \n\t"
		"and $-2, %[tmp] \n\t"
		"mov %[tmp], %%cr0 \n\t"

		"xchg %%eax, %[save]+0 \n\t"
		"xchg %%ebx, %[save]+4 \n\t"
		"xchg %%ecx, %[save]+8 \n\t"
		"xchg %%edx, %[save]+12 \n\t"
		"xchg %%esi, %[save]+16 \n\t"
		"xchg %%edi, %[save]+20 \n\t"
		"xchg %%esp, %[save]+24 \n\t"
		"xchg %%ebp, %[save]+28 \n\t"

		"test_insn: . = . + 16\n\t"
		"test_insn_end: \n\t"

		"xchg %%eax, %[save]+0 \n\t"
		"xchg %%ebx, %[save]+4 \n\t"
		"xchg %%ecx, %[save]+8 \n\t"
		"xchg %%edx, %[save]+12 \n\t"
		"xchg %%esi, %[save]+16 \n\t"
		"xchg %%edi, %[save]+20 \n\t"
		"xchg %%esp, %[save]+24 \n\t"
		"xchg %%ebp, %[save]+28 \n\t"

		/* Save EFLAGS in outregs*/
		"pushfl \n\t"
		"popl %[save]+36 \n\t"

		"xor %[tmp], %[tmp] \n\t"
		"mov %[tmp], %%gs \n\t"
		: [tmp]"=&r"(tmp), [save]"+m"(save)
		: [gdt_descr]"m"(gdt_descr), [bigseg]"r"((short)16)
		: "cc", "memory"
		);
	*outregs = save;
}

#define R_AX 1
#define R_BX 2
#define R_CX 4
#define R_DX 8
#define R_SI 16
#define R_DI 32
#define R_SP 64
#define R_BP 128

int regs_equal(const struct regs *r1, const struct regs *r2, int ignore)
{
	const u32 *p1 = &r1->eax, *p2 = &r2->eax;  // yuck
	int i;

	for (i = 0; i < 8; ++i)
		if (!(ignore & (1 << i)) && p1[i] != p2[i])
			return 0;
	return 1;
}

#define MK_INSN(name, str)                         \
	asm (				           \
		".pushsection \".text\" \n\t"	   \
		"insn_" #name ": " str " \n\t"	   \
		"insn_" #name "_end: \n\t"	   \
		".popsection \n\t"		   \
		);				   \
	extern u8 insn_##name[], insn_##name##_end[]

void test_mov_imm(const struct regs *inregs, struct regs *outregs)
{
	MK_INSN(mov_r32_imm_1, "mov $1234567890, %eax");
	MK_INSN(mov_r16_imm_1, "mov $1234, %ax");
	MK_INSN(mov_r8_imm_1, "mov $0x12, %ah");
	MK_INSN(mov_r8_imm_2, "mov $0x34, %al");
	MK_INSN(mov_r8_imm_3, "mov $0x12, %ah\n\t" "mov $0x34, %al\n\t");

	exec_in_big_real_mode(inregs, outregs,
			      insn_mov_r16_imm_1,
			      insn_mov_r16_imm_1_end - insn_mov_r16_imm_1);
	if (!regs_equal(inregs, outregs, R_AX) || outregs->eax != 1234)
		print_serial("mov test 1: FAIL\n");

	/* test mov $imm, %eax */
	exec_in_big_real_mode(inregs, outregs,
			      insn_mov_r32_imm_1,
			      insn_mov_r32_imm_1_end - insn_mov_r32_imm_1);
	if (!regs_equal(inregs, outregs, R_AX) || outregs->eax != 1234567890)
		print_serial("mov test 2: FAIL\n");

	/* test mov $imm, %al/%ah */
	exec_in_big_real_mode(inregs, outregs,
			      insn_mov_r8_imm_1,
			      insn_mov_r8_imm_1_end - insn_mov_r8_imm_1);
	if (!regs_equal(inregs, outregs, R_AX) || outregs->eax != 0x1200)
		print_serial("mov test 3: FAIL\n");
	exec_in_big_real_mode(inregs, outregs,
			      insn_mov_r8_imm_2,
			      insn_mov_r8_imm_2_end - insn_mov_r8_imm_2);
	if (!regs_equal(inregs, outregs, R_AX) || outregs->eax != 0x34)
		print_serial("mov test 4: FAIL\n");
	exec_in_big_real_mode(inregs, outregs,
			      insn_mov_r8_imm_3,
			      insn_mov_r8_imm_3_end - insn_mov_r8_imm_3);
	if (!regs_equal(inregs, outregs, R_AX) || outregs->eax != 0x1234)
		print_serial("mov test 5: FAIL\n");
}

void test_eflags_insn(struct regs *inregs, struct regs *outregs)
{
	MK_INSN(clc, "clc");
	MK_INSN(cli, "cli");
	MK_INSN(sti, "sti");
	MK_INSN(cld, "cld");
	MK_INSN(std, "std");

	exec_in_big_real_mode(inregs, outregs,
			      insn_clc,
			      insn_clc_end - insn_clc);
	if(outregs->eflags & 1)
		print_serial("clc test: FAIL\n");

	exec_in_big_real_mode(inregs, outregs,
			      insn_cli,
			      insn_cli_end - insn_cli);
	if(outregs->eflags & (1 << 9))
		print_serial("cli test: FAIL\n");

	exec_in_big_real_mode(inregs, outregs,
			      insn_sti,
			      insn_sti_end - insn_sti);
	if(!(outregs->eflags & (1 << 9)))
		print_serial("sti test: FAIL\n");

	exec_in_big_real_mode(inregs, outregs,
			      insn_cld,
			      insn_cld_end - insn_cld);
	if(outregs->eflags & (1 << 10))
		print_serial("cld test: FAIL\n");

	exec_in_big_real_mode(inregs, outregs,
			      insn_std,
			      insn_std_end - insn_std);
	if(!(outregs->eflags & (1 << 10)))
		print_serial("std test: FAIL\n");
}

void start(void)
{
	struct regs inregs = { 0 }, outregs;

	print_serial("abc\n");
	exec_in_big_real_mode(&inregs, &outregs, 0, 0);
	if (!regs_equal(&inregs, &outregs, 0))
		print_serial("null test: FAIL\n");
	test_mov_imm(&inregs, &outregs);
	test_eflags_insn(&inregs, &outregs);
	exit(0);
}

asm(
	".data \n\t"
	". = . + 4096 \n\t"
	"stacktop: \n\t"
	".text \n\t"
	"init: \n\t"
	"xor %ax, %ax \n\t"
	"mov %ax, %ds \n\t"
	"mov %ax, %es \n\t"
	"mov %ax, %ss \n\t"
	"mov $0x4000, %cx \n\t"
	"xor %esi, %esi \n\t"
	"mov %esi, %edi \n\t"
	"rep/addr32/cs/movsl \n\t"
	"mov $stacktop, %sp\n\t"
	"ljmp $0, $start \n\t"
	".pushsection .boot, \"ax\" \n\t"
	"ljmp $0xf000, $init \n\t"
	".popsection"
	);