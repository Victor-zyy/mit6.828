// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display the function stack backtrace about the kernel", mon_backtrace },
	{ "showmappings", "Display the physical page mappings about the kernel", mon_showmappings },
	{ "pagepermission", "Chaneg the virtual page permission about the kernel", mon_pagepermission },
	{ "dump", "dump the virtual addr or physical addr contents", mon_dump },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	int i = 0;
	uint32_t ebp = read_ebp();
	uint32_t eip;
	uint32_t args[5];
	struct Eipdebuginfo info;
	cprintf("Stack backtrace:\n");
	do{
		eip = *(uint32_t *)(ebp + 4);
		for(i = 0; i < 5; i++){
			args[i] = *(uint32_t *)(ebp + 4 * (i + 2));
		}
		cprintf("    ebp %08x eip %08x args %08x %08x %08x %08x %08x\n", ebp, eip, args[0], args[1], args[2], args[3], args[4]);

		debuginfo_eip(eip, &info);
		cprintf("        %s:%d: %.*s+%d\n", info.eip_file, info.eip_line, info.eip_fn_namelen, info.eip_fn_name, eip - info.eip_fn_addr);
		ebp = *(uint32_t *)ebp;
	}while(ebp != 0);

	return 0;
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
		//monitor format:
		//showmappings start_virtual_address  end_virtual_address
		if(argc != 3){
			cprintf("Usage: %s start_virtual end_virtual_address!(address_format:hexadecimal)\n", argv[0]);
			return 0;
		}
		
		// convert string to address number
		char *end_ptr = argv[1] + strlen(argv[1]);
		uint32_t v_start = strtol(argv[1], &end_ptr, 16);
		v_start = ROUNDDOWN(v_start, PGSIZE);
		end_ptr = argv[2] + strlen(argv[2]);
		uint32_t v_end = strtol(argv[2], &end_ptr, 16);
		v_end = ROUNDUP(v_end, PGSIZE);

		if(v_start > v_end){
			cprintf("Usage: %s start_virtual end_virtual_address!(address_format:hexadecimal)\n", argv[0]);
			return 0;
		}
		struct PageInfo *pg_info;
		pte_t *p_pte;
		// find the pte_entry of each virtual address
		for(v_start; v_start < v_end; v_start += PGSIZE){
			pg_info = page_lookup(kern_pgdir, (void *)v_start, &p_pte);
			if(pg_info == NULL){
				cprintf("Before V_addr: 0x%08x\t lack\n", v_start);
			}else{
				cprintf("After  V_addr: 0x%08x\t pte: 0x%08x\t P_addr: 0x%08x\n", v_start, *p_pte, (*p_pte & ~0xfff));	
			}
		}

		return 0;

}

int
mon_pagepermission(int argc, char **argv, struct Trapframe *tf)
{
	//pagepermission virtual address permission
		if(argc != 3){
			cprintf("Usage: %s virtual_addr permission(hexadecimal)\n", argv[0]);
			return 0;
		}
		
		char *end_ptr = argv[1] + strlen(argv[1]);
		uint32_t v_addr = strtol(argv[1], &end_ptr, 16);
		end_ptr = argv[2] + strlen(argv[2]);
		uint32_t permission = strtol(argv[2], &end_ptr, 16);

		struct PageInfo *pg_info;
		pte_t *p_pte;
		pg_info = page_lookup(kern_pgdir, (void *)v_addr, &p_pte);
		if(pg_info == NULL){
			cprintf("V_addr: 0x%08x\t lack\n", v_addr);
			return 0;
		}

		cprintf("V_addr: 0x%08x\t pte: 0x%08x\t P_addr: 0x%08x\n", v_addr, *p_pte, (*p_pte & ~0xfff));	
		*p_pte = (*p_pte & ~0xfff )	| permission;
		cprintf("V_addr: 0x%08x\t pte: 0x%08x\t P_addr: 0x%08x\n", v_addr, *p_pte, (*p_pte & ~0xfff));	

		return 0;	
	
}

int
mon_dump(int argc, char **argv, struct Trapframe *tf)
{

		//
		if(argc != 4){
			cprintf("Usage: %s virt_addr(1)/phy_addr(0) address number(hexadecimal)\n", argv[0]);
			return 0;
		}
		char *end_ptr = argv[1] + strlen(argv[1]);
		int flag = strtol(argv[1], &end_ptr, 10);

		end_ptr = argv[2] + strlen(argv[2]);
		uint32_t addr = strtol(argv[2], &end_ptr, 16);

		end_ptr = argv[3] + strlen(argv[3]);
		uint32_t num = strtol(argv[3], &end_ptr, 16);

		if(flag){
			struct PageInfo *pg_info;
			pte_t *p_pte;
			pg_info = page_lookup(kern_pgdir, (void *)addr, &p_pte);
			physaddr_t p_addr = (*p_pte & ~0xfff) | (addr & 0xfff);
			// necessary judgement to ensure the range extends across boundaries
			for(int i = 0; i < num / 4; i++){
				cprintf("0x%08x: 0x%08x\n", addr, *(physaddr_t*)(KADDR(p_addr)));
				p_addr += 4;
				addr += 4;
			}
		}else{
			for(int i = 0; i < num; i++){
				cprintf("0x%08x: 0x%08x\n", addr, *(physaddr_t*)(KADDR(addr)));
				addr += 4;
			}
		}	
		return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
