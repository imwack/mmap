#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xe00b4984, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x2fdef982, __VMLINUX_SYMBOL_STR(seq_release) },
	{ 0xe887354a, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0x7c4c2659, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0x4302d0eb, __VMLINUX_SYMBOL_STR(free_pages) },
	{ 0x34987a5f, __VMLINUX_SYMBOL_STR(mem_map) },
	{ 0x93fca811, __VMLINUX_SYMBOL_STR(__get_free_pages) },
	{ 0xe839969f, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0x7002429a, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0x2e60bace, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x945e4c08, __VMLINUX_SYMBOL_STR(remove_proc_entry) },
	{ 0x99c316ce, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0x3bcc8c0, __VMLINUX_SYMBOL_STR(proc_mkdir) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x7105e20d, __VMLINUX_SYMBOL_STR(remap_pfn_range) },
	{ 0xfd485ec8, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0x990395ac, __VMLINUX_SYMBOL_STR(single_open) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "CA7C058CDAE2119A87775D5");
