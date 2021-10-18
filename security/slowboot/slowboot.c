// SPDX-License-Identifier: GPL-2.0-or-later

#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/fips.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/limits.h>


#define SLWBT_MODE_REG 1
#define SLWBT_MODE_TPM 2
#define SLWBT_MODE_TPM2 3

#define SHA512_HASH_LEN 130

static u32 mode;
static int failures;

typedef struct slowboot_validation_item {
	char hash[130];
	char path[PATH_MAX];
	int is_ok;
} slowboot_validation_item;

static void svi_reg(slowboot_validation_item *item,
		const char *hash,
		const char *path)
{
	strncpy(item->hash, hash, SHA512_HASH_LEN);
	strncpy(item->path, path, PATH_MAX);
	
	switch (mode) {
	case SLWBT_MODE_TPM:
		break;
	case SLWBT_MODE_TPM2:
		break;
	default:
		break;		
	}
}

static void slowboot_validate_item (slowboot_validation_item *item)
{
	//TODO, flip_open, hash, check, set
}

static void slowboot_run_test(void)
{
	int j;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//##########TEMPLATE_INIT_SP###########=>
	slowboot_validation_item validation_items[1];
	int validation_count = 1;
	svi_reg(&(validation_items[0]),
		"a904877f33c094a4a8ebda9c2a5ded89f2817a275d9769f9ed834c1d19e2beb7dd9bcbbbd51c6af204b51d8a443900dd9cead0429e5c875b877331e53937ace1",
		"/home/corycraig/configuration_file.config"
	);
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	failures = 0;
//##########TEMPLATE_DROP_IN###########=>
	for (j = 0; j < validation_count; j++) {
		slowboot_validate_item(&(validation_items[j]));
	}
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
}

static int __init slowboot_mod_init(void)
{
	printk(KERN_INFO "%u\n", mode);
	if (mode == 0)
		mode = SLWBT_MODE_REG;
	switch (mode) {
	case SLWBT_MODE_REG:
		slowboot_run_test();
		break;
	default:
		break;
	}
	return 0;
}

static void __exit slowboot_mod_exit(void) { }

late_initcall(slowboot_mod_init);
module_exit(slowboot_mod_exit);

module_param(mode, uint, 1);
MODULE_PARM_DESC(mode, "Validation Method");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Comprehensive validation of critical files on boot");
MODULE_AUTHOR("Cory Craig <cory_craig@mail.com>");

