/*
 *    Copyright IBM Corp. 2015
 */

#ifndef S390_GEN_FACILITIES_C
#error "This file can only be included by gen_facilities.c"
#endif

#include <linux/kconfig.h>

struct facility_def {
	char *name;
	int *bits;
};

static struct facility_def facility_defs[] = {
	{
		/*
		 * FACILITIES_ALS contains the list of facilities that are
		 * required to run a kernel that is compiled e.g. with
		 * -march=<machine>.
		 */
		.name = "FACILITIES_ALS",
		.bits = (int[]){
#ifdef CONFIG_HAVE_MARCH_Z900_FEATURES
			0,  /* N3 instructions */
			1,  /* z/Arch mode installed */
#endif
#ifdef CONFIG_HAVE_MARCH_Z990_FEATURES
			18, /* long displacement facility */
#endif
#ifdef CONFIG_HAVE_MARCH_Z9_109_FEATURES
			7,  /* stfle */
			17, /* message security assist */
			21, /* extended-immediate facility */
			25, /* store clock fast */
#endif
#ifdef CONFIG_HAVE_MARCH_Z10_FEATURES
			27, /* mvcos */
			32, /* compare and swap and store */
			33, /* compare and swap and store 2 */
			34, /* general extension facility */
			35, /* execute extensions */
#endif
#ifdef CONFIG_HAVE_MARCH_Z196_FEATURES
			45, /* fast-BCR, etc. */
#endif
#ifdef CONFIG_HAVE_MARCH_ZEC12_FEATURES
			49, /* misc-instruction-extensions */
			52, /* interlocked facility 2 */
#endif
#ifdef CONFIG_HAVE_MARCH_Z13_FEATURES
			53, /* load-and-zero-rightmost-byte, etc. */
#endif
			-1 /* END */
		}
	},
};
