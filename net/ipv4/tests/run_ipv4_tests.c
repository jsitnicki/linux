#include <linux/module.h>


extern void test_fib_select_multipath(void);


static int __init run_ipv4_tests_init(void)
{
	test_fib_select_multipath();
	return 0;
}
module_init(run_ipv4_tests_init);

static void __exit run_ipv4_tests_exit(void)
{
}
module_exit(run_ipv4_tests_exit);


MODULE_LICENSE("GPL");

