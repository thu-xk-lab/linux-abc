#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/win_minmax.h>

struct lbbr {
};

static struct tcp_congestion_ops tcp_lbbr_cong_ops __read_mostly = {
	.flags 		= TCP_CONG_NON_RESTRICTED,
	.name 		= "lbbr",
	.owner 		= THIS_MODULE,
	.ssthresh 	= tcp_reno_ssthresh,
	.cong_avoid 	= tcp_reno_cong_avoid,
};

static int __init lbbr_register(void) {
	BUILD_BUG_ON(sizeof(struct lbbr) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_lbbr_cong_ops);
}

static void __exit lbbr_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_lbbr_cong_ops);
}

module_init(lbbr_register);
module_exit(lbbr_unregister);

MODULE_AUTHOR("Xiangxiang Wang <wxx15@mails.tsinghua.edu.cn>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP Linear BBR");

