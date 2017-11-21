#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/win_minmax.h>

#define BW_SCALE	24
#define BW_UNIT		(1 << BW_SCALE)

#define LBBR_SCALE	8
#define LBBR_UNIT	(1 << LBBR_SCALE)

enum lbbr_mode {
	LBBR_STARTUP,		/* ramp up sending rate rapidly to fill pipe */
	LBBR_CONG_AVOID,	/* congestion avoid phase as defined in (New)Reno */
};

struct lbbr {
	u32	min_rtt_us;		/* Min round trip time */
	u32	min_rtt_stamp;		/* Timestamp of min_rtt_us */
	struct minmax bw;		/* Max recent delivery rate in pkt/usec << 24 */
	u32	ssthresh;		/* ssthresh to start cong_avoid */
	u32	next_rtt_delivered;	/* scb->tx.delivered at end of round */
	u32	rtt_cnt;		/* count of packet-timed rounds elapsed */
	u32	full_bw;		/* recent bw, to estimate if pipe is full */
	u32	full_bw_count:3,	/* number of rounds without large bw gains */
		cwnd_gain:10,		/* current gain for setting cwnd */
		unused:19;
};

/* Window length of bw filter (in rounds): */
static const int lbbr_bw_rtts = 10;
/* Window length of min_rtt filter (in sec): */
static const u32 lbbr_min_rtt_with_sec = 10;
/* Minimum time (in ms) spent at lbbr_cwnd_min_target in LBBR_PROBE_RTT mode: */
static const u32 lbbr_probe_rtt_mode_ms = 200;

/* The gain for startup phase */
static const int lbbr_startup_gain = LBBR_UNIT * 2884 / 1000;
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
static const int lbbr_cwnd_gain = LBBR_UNIT * 2;

/* If bw has increased significantly (1.25x), there may be more bw available */
static const u32 lbbr_full_bw_thresh = LBBR_UNIT * 5 / 4;
/* But after 3 rounds w/o significant bw growth, estimate pipe is full */
static const u32 lbbr_full_bw_count = 3;

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 lbbr_cwnd_min_target = 4;

static bool lbbr_full_bw_reached(const struct sock *sk)
{
	const struct lbbr *lbbr = inet_csk_ca(sk);

	return lbbr->full_bw_count >= lbbr_full_bw_count;
}

static u32 lbbr_max_bw(struct sock *sk)
{
	const struct lbbr *lbbr = inet_csk_ca(sk);

	return minmax_get(&lbbr->bw);
}

static u32 lbbr_min_rtt(struct sock *sk)
{
	const struct lbbr *lbbr = inet_csk_ca(sk);

	return lbbr->min_rtt_us;
}

static void lbbr_check_full_bw_reached(struct sock *sk,
				       const struct rate_sample *rs)
{
	struct lbbr *lbbr = inet_csk_ca(sk);
	u32 bw_thresh;

	if (lbbr_full_bw_reached(sk) || rs->is_app_limited)
		return;

	bw_thresh = (u64)lbbr->full_bw * lbbr_full_bw_thresh >> LBBR_SCALE;
	if (lbbr_max_bw(sk) >= bw_thresh) {
		lbbr->full_bw = lbbr_max_bw(sk);
		lbbr->full_bw_count = 0;
		return;
	}
	++lbbr->full_bw_count;
}

static u32 lbbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	rate *= tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);
	rate *= gain;
	rate >>= LBBR_SCALE;
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}

static u32 lbbr_target_cwnd(struct sock *sk, u32 bw, int gain)
{
	struct lbbr *lbbr = inet_csk_ca(sk);
	u32 cwnd;
	u64 w;

	if (unlikely(lbbr->min_rtt_us == ~0U))	/* no valid RTT sample yet? */
		return TCP_INIT_CWND;		/* cap at default initial cwnd */

	w = (u64)bw * lbbr->min_rtt_us;

	/* Apply a gain to the given value, then remove the BW_SCALE shift. */
	cwnd = (((w * gain) >> LBBR_SCALE) + BW_UNIT - 1) >> BW_SCALE;

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	cwnd = (cwnd + 1) & ~1U;

	return cwnd;
}

static bool lbbr_in_slow_start(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lbbr *lbbr = inet_csk_ca(sk);
	
	return tp->snd_cwnd < lbbr->ssthresh;
}


static bool lbbr_is_cwnd_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (lbbr_in_slow_start(sk))
		return tp->snd_cwnd < 2 * tp->max_packets_out;

	return tp->is_cwnd_limited;
}

static bool lbbr_in_first_slow_start(struct sock *sk)
{
	struct lbbr *lbbr = inet_csk_ca(sk);

	return lbbr->ssthresh == TCP_INFINITE_SSTHRESH;
}

static u32 lbbr_slow_start(struct sock *sk, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lbbr *lbbr = inet_csk_ca(sk);
	u32 cwnd = min(tp->snd_cwnd, lbbr->ssthresh);

	if (acked == cwnd - tp->snd_cwnd) {
		tp->snd_cwnd += acked;
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
		return 0;
	}

	acked -= cwnd - tp->snd_cwnd;
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);

	return acked;
}

static void lbbr_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked)
{
	if (tp->snd_cwnd_cnt >= w) {
		tp->snd_cwnd_cnt = 0;
		tp->snd_cwnd++;
	}

	tp->snd_cwnd_cnt += acked;
	if (tp->snd_cwnd_cnt >= w) {
		u32 delta = tp->snd_cwnd_cnt / w;

		tp->snd_cwnd_cnt -= delta * w;
		tp->snd_cwnd += delta;
	}
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
}

static void lbbr_cong_avoid(struct sock *sk, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!lbbr_is_cwnd_limited(sk))
		return;

	if (lbbr_in_slow_start(sk)) {
		acked = lbbr_slow_start(sk, acked);
		if (!acked)
			return;
	}

	lbbr_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}

static void lbbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			  u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lbbr *lbbr = inet_csk_ca(sk);
	u32 cwnd = 0, target_cwnd = 0;

	if (!acked)
		return;

	/* If we're below target cwnd, slow start cwnd toward target cwnd. */

	if (!lbbr_full_bw_reached(sk)) {
		tp->snd_cwnd = lbbr_target_cwnd(sk, bw, lbbr->cwnd_gain);
		return;
	}

	if (lbbr_in_first_slow_start(sk)) {
		lbbr->cwnd_gain = lbbr_cwnd_gain;
		lbbr->ssthresh = max(tp->snd_cwnd >> 1U, 2U);
	}

	target_cwnd = lbbr_target_cwnd(sk, bw, lbbr->cwnd_gain);
	
	if (tp->snd_cwnd + acked > target_cwnd) {
		cwnd = min(tp->snd_cwnd + acked, target_cwnd);
		lbbr->ssthresh = max(cwnd >> 1U, 2U);
		tp->snd_cwnd = lbbr->ssthresh;
	} else {
		lbbr_cong_avoid(sk, acked);
	}
		
		
}

static void lbbr_update_max_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lbbr *lbbr = inet_csk_ca(sk);
	u64 bw;

	if (!before(rs->prior_delivered, lbbr->next_rtt_delivered)) {
		lbbr->next_rtt_delivered = tp->delivered;
		lbbr->rtt_cnt++;
	}

	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);

	if (!rs->is_app_limited || bw >= lbbr_max_bw(sk)) {
		minmax_running_max(&lbbr->bw, lbbr_bw_rtts, lbbr->rtt_cnt, bw);
	}
}

static void lbbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct lbbr *lbbr = inet_csk_ca(sk);

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	/* filter_expired = after(tcp_time_stamp, */
	/* 		       lbbr->min_rtt_stamp + lbbr_min_rtt_with_sec * HZ); */

	/* if (rs->rtt_us >= 0 && (rs->rtt_us <= lbbr->min_rtt_us || filter_expired)) { */
	if (rs->rtt_us >= 0 && rs->rtt_us <= lbbr->min_rtt_us) {
		lbbr->min_rtt_us = rs->rtt_us;
		lbbr->min_rtt_stamp = tcp_time_stamp;
	}
}

static void lbbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	lbbr_update_max_bw(sk, rs);
	lbbr_check_full_bw_reached(sk, rs);
	lbbr_update_min_rtt(sk, rs);
}

static void lbbr_main(struct sock *sk, const struct rate_sample *rs)
{
	struct lbbr *lbbr = inet_csk_ca(sk);
	
	lbbr_update_model(sk, rs);
	lbbr_set_cwnd(sk, rs, rs->acked_sacked, lbbr_max_bw(sk), lbbr->cwnd_gain);
}

static u32 lbbr_ssthresh(struct sock *sk)
{
	/* LBBR also does not use ssthresh as BBR because LBBR is based on congestion
	 * and only retransmit the lost packet.
	 */
	/* const struct tcp_sock *tp = tcp_sk(sk); */
	/* struct lbbr *lbbr = inet_csk_ca(sk); */

	/* lbbr_update_min_rtt(sk); */
	
	return TCP_INFINITE_SSTHRESH;
}

static size_t lbbr_get_info(struct sock *sk, u32 ext, int *attr,
			  union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_LBBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_BBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct lbbr *lbbr = inet_csk_ca(sk);
		u64 bw = lbbr_max_bw(sk);

		bw = bw * tp->mss_cache * USEC_PER_SEC >> BW_SCALE;
		memset(&info->lbbr, 0, sizeof(info->lbbr));
		info->lbbr.lbbr_bw_lo		= (u32)bw;
		info->lbbr.lbbr_bw_hi		= (u32)(bw >> 32);
		info->lbbr.lbbr_min_rtt 	= lbbr_min_rtt(sk);
		info->lbbr.lbbr_ssthresh 	= lbbr->ssthresh;
		info->lbbr.lbbr_target_cwnd	= lbbr_target_cwnd(sk, lbbr_max_bw(sk), lbbr_cwnd_gain);

		*attr = INET_DIAG_LBBRINFO;
		return sizeof(info->lbbr);
	}
	return 0;
}

static void lbbr_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lbbr *lbbr = inet_csk_ca(sk);

	lbbr->rtt_cnt = 0;

	lbbr->min_rtt_stamp = tcp_time_stamp;
	lbbr->min_rtt_us = tcp_min_rtt(tp);

	lbbr->cwnd_gain = lbbr_startup_gain;

	minmax_reset(&lbbr->bw, 0, 0);

	lbbr->ssthresh = TCP_INFINITE_SSTHRESH;
	lbbr->full_bw = 0;
	lbbr->full_bw_count = 0;
}

static struct tcp_congestion_ops tcp_lbbr_cong_ops __read_mostly = {
	.flags 		= TCP_CONG_NON_RESTRICTED,
	.name 		= "lbbr",
	.owner 		= THIS_MODULE,
	.init		= lbbr_init,
	/* .ssthresh 	= tcp_reno_ssthresh, */
	.ssthresh	= lbbr_ssthresh,
	/* .cong_avoid	= tcp_reno_cong_avoid, */
	.cong_control	= lbbr_main,
	.get_info	= lbbr_get_info,
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

