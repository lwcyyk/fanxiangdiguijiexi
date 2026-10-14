# Figure captions

## fig1_depth_latency: Depth and client latency

UDP at1QPS, five paired repeats per depth/cache state. Lines join the median block P50 of successful valid answers; whiskers show observed min–max across five blocks, not confidence intervals. Small markers are individual block summaries. No per-request independence or isolated per-hop cryptographic cost is inferred.

## fig2_rate_latency_success: Offered-rate sweep

Depth3 UDP; 120s offered measurement windows with 30/60/120/240 requests at 0.25/0.5/1/2QPS. Top: median of conditional-success block P50; bottom: mean block valid-answer proportion. Whiskers are observed min–max across five paired repeats, not inferential intervals. The sweep does not establish a capacity ceiling or maximum throughput.

## fig3_serial_paired_effect: Pipelined versus serial

Five within-condition paired repeats;positive values mean smaller conditional-success latency under pipelining. Diamonds equal100*(1-geometric mean of paired block-quantile ratios). Bars enumerate the empirical paired bootstrap2.5–97.5 percentiles, describing within-testbed repeat variability only. Small dots are all individual paired effects. These are not confirmatory randomized-test intervals;no condition-level significance claim is made.

## figA1_all_block_success: All block success proportions

Every completed formal block is shown, including the depth3 UDP-near pipelined block with0/120 successful valid answers. Correct NXDOMAIN replies count as success. Latency undefined for that block does not remove it from this offered-denominator outcome. For S3 rows A is authenticated serial rather than native;do not pool the two comparison families.
