
                      Bandwidth Scanner specification


          "This is Fail City and sqlalchemy is running for mayor"
                                  - or -
   How to Understand What The Heck the Tor Bandwidth Scanners are Doing


                             Karsten Loesing
                               Mike Perry
                              Aaron Gibson

0. Preliminaries

   The Tor bandwidth scanners measure the bandwidth of relays in the Tor
   network to adjust the relays' self-advertised bandwidth values.  The
   bandwidth scanners are run by a subset of Tor directory authorities
   which include the results in their network status votes.  Consensus
   bandwidth weights are then used by Tor clients to make better path
   selection decisions.  The outcome is a better load balanced Tor network
   with a more efficient use of the available bandwidth capacity by users.

   This document describes the implementation of the bandwidth scanners as
   part of the Torflow and TorCtl packages.  This document has two main
   sections:

    - Section 1 covers the operation of the continuously running bandwidth
      scanners to split the set of running relays into workable subsets,
      select two-hop paths between these relays, perform downloads, and
      write performance results to disk.

    - Section 2 describes the periodically run step to aggregate results
      in order to include them in the network status voting process.

    - Section 3 describes PID Control, an optional feedback mechanism
      that is governed by the consensus parameter "bwauthpid".

   The "interfaces" of this document are Tor's control and SOCKS protocol
   for performing measurements and Tor's directory protocol for including
   results in the network status voting process.

   The focus of this document is the functionality of the bandwidth
   scanners in their default configuration.  Whenever there are
   configuration options that significantly change behavior, this is
   noted.  But this document is not a manual and does not describe any
   configuration options in detail.  Refer to README.BwAuthorities for the
   operation of bandwidth scanners.

1. Measuring relay bandwidth

   Every directory authority that wants to include bandwidth scanner
   results in its vote operates a set of four bandwidth scanners running
   in parallel.  These bandwidth scanners divide the Tor network into four
   partitions from fastest to slowest relays and continuously measure the
   relays' bandwidth capacity.  Each bandwidth scanner runs the steps as
   described in this section.  The results of all four bandwidth scanners
   are periodically aggregated as described in the next section.

1.1. Configuring and running a Tor client

   All four bandwidth scanners use a single Tor client for their
   measurements.  This Tor client has two non-standard configuration
   options set.  The first:

      FetchUselessDescriptors 1

   configures Tor to fetch descriptors of non-running relays.  The second:

      __LeaveStreamsUnattached 1

   instructs Tor to leave streams unattached and let the controller attach
   new streams to circuits.
       

1.2. Connecting to Tor via its control port

   At startup, the bandwidth scanners connect to the Tor client via its
   control port using cookie authentication.  The bandwidth scanners
   register for events of the following types:

    - NEWCONSENSUS
    - NEWDESC
    - CIRC
    - STREAM
    - BW
    - STREAM_BW

   These events are used to learn about updated Tor directory information
   and about measurement progress.

1.3. Selecting slices of relays

   Each of the four bandwidth scanners is responsible for a subset of
   running relays, determined by a fixed percentile range of relays
   listed in the network status consensus.

   The ordering of the percentiles is determined by sorting the relays by
   the ratio of their network status consensus bandwidth to their descriptor
   values. This ensures that relays with similar amounts of measured capacity
   are measured together. Relays without the "Fast" or "Running" flags are
   discarded from both the percentile rankings, and from measurement in
   general.

   By default the four scanners divide the resulting sorted list as follows:

    1. from  0th to  12th percentile (fastest relays),
    2. from 12th to  35th percentile (fast relays),
    3. from 35th to  60th percentile (slow relays), and
    4. from 60th to 100th percentile (slowest relays).

   The bandwidth scanners further subdivide the share of relays they are
   responsible for into slices of 50 relays to perform measurements.

   A slice does not consist of 50 fixed relays, but is defined by a
   percentile range containing 50 relays.  The lower bound of the
   percentile range equals the former upper bound of the previous slice or
   0 if this is the first slice.  The upper bound is determined from the
   network status consensus at the time of starting the slice.  The upper
   percentile may exceed the percentile range that the bandwidth scanner
   is responsible for, whereas the lower percentile isn't.  The set of
   relays contained in the slice can change arbitrarily often while
   performing measurements.

   Currently, if a slice has no exits, that slice will be simply skipped.
   # XXX: See bug #4269. -MP
 
   A bandwidth scanner keeps measuring the bandwidth of the relays in a
   slice until:

    - every relay in the slice has been selected for measurement at least
      5 times, and

    - the number of successful fetches is at least 65% of the possible
      path combinations (5 x number of relays / 2).

   Note that the second requirement makes no assumptions about successful
   fetches for a given relay or path.  It is just an abstract number to
   avoid skipping slices in case of temporary network failure.

   The scanners maintain the measurement count for all relays in the current
   slice, and scan relays with the lowest scan count first.

1.4. Selecting paths for measurements

   Before selecting a new path for a measurement, a bandwidth scanner
   makes sure that it has a valid consensus, and if it doesn't, it waits
   for the Tor client to provide one.

   The bandwidth scanners then select a path and instruct Tor to build a
   circuit that meets the following requirements:

    - All relays for the new path need to be members of the current slice.

    - The minimum consensus bandwidth for relays to be selected is 1
      KiB/s.

    - Path length is always 2.

    - Nodes are selected uniformly among those with the lowest measurement
      count for the current slice. Otherwise, there is no preference for
      relays.

    - Relays in the paths must come from different /16 subnets.

    - Entry relays must have the Running and Fast flags and must not
      permit exiting to 255.255.255.255:443.

    - Exit relays must have the Running and Fast flags, must not have the
      BadExit flag, and must permit exiting to 255.255.255.255:443.

   If these restrictions cannot be met with the current slice, the slice is
   abandoned and the scanner moves on to the next slice.
   # XXX: See bug #4269 -MP.

1.5. Performing measurements

   Once the circuit is built, the bandwidth scanners download a test file
   via Tor's SOCKS port using SOCKS protocol version 5.

   All downloads go to same bandwidth authority server.

   All requests are sent to port 443 using https to avoid caching on the
   exit relay.

   We currently do not authenticate the certificate or verify the download
   length is sane. # XXX: Bug #4271. -MP.

   The requested resource for performing the measurement varies with the
   lower percentile of the slice under investigation.  The default file
   sizes by lower percentiles are:

     - 0th  to   5th percentile: 8M
     - 5th  to  10th percentile: 4M
     - 10th to  20th percentile: 2M
     - 20th to  40th percentile: 1M
     - 40th to  50th percentile: 512k
     - 50th to  80th percentile: 256k
     - 80th to 100th percentile: 128k

   The bandwidth scanners use the following fixed user-agent string for
   their requests:

      Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; \
      .NET CLR 1.0.3705; .NET CLR 1.1.4322)

   Unfinished downloads are aborted after 30 minutes.

   For each download, the bandwidth scanners process STREAM and STREAM_BW events
   with a StreamListener (in TorCtl/SQLSupport.py). The throughput for each
   stream is defined as the ratio of total read bytes over the time delta between
   the STREAM SUCCEEDED timestamp and the STREAM CLOSED event received timestamp:

   bandwidth = (STREAM_BW bytes / (CLOSED timestamp - SUCCEEDED timestamp)

   We store both read and write bandwidths in the SQL tables, but only use
   the read bytes for results.
   
1.6. Writing measurement results

   Once a bandwidth scanner has completed a slice of relays, it writes the
   measurement results to disk.

   The output file contains information about the slice number, the
   timestamp of completing the slice, and the measurement results for the
   measured relays.

   The filename of an output file is derived from the lower and upper
   slice percentiles and the measurement completion time.  The format is

      "bws-" lower percentile ":" upper percentile "-done-" timestamp

   Both lower and upper percentiles are decimal numbers rounded to 1
   decimal place.  The timestamp is formatted "YYYY-MM-DD-HH:MM:SS".

   The first line of an output file contains the slice number:

      "slicenum=" slice number NL

   The second line contains the UNIX timestamp when the output file was
   written:

      timestamp NL

   Subsequent lines contain the measurement results of all relays in the
   slice in arbitrary order.  There can be at most one such line per relay
   identity:

      "node_id=" fingerprint SP
      "nick=" nickname SP
      "strm_bw=" stream bandwidth SP
      "filt_bw=" filtered stream bandwidth SP
      "desc_bw=" descriptor bandwidth SP
      "ns_bw=" network status bandwidth NL

   The meaning of these fields is as follows: fingerprint is the
   hex-encoded, upper-case relay identity fingerprint; nickname is the
   relay's nickname; stream bandwidth and filtered stream bandwidth
   contain the average measurements; descriptor bandwidth is the average
   self-advertised bandwidth contained in relay descriptors; and network
   status bandwidth is the average relay bandwidth contained in network
   status consensuses.

   The strm_bw field is the average (mean) of all the streams for the relay
   identified by the fingerprint field. 

   The filt_bw field is computed similarly, but only the streams equal to
   or greater than the strm_bw are counted in order to filter very slow
   streams due to slow node pairings.

   The nickname field is entirely informational and may change between
   measurements.

   Only relays with at least 1 successful measurement, non-negative
   filtered stream bandwidth, and non-negative stream bandwidth are
   included in the output file. 

2. Aggregating scanner results

   Once per hour (via cron), the bandwidth scanner results are aggregated
   in order to include them in the network status consensus process.  This
   aggregation step reads in all result files produced from the four 
   bandwidth authority children as defined in Section 1.6 and produces a
   single output file to be read by a tor directory authority.

2.1. Selecting which measurements to include

   Since each bandwidth authority child writes a new file each time it
   processes a slice, there can be a lot of old files. We automatically
   exclude files older than 15 days.

   Furthermore, since routers can move between slices, we must record the
   slice timestamps for each router measurement, to ensure we use only the
   most recent slice that a router appeared in.

   We then select the most recent measurement for each node from any
   slice.

2.2. Computing bandwidth values from measurements

   If the consensus parameter "bwauthpid=1" is present, we proceed as
   specified in Section 3. This section describes the default behavior 
   (used when the consensus parameter is absent).

   Once we have determined the most recent measurements for each node, we
   compute an average of the filt_bw fields over all nodes we have measured.

   These averages are used to produce ratios for each node by dividing the
   measured value for that node by the network average. 

   These ratios are then multiplied by the most recent observed descriptor
   bandwidth we have available for each node, to produce a new value for
   the network status consensus process.

   In this way, the resulting network status consensus bandwidth values
   are effectively re-weighted proportional to how much faster the node
   was as compared to the rest of the network.

2.3. Ensuring and measuring progress

   To ensure that the scanners are making progress, we perform two checks.

   First, we read in the previous consensus over the Tor control port. If we
   have measurements for less than 60% of the current consensus, we do not 
   produce a result file. This is done to ensure that we have an accurate
   network average before computing ratios and producing measurement results.

   Second, we collect the most recent slice timestamp for each scanner child.
   If the most recent slice timestamp is older than 1.5 days, we print out a
   warning that is mailed to the scanner operator. We still produce a result
   file in this case.

2.4. Result format

   The final output file for use by the directory authorities is comprised of
   lines of the following format:

      "node_id=" fingerprint SP
      "bw=" new_bandwidth SP
      "nick=" nickname SP
      "measured_at=" slice timestamp NL

   If PID control is enabled, additional values are stored. See Section 3.4
   for those.

2.5. Usage by directory authorities 

   The Tor directory authorities use only the node_id and the bw fields.
   The rest of the fields are ignored.

   The directory authorities take the median of all votes for the bw field,
   and publish that value as the consensus bandwidth.

3. PID Control Feedback

   The goal of the bandwidth authorities is to balance load across the
   network such that a user can expect to have the same average stream
   capacity regardless of path. Any deviation from this ideal
   load balancing can be regarded as error.

   Using this model, the measurement mechanisms can be cast as a PID
   control system, allowing the new measurement ratios to multiplied by
   the current consensus values, which creates a feedback loop that
   should cause convergence to this balanced ideal.

   See https://en.wikipedia.org/wiki/PID_controller for background,
   especially https://en.wikipedia.org/wiki/PID_controller#Pseudocode

3.1. Modeling Measurement as PID Control

   The bandwidth authorities measure F_node: the filtered stream
   capacity through a given node (filtering is described in Section 1.6).

   The PID Setpoint, or target for each node is F_avg: the average F_node
   value observed across the entire network.

   The normalized PID error e(t) for each node is then:

       pid_error = e(t) = (F_node - F_avg)/F_avg. 

   In the "Process" step, we take the output of the "controller" and multiply it by
   the current consensus bandwidth for the node, and then add this new
   proportion to the consensus bandwidth, thereby adjusting the
   consensus bandwidth in proportion to the error:

     new_consensus_bw = old_consensus_bw +
                        old_consensus_bw * K_p * e(t) +
                        old_consensus_bw * K_i * \integral{e(t)} +
                        old_consensus_bw * K_d * \derivative{e(t)}

   For the case where K_p = 1, K_i=0, and K_d=0, it can be seen that this
   system is equivalent to the one defined in 2.2, except using consensus
   bandwidth instead of descriptor bandwidth:
  
       new_bw = old_bw + old_bw*e(t)
       new_bw = old_bw + old_bw*(F_node/F_avg - 1)
       new_bw = old_bw*F_node/F_avg
       new_bw = old_bw*ratio

3.2. Measurement intervals and Feedback intervals

   In order to prevent the consensus bandwidth from functioning as an
   accumulator (thus amplifying the effects of integration), we must
   tune the feedback intervals to a rate that we can expect clients
   to respond to.

   For non-Guard nodes, this is basically 4 consensus intervals, or 4
   hours. Since the bandwidth authorities also take on the order of
   hours to measure a slice of nodes, we do nothing special here.

   For Guard nodes however, clients try to keep their Guards for 4-6
   weeks. However, on the assumption that they rotate more frequently
   than this in practice, we set our Guard feedback interval to 2 weeks.

   Guard measurements are also used without feedback whenever new
   measurements are available, to compensate for changes in Guard flag
   status and associated load changes. These new measurements are
   multiplied by our most recent bandwidth value that used feedback,
   in a similar way to Section 2.2.

   For purposes of calculating the integral and the derivative of the
   error, we assume units of time that correspond to feedback intervals,
   eliminating the need to track time for any other purpose other than
   determining when to report a measurement.

   The integral component, pid_error_sum is subjected to a decay factor
   per each interval, to prevent unbounded growth in cases without
   convergence.

   The differential component is a simple delta, calculating by
   subtracting the previous pid_error from the current pid_error.

3.3. Flag weighting

   Guard+Exit nodes are treated as normal nodes in terms of measurement
   frequency (measurements are reported as soon as their slice results
   are ready), except they are given a K_p of K_p*(1.0-Wgd) (Wgd is the
   consensus bandwidth-weight for selecting Guard+Exits for the Guard
   position: See dir-spec.txt Section 3.4.3).

   K_p*(1.0-Wgd) isn't expected to be the optimal value, but we needed a
   dampening factor to slow the feedback loop, and it seems as good of an
   initial guess as any. Note that convergence towards zero error should 
   still happen eventually with this value, just at a slower rate.

   All other nodes are given K_p of 1.0.

3.4. Value storage

   In order to maintain the PID information, we store the following additional
   fields in the output file:

      "pid_error=" (PID error term as defined in Section 3.1) SP
      "pid_error_sum=" (Weighted sum of PID error) SP
      "pid_delta=" (Change in error) SP
      "pid_bw=" (Last bandwidth value used in feedback) NL

   pid_delta is purely informational, and is not used in feedback.

3.5. Tuning PID Constants

   Internally, the source uses the Standard PID Form:
   https://en.wikipedia.org/wiki/PID_controller#Ideal_versus_standard_PID_form

   The Standard PID Form sets K_i and K_d to be proportional to K_p and two
   other constants that have more relation to convergence behaviors:

       K_i = K_p/T_i
       K_d = K_d*T_d

   We have selected T_i to be 5.0 (5 measurement intervals) and T_d to be 0.5
   (one half interval). The belief is that any steady state error should be
   correctable in 5 intervals, and the current rate of change of error
   only gives us useful information for a fraction of a measurement
   interval, until clients begin to migrate to the new measurements.

3.6. Consensus Parameters

   The bandwidth auths listen for several consensus parameters to tweak
   behavior.

   In the absence of any consensus parameters, the default behavior is
   to use the PID control code to produce values identical to Section 2,
   by using default values of:

     K_p = 1.0, K_i = 0, K_d = 0, as well as bwauthcircs=0.

   This equivalence was proved in Section 3.1, and has been observed
   in practice.

   The available consensus parameters are:

    "bwauthpid=0"  
       If present, entirely disables the PID control features in 
       Section 3 and computes bandwidths according to Section 2.

       Setting this value to temporarily disable PID feedback is not
       recommended, because it causes the PID code to lose interim
       recorded state.

       To temporarily disable PID feedback, simply remove all consensus
       parameters, and the system will compute Section 2 values while
       retaining PID state.

    "bwauthcircs=1"
       If present, an additional circ_error value is computed for each
       node similar to pid_error of Section 3.1. This value is:

          circ_error = (circ_rate - circ_avg_rate)/circ_avg_rate

       Where circ_rate and circ_avg_rate are the EXTEND success rates 
       to the node, and the average success rate for the entire node class,
       respectively.

       If this error value is negative (meaning the node is failing
       more circuits than the network average), we use the smaller
       of the circ_error and the original pid_error as the new
       pid_error.

       We use this to prevent the PID control system from driving nodes
       to CPU overload. Once nodes begin failing circuits, we want to stop
       devoting additional capacity to them (and decrease it proportional
       to their failure rate relative to the rest of the network).

    "bwauthbestratio=0"
       If absent, the larger of stream bandwidth vs filtered bandwidth
       is used to compute F_node.

       If present, only filtered stream bandwidth ratios are used.
 
    "bwauthnsbw=1"
       If present, uses consensus bandwidth to determine new bandwidth
       values.

       If absent, uses descriptor bandwidth instead of feeding back
       PID control values. This may be functionally equivalent to NS
       bandwidth so long as T_i is non-zero, because error will get
       accumulated in pid_error_sum as opposed to the consensus value
       itself.

    "bwauthbyclass=1"
       If present, computes F_avg (see Section 3.1) for each class
       of Guard, Middle, Exit, and Guard+Exit nodes, and uses these
       flag-specific averages to compute pid_error.

    "bwauthpidtgt=1"
       If present, the PID setpoint bandwidth F_avg will be re-computed
       by averaging the F_node values for only those nodes whose
       descriptor bandwidth exceeds the F_avg.

       Note that this parameter causes bwauthbestratio to have no 
       effect.

    "bwauthmercy=1"
       If present, we do not accumulate a negative pid_error_sum for
       nodes with already negative pid_error. This prevents us from
       punishing relays down to 0 bandwidth.

    "bwauthkp=N"
       Sets K_p to N/10000.0. If absent, K_p=1.0.

    "bwauthti=N"
       Sets T_i to N/10000.0. If T_i=0 or absent, K_i is set to 0.

    "bwauthtd=N"
       Sets T_d to N/10000.0. If absent, K_d=0.
     
    "bwauthtidecay=N"
       Sets T_i_decay to N/10000.0. T_i_decay is an parameter
       used to dampen the pid_error_sum accumulation. If non-zero,
       the pid_error_sum integration becomes:

           K_i_decay = (1.0 - T_i_decay/T_i)
           pid_control_sum = pid_control_sum*K_i_decay + pid_error

       Intuitively, this means that after T_i sample rounds,
       the T_i'th round has experienced a reduction by T_i_decay
       for the values of T_i that are relevant to us.

       If T_i is 0 or absent, K_i_decay is set to 0.

    "bwauthpidmax=N"
       Caps pid_error_sum feedback to N/10000.0. Can be used to prevent
       runaway feedback loops for fast nodes.

       If absent, the default is 500.0, which translates to a 501X
       multiplier of descriptor bandwidth.

    "bwauthguardrate=N"
       Restricts the rate at which we perform feedback on Guard nodes
       to at most every N seconds.

       If absent, the default is 2*7*24*60*60, or two weeks.
