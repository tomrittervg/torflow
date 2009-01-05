#!/usr/bin/perl -w


use strict;
use IO::Socket;
use IO::Socket::INET;
use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );

my $META_PORT = "9052";
my $META_HOST = "127.0.0.1";

my $USER_AGENT = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322)";

# http://bitter.stalin.se/torfile
# http://www.sigma.su.se/~who/torfile
my $URL = "https://svn.torproject.org/svn/tor/trunk/doc/design-paper/tor-design.pdf"; 
my $COUNT = 2;
my $START_PCT = 0;
my $STOP_PCT = 20;
my $PCT_STEP = 5;
my $DOUBLE_FETCH = 0;
my $CURL_PROXY="--socks4a 127.0.0.1:9060";

my $LOG_LEVEL = "DEBUG";
my %log_levels = ("DEBUG", 0, "INFO", 1, "NOTICE", 2, "WARN", 3, "ERROR", 4);


sub plog
{
    my $level = shift;
    my $msg = shift;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);

    $year += 1900; # lame.
    $mon += 1;
    
    print "$level \[" . localtime() . "\]: " . $msg if($msg && $log_levels{$level} >= $log_levels{$LOG_LEVEL})
    #print "$level\[$year-$mon-$mday $hour:$min:$sec\]: " . $msg if($log_levels{$level} >= $log_levels{$LOG_LEVEL})
}

sub is_in
{
    my $element = shift;
    my $ary = shift;
    my $is_there = 0;
    foreach (@$ary) {
        if ($_ eq $element) {
            $is_there = 1;
            last;
        }
    }

    return $is_there;
}

sub compare_arrays {
    my ($first, $second) = @_;
    no warnings;  # silence spurious -w undef complaints
        return 0 unless @$first == @$second;
    for (my $i = 0; $i < @$first; $i++) {
        return 0 if $first->[$i] ne $second->[$i];
    }
    return 1;
}

sub query_exit
{
    my $mcp = shift;
    my $line;
    print $mcp "GETLASTEXIT\r\n";
    $line = <$mcp>;
    $line =~ /LASTEXIT=([\S]+)/;

    return $1;    
}


sub speedrace
{
    my $mcp = shift;
    my $skip = shift;
    my $pct = shift;
    my @build_times;
    my @fetch_times;
    my $tot_fetch_time = 0;
    my $tot_build_time = 0;
    my $i = 0;
    my $line;

    # Weak new-nym
    print $mcp "PERCENTSKIP $skip\r\n";
    $line = <$mcp>;
    die "Error setting percentskip: $line" if (not $line =~ /^250/);

    print $mcp "PERCENTFAST $pct\r\n";
    $line = <$mcp>;
    die "Error setting percentfast: $line" if (not $line =~ /^250/);

    # So this is a really big hack. Since metatroller builds circuits on 
    # the fly where as tor has a pool of pre-built circuits to use, 
    # we want to get it to build a circuit for us but not count 
    # that construction time. The way we do this is to issue
    # a NEWNYM and then get the url TWICE. 

    while($#build_times+1 < $COUNT) {
        my $t0;
        my $delta_build;
        my $delta_fetch;
        my $fetch_exit;
        my $build_exit;
        my $ret;

        print $mcp "NEWNYM\r\n";
        $line = <$mcp>;
        die "Error sending NEWNYM: $line" if (not $line =~ /^250/);
 
        # Build the circuit... 
        do {
            $i++;
            
            $t0 = [gettimeofday()];
            $ret = 
#                system("tsocks wget -U \"$USER_AGENT\" \'$URL\' -O - 2>&1 > /dev/null");
                system("curl $CURL_PROXY -m 600 -A \"$USER_AGENT\" \'$URL\' >& /dev/null");

            if($ret == 2) {
                plog "NOTICE", "wget got Sigint. Dying\n";
                exit;
            }
            plog "NOTICE", "wget failed with ret=$ret.. Retrying...\n" 
                if($ret != 0);
            $delta_build = tv_interval $t0;
            plog "NOTICE", "Timer exceeded limit: $delta_build\n"
                if($delta_build >= 550.0);
        } while(0);
#        } while($ret != 0 || $delta_build >= 550.0);

        $build_exit = query_exit($mcp);
        $fetch_exit = $build_exit;

        plog "DEBUG", "Got 1st via $build_exit\n";

        # Now do it for real
        if($DOUBLE_FETCH) {
            do {
                $i++;
                $t0 = [gettimeofday()];
                $ret = 
#                system("tsocks wget -U \"$USER_AGENT\" \'$URL\' -O - 2>&1 > /dev/null");
                    system("curl $CURL_PROXY -m 600 -A \"$USER_AGENT\" \'$URL\' >& /dev/null");

                if($ret == 2) {
                    plog "NOTICE", "wget got Sigint. Dying\n";
                    exit;
                }
                plog "NOTICE", "wget failed with ret=$ret.. Retrying with clock still running\n" 
                    if($ret != 0);
                $delta_fetch = tv_interval $t0;
                plog "NOTICE", "Timer exceeded limit: $delta_fetch\n"
                    if($delta_fetch >= 550.0);
            } while($ret != 0 || $delta_fetch >= 550.0);

            $fetch_exit = query_exit($mcp);

            if($fetch_exit eq $build_exit) {
                $tot_build_time += $delta_build;
                push(@build_times, $delta_build);
                plog "DEBUG", "$skip-$pct% circuit build+fetch took $delta_build for $fetch_exit\n";

                push(@fetch_times, $delta_fetch);
                $tot_fetch_time += $delta_fetch;
                plog "DEBUG", "$skip-$pct% fetch took $delta_fetch for $fetch_exit\n";
            } else {
                plog "NOTICE", "Ignoring strange exit swap $build_exit -> $fetch_exit. Circuit failure?\n";
            }
        } else {
            $tot_build_time += $delta_build;
            push(@build_times, $delta_build);
            plog "DEBUG", "$skip-$pct% circuit build+fetch took $delta_build for $fetch_exit\n";
        }
    }
    my $avg_build_time = $tot_build_time/($#build_times+1);
    my $build_dev = 0;
    foreach(@build_times) {
        $build_dev += 
            ($_ - $avg_build_time)*($_ - $avg_build_time);
    }
    $build_dev = sqrt($build_dev / ($#build_times+1));
   
    if($DOUBLE_FETCH) { 
        my $avg_fetch_time = $tot_fetch_time/($#fetch_times+1);
        my $fetch_dev = 0;
        foreach(@fetch_times) {
            $fetch_dev += 
                ($_ - $avg_fetch_time)*($_ - $avg_fetch_time);
        }
        $fetch_dev = sqrt($fetch_dev / ($#fetch_times+1));
        plog "INFO", "RANGE $skip-$pct " . ($#fetch_times+1) . " fetches: avg=$avg_fetch_time, dev=$fetch_dev\n";
    }
    plog "INFO", "RANGE $skip-$pct " . ($#build_times+1) . " build+fetches: avg=$avg_build_time, dev=$build_dev\n";
    plog "INFO", "  " . ($COUNT*($DOUBLE_FETCH+1)) . " fetches took $i tries\n";
}

sub main
{
    my $mcp = IO::Socket::INET->new(
            Proto    => "tcp",
            PeerAddr => $META_HOST,
            PeerPort => $META_PORT)
        or die "The Metatroller is not enabled";
    my $line = <$mcp>;
    $line = <$mcp>;

    delete $ENV{"http_proxy"};
    delete $ENV{"HTTP_PROXY"};
    delete $ENV{"proxy"};
    delete $ENV{"PROXY"};
    $ENV{"TSOCKS_CONF_FILE"} = "./tsocks.conf";

    print $mcp "GUARDNODES 0\r\n";
    $line = <$mcp>;
    die "Error setting Guard Nodes: $line" if (not $line =~ /^250/);

    print $mcp "UNIFORM 1\r\n";
    $line = <$mcp>;
    die "Error setting UNIFORM: $line" if (not $line =~ /^250/);

    print $mcp "ORDEREXITS 1\r\n";
    $line = <$mcp>;
    die "Error setting ORDEREXITS: $line" if (not $line =~ /^250/);

    print $mcp "PATHLEN 2\r\n";
    $line = <$mcp>;
    die "Error setting PATHLEN: $line" if (not $line =~ /^250/);

    my $pct = $START_PCT;
    plog "INFO", "Beginning time loop\n";
        
    while($pct < $STOP_PCT) {
        print $mcp "RESETSTATS\r\n";
        $line = <$mcp>;
        die "Error on RESETSTATS: $line" if (not $line =~ /^250/);
        print $mcp "COMMIT\r\n";
        $line = <$mcp>;
        die "Error on COMMIT: $line" if (not $line =~ /^250/);
        plog "DEBUG", "Reset stats\n";
        speedrace($mcp, $pct, $pct+$PCT_STEP); 
        plog "DEBUG", "speedroced\n";
        print $mcp "CLOSEALLCIRCS\r\n";
        $line = <$mcp>;
        die "Error on CLOSEALLCIRCS: $line" if (not $line =~ /^250/);
        print $mcp "SAVESTATS ./data/speedraces/stats-$pct:".($pct+$PCT_STEP)."\r\n";
        $line = <$mcp>;
        die "Error on SAVESTATS: $line" if (not $line =~ /^250/);
        plog "DEBUG", "Wrote stats\n";
        $pct += $PCT_STEP; 
        print $mcp "COMMIT\r\n";
        $line = <$mcp>;
        die "Error on COMMIT: $line" if (not $line =~ /^250/);
    }
}

main();
