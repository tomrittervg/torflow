#!/usr/bin/perl -w

use strict;
use IO::Socket::INET;

# specify the port
my $port = 8041;

# create the socket
my $server = IO::Socket::INET->new(Listen=>100, LocalPort=>$port, Proto=>'tcp', Reuse=>'yes');

# set the number of bytes one line contains: 1024 Byte = 1 kB
my $line_count = 1000000;

# print some startup-information
print "pid ".$$.": listening on port ".$server->sockport."\n";

# main loop
while(my $client = $server->accept) {
	if(fork()) {
		# parent
		close($client);
	} else {
		# child
		print "pid ".$$.": accepted connection from ".$client->peerhost."\n";
		while(my $line = <$client>) {
			if ($line =~ /(\d+)/) {
				my $counter = $1;
				while($counter>0) {
					my $send = ($counter>$line_count) ? $line_count : $counter;
					print $client "X" x $send;
					print $client "\r\n";
					$counter -= $send;
				}
			}
			elsif ($line =~ m/close/) {
				print "pid ".$$.": closing connection to ".$client->peerhost."\n";
				close($client);
				exit(0);
			}
		}
		close($client);
	}
}
