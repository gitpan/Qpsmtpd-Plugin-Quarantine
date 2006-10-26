# Copyright(C) 2006 David Muir Sharnoff <muir@idiom.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# This software is available without the GPL: please write if you need
# a non-GPL license.  All submissions of patches must come with a
# copyright grant so that David Sharnoff remains able to change the
# license at will.

package Qpsmtpd::Plugin::Quarantine::Batch;

require Exporter;
use OOPS;
use strict;
use Qpsmtpd::Plugin::Quarantine::Common;
use Qpsmtpd::Plugin::Quarantine::Sendmail;
use Mail::SendVarious;
use Mail::SendVarious qw(make_message $mail_error);
use Scalar::Util qw(refaddr);
use IO::Pipe;
use Time::CTime;

my $mailq_timefmt = "%a %b %d %X";

our @ISA = qw(Exporter);
our @EXPORT = qw(cronjob sendqueued mailq);
our @EXPORT_OK = qw(
	find_oldest_bucket prune_headers 
	prune_recipients generate_recipients 
	prune_senders generate_senders 
	fork_agent indent);

my $debug = 1;

my $recipients_deleted = 0;
my $recipients_settings = 0;
my $recipients_count = 0;
my $senders_deleted = 0;
my $senders_count = 0;

sub cronjob
{
	my $start = time;

	print "# cleaning out messages\n" if $debug;
	my $messages_deleted = 0;
	for(;;) {
		my $done;
		my $del;
		transaction(sub {
			my $oops = get_oops();
			my $oldest = find_oldest_bucket($oops);
			if ($oldest and (time - $oldest) / 86400 > $defaults{message_longevity}) {
				printf "# Oldest bucket is dated %s, must prune headers\n", scalar(localtime($oldest)) if $debug;
				$del = prune_headers($oops);
			} else {
				printf "# Oldest bucket is dated %s, we're done\n", scalar(localtime($oldest)) if $debug;
				$done = 1;
			}
		});
		$messages_deleted += $del;
		last if $done;
	}

	print "Messages deleted: $messages_deleted\n\n";
	print "\n\n";

	print "# cleaning up recipients...\n" if $debug;
	prune_recipients();
	print "Recipients deleted: $recipients_deleted\n";
	print "Recipients kept: $recipients_count\n";
	print "Recipients with settings: $recipients_settings\n";
	print "\n\n";

	print "# cleaning up senders...\n" if $debug;
	prune_senders();
	print "Senders kept: $senders_count\n";
	print "Senders deleted: $senders_deleted\n";
	print "\n\n";

	printf "Time for batch run: %d (seconds)\n", time - $start;
}

sub find_oldest_bucket
{
	my ($oops) = @_;

	my $qd = $oops->{quarantine};

	my $b0 = $qd->{buckets};
	my ($b0first) = sort { $a <=> $b } keys %{$b0};
	my $b1 = $b0->{$b0first};
	my ($b1first) = sort { $a <=> $b } keys %{$b1};

	my $bucket = $b1->{$b1first};

	return ($b0, $b0first, $b1, $b1first, $bucket) if wantarray;
	return $b0first * 86400 + $b1first * 3600;
}

my $mqueue_sent;
my $mqueue_unsent;

sub sendqueued
{
	fork_agent(\&generate_mqueue, \&transaction_wrapper2, \&mqueue_agent1, \&mqueue_agent2, \&mqueue_postcommit, $defaults{mqueue_stride_length});
}

sub mqueue_agent1
{
	my ($oops, $mqueue) = @_;
	my $mq = $oops->{mqueue}{$mqueue} || return;
	return unless time - $mq->{last_attempt} >= $defaults{mqueue_minimum_gap};
	$oops->lock($oops->{mqueue}{$mqueue});
}

sub mqueue_agent2
{
	my ($oops, $mqueue) = @_;
	my $mq = $oops->{mqueue}{$mqueue} || return;
	return unless time - $mq->{last_attempt} >= $defaults{mqueue_minimum_gap};

	if (sendmail(%$mq, debuglogger => sub { 1 }, errorlogger => sub { 1 })) {
		delete $oops->{mqueue}{$mqueue};
		$mqueue_sent++;
		return;
	}
	$mq->{last_attempt} = time;
	$mq->{attempt_count}++;
	$mq->{last_error} = $mail_error;

	if (time - $mq->{first_attempt} >= $mq->{mqueue_maximum_keep} 
		and $mq->{attempt_count} >= $defaults{mqueue_minimum_attempts}) 
	{
		delete $oops->{mqueue}{$mqueue};
		if ($mq->{from} ne "<>" && $mq->{from} ne $defaults{bounce_from} && $mq->{from} =~ /^mailer-daemon\@/i) {
			my (undef, $mes) = make_message(%$mq);
			sendmail_or_postpone(
				from		=> $defaults{bounce_from},
				subject		=> "Returned mail: $mq->{last_error}",
				to		=> $mq->{from},
				body		=> <<END,
We attempted to send a message on your behalf but we could
not do so.  The specific problem we had was:

 $mq->{last_error}

The message we were trying to send was:

$mes
END
				debuglogger	=> sub { 1 },
			);
		}
	}
}

sub mqueue_postcommit
{
	send_postponed();
}

sub generate_mqueue
{
	my ($pipe) = @_;

	my $oops = get_oops(readonly => 1, less_caching => 1);
	my $qd = $oops->{quarantine};

	for my $mqueue (keys %{$qd->{mqueue}}) {
		print $pipe "$mqueue\n";
	}
}

sub mailq
{
	my $oops = get_oops(readonly => 1, less_caching => 1);
	my $qd = $oops->{quarantine};
	my $count = 0;
	my $size = 0;
	for my $mqueue (keys %{$qd->{mqueue}}) {
		my $mq = $qd->{mqueue}{$mqueue};
		my ($from, $message, @to) = make_message(%$mq);
		printf "%15s %6d %20s  %s\n", $mqueue, length($message), strftime($mailq_timefmt, localtime($mq->{first_attempt})), $from;
		print  "    ($mq->{last_error})\n";
		for my $t (@to) {
			print  "\t\t\t\t\t $t\n";
		}
		$count++;
		$size += length($message);
	}
	printf "-- %d Kbytes in %d Requests.\n", $size / 1024, $count;
}

sub prune_headers
{
	my ($oops, $messages) = @_;

	$messages = $defaults{delete_batchsize}
		unless $messages;

	my $qd = $oops->{quarantine};

	my ($b0, $b0first, $b1, $b1first, $bucket) = find_oldest_bucket($oops);

	my $pruned = 0;
	my ($hcksum, $pheader);
	while (($hcksum, $pheader) = each(%$bucket)) {
		return --$pruned if $pruned++ >= $messages;

		my $wasdone = $pheader->{done};
		my $pbody = $pheader->{body};
		my $psender = $pheader->{sender};
		my $recipients = $pheader->{recipients};

		print STDERR <<END if $debug;
Removing....
From $psender->{address}
From: $pheader->{from}To: $pheader->{to}Subject: $pheader->{subject}Date: $pheader->{date}
END

		%$pheader = ();

		if (refaddr($pbody->{last_reference}) == refaddr($pheader)) {
			delete $pbody->{last_reference};
			my $bcksum = $pbody->{cksum};
			delete $qd->{bodies}{$bcksum};
			print STDERR "(body too)\n\n";
		} else {
			print STDERR "\n";
		}
		delete $bucket->{$hcksum};
		delete $qd->{headers}{$hcksum};
		delete $psender->{headers}{$hcksum};
		for my $r (@{$pheader->{recipients}}) {
			my $rd = $qd->{recipients}{$r};
			if ($rd->{headers}{$hcksum}) {
				delete $rd->{headers}{$hcksum};
				$rd->{mcount}-- unless $wasdone;
			}
		}
	}
	delete $b1->{$b1first};
	return $pruned;
}


sub prune_recipients
{
	fork_agent(\&generate_recipients, \&transaction_wrapper, \&recipient_agent, $defaults{recipent_stride_length});
}

sub recipient_agent
{
	my ($oops, $recipient) = @_;
	chomp($recipient);
	my $qd = $oops->{quarantine};
	my $rd = $qd->{recipients}{$recipient};
	unless ($rd) {
		print STDERR "That's odd, cannot find recipient '$recipient'\n";
		return;
	}
	if (
		(
			(time - $rd->{last_timestamp}) / 86400 > $defaults{keep_idle_recipients} 
			&& 
			! %{$rd->{headers}}
		)
		||
		(
			(time - $rd->{last_timestamp}) / 86400 > $defaults{message_longevity}
			&&
			$rd->has_settings()
			&&
			! %{$rd->{headers}}
		)
	) {
		delete $qd->{recipients}{$recipient};
		$recipients_deleted++;
	} else {
		$recipients_settings++ if $rd->has_settings();
		$recipients_count++;
	}
}

sub generate_recipients
{
	my ($pipe) = @_;

	my $oops = get_oops(readonly => 1, less_caching => 1);

	my $qd = $oops->{quarantine};

	for my $recipient (keys %{$qd->{recipients}}) {
		print $pipe "$recipient\n";
	}
}

sub prune_senders
{
	fork_agent(\&generate_senders, \&transaction_wrapper, \&sender_agent, $defaults{sender_stride_length});
}

sub sender_agent
{
	my ($oops, $sender) = @_;
	chomp($sender);
	my $qd = $oops->{quarantine};
	my $psender = $qd->{senders}{$sender};
	unless ($psender) {
		print STDERR "That's odd, cannot find sender '$sender'\n";
		return;
	}
	my ($ip, $tstamp);
	my $kept;
	while (($ip, $tstamp) = each %{$psender->{send_ip_used}}) {
		if (time - $tstamp > 86400 * $defaults{renotify_sender_ip} * 2) {
			delete $psender->{send_ip_used}{$ip};
		} else {
			$kept++;
		}
	}

	my $spams_sent;
	my $today = time / 86400;
	for my $spamday ($psender->{spams_sent_perday}) {
		if ($today - $spamday > $defaults{sender_history_to_keep}) {
			delete $psender->{spams_sent_perday}{$spamday};
			next;
		}
		$spams_sent += $psender->{spams_sent_perday}{$spamday};
	}

	if ($spams_sent >= $defaults{report_senders_after}) {
		print "Sender $sender has sent $spams_sent in the last $defaults{sender_history_to_keep} days\n";
		my ($hsum, $pheader);
		while (($hsum, $pheader) = each %{$psender->{headers}}) {
			print "\nFor example:\n";
			indent($pheader->{header});
			indent($pheader->{body}{body}, limit => 100);
			last;
		}
	}

	if (! $kept && ! %$psender->{spams_sent_perday} && ! $psender->has_settings() && ! %{$psender->{headers}}) {
		delete $qd->{senders}{$sender};
		$senders_deleted++;
	} else {
		$senders_count++;
	}
}

sub generate_senders
{
	my ($pipe) = @_;

	my $oops = get_oops(readonly => 1, less_caching => 1);

	my $qd = $oops->{quarantine};

	for my $sender (keys %{$qd->{senders}}) {
		print $pipe "$sender\n";
	}
}

sub indent
{
	my ($text, %args) = @_;
	my $tab = $args{indent} || "\t";
	my $limit = $args{limit} || 0;
	while (--$limit != 0 && $text =~ /^(.*)/gm) {
		print "$tab$1\n";
	}
}

sub fork_agent
{
	my ($generate, $handler, @args) = @_;
	my $pipe = new IO::Pipe;
	my $pid;

	if ($pid = fork()) {
		# parent
		$pipe->reader();
		while (<$pipe>) {
			&$handler(@args, $_);
		}
		&$handler(@args);
		return $pid;
	} elsif (defined $pid) {
		# child
		$pipe->writer();
		&$generate($pipe);
		exit(0);
	} else {
		die "Could not fork: $!";
	}
}

my @buf;

sub transaction_wrapper
{
	my ($agent, $batch_size, $line) = @_;
	push(@buf, $line)
		if defined $line;
	if (@buf >= $batch_size or ! defined($line) or $line eq "DO-COMMIT\n") {
		transaction(sub {
			my $oops = get_oops();
			for my $line (@buf) {
				&$agent($oops, $line);
			}
			$oops->commit();
		});
		undef @buf;
	}
}

sub transaction_wrapper2
{
	my ($agent1, $agent2, $postcommit, $batch_size, $line) = @_;
	push(@buf, $line)
		if defined $line;
	if (@buf >= $batch_size or ! defined($line) or $line eq "DO-COMMIT\n") {
		transaction(sub {
			my $oops = get_oops();
			for my $line (@buf) {
				&$agent1($oops, $line);
			}
			for my $line (@buf) {
				&$agent2($oops, $line);
			}
			$oops->commit();
		});
		undef @buf;
		&$postcommit();
	}
}

1;
