#!/bin/perl
# this is the part of smarthome scripts
# This particular is ajax security hub monitor service handler.
use warnings;
use strict;
use v5.10; # for 'state' decl
use Carp;
use Digest::CRC qw(crc16);
use Errno qw( EAGAIN EWOULDBLOCK );
use Fcntl qw( F_GETFL F_SETFL O_NONBLOCK );
use File::Path qw(make_path);
use File::Basename;
use Getopt::Long;
use POSIX;
use Socket;

#these are from config file:
my %o; # options

# local vars:
my $debug = 0; # screen output is not suppressed
my $config_path = 'ajax_service.config'; # default

####################################################

GetOptions (
  'c=s' => \$config_path,
  'd' => \$debug,
  'h' => \&help,
) or die "GetOptions: $!";

load_config( $config_path );

my $proto = getprotobyname( 'tcp' );

my $t = time;
for(; ; sleep( 5 ) )
{
  last if socket( Server, PF_INET, SOCK_STREAM, $proto );
  time - $t > $o{ 'error recovery time' } and report_and_exit( "socket: $!" );
}

for(; ; sleep( 5 ) )
{
  last if setsockopt( Server, SOL_SOCKET, SO_REUSEADDR, pack( 'l', 1 ) );
  time - $t > $o{ 'error recovery time' } and report_and_exit( "setsockopt: $!" );
}

for(; ; sleep( 5 ) )
{
  last if bind( Server, sockaddr_in($o{ 'port' }, inet_aton($o{ 'host' } ) ) );
  time - $t > $o{ 'error recovery time' } and report_and_exit( "bind: $!" );
}

for(; ; sleep( 5 ) )
{
  last if listen( Server, SOMAXCONN );
  time - $t > $o{ 'error recovery time' } and report_and_exit( "listen: $!" );
}

#---------------------------------------------
dolog( '* Started' );

my ( $answer, $changed, $conn_start, $fcntl_fl, $rawmsg, $rawmsglen, $sia, $lastsia, $paddr );
my $lastlogged = 0;
my $dup_count = 0; # how many times last message repeated
my $dup_first_arrived = 0; # when the 1st (original) dup message have arrived

#---------------------------------------------
for ( ; $paddr = accept( Client, Server ); close Client )
{
  my( $port, $iaddr ) = sockaddr_in( $paddr );
  my $name = gethostbyaddr( $iaddr, AF_INET );

  $debug and dolog( "connection from $name [", inet_ntoa( $iaddr ), "] at port $port" );

  if ( ! ( $fcntl_fl = fcntl(Client, F_GETFL, 0 ) ) || ! fcntl( Client, F_SETFL, $fcntl_fl || O_NONBLOCK ) )
  {
    dolog( "fcntl( Client ): $!" );
    next;
  }

  #---------------------------------------------
  # we'll keep this conn alive for max 15 sec to prevent stalls
  for( $conn_start = time; time - $conn_start < 15; sleep( 1 ) )
  {
    $rawmsg = '';
    $rawmsglen = sysread( Client, $rawmsg, 999 );

    next if ( ! defined( $rawmsg ) || ! $rawmsglen );

    $debug and dolog( '+ read ', $rawmsglen, ' bytes, ', time - $conn_start, ' seconds passed' );

    if ( ! defined( $rawmsglen ) || $rawmsglen < 0 )
    {
      next if ( $! == EAGAIN || $! == EWOULDBLOCK );

      $debug and dolog( "! Error ($!) reading Client msg: '$rawmsg'. Length: $rawmsglen" );

      last;
    }

    $sia = parseSIA( $rawmsg );

    $answer = gen_answer( $sia );

    $debug and dolog( 'DBG: answer: ', substr( $answer, 1, length( $answer ) - 2 ) );
    syswrite( Client, $answer, length $answer ); # don't care if errrrrrr

    next if $sia->{ 'status' } eq 'fatal';

    $changed = '';

    if ( defined( $lastsia ) )
    {
      foreach ( qw~account id lpref msg rpref status~ )
      {
        next if ( ! defined( $sia->{ $_ } ) || ! defined( $lastsia->{ $_ } ) );
        next if ( ( '' . $sia->{ $_ } ) eq ( '' . $lastsia->{ $_ } ) );

        $changed .= ( $changed eq '' ? '' : ', ' ) . $_;
      }
    }

    if ( defined( $lastsia ) && $changed eq '' )
    {
      ++$dup_count;

      next if time < $lastlogged + 3600; # 1 hour between the same nags

      dolog( '--- No new events... Last one repeated ', $dup_count, ' times within ', POSIX::round( ( time - $dup_first_arrived ) / 360) / 10, ' hrs:' );
    }
    else
    {
      $dup_count = 0;
      $dup_first_arrived = time;
    }

    $lastlogged = time;
    $lastsia = $sia;

    dolog( '< Status: ', $sia->{ 'status' }, '/', $sia->{ 'answer' }, ', ID: ', $sia->{ 'id' }, ', seq # ', $sia->{ 'seq' }, ', Recv: ', $sia->{ 'rpref' },
           ', Acct prefix: ', $sia->{ 'lpref' }, ', Acct: ', $sia->{ 'account' },
           $sia->{ 'msg' } ne '' ? ', Payload: ' . $sia->{ 'msg' } : ', NO payload', ', Time: ', $sia->{ 'time' } );

    $changed ne '' and dolog( '* Changed since last report: ', $changed );

    dolog( '>     Reply: ', substr( $answer, 1, length( $answer) - 2 ) );

    last;
  } # for( $conn_start... )
} # for ( accept )

dolog( '--- exitting: ', $!, '  ---' );

close Server;

exit(0);

#############################################################
# ajax sample:
#<0x0a>85420026"NULL"0000L0#000[]_21:58:31,08-08-2019<0x0d>
sub parseSIA
{
  my $data = $_[0];
  $data =~ s/[\s\0]*$//;

  my $sia = { 'status' => 'fatal', 'answer' => 'NAK' };
  my @errors;

  if ( ord(substr( $data, 0, 1 )) != 0x0a || ord(substr( $data, -1, 1)) == 0x0d )
  {
    dolog( '! parseSIA input has no \n and the beginning or \r at the end !' );
    return $sia;
  }

  $data = substr( $data, 1, length( $data ) - 1 );
  $sia->{ 'raw data' } = $data;
  my $str;

  # Check if CRC 2 Byte Binary or 4 Byte HEX
  if ( substr( $data, 4, 1 ) eq '0' && substr( $data, 8, 1 ) eq '"' ) # hex
  {
    $str = substr( $data, 8 );
    $sia->{ 'len' } = hex( substr( $data, 4, 4 ) );
    $sia->{ 'crc' } = hex( substr( $data, 0, 4 ) );
    $sia->{ 'crcformat' } = 'hex';
  }

  elsif ( substr( $data, 2, 1 ) eq '0' && substr( $data, 6, 1 ) eq '"' ) # bin
  {
    $str = substr( $data, 6 );
    $sia->{ 'len' } = hex( substr( $data, 2, 4 ) );
    $sia->{ 'crc' } = ord( substr( $data, 0, 1 ) ) * 256 + ord( substr( $data, 1, 1 ) );
    $sia->{ 'crcformat' } = 'bin';
  }

  else
  {
    dolog( 'Cant determine message format' );
    return $sia;
  }

  my $calc_len = length $str;

  if ( $calc_len != $sia->{ 'len' } )
  {
    push @errors, 'Length is different to the value in the message';
    push @errors, 'Msg len= ' . $sia->{ 'len' } . ', calc len=' . $calc_len;
  }

  my $calc_crc = crc16( $str );

  if ( $calc_crc != $sia->{ 'crc' } )
  {
    push @errors, 'CRC is different to the value in the message';
    push @errors, 'Msg crc= ' . $sia->{ 'crc' } . ', calc crc=' . $calc_crc;
  }

  # Example str:
  # "SIA-DCS"0002R1L232#78919[1234|NFA129][S123Main St., 55123]_11:10:00,10-12-2019
  # "SIA-DCS"0002R1L232#78919[ ][ ]_11:10:00,10-12-2019
  # "SIA-DCS"0266L0#alarm1[alarm2|Nri1OP0001*Familie*]_16:22:03,06-08-2018
  # http://s545463982.onlinehome.us/DC09Gen/
  # "*SIA-DCS"9876R579BDFL789ABC#12345A[209c9d400b655df7a26aecb6a887e7ee6ed8103217079aae7cbd9dd7551e96823263460f7ef0514864897ae9789534f1
  # regex = /\"(.+)\"(\d{4})(R(.{1,6})){0,1}(L(.{1,6}))\#([\w\d]+)\[(.+)/gm; // befor Isue 11
  # regex = /\"(.+)\"(\d{4})(R(.{0,6})){0,1}(L(.{0,6}))\#([\w\d]+)\[(.+)/gm; // Isue 11
  # ajax: "NULL"0000L0#000[]_21:58:31,08-08-2019
  # fmt:
  #   "string" - id (SIA-DCS, ACK) - required
  #   \d{4}    - sqeuence number (0002 or 0003) - required
  #   (R.{0,6})? - Receiver Number - optional (R0, R1, R123456)
  #   L.{0,6}  - Prefix Account number - required (L0, L1, L1232) - required
  #   # - literal
  #   [\w\d]+  - Account number - required (1224, ABCD124) - required
  #   [ - literal
  #   (.+) - message

  #$debug and dolog( map sprintf('%x ', ord($_)), split( //, $str ) );
  #$debug and dolog( map print($_,'  '), split( //, $str ) );

  if ( $str =~ /^"(.+)"(\d{4})(R(.{0,6}))?(L(.{0,6}))#([\w\d]+)\[([^\]]*)\]_?(.+)?/ )
  {
    my $lpref;

    $sia->{ 'id' }    = $1; # id (SIA-DCS, ACK) - required
    $sia->{ 'seq' }   = $2; # sequence number (0002 or 0003) - required
    $sia->{ 'rpref' } = $4; # Receiver Number - optional (R0, R1, R123456)

    $5 eq 'L' and $lpref = '0';

    $sia->{ 'lpref' } = defined( $6 ) ? $6 : $lpref; # Prefix Acount number - required (L0, L1, L1232) - required
    $sia->{ 'account' }   = $7; # Account number - required (1224, ABCD124) - required
    $sia->{ 'msg' }   = $8;
    $sia->{ 'time' }  = $9;
                                                            #  1:hh   2:mm   3:ss   4:mon  5:day  6:year
    if ( defined( $sia->{ 'time' } ) && $sia->{ 'time' } =~ /^(\d\d):(\d\d):(\d\d),(\d\d)-(\d\d)-(\d\d\d\d)/ )
    {
      $sia->{ 'ts' } = POSIX::mktime( $3, $2, $1, $5, $4 - 1, $6 - 1900 );

      if ( abs( $sia->{ 'ts' } - time ) > 20 ) # time correction needed
      {
#        $sia->{ 'status' } = 'warn';
#        $sia->{ 'answer' } = 'NAK';
#        push @errors, '? Time correction is needed. Shift is ' . ( $sia->{ 'ts' } - time ) . ' sec ( hub - server )';
        if ( time > $lastlogged + 3600 ) # 1 hour between the same nags
        {
          dolog( '? Time correction is needed. Shift is ', nice_time_range( $sia->{ 'ts' } - time ), ' ( hub - server )' );
        }
      }
    }
    else
    {
      $sia->{ 'ts' } = undef;
    }

    if ( $#errors == -1 )
    {
      $sia->{ 'status' } = 'OK';
      $sia->{ 'answer' } = 'ACK';
    }

    if ( $debug )
    {
      dolog( '         parseSIA: ' );

      while ( my($k,$v) = each %$sia )
      {
        dolog( '                   \'', $k, "' = <", ( defined($v) ? $v : '!UNDEF!' ), '>' );
      }
    }

    $#errors == -1 and return $sia;
  } # if ( $str =~ 
  else
  {
    push @errors, 'unknown message format';
  }

  dolog( '! Error(s) parsing input message: ', join(', ', @errors) );
  dolog( '! ... received: ', $data );

  return $sia;
}

#####################################
# SIA: produce [n]ACK,etc string to answer to client
# in: recevied and parsed message hash
# out: undef if error, message to Client if OK
sub gen_answer
{
  my $sia = $_[0];

  my $str;
  my $doack = defined( $sia );

  if ( $sia->{ 'answer' } eq 'ACK' )
  {
     $str = '"ACK"' . $sia->{ 'seq' }
     . ( defined( $sia->{ 'rpref' } ) ? 'R' . $sia->{ 'rpref' } : '' )
     . 'L' . $sia->{ 'lpref' }
     . '#' . $sia->{ 'account' } . '[]';
  }

  elsif ( $sia->{ 'answer' } eq 'NAK' )
  {
    $str = '"NAK"0000R0L0A0[]_' . get_times( 'sia' );
  }

  elsif ( $sia->{ 'answer' } eq 'DOU' )
  {
    $str = '"DOU"0000R0L0A0[]_' . get_times( 'sia' );
  }

  else # unknown
  {
    dolog( '! Invalid answer action: ', $sia->{ 'answer' }, '. Replying with NAK' );
    $str = '"NAK"0000R0L0A0[]_' . get_times( 'sia' );
  }

  my $crc = crc16( $str );

  if ( exists $sia->{ 'crcformat' } && $sia->{ 'crcformat' } eq 'bin' )
  {
    $crc = sprintf( '%c%c', $crc >> 8 & 0xff, $crc & 0xff);
  }
  else # hex by default
  {
    $crc = sprintf( '%04X', $crc );
  }

  return chr(0x0a) . $crc . sprintf( '0%03X', length $str ) . $str . chr(0x0d);
}

####################################################
# in: seconds, out: "X (hours|minutes|etc...)"
sub nice_time_range
{
  my $t = $_[0];
  my $r = '';
  my @ranges = ( 1, 60, 3600, 86400, 2592000 );
  my @range_str = qw( second minute hour day month );
  my $range = $#ranges; # decrements on next
  my $sign = '';

  if ( $t == 0 )
  {
    return '0 (same time)';
  }

  if( $t < 0 )
  {
    $sign = '-';
    $t = -$t;
  }

  while( $t >= 1 && $range > -1 )
  {
    if ( $t >= $ranges[ $range ] )
    {
      my $cnt = POSIX::round( $t / $ranges[ $range ] );
      $t -= $cnt * $ranges[ $range ];
      $r .= ( $r ne '' ? ', ' : '' ) . $cnt . ' ' . $range_str[ $range ] . ( $cnt > 1 ? 's' : '' );
    }

    --$range;
  }

  return $sign . $r;
}

####################################################
sub get_times
{
  if ( $_[0] eq 'sia' )
  {
    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = gmtime(time); $year += 1900; ++$mon;
    return sprintf '%02d:%02d:%02d,%02d-%02d-%d', $hour, $min, $sec, $mday, $mon, $year;
  }

  my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(time); $year += 1900; ++$mon;
  $_[0] eq 'ts' and return sprintf '%d%02d%02d%02d%02d%02d', $year, $mon, $mday, $hour, $min, $sec;
  $_[0] eq 'd'  and return sprintf '%d.%02d.%02d', $year, $mon, $mday;
  $_[0] eq 'h'  and return sprintf '%02d', $hour;
  $_[0] eq 'hm' and return sprintf '%02d.%02d', $hour, $min;
  if ( $_[0] eq 'hms' || $_[0] eq 't' )
  {
    return sprintf '%02d.%02d.%02d', $hour, $min, $sec;
  }
  $_[0] eq 'dt' and return (get_times( 'd' ) . ',' . get_times( 't' ));
}

#####################################
sub dolog
{
  state $last_msg = '';
  state $last_used = 0;
  state $nag_period = 5;
  my $s = '';

  foreach ( @_ )
  {
    defined( $_ ) or $_ = '<UNDEF>';
    $s .= $_;
  }

  my $same_as_last = $s eq $last_msg;

  if ( ++$last_used % $nag_period == 0 )
  {
    if ( $same_as_last )
    {
      $s = '';
    }
    else
    {
      $last_msg = $s;
      $s = get_times( 'dt' ) . ' ' . $s;
    }

    $s = '. Last log entry repeated ' . $last_used . " times.\n" . $s;
    $nag_period *= 2;
  }

  if ( ! $same_as_last )
  {
    $last_used = 0;
    $nag_period = 5;
  }

  if ( $debug )
  {
    print get_times( 'dt' ), ' ', $s, "\n";
    return;
  }

  open LOG, '>>', $o{ 'log file' } or report_and_exit( $o{ 'log file' }, ": $!" );
  print LOG get_times( 'dt' ), ' ', $s, "\n";
  close LOG;
}

#####################################
sub help
{
  print "Use: ajax_service.pl [options]\n";
  print "Options:\n\t-c config_file_path\n\t-d - debug\n";
  exit(1);
}

#############################################################
sub report_and_exit
{
  if ( $debug )
  {
    print join "\n", @_;
  }
  else
  {
    if ( exists $o{ 'whine email' } and $o{ 'whine email' } ne '' )
    {
      open M, '|-', '/sbin/sendmail ' . $o{ 'whine email' } or croak "sendmail: $!/$?";
      print M "From: ajax_service\n";
      print M "To: " . $o{ 'whine email' } . "\n";
      print M "\n\n" . join("\n", @_);

      if ( open( L, '<', $o{ 'log file' }) )
      {
        print M "\nLog file follows:\n";
        while(<L>)
        {
          print M $_;
        }
        close L;
      }
      close M;
    } # email

    dolog( @_);
  }

  exit($? > $! ? $? : $!);
}

#############################################################
sub load_config
{
  my $file = $_[0];

  if ( ! -f $file )
  {
    $file =~ m?/? and croak "Can't open config: $file";

    $file = dirname(__FILE__) . '/' . $file;
  }

  $debug and print "+ Loading config: $file\n";

  my $cfg;
  open C, '<', $file or die "config file: '$file': $!";
  sysread( C, $cfg, 999999 ) or die "config is empty?";
  close C;
  eval $cfg;
}

# SIA2 fmt:
# SSRRL[#AAAAAA|EMMZZZZ/MMZZZZ/MMZZZZ][DC4]
# SS - Protocol identifier for SIA protocol 2
# RR - Receiver number 00-FE
# L  - Line number 1-E
# [  - Beginning data delimiter
#   #  - Account ID block code
#   AAAAAA - Account ID, maximum sixteen digits (Patriot 5.2 currently only supports a maximum of six digits)
#   |  - Field separator
#     E  - Function block code
#     MM - Event code or modifier
#     ZZZZ - Zone code, or user code, or time/date information
#     /  - Data code packet separator
# ]  - Ending data delimiter
# [DC4] - Terminator, 14 Hex

