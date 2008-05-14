package Test::POE::Server::TCP;

use strict;
use warnings;
use POE qw(Wheel::SocketFactory Wheel::ReadWrite Filter::Line);
use Socket;
use Carp qw(carp croak);
use vars qw($VERSION);

$VERSION = '0.02';

sub spawn {
  my $package = shift;
  my %opts = @_;
  $opts{lc $_} = delete $opts{$_} for keys %opts;
  my $options = delete $opts{options};
  my $self = bless \%opts, $package;
  $self->{_prefix} = 'testd_';
  $self->{session_id} = POE::Session->create(
	object_states => [
	   $self => { shutdown       => '_shutdown',
		      send_event     => '__send_event',
		      send_to_client => '_send_to_client',
		      disconnect     => '_disconnect',
	            },
	   $self => [ qw(_start register unregister _accept_client _accept_failed _conn_input _conn_error _conn_flushed _conn_alarm _send_to_client __send_event _disconnect) ],
	],
	heap => $self,
	( ref($options) eq 'HASH' ? ( options => $options ) : () ),
  )->ID();
  return $self;
}

sub session_id {
  return $_[0]->{session_id};
}

sub getsockname {
  return unless $_[0]->{listener};
  return $_[0]->{listener}->getsockname();
}

sub port {
  my $self = shift;
  return ( sockaddr_in( $self->getsockname() ) )[0];
}

sub _conn_exists {
  my ($self,$wheel_id) = @_;
  return 0 unless $wheel_id and defined $self->{clients}->{ $wheel_id };
  return 1; 
}

sub shutdown {
  my $self = shift;
  $poe_kernel->call( $self->{session_id}, 'shutdown' );
}

sub _start {
  my ($kernel,$self,$sender) = @_[KERNEL,OBJECT,SENDER];
  $self->{session_id} = $_[SESSION]->ID();
  if ( $self->{alias} ) {
	$kernel->alias_set( $self->{alias} );
  } 
  else {
	$kernel->refcount_increment( $self->{session_id} => __PACKAGE__ );
  }
  if ( $kernel != $sender ) {
    my $sender_id = $sender->ID;
    $self->{events}->{$self->{_prefix} . 'all'}->{$sender_id} = $sender_id;
    $self->{sessions}->{$sender_id}->{'ref'} = $sender_id;
    $self->{sessions}->{$sender_id}->{'refcnt'}++;
    $kernel->refcount_increment($sender_id, __PACKAGE__);
    $kernel->post( $sender, $self->{_prefix} . 'registered', $self );
    $kernel->detach_myself();
  }

  $self->{listener} = POE::Wheel::SocketFactory->new(
      ( defined $self->{address} ? ( BindAddress => $self->{address} ) : () ),
      ( defined $self->{port} ? ( BindPort => $self->{port} ) : ( BindPort => 0 ) ),
      SuccessEvent   => '_accept_client',
      FailureEvent   => '_accept_failed',
      SocketDomain   => AF_INET,             # Sets the socket() domain
      SocketType     => SOCK_STREAM,         # Sets the socket() type
      SocketProtocol => 'tcp',               # Sets the socket() protocol
      Reuse          => 'on',                # Lets the port be reused
  );

  return;
}

sub _accept_client {
  my ($kernel,$self,$socket,$peeraddr,$peerport) = @_[KERNEL,OBJECT,ARG0..ARG2];
  my $sockaddr = inet_ntoa( ( unpack_sockaddr_in ( CORE::getsockname $socket ) )[1] );
  my $sockport = ( unpack_sockaddr_in ( CORE::getsockname $socket ) )[0];
  $peeraddr = inet_ntoa( $peeraddr );

  my $wheel = POE::Wheel::ReadWrite->new(
	Handle => $socket,
	_get_filters(
                  $self->{filter},
                  $self->{inputfilter},
                  $self->{outputfilter}
        ),
	InputEvent => '_conn_input',
	ErrorEvent => '_conn_error',
	FlushedEvent => '_conn_flushed',
  );

  return unless $wheel;
  
  my $id = $wheel->ID();
  $self->{clients}->{ $id } = 
  { 
				wheel    => $wheel, 
				peeraddr => $peeraddr,
				peerport => $peerport,
				sockaddr => $sockaddr,
				sockport => $sockport,
  };
  $self->_send_event( $self->{_prefix} . 'connected', $id, $peeraddr, $peerport, $sockaddr, $sockport );

  #$self->{clients}->{ $id }->{alarm} = $kernel->delay_set( '_conn_alarm', $self->{time_out} || 300, $id );
  return;
}

sub _get_filters {
    my ($client_filter, $client_infilter, $client_outfilter) = @_;
    if (defined $client_infilter or defined $client_outfilter) {
      return (
        "InputFilter"  => _load_filter($client_infilter),
        "OutputFilter" => _load_filter($client_outfilter)
      );
      if (defined $client_filter) {
        carp(
          "Filter ignored with InputFilter or OutputFilter"
        );
      }
    }
    elsif (defined $client_filter) {
     return ( "Filter" => _load_filter($client_filter) );
    }
    else {
      return ( Filter => POE::Filter::Line->new(), );
    }

}

# Get something: either arrayref, ref, or string
# Return filter
sub _load_filter {
    my $filter = shift;
    if (ref ($filter) eq 'ARRAY') {
        my @args = @$filter;
        $filter = shift @args;
        if ( _test_filter($filter) ){
            return $filter->new(@args);
        } else {
            return POE::Filter::Line->new(@args);
        }
    }
    elsif (ref $filter) {
        return $filter->clone();
    }
    else {
        if ( _test_filter($filter) ) {
            return $filter->new();
        } else {
            return POE::Filter::Line->new();
        }
    }
}

# Test if a Filter can be loaded, return sucess or failure
sub _test_filter {
    my $filter = shift;
    my $eval = eval {
        (my $mod = $filter) =~ s!::!/!g;
        require "$mod.pm";
        1;
    };
    if (!$eval and $@) {
        carp(
          "Failed to load [$filter]\n" .
          "Reason $@\nUsing defualt POE::Filter::Line "
        );
        return 0;
    }
    return 1;
}

sub _accept_failed {
  my ($kernel,$self,$operation,$errnum,$errstr,$wheel_id) = @_[KERNEL,OBJECT,ARG0..ARG3];
  warn "Wheel $wheel_id generated $operation error $errnum: $errstr\n";
  delete $self->{listener};
  $self->_send_event( $self->{_prefix} . 'listener_failed', $operation, $errnum, $errstr );
  return;
}

sub disconnect {
  my $self = shift;
  $poe_kernel->call( $self->{session_id}, '_disconnect', @_ );
}

sub _disconnect {
  my ($kernel,$self,$id) = @_[KERNEL,OBJECT,ARG0];
  return unless $self->_conn_exists( $id );
  $self->{clients}->{ $id }->{quit} = 1;
  return 1;
}

sub _conn_input {
  my ($kernel,$self,$input,$id) = @_[KERNEL,OBJECT,ARG0,ARG1];
  return unless $self->_conn_exists( $id );
  #$kernel->delay_adjust( $self->{clients}->{ $id }->{alarm}, $self->{time_out} || 300 );
  $self->_send_event( $self->{_prefix} . 'client_input', $id, $input );
  return;
}

sub _conn_error {
  my ($self,$errstr,$id) = @_[OBJECT,ARG2,ARG3];
  return unless $self->_conn_exists( $id );
  delete $self->{clients}->{ $id };
  $self->_send_event( $self->{_prefix} . 'disconnected', $id );
  return;
}

sub _conn_flushed {
  my ($self,$id) = @_[OBJECT,ARG0];
  return unless $self->_conn_exists( $id );
  if ( $self->{clients}->{ $id }->{BUFFER} ) {
    my $item = shift @{ $self->{clients}->{ $id }->{BUFFER} };
    unless ( $item ) {
      delete $self->{clients}->{ $id }->{BUFFER};
      $self->_send_event( $self->{_prefix} . 'client_flushed', $id );
      return;
    }
    $self->{clients}->{ $id }->{wheel}->put($item);
    return;
  }
  unless ( $self->{clients}->{ $id }->{quit} ) {
    $self->_send_event( $self->{_prefix} . 'client_flushed', $id );
    return;
  }
  delete $self->{clients}->{ $id };
  $self->_send_event( $self->{_prefix} . 'disconnected', $id );
  return;
}

sub _conn_alarm {
  my ($kernel,$self,$id) = @_[KERNEL,OBJECT,ARG0];
  return unless $self->_conn_exists( $id );
  delete $self->{clients}->{ $id };
  $self->_send_event( $self->{_prefix} . 'disconnected', $id );
  return;
}

sub _shutdown {
  my ($kernel,$self) = @_[KERNEL,OBJECT];
  delete $self->{listener};
  delete $self->{clients};
  $kernel->alarm_remove_all();
  $kernel->alias_remove( $_ ) for $kernel->alias_list();
  $kernel->refcount_decrement( $self->{session_id} => __PACKAGE__ ) unless $self->{alias};
#  $self->_pluggable_destroy();
  $self->_unregister_sessions();
  return;
}

sub register {
  my ($kernel, $self, $session, $sender, @events) =
    @_[KERNEL, OBJECT, SESSION, SENDER, ARG0 .. $#_];

  unless (@events) {
    warn "register: Not enough arguments";
    return;
  }

  my $sender_id = $sender->ID();

  foreach (@events) {
    $_ = $self->{_prefix} . $_ unless /^_/;
    $self->{events}->{$_}->{$sender_id} = $sender_id;
    $self->{sessions}->{$sender_id}->{'ref'} = $sender_id;
    unless ($self->{sessions}->{$sender_id}->{refcnt}++ or $session == $sender) {
      $kernel->refcount_increment($sender_id, __PACKAGE__);
    }
  }

  $kernel->post( $sender, $self->{_prefix} . 'registered', $self );
  return;
}

sub unregister {
  my ($kernel, $self, $session, $sender, @events) =
    @_[KERNEL,  OBJECT, SESSION,  SENDER,  ARG0 .. $#_];

  unless (@events) {
    warn "unregister: Not enough arguments";
    return;
  }

  $self->_unregister($session,$sender,@events);
  undef;
}

sub _unregister {
  my ($self,$session,$sender) = splice @_,0,3;
  my $sender_id = $sender->ID();

  foreach (@_) {
    $_ = $self->{_prefix} . $_ unless /^_/;
    my $blah = delete $self->{events}->{$_}->{$sender_id};
    unless ( $blah ) {
	warn "$sender_id hasn't registered for '$_' events\n";
	next;
    }
    if (--$self->{sessions}->{$sender_id}->{refcnt} <= 0) {
      delete $self->{sessions}->{$sender_id};
      unless ($session == $sender) {
        $poe_kernel->refcount_decrement($sender_id, __PACKAGE__);
      }
    }
  }
  undef;
}

sub _unregister_sessions {
  my $self = shift;
  my $testd_id = $self->session_id();
  foreach my $session_id ( keys %{ $self->{sessions} } ) {
     if (--$self->{sessions}->{$session_id}->{refcnt} <= 0) {
        delete $self->{sessions}->{$session_id};
	$poe_kernel->refcount_decrement($session_id, __PACKAGE__) 
		unless ( $session_id eq $testd_id );
     }
  }
}

sub __send_event {
  my( $self, $event, @args ) = @_[ OBJECT, ARG0, ARG1 .. $#_ ];
  $self->_send_event( $event, @args );
  return;
}

#sub send_event {
#  my $self = shift;
#  $poe_kernel->post( $self->{session_id}, '__send_event', @_ );
#}

sub _send_event  {
  my $self = shift;
  my ($event, @args) = @_;
  my $kernel = $POE::Kernel::poe_kernel;
  my %sessions;

  $sessions{$_} = $_ for (values %{$self->{events}->{$self->{_prefix} . 'all'}}, values %{$self->{events}->{$event}});

  $kernel->post( $_ => $event => @args ) for values %sessions;
  undef;
}

sub send_to_client {
  my $self = shift;
  $poe_kernel->call( $self->{session_id}, '_send_to_client', @_ );
}

sub _send_to_client {
  my ($kernel,$self,$id,$output) = @_[KERNEL,OBJECT,ARG0..ARG1];
  return unless $self->_conn_exists( $id );
  return unless $output;

  if ( ref $output eq 'ARRAY' ) {
    my $first = shift @{ $output };
    $self->{clients}->{ $id }->{BUFFER} = $output;
    $self->{clients}->{ $id }->{wheel}->put($first);
    return 1;
  }

  $self->{clients}->{ $id }->{wheel}->put($output);
  return 1;
}

q{Putting the test into POE};

__END__

=head1 NAME

Test::POE::Server::TCP - A POE Component providing TCP server services for test cases

=head1 SYNOPSIS

   # An echo server test

   use strict;
   use Test::More;
   use POE qw(Wheel::SocketFactory Wheel::ReadWrite Filter::Line);
   use Test::POE::Server::TCP;
   
   plan tests => 5;
   
   my @data = (
     'This is a test',
     'This is another test',
     'This is the last test',
   );
   
   POE::Session->create(
     package_states => [
   	'main' => [qw(
   			_start
   			_sock_up
   			_sock_fail
   			_sock_in
   			_sock_err
   			testd_registered
   			testd_connected
   			testd_disconnected
   			testd_client_input
   	)],
     ],
     heap => { data => \@data, },
   );
   
   $poe_kernel->run();
   exit 0;
   
   sub _start {
     $_[HEAP]->{testd} = Test::POE::Server::TCP->spawn(
   	address => '127.0.0.1',
   	port => 0,
     );
     return;
   }
   
   sub testd_registered {
     my ($heap,$object) = @_[HEAP,ARG0];
     $heap->{port} = $object->port();
     $heap->{factory} = POE::Wheel::SocketFactory->new(
   	RemoteAddress  => '127.0.0.1',
   	RemotePort     => $heap->{port},
   	SuccessEvent   => '_sock_up',
   	FailureEvent   => '_sock_fail',
     );
     return;
   }
   
   sub _sock_up {
     my ($heap,$socket) = @_[HEAP,ARG0];
     delete $heap->{factory};
     $heap->{socket} = POE::Wheel::ReadWrite->new(
   	Handle => $socket,
   	InputEvent => '_sock_in',
   	ErrorEvent => '_sock_err',
     );
     $heap->{socket}->put( $heap->{data}->[0] );
     return;
   }
   
   sub _sock_fail {
     my $heap = $_[HEAP];
     delete $heap->{factory};
     $heap->{testd}->shutdown();
     return;
   }
   
   sub _sock_in {
     my ($heap,$input) = @_[HEAP,ARG0];
     my $data = shift @{ $heap->{data} };
     ok( $input eq $data, 'Data matched' );
     unless ( scalar @{ $heap->{data} } ) {
       delete $heap->{socket};
       return;
     }
     $heap->{socket}->put( $heap->{data}->[0] );
     return;
   }
   
   sub _sock_err {
     delete $_[HEAP]->{socket};
     return;
   }
   
   sub testd_connected {
     my ($heap,$state,$id) = @_[HEAP,STATE,ARG0];
     pass($state);
     return;
   }
   
   sub testd_disconnected {
     pass($_[STATE]);
     $poe_kernel->post( $_[SENDER], 'shutdown' );
     return;
   }
   
   sub testd_client_input {
     my ($sender,$id,$input) = @_[SENDER,ARG0,ARG1];
     my $testd = $_[SENDER]->get_heap();
     $testd->send_to_client( $id, $input );
     return;
   }

=head1 DESCRIPTION

Test::POE::Server::TCP is a L<POE> component that provides a TCP server framework for inclusion in 
client component test cases, instead of having to roll your own.

Once registered with the component, a session will receive events related to client connects, disconnects,
input and flushed output. Each of these events will refer to a unique client ID which may be used in 
communication with the component when sending data to the client or disconnecting a client connection.

=head1 CONSTRUCTOR

=over 

=item spawn

Takes a number of optional arguments:

  'alias', set an alias on the component;
  'address', bind the listening socket to a particular address;
  'port', listen on a particular port, default is 0, assign a random port;
  'options', a hashref of POE::Session options;
  'filter', specify a POE::Filter to use for client connections, default is POE::Filter::Line;
  'inputfilter', specify a POE::Filter for client input;
  'outputfilter', specify a POE::Filter for output to clients;

The semantics for C<filter>, C<inputfilter> and C<outputfilter> are the same as for L<POE::Component::Server::TCP> in that one
may provide either a C<SCALAR>, C<ARRAYREF> or an C<OBJECT>.

If the component is C<spawn>ed within another session it will automatically C<register> the parent session
to receive C<all> events.

=back

=head1 METHODS

=over

=item session_id

Returns the POE::Session ID of the component.

=item shutdown

Terminates the component. Shuts down the listener and disconnects connected clients.

=item send_to_client

Send some output to a connected client. First parameter must be a valid client id. Second parameter is a string of text to send.

=item disconnect

Places a client connection in pending disconnect state. Requires a valid client ID as a parameter. Set this, then send an applicable message to the client using send_to_client() and the client connection will be terminated.

=item getsockname

Access to the L<POE::Wheel::SocketFactory> method of the underlying listening socket.

=item port 

Returns the port that the component is listening on.

=back

=head1 INPUT EVENTS

These are events that the component will accept:

=over

=item register

Takes N arguments: a list of event names that your session wants to listen for, minus the 'testd_' prefix.

Registering for 'all' will cause it to send all TESTD-related events to you; this is the easiest way to handle it.

=item unregister

Takes N arguments: a list of event names which you don't want to receive. If you've previously done a 'register' for a particular event which you no longer care about, this event will tell the POP3D to stop sending them to you. (If you haven't, it just ignores you. No big deal).

=item shutdown

Terminates the component. Shuts down the listener and disconnects connected clients.

=item send_to_client

Send some output to a connected client. First parameter must be a valid client ID. 
Second parameter is a string of text to send.

=item disconnect

Places a client connection in pending disconnect state. Requires a valid client ID as a parameter. Set this, then send an applicable message to the client using send_to_client() and the client connection will be terminated.

=back

=head1 OUTPUT EVENTS

The component sends the following events to registered sessions:

=over

=item testd_registered

This event is sent to a registering session. ARG0 is the Test::POE::Server::TCP object.

=item testd_listener_failed

Generated if the component cannot either start a listener or there is a problem
accepting client connections. ARG0 contains the name of the operation that failed. 
ARG1 and ARG2 hold numeric and string values for $!, respectively.

=item testd_connected

Generated whenever a client connects to the component. ARG0 is the client ID, ARG1
is the client's IP address, ARG2 is the client's TCP port. ARG3 is our IP address and
ARG4 is our socket port.

=item testd_disconnected

Generated whenever a client disconnects. ARG0 is the client ID.

=item testd_client_input

Generated whenever a client sends us some traffic. ARG0 is the client ID, ARG1 is the data sent ( tokenised by whatever POE::Filter you 
specified. 

=item testd_client_flushed

Generated whenever anything we send to the client is actually flushed down the 'line'. ARG0 is the client ID.

=back

=head1 AUTHOR

=head1 LICENSE

Copyright C<(c)> Chris Williams

This module may be used, modified, and distributed under the same terms as Perl itself. Please see the license that came with your Perl distribution for details.

=head1 SEE ALSO

L<POE>

L<POE::Component::Server::TCP>

=cut
