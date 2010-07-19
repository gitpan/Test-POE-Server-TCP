
use strict;
use warnings;

BEGIN { require v5.6.0; }

use ExtUtils::MakeMaker 6.31;



my %WriteMakefileArgs = (
  'ABSTRACT' => 'A POE Component providing TCP server services for test cases',
  'AUTHOR' => 'Chris Williams <chris@bingosnet.co.uk>',
  'BUILD_REQUIRES' => {
    'ExtUtils::MakeMaker' => '6.42',
    'Test::More' => '0.47',
    'Text::ParseWords' => '0'
  },
  'CONFIGURE_REQUIRES' => {
    'ExtUtils::MakeMaker' => '6.42'
  },
  'DISTNAME' => 'Test-POE-Server-TCP',
  'EXE_FILES' => [],
  'LICENSE' => 'perl',
  'NAME' => 'Test::POE::Server::TCP',
  'PREREQ_PM' => {
    'POE' => '1.004',
    'POE::Filter' => '0',
    'POE::Filter::Line' => '0',
    'POE::Wheel::ReadWrite' => '0',
    'POE::Wheel::SocketFactory' => '0'
  },
  'VERSION' => '1.14',
  'test' => {
    'TESTS' => 't/*.t'
  }
);


unless ( eval { ExtUtils::MakeMaker->VERSION(6.56) } ) {
  my $br = delete $WriteMakefileArgs{BUILD_REQUIRES};
  my $pp = $WriteMakefileArgs{PREREQ_PM};
  for my $mod ( keys %$br ) {
    if ( exists $pp->{$mod} ) {
      $pp->{$mod} = $br->{$mod} if $br->{$mod} > $pp->{$mod};
    }
    else {
      $pp->{$mod} = $br->{$mod};
    }
  }
}

delete $WriteMakefileArgs{CONFIGURE_REQUIRES}
  unless eval { ExtUtils::MakeMaker->VERSION(6.52) };

WriteMakefile(%WriteMakefileArgs);



