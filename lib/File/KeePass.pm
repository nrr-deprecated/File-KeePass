package File::KeePass;

=head1 NAME

File::KeePass - Interface to KeePass V1 database files

=cut

use strict;
use warnings;
use Carp qw(croak);
use Crypt::Rijndael;
use Digest::SHA qw(sha256);

use constant DB_HEADER_SIZE   => 124;
use constant DB_SIG_1         => 0x9AA2D903;
use constant DB_SIG_2_v1      => 0xB54BFB65;
use constant DB_SIG_2_v2      => 0xB54BFB67;
use constant DB_VER_DW        => 0x00030002;
use constant DB_FLAG_SHA2     => 1;
use constant DB_FLAG_RIJNDAEL => 2;
use constant DB_FLAG_ARCFOUR  => 4;
use constant DB_FLAG_TWOFISH  => 8;

our $VERSION = '0.03';
my %locker;

sub new {
    my $class = shift;
    return bless {@_}, $class;
}

sub auto_lock {
    my $self = shift;
    $self->{'auto_lock'} = shift if @_;
    return !exists($self->{'auto_lock'}) || $self->{'auto_lock'};
}

###----------------------------------------------------------------###

sub load_db {
    my $self = shift;
    my $file = shift || croak "Missing file\n";
    my $pass = shift || croak "Missing pass\n";

    open(my $fh, '<', $file) || croak "Couldn't open $file: $!\n";
    my $size = -s $file;
    read($fh, my $buffer, $size);
    close $fh;
    croak "Couldn't read entire file contents of $file.\n" if length($buffer) != $size;
    return $self->parse_db($buffer, $pass);
}

sub save_db {
    my $self = shift;
    my $file = shift || croak "Missing file\n";
    my $pass = shift || croak "Missing pass\n";

    my $buf = $self->gen_db($pass);
    my $bak = "$file.bak";
    my $tmp = "$file.new.".int(time());
    open(my $fh, '>', $tmp) || croak "Couldn't open $tmp: $!\n";
    print $fh $buf;
    close $fh;
    if (-s $tmp ne length($buf)) {
        croak "Written file size of $tmp didn't match (".(-s $tmp)." != ".length($buf).") - not moving into place\n";
        unlink($tmp);
    }

    # try to move the file into place
    if (-e $bak) {
        if (!unlink($bak)) {
            unlink($tmp);
            croak "Couldn't removing already existing backup $bak: $!\n";
        }
    }
    if (-e $file) {
        if (!rename($file, $bak)) {
            unlink($tmp);
            croak "Couldn't backup $file to $bak: $!\n";
        }
    }
    rename($tmp, $file) || croak "Couldn't move $tmp to $file: $!\n";
    if (!$self->{'keep_backup'} && -e $bak) {
        unlink($bak) || croak "Couldn't removing temporary backup $bak: $!\n";
    }

    return 1;
}

sub clear {
    my $self = shift;
    $self->unlock;
    delete $self->{'groups'};
    delete $self->{'header'};
}

###----------------------------------------------------------------###

sub parse_db {
    my ($self, $buffer, $pass) = @_;

    # parse and verify headers
    my $head = $self->parse_header($buffer);
    $buffer = substr($buffer, $head->{'header_size'});

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'}; # i suppose this introduces cryptographic overhead
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);

    # decrypt the buffer
    if ($head->{'enc_type'} eq 'rijndael') {
        $buffer = $self->decrypt_rijndael_cbc($buffer, $key, $head->{'enc_iv'});
    } else {
        die "Unimplemented enc_type $head->{'enc_type'}";
    }

    croak "The file could not be decrypted either because the key is wrong or the file is damaged.\n"
        if length($buffer) > 2**31 || (!length($buffer) && $head->{'n_groups'});
    croak "The file checksum did not match.\nThe key is wrong or the file is damaged (or we need to implement utf8 input a bit better)\n"
        if $head->{'checksum'} ne sha256($buffer);

    # read the db
    my ($groups, $gmap, $pos) = $self->parse_groups($buffer, $head->{'n_groups'});
    $self->parse_entries($buffer, $head->{'n_entries'}, $pos, $gmap, $groups);

    $self->{'header'} = $head;

    $self->unlock if $self->{'groups'}; # make sure we don't leave dangling keys should we reopen a new db
    $self->{'groups'} = $groups;
    $self->lock if $self->auto_lock;
    return 1;
}

sub parse_header {
    my ($self, $buffer) = @_;
    my $size = length($buffer);
    my ($sig1, $sig2) = unpack 'LL', $buffer;

    if ($sig1 != DB_SIG_1) {
        croak "File signature (sig1) did not match ($sig1 != ".DB_SIG_1().")\n";
    }
    elsif ($sig2 eq DB_SIG_2_v1) {
        croak "File was smaller than db header ($size < ".DB_HEADER_SIZE().")\n" if $size < DB_HEADER_SIZE;
        my @f = qw(sig1 sig2 flags ver seed_rand enc_iv n_groups n_entries checksum seed_key seed_rot_n);
        my $t =   'L    L    L     L   a16       a16    L        L         a32      a32      L';
        my %h = (version => 1, header_size => DB_HEADER_SIZE);
        @h{@f} = unpack $t, $buffer;
        croak "Unsupported file version ($h{'ver'}).\n" if $h{'ver'} & 0xFFFFFF00 != DB_VER_DW & 0xFFFFFF00;

        $h{'enc_type'} = ($h{'flags'} & DB_FLAG_RIJNDAEL) ? 'rijndael'
                       : ($h{'flags'} & DB_FLAG_TWOFISH)  ? 'twofish'
                       : die "Unknown encryption type\n";
        return \%h;

    }
    elsif ($sig2 eq DB_SIG_2_v2) {
        my %h = (sig1 => $sig1, sig2 => $sig2, version => 2, enc_type => 'rijndael');
        my $pos = 8;
        ($h{'ver'}) = unpack "\@$pos L", $buffer;
        $pos += 4;
        croak "Unsupported file version2 ($h{'ver'}).\n" if $h{'ver'} & 0xFFFF0000 > 0x00020000 & 0xFFFF0000;

        while (1) {
            my ($type, $size) = unpack "\@$pos CS", $buffer;
            $pos += 3;
            if (!$type) {
                $pos += $size;
                last;
            }
            my ($val) = unpack "\@$pos a$size", $buffer;
            $pos += $size;
            if ($type == 1) {
                $h{'comment'} = $val;
            } elsif ($type == 2) {
                $h{'cipher_id'} = $val;
            } elsif ($type == 3) {
                $h{'compression_flags'} = $val;
            } elsif ($type == 4) {
                $h{'master_seed'} = $h{'seed_rand'} = unpack 'a16', $val;
            } elsif ($type == 5) {
                $h{'seed_key'} = unpack 'a32', $val;
            } elsif ($type == 6) {
                $h{'seed_rot_n'} = unpack 'L', $val;
            } elsif ($type == 7) {
                $h{'enc_iv'} = unpack 'a16', $val;
            } elsif ($type == 8) {
                $h{'protected_stream_key'} = $val;
            } elsif ($type == 9) {
                $h{'stream_start_bytes'} = $val;
            } elsif ($type == 10) {
                $h{'inner_random_stream_id'} = $val;
            } else {
                print "$type, $val\n";
            }
        }

        $h{'header_size'} = $pos;
        croak "Parsing of keepass v2 files is not yet supported.\n";
        return \%h;
    }
    else {
        die "Second file signature did not match ($sig2 != ".DB_SIG_2_v1()." or ".DB_SIG_2_v2().")\n";
    }
}

sub parse_groups {
    my ($self, $buffer, $n_groups) = @_;
    my $pos = 0;

    my @groups;
    my %gmap; # allow entries to find their groups (group map)
    my @gref = (\@groups); # group ref pointer stack - let levels nest safely
    my $group = {};
    while ($n_groups) {
        my $type = unpack 'S', substr($buffer, $pos, 2);
        $pos += 2;
        die "Group header offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Group header offset is out of range. ($pos, $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $group->{'id'}       = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 2) {
            ($group->{'title'}   = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 3) {
            $group->{'created'}  = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 4) {
            $group->{'modified'} = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 5) {
            $group->{'accessed'} = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 6) {
            $group->{'expires'}  = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 7) {
            $group->{'icon'}     = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 8) {
            $group->{'level'}    = unpack 'S', substr($buffer, $pos, 2);
        } elsif ($type == 0xFFFF) {
            $group->{'created'} ||= '';
            $n_groups--;
            $gmap{$group->{'id'}} = $group;
            my $level = $group->{'level'} || 0;
            if (@gref > $level + 1) { # gref is index base 1 because the root is a pointer to \@groups
                splice @gref, $level + 1;
            } elsif (@gref < $level + 1) {
                push @gref, ($gref[-1]->[-1]->{'groups'} = []);
            }
            push @{ $gref[-1] }, $group;
            $group = {};
        } else {
            $group->{'unknown'}->{$type} = substr($buffer, $pos, $size);
        }
        $pos += $size;
    }

    return (\@groups, \%gmap, $pos);
}

sub parse_entries {
    my ($self, $buffer, $n_entries, $pos, $gmap, $groups) = @_;

    my $entry = {};
    while ($n_entries) {
        my $type = unpack 'S', substr($buffer, $pos, 2);
        $pos += 2;
        die "Entry header offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Entry header offset is out of range for type $type. ($pos, ".length($buffer).", $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $entry->{'id'}        = unpack 'H*', substr($buffer, $pos, $size);
        } elsif ($type == 2) {
            $entry->{'group_id'}  = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 3) {
            $entry->{'icon'}      = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 4) {
            ($entry->{'title'}    = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 5) {
            ($entry->{'url'}      = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 6) {
            ($entry->{'username'} = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 7) {
            ($entry->{'password'} = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 8) {
            ($entry->{'comment'}  = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 9) {
            $entry->{'created'}   = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xA) {
            $entry->{'modified'}  = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xB) {
            $entry->{'accessed'}  = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xC) {
            $entry->{'expires'}   = $self->parse_date(substr($buffer, $pos, $size));
	} elsif ($type == 0xD) {
            ($entry->{'bin_desc'} = substr($buffer, $pos, $size)) =~ s/\0$//;
	} elsif ($type == 0xE) {
            $entry->{'binary'}    = substr($buffer, $pos, $size);
        } elsif ($type == 0xFFFF) {
            $entry->{'created'} ||= '';
            $n_entries--;
            my $gid = delete $entry->{'group_id'};
            my $ref = $gmap->{$gid};
            if (!$ref) { # orphaned nodes go in special group
                $gid = -1;
                if (!$gmap->{$gid}) {
                    push @$groups, ($gmap->{$gid} = {id => $gid, title => '*Orphaned*', icon => 0});
                }
                $ref = $gmap->{$gid};
            }

            if ($entry->{'comment'} && $entry->{'comment'} eq 'KPX_GROUP_TREE_STATE') {
                if (!defined($entry->{'binary'}) || length($entry->{'binary'}) < 4) {
                    warn "Discarded metastream KPX_GROUP_TREE_STATE because of a parsing error."
                } else {
                    my $n = unpack 'L', substr($entry->{'binary'}, 0, 4);
                    if ($n * 5 != length($entry->{'binary'}) - 4) {
                        warn "Discarded metastream KPX_GROUP_TREE_STATE because of a parsing error.";
                    } else {
                        for (my $i = 0; $i < $n; $i++) {
                            my $group_id    = unpack 'L', substr($entry->{'binary'}, 4 + $i * 5, 4);
                            my $is_expanded = unpack 'C', substr($entry->{'binary'}, 8 + $i * 5, 1);
                            $gmap->{$group_id}->{'expanded'} = $is_expanded;
                        }
                    }
                }
                $entry = {};
                next;
            }

            push @{ $ref->{'entries'} }, $entry;
            $entry = {};
        } else {
            $entry->{'unknown'}->{$type} = substr($buffer, $pos, $size);
        }
        $pos += $size;
    }
}

sub parse_date {
    my ($self, $packed) = @_;
    my @b = unpack('C*', $packed);
    my $year = ($b[0] << 6) | ($b[1] >> 2);
    my $mon  = (($b[1] & 0b11)     << 2) | ($b[2] >> 6);
    my $day  = (($b[2] & 0b111111) >> 1);
    my $hour = (($b[2] & 0b1)      << 4) | ($b[3] >> 4);
    my $min  = (($b[3] & 0b1111)   << 2) | ($b[4] >> 6);
    my $sec  = (($b[4] & 0b111111));
    return sprintf "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $day, $hour, $min, $sec;
}

###----------------------------------------------------------------###

sub decrypt_rijndael_cbc {
    my ($self, $buffer, $key, $enc_iv) = @_;
    my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($enc_iv);
    $buffer = $cipher->decrypt($buffer);
    my $extra = ord(substr $buffer, -1, 1);
    substr($buffer, length($buffer) - $extra, $extra, '');
    return $buffer;
}

sub encrypt_rijndael_cbc {
    my ($self, $buffer, $key, $enc_iv) = @_;
    my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($enc_iv);
    my $extra = (16 - length($buffer) % 16) || 16; # always pad so we can always trim
    $buffer .= chr($extra) for 1 .. $extra;
    return $cipher->encrypt($buffer);
}

###----------------------------------------------------------------###

sub gen_date {
    my ($self, $date) = @_;
    return "\0\0\0\0\0" if ! $date;
    my ($year, $mon, $day, $hour, $min, $sec) = $date =~ /^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$/ ? ($1,$2,$3,$4,$5,$6) : die "Invalid date ($date)";
    return pack('C*',
                ($year >> 6) & 0b111111,
                (($year & 0b111111) << 2) | (($mon >> 2) & 0b11),
                (($mon & 0b11) << 6) | (($day & 0b11111) << 1) | (($hour >> 4) & 0b1),
                (($hour & 0b1111) << 4) | (($min >> 2) & 0b1111),
                (($min & 0b11) << 6) | ($sec & 0b111111),
               );
}

sub gen_db {
    my $self = shift;
    my $pass = shift;
    croak "Missing pass\n" if ! defined($pass);
    my $groups = shift || $self->groups;
    croak "Please unlock before calling gen_db" if $self->is_locked($groups);
    my $head   = shift || {};

    srand((time() ^ $$) * rand()) if ! $self->{'srand'};
    foreach my $key (qw(seed_rand enc_iv)) {
        next if defined $head->{$key};
        $head->{$key} = '';
        $head->{$key} .= chr(int(255 * rand())) for 1..16;
    }
    $head->{'seed_key'}   = sha256(time.rand().$$) if ! defined $head->{'seed_key'};
    $head->{'seed_rot_n'} = 50_000 if ! defined $head->{'seed_rot_n'};

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'};
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);

    my $buffer  = '';
    my $entries = '';
    my @g = $self->find_groups({}, $groups);
    if (grep {$_->{'expanded'}} @g) {
        my $e = ($self->find_entries({title => 'Meta-Info', username => 'SYSTEM', comment => 'KPX_GROUP_TREE_STATE', url => '$'}))[0] || $self->add_entry({
            comment  => 'KPX_GROUP_TREE_STATE',
            title    => 'Meta-Info',
            username => 'SYSTEM',
            url      => '$',
            id     => '00000000000000000000000000000000',
            group    => $g[0],
        });
        $e->{'bin_desc'} = 'bin-stream';
        $e->{'binary'} = pack 'L', scalar(@g);
        $e->{'binary'} .= pack('LC', $_->{'id'}, $_->{'expanded'} ? 1 : 0) for @g;
    }
    foreach my $g (@g) {
        $head->{'n_groups'}++;
        my @d = ([1,      pack('LL', 4, $g->{'id'})],
                 [2,      pack('L', length($g->{'title'})+1)."$g->{'title'}\0"],
                 [3,      pack('L',  5). $self->gen_date($g->{'created'}  || $self->now)],
                 [4,      pack('L',  5). $self->gen_date($g->{'modified'} || $self->now)],
                 [5,      pack('L',  5). $self->gen_date($g->{'accessed'} || $self->now)],
                 [6,      pack('L',  5). $self->gen_date($g->{'expires'}  || $self->default_exp)],
                 [7,      pack('LL', 4, $g->{'icon'}  || 0)],
                 [8,      pack('LS', 2, $g->{'level'} || 0)],
                 [0xFFFF, pack('L', 0)]);
        push @d, [$_, $g->{'unknown'}->{$_}] for keys %{ $g->{'unknown'} || {} };
        $buffer .= pack('S',$_->[0]).$_->[1] for sort {$a->[0] <=> $b->[0]} @d;
        foreach my $e (@{ $g->{'entries'} || [] }) {
            $head->{'n_entries'}++;
            my @d = (
                     [1,      pack('LH*', length($e->{'id'})/2, $e->{'id'})],
                     [2,      pack('LL', 4, $g->{'id'}   || 0)],
                     [3,      pack('LL', 4, $e->{'icon'} || 0)],
                     [4,      pack('L', length($e->{'title'})+1)."$e->{'title'}\0"],
                     [5,      pack('L', length($e->{'url'})+1).   "$e->{'url'}\0"],
                     [6,      pack('L', length($e->{'username'})+1). "$e->{'username'}\0"],
                     [7,      pack('L', length($e->{'password'})+1). "$e->{'password'}\0"],
                     [8,      pack('L', length($e->{'comment'})+1).  "$e->{'comment'}\0"],
                     [9,      pack('L', 5). $self->gen_date($e->{'created'}  || $self->now)],
                     [0xA,    pack('L', 5). $self->gen_date($e->{'modified'} || $self->now)],
                     [0xB,    pack('L', 5). $self->gen_date($e->{'accessed'} || $self->now)],
                     [0xC,    pack('L', 5). $self->gen_date($e->{'expires'}  || $self->default_exp)],
                     [0xD,    pack('L', length($e->{'bin_desc'})+1)."$e->{'bin_desc'}\0"],
                     [0xE,    pack('L', length($e->{'binary'})).$e->{'binary'}],
                     [0xFFFF, pack('L', 0)]);
            push @d, [$_, $e->{'unknown'}->{$_}] for keys %{ $e->{'unknown'} || {} };
            $entries .= pack('S',$_->[0]).$_->[1] for sort {$a->[0] <=> $b->[0]} @d;
        }
    }
    $buffer .= $entries; $entries = '';

    $head->{'checksum'} = sha256($buffer);
    $head->{'sig1'}  = DB_SIG_1();
    $head->{'sig2'}  = DB_SIG_2_v1();
    $head->{'flags'} = DB_FLAG_RIJNDAEL();
    $head->{'ver'}   = DB_VER_DW();

    return $self->gen_header($head) . $self->encrypt_rijndael_cbc($buffer, $key, $head->{'enc_iv'});
}

sub gen_header {
    my ($self, $args) = @_;
    local $args->{'n_groups'}  = $args->{'n_groups'}  || 0;
    local $args->{'n_entries'} = $args->{'n_entries'} || 0;
    my $header = ''
        .pack('L4', @{ $args }{qw(sig1 sig2 flags ver)})
        .$args->{'seed_rand'}
        .$args->{'enc_iv'}
        .pack('L2', @{ $args }{qw(n_groups n_entries)})
        .$args->{'checksum'}
        .$args->{'seed_key'}
        .pack('L', $args->{'seed_rot_n'});
    die "Invalid generated header\n" if length($header) != DB_HEADER_SIZE;
    return $header;
}

###----------------------------------------------------------------###

sub dump_groups {
    my ($self, $args, $groups) = @_;
    my $t = '';
    my %gargs; for (keys %$args) { $gargs{$2} = $args->{$1} if /^(group_(.+))$/ };
    foreach my $g ($self->find_groups(\%gargs, $groups)) {
        my $indent = '    ' x $g->{'level'};
        $t .= $indent.($g->{'expanded'} ? '-' : '+')."  $g->{'title'} ($g->{'id'}) $g->{'created'}\n";
        local $g->{'groups'}; # don't recurse while looking for entries since we are already flat
        $t .= "$indent    > $_->{'title'}\t($_->{'id'}) $_->{'created'}\n" for $self->find_entries($args, [$g]);
    }
    return $t;
}

sub groups { shift->{'groups'} || croak "No groups loaded yet\n" }

sub header { shift->{'header'} || croak "No header loaded yet\n" }

sub add_group {
    my ($self, $args, $top_groups) = @_;
    $args = {%$args};
    my $groups;
    my $parent_group = delete $args->{'group'};
    if (defined $parent_group) {
        $parent_group = $self->find_group({id => $parent_group}, $top_groups) if ! ref($parent_group);
        $groups = $parent_group->{'groups'} ||= [] if $parent_group;
    }
    $groups ||= $top_groups || ($self->{'groups'} ||= []);

    $args->{$_} = $self->now for grep {!defined $args->{$_}} qw(created accessed modified);;
    $args->{'expires'} ||= $self->default_exp;

    push @$groups, $args;
    $self->find_groups({}, $groups); # sets title, level, icon and id
    return $args;
}

sub finder_tests {
    my ($self, $args) = @_;
    my @tests;
    foreach my $key (keys %{ $args || {} }) {
        next if ! defined $args->{$key};
        my ($field, $op) = ($key =~ m{ ^ (\w+) \s* (|!|=|!~|=~|gt|lt) $ }x) ? ($1, $2) : croak "Invalid find match criteria \"$key\"";
        push @tests,  (!$op || $op eq '=') ? sub {  defined($_[0]->{$field}) && $_[0]->{$field} eq $args->{$key} }
                    : ($op eq '!')         ? sub { !defined($_[0]->{$field}) || $_[0]->{$field} ne $args->{$key} }
                    : ($op eq '=~')        ? sub {  defined($_[0]->{$field}) && $_[0]->{$field} =~ $args->{$key} }
                    : ($op eq '!~')        ? sub { !defined($_[0]->{$field}) || $_[0]->{$field} !~ $args->{$key} }
                    : ($op eq 'gt')        ? sub {  defined($_[0]->{$field}) && $_[0]->{$field} gt $args->{$key} }
                    : ($op eq 'lt')        ? sub {  defined($_[0]->{$field}) && $_[0]->{$field} lt $args->{$key} }
                    : croak;
    }
    return @tests;
}

sub find_groups {
    my ($self, $args, $groups, $level) = @_;
    my @tests = $self->finder_tests($args);
    my @groups;
    my %used;
    my $container = $groups || $self->groups;
    for my $g (@$container) {
        $g->{'level'} = $level || 0;
        $g->{'title'} = '' if ! defined $g->{'title'};
        $g->{'icon'}  ||= 0;
        while (!defined($g->{'id'}) || $used{$g->{'id'}}++) {
            warn "Found duplicate group_id - generating new one for \"$g->{'title'}\"" if defined($g->{'id'});
            $g->{'id'} = int((2**32-1) * rand());
        }
        if (!@tests || !grep{!$_->($g)} @tests) {
            push @groups, $g;
            push @{ $self->{'__group_groups'} }, $container if $self->{'__group_groups'};
        }
        push @groups, $self->find_groups($args, $g->{'groups'}, $g->{'level'} + 1) if $g->{'groups'};
    }
    return @groups;
}

sub find_group {
    my $self = shift;
    local $self->{'__group_groups'} = [] if wantarray;
    my @g = $self->find_groups(@_);
    croak "Found too many groups (@g)" if @g > 1;
    return wantarray ? ($g[0], $self->{'__group_groups'}->[0]) : $g[0];
}

sub delete_group {
    my $self = shift;
    my ($g, $c) = $self->find_group(@_);
    return if !$g || !$c;
    for my $i (0 .. $#$c) {
        next if $c->[$i] ne $g;
        splice(@$c, $i, 1, ());
        last;
    }
    return $g;
}

###----------------------------------------------------------------###

sub add_entry {
    my ($self, $args, $groups) = @_;
    $groups ||= $self->groups;
    croak "You must unlock the passwords before adding new entries.\n" if $self->is_locked($groups);
    $args = {%$args};
    my $group = delete($args->{'group'}) || $groups->[0] || $self->add_group({});
    if (! ref($group)) {
        $group = $self->find_group({id => $group}, $groups) || croak "Couldn't find a matching group to add entry to";
    }

    $args->{$_} = ''         for grep {!defined $args->{$_}} qw(title url username password comment bin_desc binary);
    $args->{$_} = 0          for grep {!defined $args->{$_}} qw(id icon);
    $args->{$_} = $self->now for grep {!defined $args->{$_}} qw(created accessed modified);
    $args->{'expires'} ||= $self->default_exp;
    while (!$args->{'id'} || $args->{'id'} !~ /^[a-f0-9]{32}$/ || $self->find_entry({id => $args->{'id'}}, $groups)) {
        $args->{'id'} = unpack 'H32', sha256(time.rand().$$);
    }

    push @{ $group->{'entries'} ||= [] }, $args;
    return $args;
}

sub find_entries {
    my ($self, $args, $groups) = @_;
    local @{ $args }{'expires gt', 'active'} = ($self->now, undef) if $args->{'active'};
    my @tests = $self->finder_tests($args);
    my @entries;
    foreach my $g ($self->find_groups({}, $groups)) {
        foreach my $e (@{ $g->{'entries'} || [] }) {
            local $e->{'group_id'}    = $g->{'id'};
            local $e->{'group_title'} = $g->{'title'};
            if (!@tests || !grep{!$_->($e)} @tests) {
                push @entries, $e;
                push @{ $self->{'__entry_groups'} }, $g if $self->{'__entry_groups'};
            }
        }
    }
    return @entries;
}

sub find_entry {
    my $self = shift;
    local $self->{'__entry_groups'} = [] if wantarray;
    my @e = $self->find_entries(@_);
    croak "Found too many entries (@e)" if @e > 1;
    return wantarray ? ($e[0], $self->{'__entry_groups'}->[0]) : $e[0];
}

sub delete_entry {
    my $self = shift;
    my ($e, $g) = $self->find_entry(@_);
    return if !$e || !$g;
    for my $i (0 .. $#{ $g->{'entries'} || [] }) {
        next if $g->{'entries'}->[$i] ne $e;
        splice(@{ $g->{'entries'} }, $i, 1, ());
        last;
    }
    return $e;
}

sub now {
    my ($sec, $min, $hour, $day, $mon, $year) = localtime;
    return sprintf '%04d-%02d-%02d %02d:%02d:%02d', $year+1900, $mon+1, $day, $hour, $min, $sec;
}

sub default_exp { shift->{'default_exp'} || '2999-12-31 23:23:59' }

###----------------------------------------------------------------###

sub is_locked {
    my $self = shift;
    my $groups = shift || $self->groups;
    return $locker{"$groups"} ? 1 : 0;
}

sub lock {
    my $self = shift;
    my $groups = shift || $self->groups;
    return 2 if $locker{"$groups"}; # not quite as fast as Scalar::Util::refaddr

    my $ref = $locker{"$groups"} = {};
    foreach my $key (qw(_key _enc_iv)) {
        $ref->{$key} = '';
        $ref->{$key} .= chr(int(255 * rand())) for 1..16;
    }

    foreach my $e ($self->find_entries({}, $groups)) {
        my $pass = delete $e->{'password'}; $pass = '' if ! defined $pass;
        $ref->{"$e"} = $self->encrypt_rijndael_cbc($pass, $ref->{'_key'}, $ref->{'_enc_iv'}); # we don't leave plaintext in memory
    }

    return 1;
}

sub unlock {
    my $self = shift;
    my $groups = shift || $self->groups;
    return 2 if !$locker{"$groups"};
    my $ref = $locker{"$groups"};
    foreach my $e ($self->find_entries({}, $groups)) {
        my $pass = $ref->{"$e"};
        $pass = eval { $self->decrypt_rijndael_cbc($pass, $ref->{'_key'}, $ref->{'_enc_iv'}) } if $pass;
        $pass = '' if ! defined $pass;
        $e->{'password'} = $pass;
    }
    delete $locker{"$groups"};
    return 1;
}

sub locked_entry_password {
    my $self = shift;
    my $entry = shift;
    my $groups = shift || $self->groups;
    my $ref = $locker{"$groups"} || croak "Passwords aren't locked";
    $entry = $self->find_entry({id => $entry}, $groups) if ! ref $entry;
    return if ! $entry;
    my $pass = $ref->{"$entry"};
    $pass = eval { $self->decrypt_rijndael_cbc($pass, $ref->{'_key'}, $ref->{'_enc_iv'}) } if $pass;
    $pass = '' if ! defined $pass;
    $entry->{'accessed'} = $self->now;
    return $pass;
}

###----------------------------------------------------------------###

1;

__END__

=head1 SYNOPSIS

    use File::KeePass;
    use Data::Dumper qw(Dumper);

    my $k = File::KeePass->new;
    if (! eval { $k->load_db($file, $master_pass) }) {
        die "Couldn't load the file $file: $@";
    }

    print Dumper $k->groups; # passwords are locked

    $k->unlock;
    print Dumper $k->groups; # passwords are now visible

    $k->clear; # delete current db from memory


    my $group = $k->add_group({
        title => 'Foo',
    }); # root level group
    my $gid = $group->{'id'};

    my $group = $k->find_group({id => $gid});
    # OR
    my $group = $k->find_group({title => 'Foo'});


    my $group2 = $k->add_group({
        title => 'Bar',
        group => $gid,
        # OR group => $group,
    }); # nested group


    my $e = $k->add_entry({
        title    => 'Something',
        username => 'someuser',
        password => 'somepass',
        group    => $gid,
        # OR group => $group,
    });
    my $eid = $e->{'id'};

    my $e = $k->find_entry({id => $eid});
    # OR
    my $e = $k->find_entry({title => 'Something'});

    $k->lock;
    print $e->{'password'}; # eq undef
    print $k->locked_entry_password($e); # eq 'somepass'

    $k->unlock;
    print $e->{'password'}; # eq 'somepass'


    $k->save_db("/some/file/location.kdb", $master_pass);

=head1 METHODS

=over 4

=item new

Returns a new File::KeePass object.  Any named arguments are added to self.

=item auto_lock

Default true.  If true, passwords are automatically hidden when a database loaded
via parse_db or load_db.

    $k->auto_lock(0); # turn off auto locking

=item load_db

Takes a kdb filename and a master password.  Returns true on success.  Errors die.
The resulting database can be accessed via various methods including $k->groups.

=item save_db

Takes a kdb filename and a master password.  Stores out the current groups in the object.
Writes attempt to write first to $file.new.$epoch and are then renamed into the correct
location.

You will need to unlock the db via $k->unlock before calling this method if the database
is currently locked.

=item clear

Clears any currently loaded groups database.

=item parse_db

Takes an encrypted kdb database and a master password.  Returns true on success.  Errors die.
The resulting database can be accessed via various methods including $k->groups.

=item parse_header

Used by parse_db.

=item parse_groups

Used by parse_db.

=item parse_entries

Used by parse_db.

=item parse_date

Parses a kdb packed date.

=item decrypt_rijndael_cbc

Takes an encrypted string, a key, and an encryption_iv string.  Returns a plaintext string.

=item encrypt_rijndael_cbc

Takes a plaintext string, a key, and an encryption_iv string.  Returns an encrypted string.

=item gen_db

Takes a master password.  Optionally takes a "groups" arrayref and a "headers" hashref.
If groups are not passed, it defaults to using the currently loaded groups.  If headers are
not passed, a fresh set of headers are generated based on the groups and the master password.
The headers can be passed in to test round trip portability.

You will need to unlock the db via $k->unlock before calling this method if the database
is currently locked.

=item gen_header

Returns a kdb file header.

=item gen_date

Returns a kdb packed date.

=item dump_groups

Returns a simplified string representation of the currently loaded database.

    print $k->dump_groups;

You can optionally pass a match argument hashref.  Only entries matching the
criteria will be returned.

=item groups

Returns an arrayref of groups from the currently loaded database.  Groups returned
will be hierarchal.  Note, groups simply returns a reference to all of the data.  It
makes no attempts at cleaning up the data (find_groups will make sure the data is groomed).

    my $g = $k->groups;

Groups will look similar to the following:

    $g = [{
         expanded => 0,
         icon     => 0,
         id       => 234234234,
         title    => 'Foo',
         level    => 0,
         entries => [{
             accessed => "2010-06-24 15:09:19",
             bin_desc => "",
             binary   => "",
             comment  => "",
             created  => "2010-06-24 15:09:19",
             expires  => "2999-12-31 23:23:59",
             icon     => 0,
             modified => "2010-06-24 15:09:19",
             title    => "Something",
             password => 'somepass', # will be hidden if the database is locked
             url      => "",
             username => "someuser",
             id       => "0a55ac30af68149f62c072d7cc8bd5ee"
         }],
         groups => [{
             expanded => 0,
             icon     => 0,
             id       => 994414667,
             level    => 1,
             title    => "Bar"
         }],
     }];

=item header

Returns the current loaded db header.

=item add_group

Adds a new group to the database.  Returns a reference to the new
group.  If a database isn't loaded, it begins a new one.  Takes a
hashref of arguments for the new entry including title, icon,
expanded.  A new random group id will be generated.  An optional group
argument can be passed.  If a group is passed the new group will be
added under that parent group.

    my $group = $k->add_group({title => 'Foo'});
    my $gid = $group->{'id'};

    my $group2 = $k->add_group({title => 'Bar', group => $gid});

The group argument's value may also be a reference to a group - such as
that returned by find_group.

=item finder_tests {

Used by find_groups and find_entries.  Takes a hashref of arguments and returns a list
of test code refs.

    {title => 'Foo'} # will check if title equals Foo
    {'title !' => 'Foo'} # will check if title does not equal Foo
    {'title =~' => qr{^Foo$}} # will check if title does matches the regex
    {'title !~' => qr{^Foo$}} # will check if title does not match the regex

=item find_groups

Takes a hashref of search criteria and returns all matching groups.  Can be passed id,
title, icon, and level.  Search arguments will be parsed by finder_tests.

    my @groups = $k->find_groups({title => 'Foo'});

    my @all_groups_flattened = $k->find_groups({});

The find_groups method also checks to make sure group ids are unique and that all needed
values are defined.

=item find_group

Calls find_groups and returns the first group found.  Dies if multiple results are found.
In scalar context it returns only the group.  In list context it returns the group, and its
the arrayref in which it is stored (either the root level group or a sub groups group item).

=item delete_group

Passes arguments to find_group to find the group to delete.  Then deletes the group.  Returns
the group that was just deleted.

=item add_entry

Adds a new entry to the database.  Returns a reference to the new
entry.  An optional group argument can be passed.  If a group is not
passed, the entry will be added to the first group in the database.  A
new entry id will be created if one is not passed or if it conflicts with
an existing group.

The following fields can be passed.

    accessed => "2010-06-24 15:09:19", # last accessed date
    bin_desc => "", # description of the stored binary - typically a filename
    binary   => "", # raw data to be stored in the system - typically a file
    comment  => "", # a comment for the system - auto-type info is normally here
    created  => "2010-06-24 15:09:19", # entry creation date
    expires  => "2999-12-31 23:23:59", # date entry expires
    icon     => 0, # icon number for use with agents
    modified => "2010-06-24 15:09:19", # last modified
    title    => "Something",
    password => 'somepass', # will be hidden if the database is locked
    url      => "",
    username => "someuser",
    id       => "0a55ac30af68149f62c072d7cc8bd5ee" # randomly generated automatically

    group    => $gid, # which group to add the entry to

The group argument's value may also be a reference to a group - such as
that returned by find_group.

=item find_entries

Takes a hashref of search criteria and returns all matching groups.
Can be passed an entry id, title, username, comment, url, active,
group_id, group_title, or any other entry property.  Search arguments
will be parsed by finder_tests.

    my @entries = $k->find_entries({title => 'Something'});

    my @all_entries_flattened = $k->find_entries({});

=item find_entry

Calls find_entries and returns the first entry found.  Dies if multiple results are found.
In scalar context it returns only the entry.  In list context it returns the entry, and its
group.

=item delete_entry

Passes arguments to find_entry to find the entry to delete.  Then deletes the entry.  Returns
the entry that was just deleted.

=item now

Returns the current localtime datetime stamp.

=item is_locked

Returns true if the current database is locked.

=item lock

Locks the database.  This moves all passwords into a protected, in memory, encrypted
storage location.  Returns 1 on success.  Returns 2 if the db is already locked.  If
a database is loaded vai parse_db or load_db and auto_lock is true, the newly loaded
database will start out locked.

=item unlock

Unlocks a previously locked database.  You will need to unlock a database before
calling save_db or gen_db.

=item locked_entry_password

Allows access to individual passwords for a database that is locked.  Dies if the database
is not locked.

=back

=head1 BUGS

Only Rijndael is supported.

Only passkeys are supported (no key files).

This module makes no attempt to act as a password agent.  That is the job of File::KeePass::Agent.
This isn't really a bug but some people will think it is.

Groups and entries don't have true objects associated with them.  At the moment this is by design.
The data is kept as plain boring data.

=head1 SOURCES

Knowledge about the KeePass DB v1 format was gleaned from the source code of keepassx-0.4.3.  That
source code is published under the GPL2 license.  KeePassX 0.4.3 bears the copyright of

    Copyright (C) 2005-2008 Tarek Saidi <tarek.saidi@arcor.de>
    Copyright (C) 2007-2009 Felix Geyer <debfx-keepassx {at} fobos.de>

The encryption/decryption algorithms of File::KeePass are of derivative nature from KeePassX and could
not have been created without this insight - though the perl code is from scratch.

=head1 AUTHOR

Paul Seamons <paul at seamons dot com>

=head1 LICENSE

This module may be distributed under the same terms as Perl itself.

=cut
