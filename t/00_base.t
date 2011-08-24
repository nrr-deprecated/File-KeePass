#!/usr/bin/perl

=head1 NAME

00_base.t - Check basic functionality of File::KeePass

=cut

use strict;
use warnings;
use Test::More tests => 70;

use_ok('File::KeePass');

my $dump;
my $pass = "foo";
my $obj  = File::KeePass->new;
ok(!eval { $obj->groups }, "General - No groups until we do something");
ok(!eval { $obj->header }, "General - No header until we do something");

###----------------------------------------------------------------###

# create some new groups
my $g = $obj->add_group({
    title => 'Foo',
    icon  => 1,
    expanded => 1,
});
ok($g, "Groups - Could add a group");
my $gid = $g->{'id'};
ok($gid, "Groups - Could add a group");
ok($obj->groups, "Groups - Now we have groups");
ok(!eval { $obj->header }, "Groups - Still no header until we do something");
ok($g = $obj->find_group({id => $gid}), "Groups - Found a group");
is($g->{'title'}, 'Foo', "Groups - Was the same group");

my $g2 = $obj->add_group({
    title    => 'Bar',
    group    => $gid,
});
my $gid2 = $g2->{'id'};
ok($g2 = $obj->find_group({id => $gid2}), "Groups - Found a child group");
is($g2->{'title'}, 'Bar', "Groups - Was the same group");

###----------------------------------------------------------------###

# search tests
my $g2_2 = $obj->find_group({'id =' => $gid2});
is($g2_2, $g2, "Search - eq searching works");

($g2_2, my $gcontainer) = $obj->find_group({'id =' => $gid2});
is($g2_2, $g2, "Search - find_group wantarray works");
is($gcontainer, $g->{'groups'}, "Search - find_group wantarray works");

$g2_2 = $obj->find_group({'id !' => $gid});
is($g2_2, $g2, "Search - ne searching works");

$g2_2 = $obj->find_group({'id !~' => qr/^\Q$gid\E$/});
is($g2_2, $g2, "Search - Negative match searching works");

$g2_2 = $obj->find_group({'id =~' => qr/^\Q$gid2\E$/});
is($g2_2, $g2, "Search - Positive match searching works");

$g2_2 = $obj->find_group({'title lt' => 'Foo'});
is($g2_2, $g2, "Search - Less than searching works");

my $g_2 = $obj->find_group({'title gt' => 'Bar'});
is($g_2, $g, "Search - Greater than searching works");

###----------------------------------------------------------------###

# try adding an entry
my $e  = $obj->add_entry({title => 'bam', password => 'flimflam'}); # defaults to first group
ok($e, "Entry - Added an entry");
my $eid = $e->{'id'};
ok($eid, "Entry - Added an entry");
my $e2 = $obj->add_entry({title => 'bim', username => 'BIM', group => $g2});
my $eid2 = $e2->{'id'};

my @e = $obj->find_entries({title => 'bam'});
is(scalar(@e), 1, "Entry - Found one entry");
is($e[0]->{'id'}, $eid, "Entry - Is the right one");

ok(!eval { $obj->locked_entry_password($e[0]) }, 'Entry - Can unlock unlocked password');

@e = $obj->find_entries({active => 1});
is(scalar(@e), 2, "Entry - Found right number of active entries");

my $e_2 = $obj->find_entry({title => 'bam'});
is($e_2, $e, "Entry - find_entry works");

($e_2, my $e_group) = $obj->find_entry({title => 'bam'});
is($e_2, $e, "Entry - find_entry works");
is($e_group, $g, "Entry - find_entry works");

my ($e2_2, $e2_group) = $obj->find_entry({title => 'bim'});
is($e2_2, $e2, "Entry - find_entry works");
is($e2_group, $g2, "Entry - find_entry works");

###----------------------------------------------------------------###

# turn it into the binary encrypted blob
ok(!eval { $obj->gen_db }, "Parsing - can't gen without a password");
my $db = $obj->gen_db($pass);
ok($db, "Parsing - Gened a db");

# now try parsing it and make sure it is still in ok form
$obj->auto_lock(0);

my $ok = $obj->parse_db($db, $pass);
ok($ok, "Parsing - Re-parsed groups");
ok($obj->header, "Parsing - We now have a header");

ok($g = $obj->find_group({id => $gid}), "Parsing - Found a group in parsed results");
is($g->{'title'}, 'Foo', "Parsing - Was the correct group");

$e = eval { $obj->find_entry({title => 'bam'}) };
ok($e, "Parsing - Found one entry");
is($e->{'id'}, $eid, "Parsing - Is the right one");


###----------------------------------------------------------------###

# test locking and unlocking
ok(!$obj->is_locked, "Locking - Object isn't locked");
is($e->{'password'}, 'flimflam', 'Locking - Had a good unlocked password');

$obj->lock;
ok($obj->is_locked, "Locking - Object is now locked");
is($e->{'password'}, undef, 'Locking - Password is now hidden');
is($obj->locked_entry_password($e), 'flimflam', 'Locking - Can access single password');
is($e->{'password'}, undef, 'Locking - Password is still hidden');

$obj->unlock;
ok(!$obj->is_locked, "Locking - Object isn't locked");
is($e->{'password'}, 'flimflam', 'Locking - Had a good unlocked password again');


# make sure auto_lock does come one
$obj->auto_lock(1);
$ok = $obj->parse_db($db, $pass);
ok($ok, "Locking - Re-parsed groups");
ok($obj->is_locked, "Locking - Object is auto locked");


###----------------------------------------------------------------###

# test file operations
$obj->unlock;
my $file = __FILE__.".kdb";

ok(!eval { $obj->save_db }, "File - Missing file");
ok(!eval { $obj->save_db($file) }, "File - Missing pass");
ok($obj->save_db($file, $pass), "File - Saved DB");
ok(-e $file, "File - File now exists");
{
    local $obj->{'keep_backup'} = 1;
    ok($obj->save_db($file, $pass), "File - Saved over the top but kept backup");
}
ok($obj->save_db($file, $pass), "File - Saved over the top");
$obj->clear;
ok(!eval { $obj->groups }, "File - Cleared out object");

ok(!eval { $obj->load_db }, "File - Missing file");
ok(!eval { $obj->load_db($file) }, "File - Missing pass");
ok($obj->load_db($file, $pass), "File - Loaded from file");

ok($g = $obj->find_group({id => $gid}), "File - Found a group in parsed results");
is($g->{'title'}, 'Foo', "File - Was the correct group");
ok($g->{'expanded'}, "File - Expanded was passed along correctly");

unlink($file);
unlink("$file.bak");

###----------------------------------------------------------------###

$dump = eval { $obj->dump_groups };
diag($dump);
ok($dump, "General - Ran dump groups");

###----------------------------------------------------------------###

ok(!eval { $obj->delete_entry({}) }, "Delete - fails on delete of too many entries");
ok(scalar $obj->find_entry({title => 'bam'}), 'Delete - found entry');
$obj->delete_entry({title => 'bam'});
ok(!$obj->find_entry({title => 'bam'}), 'Delete - delete_entry worked');

ok(!eval { $obj->delete_group({}) }, "Delete - fails on delete of too many groups");
ok(scalar $obj->find_group({title => 'Bar'}), 'Delete - found group');
$obj->delete_group({title => 'Bar'});
ok(!$obj->find_group({title => 'Bar'}), 'Delete - delete_group worked');

$dump = eval { $obj->dump_groups };
diag($dump);

###----------------------------------------------------------------###

# test for correct stack unwinding during the parse_group phase
my ($G, $G2, $G3);
my $obj2 = File::KeePass->new;
$G = $obj2->add_group({ title => 'hello' });
$G = $obj2->add_group({ title => 'world',    group => $G });
$G = $obj2->add_group({ title => 'i am sam', group => $G });
$G = $obj2->add_group({ title => 'goodbye' });
$dump = "\n".eval { $obj2->dump_groups };
$ok = $obj2->parse_db($obj2->gen_db($pass), $pass);
my $dump2 = "\n".eval { $obj2->dump_groups };
#diag($dump);
is($dump2, $dump, "Dumps should match after gen_db->parse_db") && diag($dump);
#exit;

###----------------------------------------------------------------###

# test for correct stack unwinding during the parse_group phase
$obj2 = File::KeePass->new;
$G  = $obj2->add_group({ title => 'personal' });
$G2 = $obj2->add_group({ title => 'career',  group => $G  });
$G2 = $obj2->add_group({ title => 'finance', group => $G  });
$G3 = $obj2->add_group({ title => 'banking', group => $G2 });
$G3 = $obj2->add_group({ title => 'credit',  group => $G2 });
$G2 = $obj2->add_group({ title => 'health',  group => $G  });
$G2 = $obj2->add_group({ title => 'web',     group => $G  });
$G3 = $obj2->add_group({ title => 'hosting', group => $G2 });
$G3 = $obj2->add_group({ title => 'mail',    group => $G2 });
$G  = $obj2->add_group({ title => 'Foo'      });
$dump = "\n".eval { $obj2->dump_groups };
$ok = $obj2->parse_db($obj2->gen_db($pass), $pass);
$dump2 = "\n".eval { $obj2->dump_groups };
#diag($dump2);
is($dump2, $dump, "Dumps should match after gen_db->parse_db") && diag($dump);
