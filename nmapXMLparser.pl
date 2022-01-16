#!/usr/bin/perl

my $version="3.0.0 a"; 
my $start_time=time();
$| = 1; 

my @ARGV_in = @ARGV; 
my @full_path=split(/\//x,$0); 
my $Directory=$full_path[($#full_path-1)]; 
our $ScriptName=$full_path[$#full_path]; 
  
# ----------------------------------------- */
#         CONFIGURABLE VARIABLES            */ 
# ----------------------------------------- */ 
my $help = 0; 
my $THREADED = 0;
my $FORKED = 0;
my $CLI = 0; 
my $BATCH_COMMIT = 0; 

my $LIMIT;
my $LOG = 0; 
my $RANDOM = 1	; 
my $CONFIG = "/etc/dna.cfg";

# set default max threads equal to number of CPUS; 
my $MaximumProcesses = `nproc`; chomp($MaximumProcesses);
   
# ----------------------------------------- */
#         GLOBAL VARIABLES            */ 
# ----------------------------------------- */
#our $TERM; # for threading 
our $UPDATE = 0;

our %Global;
our %Stats; 
our %Cache;
our $DNA;
our @TARGETIDS;   

our %ScanStatus = (
	0 => 'unknown', 1 => 'created', 2 => 'starting', 3 => 'running',
	4 => 'paused', 5 => 'stopping', 6 => 'stopped', 7 => 'completed',
	7 => 'XML error', 8 => 'parsed', 9 => 'error', 10 => 're-scan',
	11 => 'died', 12 => 'synced rezults', 13 => 'requeued',
	14 => 'killed',
);
our %ScanStatusTable;

# GLOBAL SQL variable declarations
our $dbh;
our %SQL; 
our $getlastinsert; 
our $logfile; 
our $nmap; 

$Global{ArchiveDestination} = `pwd`;
$Global{skiplog} = 0; 
chomp($Global{ArchiveDestination});

# ----------------------------------------- */
#         LOCAL VARIABLES                   */ 
# ----------------------------------------- */

# CLI args....
my ($VERBOSE_in,$DEBUG_in,$CONFIG_in,$KEYFILE_in,$LOGFILE_in);
my ($DBuser_in,$DBpass_in,$DBname_in,$DBport_in,$DBhost_in);
my ($log,$LOGFILE,$archiveto,$ArchiveDestination);
my ($scanID,$FILEIN,$DIRIN,$IP,$FILELIST,$DIRECTORY);
my $NOVERIFYTRACE = 0;
my $WAIT = 0;  
my $SORT = "ASC";
my $PROCESSES = 1; 
my $REPARSE = 0; 
my $currentlyRunning = 0; 
 	

# ----------------------------------------- */
#         require statements 
# ----------------------------------------- */
use warnings;
use strict;
use Carp;
use Data::Dumper; 
  
use Getopt::Long;
use POSIX; 
use DBI;
use File::Basename;
use XML::LibXML;
use Term::ProgressBar;
use Digest::MD5::File qw(file_md5 file_md5_hex);
use List::Util qw(shuffle);

use XML::NmapParser;
use Utility; 
use Utility::DistributedNMAP; 

#my @LIBRARY = ( 
#	"service.pm",
#	"port.pm",
#	"host.pm",
#	"common.pm",
#	"dNa.pm", 
#	"os.pm",
#	'scan.pm',
#	'target.pm',
#	'agent.pm',
#);

#foreach (@LIBRARY) {
#	if ( -f "./$_") { require "./$_";
#	} elsif ( -f "/usr/local/bin/$_") { require "/usr/local/bin/$_"; }
#}

# ----------- MAIN PROCESSING ------------- */	
our $MAX_THREADS = `nproc`;
Getopt::Long::Configure qw(bundling no_ignore_case);
my $result=GetOptions(
        'help!' => \$help,
        'file=s' => \$FILEIN,
        'filelist=s' => \$FILELIST,
        'dir=s' => \$DIRIN,

        'config=s' => \$CONFIG_in,
        'archiveto=s' => \$ArchiveDestination,
        'db=s' => \$DBname_in,
        'dbuser=s' => \$DBuser_in,
        'dbpass=s' => \$DBpass_in,
        'dbport=i' => \$DBport_in,
        'dbhost=s' => \$DBhost_in,

        'limit=i' => \$LIMIT,
        'processes=i' => \$PROCESSES,
        'log=s' => \$LOGFILE,
        'sort=s' => \$SORT,
        'random!' => \$RANDOM,
        'threaded!' => \$THREADED,
        'forked!' => \$FORKED,
        'cli' => \$CLI,
        'running!' => \$currentlyRunning,
        'noverifytrace!' => \$NOVERIFYTRACE,
        'noverify!' => \$NOVERIFYTRACE,
        'update!' => \$UPDATE,
        'reparse!' => \$REPARSE,
        'skiplog!' => \$Global{skiplog},
        'wait!' => \$WAIT,
        'verbose!' => \$VERBOSE_in,
        'debug!' => \$DEBUG_in);
	
	
if ($help) {
	print "$0 version: $version\n";
	print "\n";
	print "\t--help (this help text)\n";
	print "\t --user=<Database Username> --pass=<Database user's password> --db=<database name>\n";
	print "\t [--file=<NMAP XML data to parse> | --dir=<directory containing NMAP XML data to parse>]\n";
	print "\t --config=<alternate location for helix.cfg file>\n";
	print "\t --scan_name=<Create new scangroup to assoaicte with nmap results\n";
	print "\t \n";
	print "\t \n";
	print "\t \n";
	print "\t  \n";	
	
	exit 0; 
} 

if ( ! defined($LIMIT)) { $LIMIT = '99999999'; }
sleep 1; 

my @args; 
foreach (@ARGV_in) { if ( $_ =~ /processes/ ) { push(@args, " --processes=1 "); } else { push(@args,$_); } }
my $RUNNING = Utility->AmIRunning($ScriptName . " " . join(" ",@ARGV_in));
$RUNNING++;
if ($PROCESSES > 1 ) { 
	my $args = join(" ",@args);  
	while ($RUNNING < $PROCESSES ) {
		system("/usr/bin/screen -d -m -S $ScriptName.$RUNNING  /usr/bin/perl  $0  $args");
		printf STDOUT "launched screen: /usr/bin/screen -d -m -S %s.%s  /usr/bin/perl  %s  %s\n", $ScriptName,$RUNNING,$0,$args;
		$RUNNING++; 		
	}  
}

# just in case default config is over ridden by a CLI option.....
if (defined($CONFIG_in)) { $CONFIG = $CONFIG_in; }

if (defined($CONFIG)) { 
		foreach ( split(',',$CONFIG) ) { 
		my $hash = Utility->readConfig($_);
		foreach ( keys %{$hash}) { $Global{$_} = $hash->{$_}; }
		if ( $_ =~ /dna/ ) { $DNA = Utility::DistributedNMAP->new(config => $_); }
	}
}

our $dbVars = $DNA->DBvariables();
if (defined($DEBUG_in)){  $Global{DEBUG} = 1 ; }
if (defined($VERBOSE_in)){ $Global{VERBOSE} = 1; }
if ($BATCH_COMMIT) { $Global{BatchCommits} = $BATCH_COMMIT; } 

if (defined($LIMIT)) { $Global{LIMIT} = $LIMIT; }

if ($NOVERIFYTRACE) { $Global{VerifyTrace} = 0; }
if ( $UPDATE ) { $Global{UPDATE} = 1; }
else { $Global{UPDATE} = 0; }

$Global{SORT} = $SORT; 
if ( defined($ArchiveDestination)) { $Global{ArchiveDestination} = $ArchiveDestination; }
$Global{ArchiveSucess} = "$Global{ArchiveDestination}/PROCESSED";
$Global{ArchiveXMLerror} = "$Global{ArchiveDestination}/ERROR";
if (! -d $Global{ArchiveSucess}) { mkdir $Global{ArchiveSucess}; }
if ( ! -d $Global{ArchiveXMLerror} ) { mkdir $Global{ArchiveXMLerror}; }
 
our %params;

#open ($logfile, ">>",  "$0-processing.log");
#printf $logfile "# starting at %s\n", scalar localtime($start_time);

if (defined($scanID)) { 
	foreach ( split(",",$scanID) ) { 
		my $dir = sprintf("%s/%s",$Global{ScanResultDestination}, $_ ); 
		ProcessDirectory($dir);
		updateCounts($_);
	}
	
} elsif (defined($DIRIN)) { 
	foreach ( split(",",$DIRIN) ) {
		ProcessDirectory($_);
		my @array = split('/',$_); 		
		my $scanID = pop(@array);
		updateCounts($scanID);
	}
} elsif ($FILEIN) {
	worker(split(",",$FILEIN));	
} elsif ($FILELIST) {
	worker(split(",",$FILELIST));
} else { 
	die "no input specified.....\nbye, bye!\n"; 
}

if ( defined($dbh)) { 
	$getlastinsert->finish();
	$dbh->commit();
	$dbh->disconnect(); 	
}



printf STDOUT "\n\n";

printf "completed\ntotal run time %s seconds.\n", Utility->sec2human(time() - $start_time);

exit 0; 



sub connectDB {
	my (%params) = @_; 
	 
	if ( !defined($dbh)) { 
		
		my $AutoCommit = 0; my $PrintError = 1;my $RaiseError = 1; my $PrintWarn = 1; 
		
		if ( defined($params{AutoCommit})) { $AutoCommit = $params{AutoCommit}; }
		if ( defined($params{PrintError})) { $PrintError = $params{PrintError}; }
		if ( defined($params{RaiseError})) { $RaiseError = $params{RaiseError}; }
		if ( defined($params{PrintWarn})) { $PrintWarn = $params{PrintWarn}; }
		
		my $dsn = sprintf("DBI:mysql:database=%s;host=%s;port=%s",$Global{DBname},$Global{DBhost},$Global{DBport});
		$dbh = DBI->connect($dsn, "$Global{DBrwuser}", "$Global{DBrwpass}" , { AutoCommit => $AutoCommit, PrintError => $PrintError , RaiseError => $RaiseError, PrintWarn => $PrintWarn});
		if (defined($dbh->err())) {
			$dbh = "$DBI::errstr\n";
		} else { 
			$getlastinsert = $dbh->prepare('select last_insert_id()');
		} 
	}	
}

sub worker {
	my (@files) = @_;  

	my @array;
	if (defined(($Global{LIMIT})) && ( ($#files +1 ) > $Global{LIMIT} )) {
		my %hash;
		foreach ( @files) { $hash{$_} = 1;  if ( scalar( keys %hash) > $Global{LIMIT} ) { last; } }
		@files = keys %hash;  
	}

	if ($RANDOM){
		my %hash; 
		foreach (@files) { $hash{$_} = 1; }
		@files = keys %hash; 
	}
	my $counter = 0;  
	if ( scalar(@files) < $LIMIT ) { $LIMIT = scalar(@files); }
	foreach (@files) {
		if ( -f $_ ) {
			if ((defined($Global{LIMIT})) && ($counter >= ($Global{LIMIT})  )) {  last; }
			else {
				connectDB();
				printf STDOUT "\tprocessing file %s ", $_;
				if (defined($Global{LIMIT})) { printf STDOUT "%s of %s\n", ($counter+1),$LIMIT;} else { printf STDOUT "%s of %s\n",$counter,scalar(@files); } 
				::ProcessFile($_);
				$counter++;
				$getlastinsert->finish();
				$dbh->commit(); 
			} 			
		} else { printf STDOUT "file %s not found....skipping\n", $_; }
	}
	
	if ($counter > 1 ) {printf STDOUT "\nworker completed processing %s files\n", $counter;}
	elsif ($counter eq 1 ) {printf STDOUT "\nworker completed processing %s file\n", $counter;}
	else{ printf STDOUT "\nworker processed NO files\n"; }
	
	
	return 0; 
}


sub ProcessFile { 
	my ($file) = @_;	

	my $returnVal = 0;
	my $LIVE = 0;
	
	my $start = time(); 
	my ($name,$PATH,undef) = fileparse($file);
	my $path = $Global{ScanResultDestination};
	if ( ! -d "$path/PROCESSED") { system("mkdir -p $path/{PROCESSED,ERROR,RETRY}"); }
		
	my ($Scan,$Target) = split(/-/,$name);
	$Target =~ s/\.xml//g; 
	
	my $md5sum = file_md5_hex($file);
	my $now = time();
	
	if ( ::XMLerror($file) ) {
		if ( -f $file ) {			
			if ( -f "$PATH/ERROR/$name" ) { Utility->RenameExistingFile("$PATH/ERROR/$name",0); }
			my ($name,$extenstion)  = split(/\./,$file); 
			system("mv $name.* $PATH/ERROR/");
		} 						
		$returnVal = 0; 
	} else {
		if ( -f $file ) {
			my $nmapID = "-1"; my $new = 0; 
			undef($nmap);
			$nmap = XML::NmapParser->new();
			$nmap->parse($file);
			
			($nmapID,$new) = getNmapID($nmap,$file,$md5sum);
			if (($new) || ($Global{UPDATE})) { 
				if ( $nmap->live() eq "0" ) { 
					printf STDOUT "\n\t\t(%s) no live hosts....skipping!! (%i)\n",$file,__LINE__;
					ArchiveProcessedFile($PATH,$name)
				} else {
					connectDB();
					my $progress; 
					my @array; 
					printf STDOUT "\n\t\t%s => %s scanned, %s live\n",$file,$nmap->scanned(), $nmap->live();
					my @ipList = $nmap->get_ips("up");
					my %ipCounter; my $counter = 0; 
					if ($Global{VERBOSE}) { $progress = Term::ProgressBar->new($#ipList + 1); }
					for my $ip (@ipList) {
						my @trace;
						my $PROCESS = 0;
						$counter++;
						if ($Global{VERBOSE}) { $progress->update($counter);}
						else { printf STDOUT "\t\t\tprocessing ip: %s\n", $ip; }
						  
						my $host = $nmap->get_host($ip);
						if ( $host->status() eq "down" )  { next; }
						if ($Global{VerifyTrace} eq "1") { 
							@trace = $host->traceroute();
							if ( (@trace) && ($host->status() eq "up") ) { 
								if ($trace[$#trace]->{ipaddr} eq $ip ) { $PROCESS = 1; } else { $PROCESS = 0; }
							} 
						} elsif ( $Global{VerifyTrace} eq "0")  { $PROCESS = 1;}
						if ( $PROCESS)  { 
							$dbh->do("BEGIN"); 
							my @openPorts = ::ProcessHost($host,$ip,$nmapID,$name);
							if ( ($Global{VerifyTrace}) || (scalar @openPorts > 0) )  { 
								$ipCounter{$ip} = [ @openPorts ] ;
								if ( $Global{DEBUG}) {foreach ( @openPorts) { printf STDOUT "\t\t\t\t%s open\n", $_; }} 
							}
							$Stats{$name}{addedHosts}++;
							$dbh->commit(); 
						}
					}
					$LIVE = scalar ( keys %ipCounter);
					if ( $Global{VerifyTrace}) { printf STDOUT "(%s verified live) [time to process: %s]\n", $LIVE, Utility->sec2human(time() - $start); }
					else { printf STDOUT "(%s w/ open ports [NO verification]) [time to process: %s]\n", $LIVE, Utility->sec2human(time() - $start);}
					$returnVal = 1;
				}									
			} else { 
				printf "\t\talready processed.....skipping\n";
			}   
		}	
	}
	
	if ( -f $file ) { 

		if ( -f "$Global{ScanResultDestination}/PROCESSED/$name" ) { RenameExistingFile("$Global{ScanResultDestination}/PROCESSED/$name",0); }
		my ($name,$extenstion)  = split(/\./,$file);
		printf STDOUT "mv $file $Global{ScanResultDestination}/PROCESSED/ \n"; 
		system("mv $file $Global{ScanResultDestination}/PROCESSED/");

		
	}
	
	
#	printf $logfile "COMPLETE\n";	
	return $returnVal; 	 
}


sub processPorts {
	my ($hid,@ports) = @_;
	
	my @open;
	for my $port (@ports) {
		my $pid; 
#		if ($port->name() eq "tcpwrapped") { next;}
#		elsif ($port->state() eq "closed" ) { next; }
#		elsif ( $port->confidence() eq "3" ) { next; }
#		elsif (( $port->state() eq "filtered" ) && ($port->reason() eq "no-response")) { next; }
#		elsif ($port->state() eq "open" ) { 
			($pid) = insertPort($port,$hid);
			push(@open, sprintf("%s/%s",$port->port(),$port->proto()) );
#		}
#		else {
#			printf STDOUT "name: %s ",$port->name();
#			printf STDOUT "state: %s ",$port->state();   
#			printf STDOUT "reason: %s ",$port->reason();
#			printf STDOUT "confidence: %s ",$port->confidence();
#			printf "line %s\n", __LINE__;
#			print Dumper $port;  
#			die "unknown condition\n";  
#		}
	}
	return @open; 
}

sub ProcessHost {

	my ($host,$ip,$nmapID,$filename) = @_;
	my ($scanID,undef) = split(/-/,$filename,2); 
	my $returnVal = 0;
	if ( $Global{DEBUG}) { printf STDOUT "processing ip: %s ", $ip; }
		
	my $hid = getHostID($host,$nmapID);
	if ( $hid eq "-1") { $hid = insertHost($host,$nmapID);} 



	#process open tcp port(s)
	my @openPorts;
	if (defined($host->tcp_open_ports())) {
		my @array = processPorts($hid,$host->tcp_open_ports());
		if ( scalar  @array ) { push(@openPorts,@array); }
	}
	if (defined($host->udp_open_ports())) {
		my @array = processPorts($hid,$host->tcp_open_ports());
		if ( scalar  @array ) { push(@openPorts,@array); }
	}
	
	if ( defined($host->os_sig()) ) { 
		my $OS = $host->os_sig();
		if (( defined($OS->all()) )  && (scalar $OS->all()))  {
			die "need to work on this code\n";  
			my @array = processOS($hid,$OS->all());
		}
	}
	
	if ((defined($host->hostscripts())) && (scalar $host->hostscripts() > 0 )) {
		my @array = processHostScripts($hid,$host->hostscripts());   
	}
	
	return @openPorts; 
} 


sub processOS { 
	my ($hid, @OS) = @_;
	my @osmatchIDs; my @OSmatches; 
	
	for my $os (@OS) {
		my $osmatchID; 
		if ( ref($os) eq "XML::NmapParser::Host::OS::osmatch" ){ 
			$osmatchID = ::GetOSmatchID($os->name(),$os->accuracy());
			push(@osmatchIDs,$osmatchID);
			$SQL{InsertOSmatch2Host}->execute($osmatchID,$hid);
		}
		
		my %params;
		if ( !defined($SQL{FindTopOSmatch})) {
#			$SQL{FindTopOSmatch} = $dbh->prepare("SELECT osmatchID FROM osmatch WHERE osmatchID in (?) ORDER BY accuracy  DESC LIMIT 1;");
		}
		my $matches = join(',',@osmatchIDs);
		$SQL{FindTopOSmatch}->execute($matches); 
		my $TopOSmatchID = $SQL{FindTopOSmatch}->fetchrow_array();
		$params{osmatchID} = $TopOSmatchID;
#		my $rc = ::UpdateHost($hid, %params);
		
		my @classes = $os->osclass(); 
		for my $class (@classes) {
			my $osclassID = ::GetOSclassID($class);
#			$SQL{InsertOSmatch2OSclass}->execute($osmatchID,$osclassID);
		}
	}		
	return @OSmatches; 
}
#	
#	# deal with OSmatchs and OSclass matches.....
#	
##	printf "%s => %s\n", $host->ipv4_addr(),$OS; 
#	if ($OS->all()) {  
#		my @OSmatches = $OS->all();
#		my @osmatchIDs;  
#	} else { 
#		print "no OS info\n" if $Global{DEBUG}; 
#	}                                                                                                                                                              
#
	
sub processHostScripts {
	my ($hid,@scripts) = @_ ;
	
	for my $script (@scripts) {
		
		my $name = $script->name();  
		if ( $script->{Script}{id}  eq "smb-os-discovery") {
			processNSEspecial($hid,$script);
		} elsif ( $script->{Script}{id}  eq "nbstat") {
			my %params; 
			if ( $script->output() =~ m/NetBIOS \s+ name: \s+ (\w+), \s+ NetBIOS \s+ user: \s+ (.*), \s+ NetBIOS \s+ MAC: \s+ (.*) \s+ .*/ox) {
				$params{nbname} = $1;  
				($params{mac},undef) = split(/ /,$3,2) if ($3 != /unknown/ );
				
				printf "debug> [%s] [len:%s]", $params{mac}, length($params{mac}); 
			}
			if ( scalar keys %params) { updateHost(hid => $hid, %params); }			
		} else {
			my $scriptID = getScriptID($script); 
		}
	}		

}	


sub GetOSmatchID { 
	
	my ($OSname,$accuracy) = @_;
	
	my $OSMATCHID = 0; 
	
	my $QueryOSmatchID = $dbh->prepare("SELECT osmatchid FROM osmatch WHERE name=? AND accuracy=?");
	$QueryOSmatchID->execute($OSname,$accuracy);
	if ( $QueryOSmatchID->rows() eq "1") { 
		($OSMATCHID) = $QueryOSmatchID->fetchrow_array();  
	} elsif ( $QueryOSmatchID->rows() eq "0") {
		my $InsertNewOSmatch = $dbh->prepare("INSERT INTO osmatch(name,accuracy) VALUES(?,?)");
		$InsertNewOSmatch->execute($OSname,$accuracy); 
		$getlastinsert->execute;
		($OSMATCHID) = $getlastinsert->fetchrow_array();
	} else { 
		printf STDOUT ">> %s << \t",$QueryOSmatchID->rows(); 
		die "ERROR ::GetOSmatchID() \n";
	}
#	$dbh->commit();
	return $OSMATCHID;
}

#
sub PrepareSQLcalls {return 0; }

sub FinishSQL { foreach ( keys %SQL) { $SQL{$_}->finish(); } return 0; }


sub XMLerror {
	my ($file) = @_;
	my $RC = 0;
	if ( -f $file) { 
		open(XMLLINT, "xmllint $file  2>&1 | grep -c \": parser error :\" |");
		my @xmllint = <XMLLINT>;
		close(XMLLINT);
		if (defined($xmllint[0])) { 
			chomp($xmllint[0]);
			if ( $xmllint[0] > 0 ) {
				printf "XML error in file [%s]......skipping\n",$file;
				$RC = 1;
			}
		} else { $RC = 1; }
	} else { $RC = 1; } 
	
	return $RC;
}

sub UpdateNmap { 
	my ($scanKey,$nmapID) = @_; 
	
	if (! defined($SQL{UpdateNmap4ScanStatus})) { $SQL{UpdateNmap4ScanStatus} = $dbh->prepare("UPDATE nmap set ScanKey = ?, modified =? where nmapID = ? "); }
	$SQL{UpdateNmap4ScanStatus}->execute($scanKey,time(),$nmapID); 	
	
}

sub UpdateScanStatusByFileDetails {
	
	my ($file,$name,$md5sum,$ScanKey) = @_;
	if (! defined($ScanKey)) {
		my $statusTable = $DNA->readScanStatusTable(resultsFilename => $name, resultsmd5sum => $md5sum);
		if ( scalar keys %{$statusTable} > 1 ) {
			my @keys = keys %{$statusTable};
			$ScanKey = shift(@keys);
			foreach (@keys) { 
				$dbh->do("UPDATE ScanStatus set status = '9', resultsFilename = NULL, resultsmd5sum = NULL where statusKey = $_");
				$dbh->commit();
			}
		} else {
			($ScanKey) = keys %{$statusTable};
		}
	}	
	
	my $launched; 

	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($file);
	my @file = Utility->ReadFile($file); 
	for my $line (@file) { 
		if ( $line =~ /^<nmaprun / ) {
			chomp($line); 
			my @array = split(' ',$line);
			foreach (@array) { 
				if ( $_ =~ /start=/) { 
					(undef,$launched) = split(/=/,$_);
					$launched =~ s/"//g;
					last;  
				}
			}
			last;
		}
	}  

	my %params;
	$params{pid} = 0;  
	$params{status} = 15;
	$params{launched} = $launched;
	$params{finished} = $ctime;
	# $params{nmapID} = '';
	$params{resultsFilename} = $name;
	$params{resultsmd5sum} = $md5sum;
	
	::UpdateScanStatusTable($ScanKey,\%params);
	
	return 0; 

} 


sub sortFiles { 
	my (@files) = @_; 
	my @array; 
	
	my %SORTED; 
	for my $file (@files) { 
		my @array;
		my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size, $atime,$mtime,$ctime,$blksize,$blocks) = stat($file);
		if ( defined($size)) { 
			if (defined($SORTED{$size})) { 
				@array = @{$SORTED{$size}};
			} 
			push(@array, $file); 
			$SORTED{$size} = [ @array ];			
		}
	}
	if( $Global{SORT} eq "DESC") { foreach ( sort { $b <=> $a } keys %SORTED) {for my $file ( @{$SORTED{$_}} ) { push(@array,$file); } } } 
	elsif( $Global{SORT} eq "ASC") { foreach ( sort { $a <=> $b } keys %SORTED) {for my $file ( @{$SORTED{$_}} ) { push(@array,$file); } } } 
	elsif( $Global{SORT} eq "RANDOM") { foreach ( shuffle keys %SORTED) {for my $file ( @{$SORTED{$_}} ) { push(@array,$file); } } }	
	
	return @array; 

}



sub DeleteNMAPresults { 
	my ($nmapID) = @_; 
	
	my @hosts = $DNA->readHosts_v2(nmapID => $nmapID);
	my @HIDS; foreach ( @hosts ) { push(@HIDS,$_->ID()); }
	if (@HIDS) {
		$DNA->deleteHosts(hid => join(",",@HIDS)); 
	}  
}


sub ProcessDirectory { 
	my ($dir) = @_;
	 
	printf STDOUT "processing XML files in %s......",$dir;
	my @FILES  = glob("$dir/*.xml");
	if ( @FILES ) {
		printf STDOUT "\t%s files available to process....", Utility->commify( scalar @FILES );	
		my @sortedFiles = sortFiles(@FILES);
		if (@sortedFiles) { 
			if ( -d "$Global{ArchiveDestination}/PROCESSED") { print "\n"; } 
			else {system("mkdir -p $dir/{PROCESSED,ERROR,RETRY}"); print "\n"; }
			::worker(@sortedFiles);
		}
	}
	return scalar @FILES; 	
}

sub updateCounts {
	
	my ($scanID) = @_;
	
	my $openPorts = $DNA->fetchOpenPortHosts4Scan(scanID => $scanID,  update => 'yes');
	my $liveHosts = $DNA->updateLiveHosts4Scan(scanID => $scanID,  update => 'yes');

	my ($SCAN) = $DNA->readScanTable(scanID => $scanID );
	$SCAN->_addDBcredentials(%{$dbVars});
	my ($stop,$start) = $SCAN->scanStartStop();
	$SCAN->updateStartStop();
	
}

# ---------------------------------------------

	 
# $hid = insetrtNewHost($host,$nmapID);


sub getHid {
	my ($host,$nmapID) = @_;
	my $hid = -1; 
		 
	croak "nmapID not defined" unless defined($nmapID);
	croak "nmapID not defined" unless defined($nmapID);
	
	connectDB();
	my $QUERY = $dbh->prepare("select hid from hosts where ip4str = ? AND starttime = ? AND endtime = ? ");
	$QUERY->execute($host->ip4str,$host->starttime(), $host->endtime());
	
	$QUERY->execute();
	if ( $QUERY->rows() > 0 ) {  
		if ( $QUERY->rows() eq 1 ) { ($hid) = $QUERY->fetchrow_array();
		} elsif ( $QUERY->rows() > 1 ) { printf "\nmultiple records found %s\n", __LINE__; die "\n"; 
		} else { $hid = "-1"; }
	}
	$QUERY->finish(); 		
	
	if ( $hid eq "-1" ) { $hid = insertNewHost($host,$nmapID); }
	
	return $hid; 
	
}



sub insertNewHost { 
	my ($host,$nmapID) = @_;
	
	croak "nmapID not defined" unless defined($nmapID);
	croak "nmapID not defined" unless defined($nmapID);
	 
	my $hid = -1;
	my %params;
	$params{nmapID} = $nmapID; 
	if ( defined($host->ipv4_addr()) ) {$params{ip4str} = $host->ipv4_addr();}
	if ( defined($host->ipv6_addr()) ) {$params{ip6str} = $host->ipv6_addr();}
	if ( defined($host->uptime_seconds()) ) { $params{uptime} = $host->uptime_seconds();}
	if ( defined($host->starttime())) { $params{starttime} = $host->starttime(); }
	if ( defined($host->endtime())) { $params{endtime} = $host->endtime(); }
	if ( defined($host->mac_addr())) {  $params{mac} = $host->mac_addr(); }
	if ( defined($host->distance())) { $params{distance} = $host->distance(); }
	
	if ( defined($host->hostname())) {
		$params{hostname} = $host->hostname();
        my @ARRAY = split(/\./, $params{hostname});
        shift(@ARRAY);
        if ( @ARRAY ) {
                my $domain = join('.',@ARRAY);
                $params{domain} = $domain;
        }
	}
	if (defined($host->traceroute())) { 
        my @trace = $host->traceroute();
        if (@trace) {
                my @Traceroute;
                for my $hop ( @trace) { push(@Traceroute,"$hop->{ttl};$hop->{ipaddr}");}
                $params{traceroute} = join(',',@Traceroute);
        }		
	}
	
	my @fields; my @values; 
	foreach ( keys %{params}) {
		push(@fields, $_); push(@values,"'$params{$_}'");
	}
	my $FIELDS = join(',',@fields); my $VALUES = join(',',@values);
	if ( !defined($dbh)) { 
		$dbh = ::DBconnect($Global{DBname},$Global{DBrwuser},$Global{DBrwpass},$Global{DBhost},$Global{DBport});
		$getlastinsert = $dbh->prepare('select last_insert_id()'); 		
	}
	
	my $insertSTMT = sprintf("INSERT INTO hosts(%s) VALUES(%s)", join(",",@fields), join(",",@values));
	my $INSERT = $dbh->prepare("$insertSTMT");
	$INSERT->execute(); 
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();
	} else {
		if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }
		
		$getlastinsert->execute;
		($hid) = $getlastinsert->fetchrow_array();
		updateIPhistoryRecord($host,$nmapID,$hid);
	}
	$INSERT->finish();
	
	return $hid;	
}


sub updateIPhistoryRecord  { 
	my ($host,$nmapID,$hid) = @_ ;
		
	croak "nmapID not defined" unless defined($nmapID);
	croak "missing 'hid' arguement " unless $hid;
	
	croak "'ip4str' undefined" unless defined($host->ipv4_addr());
	croak "'starttime' undefined" unless (defined($host->starttime()));
	croak "'endtime' undefined" unless (defined($host->endtime()));
	
	if ( !defined($dbh)) { 
		$dbh = ::DBconnect($Global{DBname},$Global{DBrwuser},$Global{DBrwpass},$Global{DBhost},$Global{DBport}); 		
	}
	
	my $INSERT = $dbh->prepare("INSERT INTO IPhistory(ip4str,firstseen,lastseen,scans,hids) VALUES(?,?,?,?,?) ON DUPLICATE KEY update lastseen = ?, scans = CONCAT_WS(',',scans, ?), hids = CONCAT_WS(',',hids, ?)");
	$INSERT->execute($host->ipv4_addr(),$host->starttime(),$host->endtime(),$nmapID,$hid,$host->endtime(),$nmapID,$hid);
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();
	} else { if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }}
		
	$INSERT->finish();

}

sub insertPort {
	
	my ($port, $hid) = @_ ;
	my ($pid,$serviceID) = getPID($port);

	if ( $pid eq "-1") { 
		connectDB();
		printf "\n(reason: %s)\n", $port->reason() if $Global{DEBUG}; 
		my $INSERT = $dbh->prepare("INSERT INTO ports(port,protocol,state,reason,serviceID) values(?,?,?,?,?)");
		$INSERT->execute($port->port(),$port->protocol(),$port->state(),$port->reason(),$serviceID);
		if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();		
		} else {
			if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }
			$getlastinsert->execute;
			($pid) = $getlastinsert->fetchrow_array();
			insertHostPort($hid,$pid); 
		}
		$INSERT->finish();
	} else { insertHostPort($hid,$pid); }
	
	if ($port->scripts()) { 
		for my $portScript ($port->scripts())  {
			my $scriptID = getScriptID($portScript);
			insertHostport2NSEscript($hid,$pid,$scriptID); 
		}
	}
	                                                                                                                        
	return $pid;	
	 
} 


sub getPID { 
	my ($port) = @_;
	my $pid = -1; 
	
	my $serviceID = getServiceID($port->service());
	if ( $serviceID eq "-1") { $serviceID = insertService($port->service()); } 
	
	connectDB();
	my $QUERY = $dbh->prepare("select * from ports where port = ? AND protocol = ? AND state = ? and serviceID = ? ");
	$QUERY->execute($port->port(),$port->protocol(),$port->state(),$serviceID);
	if ( $QUERY->rows() > 0 ) { 
		if ( $QUERY->rows() eq 1 ) { my ($hashREF) = $QUERY->fetchrow_hashref();  $pid = $hashREF->{pid}; }
		elsif ( $QUERY->rows() > 1 ) { 
			printf "\nmultiple records found %s\n", __LINE__; die"\n" 
		} else { $pid = "-1"; }
	}
	$QUERY->finish();
	
	return ($pid,$serviceID); 
	
}
	
sub getServiceID { 
	my ($service) = @_;
	my $serviceID = -1; 

	my @where; 
	if ((defined($service->name())) && ( $service->name() ne "-1")) { push(@where, sprintf("name = '%s'",$service->name())); } else { push(@where, sprintf("name is NULL "));}
	if ((defined($service->method())) && ( $service->method() ne "-1")) { push(@where, sprintf("method = '%s'",$service->method())); } else { push(@where, sprintf("method is NULL "));}
	if ((defined($service->devicetype())) && ( $service->devicetype() ne "-1")) { push(@where, sprintf("devicetype = '%s'",$service->devicetype())); } else { push(@where, sprintf("devicetype is NULL "));}
	if ((defined($service->product())) && ( $service->product() ne "-1")) { push(@where, sprintf("product = '%s'",$service->product())); } else { push(@where, sprintf("product is NULL "));}
	if ((defined($service->confidence())) && ( $service->confidence() ne "-1")) { push(@where, sprintf("conf = '%s'",$service->confidence())); } else { push(@where, sprintf("conf is NULL "));}
	if ((defined($service->tunnel())) && ( $service->tunnel() ne "-1")) { push(@where, sprintf("tunnel = '%s'",$service->tunnel())); } else { push(@where, sprintf("tunnel is NULL "));}
	
	if ( scalar @where ) {
		
		my $where = join(" AND ", @where);  
		connectDB();
		my $QUERY = $dbh->prepare("SELECT serviceID FROM services WHERE $where ");
		$QUERY->execute();
		if ( $QUERY->rows() > 0 ) {  
			if ( $QUERY->rows() eq 1 ) { 
				($serviceID) = $QUERY->fetchrow_array();				
			} elsif ( $QUERY->rows() > 1 ) { 
				printf "\nmultiple records found %s\n", __LINE__; 
				die "\n";  
			} else { $serviceID = "-1"; print "\n"; }
		}
		$QUERY->finish(); 		
	}
	if ( $serviceID eq "-1" ) { $serviceID = insertService($service); }
	
	return $serviceID; 
	
}
	
sub insertService { 
	my ($service) = @_;
	my $serviceID = -1; 

	my @fields, my @values;	
	if ((defined($service->name())) && ($service->name() ne "-1")) { push(@fields, "name"); push(@values, sprintf("'%s'",$service->name())); }
	if ((defined($service->method())) && ($service->method() ne "-1")) { push(@fields, "method"); push(@values, sprintf("'%s'",,$service->method())); }
	if ((defined($service->devicetype())) && ($service->devicetype() ne "-1")) { push(@fields, "devicetype"); push(@values,sprintf("'%s'",,$service->devicetype())); }
	if ((defined($service->product())) && ($service->product() ne "-1")) { push(@fields, "product"); push(@values, sprintf("'%s'",$service->product())); }
	if ((defined($service->confidence())) && ($service->confidence() ne "-1")) { push(@fields,"conf"); push(@values, sprintf("'%s'",$service->confidence())); }
	if ((defined($service->tunnel())) && ( $service->tunnel() ne "-1")) { push(@fields,"tunnel"); push(@values, sprintf("'%s'",$service->tunnel())); }
	my $FIELDS = join(',',@fields); my $VALUES = join(',',@values);
	my $insertSTMT = sprintf("INSERT INTO services(%s) VALUES(%s)", join(",",@fields), join(",",@values));
	
	connectDB();
	my $INSERT = $dbh->prepare("$insertSTMT");
	$INSERT->execute();
	
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();		
	} else {
		if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }
		$getlastinsert->execute;
		($serviceID) = $getlastinsert->fetchrow_array();
	}
	$INSERT->finish();
	
	return $serviceID; 		

} 
				
sub insertNSEScript { 
	my ($name,$output) = @_ ;
	my $scriptID = -1;
	
	connectDB();
	my $INSERT = $dbh->prepare("INSERT INTO NSEscript(scriptname,output) VALUES(?,?)"); 
	$INSERT->execute($name,$output);
	
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();		
	} else {
		if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }
#		$getlastinsert->{TraceLevel} = "3|SQL";
		$getlastinsert->execute;
		($scriptID) = $getlastinsert->fetchrow_array();
	}
	
	return $scriptID; 	

}

sub getScriptID {
	
	my ($script)  = @_;
	my $scriptID = -1;  
	
	connectDB();
	my $QUERY = $dbh->prepare("SELECT scriptID FROM NSEscript WHERE scriptname = ? AND output = ? ");
	$QUERY->execute($script->name(), $script->output());
	if ( $QUERY->rows() > 0 ) { 
		if ( $QUERY->rows() eq 1 ) { ($scriptID) = $QUERY->fetchrow_array();
		} elsif ( $QUERY->rows() > 1 ) { printf "\nmultiple records found %s\n", __LINE__; die"\n" 
		} else { $scriptID = "-1"; }
	}
	$QUERY->finish();
		 	
	
	if ( $scriptID eq "-1" ) { 
		$scriptID = insertNSEScript($script->name(), $script->output()); 
	}
	
	return $scriptID;  
	
}


sub insertHostPort {
	my ($hid,$pid,$nmapID) = @_ ;
	connectDB();
	my $INSERT = $dbh->prepare("INSERT IGNORE INTO hostport(hid,pid) VALUES(?,?)");
	printf STDOUT "INSERT IGNORE INTO hostport(hid,pid) VALUES(%s,%s);",$hid,$pid if $Global{DEBUG}; 
	$INSERT->execute($hid,$pid);
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();		
	} else {if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }}
	$INSERT->finish(); 
}

sub insertHostport2NSEscript { 
	my ($hid,$pid,$scriptID) = @_ ;
	connectDB();
	my $INSERT = $dbh->prepare("INSERT IGNORE INTO hostport2NSEscript(hid,pid,scriptID) VALUES(?,?,?)");
#	$INSERT->{TraceLevel} = "3|SQL";
	$INSERT->execute($hid,$pid,$scriptID);
	if ( $dbh->err() ) {
		print Dumper $scriptID;
		printf STDOUT "error>$dbh->err()\n";
		$dbh->rollback();		
	} else {if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }}

	$INSERT->finish(); 
}




sub getNmapID {
	my ($nmap, $filename, $md5sum) = @_;
	my $nmapID = -1; my $new = 0; 

	croak "missing 'nmap' arguement " unless defined($nmap);
	croak "missing 'filename' arguement " unless defined($filename);
	croak "missing 'md5sum' arguement " unless defined($md5sum);
	
	my ($name,$PATH,undef) = fileparse($filename);
	
	connectDB();
	my $QUERY = $dbh->prepare("SELECT * FROM nmap WHERE filename = ? AND md5sum = ?");
	$QUERY->execute($name, $md5sum);
	if ( $QUERY->rows() > 0 ) {
		if ( $QUERY->rows() eq "1") { my ($hashREF) = $QUERY->fetchrow_hashref(); $nmapID = $hashREF->{nmapID};  			
		} elsif ( $QUERY->rows() > 1 ) { printf "\nmultiple records found %s\n", __LINE__; die"\n"
		} else { $nmapID = "-1"; }
	}
	
	if ( $nmapID eq "-1" ) { $nmapID = InsertNmap($nmap, $name, $md5sum); $new = 1;  }
	
	return ($nmapID,$new); 

}	

sub InsertNmap {
	
	my ($nmap,$file,$md5sum) = @_;
	my $nmapID = -1;
	
	croak "missing 'nmap' arguement " unless defined($nmap);
	croak "missing 'file' arguement " unless defined($file);
	croak "missing 'md5sum' arguement " unless defined($md5sum);
		  
	connectDB();
	my $INSERT = $dbh->prepare("INSERT INTO nmap(nmapversion,xmlversion,starttime,endtime,elapsedTime,hostsTotal,
		hostsUp,hostsDown,exitMsg,numberOfServices,scanType,scanProtocol,portsScanned,nmapArgs,filename,md5sum,
		created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
	$INSERT->execute($nmap->{parsed}{nmaprun}{version},$nmap->{parsed}{nmaprun}{xmloutputversion},$nmap->{parsed}{nmaprun}{start},
		$nmap->{parsed}{runstats}{finished}{time},$nmap->{parsed}{runstats}{finished}{elapsed},$nmap->{parsed}{runstats}{hosts}{total},
		$nmap->{parsed}{runstats}{hosts}{up},$nmap->{parsed}{runstats}{hosts}{down},$nmap->{parsed}{runstats}{finished}{exit},
		$nmap->{parsed}{scaninfo}{numservices},$nmap->{parsed}{scaninfo}{type},$nmap->{parsed}{scaninfo}{protocol},
		$nmap->{parsed}{scaninfo}{services},$nmap->{parsed}{nmaprun}{args},$file,$md5sum,time());
		
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();		
	} else {if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }}
	$INSERT->finish(); 	

	$getlastinsert->execute;
	($nmapID) = $getlastinsert->fetchrow_array();
	
	return $nmapID; 
}


sub ArchiveProcessedFile { 
	my ($PATH,$filename) = @_ ; 
	if ( -f "$PATH/PROCESSED/$filename" ) { Utility->RenameExistingFile("$PATH/PROCESSED/$filename",0); }
	if ( -f $filename ) { 
		printf STDOUT "mv -f $filename $PATH/PROCESSED/$filename \n";
		system("debug> mv -f $filename $PATH/PROCESSED/$filename"); 
		Utility->CompressFile("$PATH/PROCESSED/$filename");		
	}

}

sub getHostID { 
	my ($host,$nmapID) = @_;
	my $hid = -1;
	
	croak "host not defined" unless defined($host);
	croak "nmapID not defined" unless defined($nmapID);
	
	connectDB();

	my $QUERY = $dbh->prepare("SELECT hid FROM hosts WHERE ip4str = ? AND starttime = ? and endtime = ? ");
	$QUERY->execute($host->ipv4_addr(),$host->starttime(),$host->endtime());
	if ( $QUERY->rows > 0 ) { 
		if ($QUERY->rows eq 1 ) { ($hid) = $QUERY->fetchrow_array(); }
		else { die "multiple rows returned\n";}
	} 
	
	return $hid
}


sub insertHost { 
	my ($host,$nmapID) = @_;
	
	croak "host not defined" unless defined($host);
	croak "nmapID not defined" unless defined($nmapID);
	 
	my $hid = -1; my %params;$params{nmapID} = $nmapID; 
	if ( defined($host->ipv4_addr()) ) {$params{ip4str} = $host->ipv4_addr();}
	if ( defined($host->ipv6_addr()) ) {$params{ip6str} = $host->ipv6_addr();}
	if ( defined($host->uptime_seconds()) ) { $params{uptime} = $host->uptime_seconds();}
	if ( defined($host->starttime())) { $params{starttime} = $host->starttime(); }
	if ( defined($host->endtime())) { $params{endtime} = $host->endtime(); }
	if ( defined($host->mac_addr())) {  $params{mac} = $host->mac_addr(); }
	if ( defined($host->distance())) { $params{distance} = $host->distance(); }
	
	if ( defined($host->hostname())) {
		$params{hostname} = $host->hostname();
        my @ARRAY = split(/\./, $params{hostname});
        shift(@ARRAY);
        if ( @ARRAY ) {
                my $domain = join('.',@ARRAY);
                $params{domain} = $domain;
        }
	}
	if (defined($host->traceroute())) { 
        my @trace = $host->traceroute();
        if (@trace) {
                my @Traceroute;
                for my $hop ( @trace) { push(@Traceroute,"$hop->{ttl};$hop->{ipaddr}");}
                $params{traceroute} = join(',',@Traceroute);
        }		
	}
	
	my @fields; my @values; 
	foreach ( keys %{params}) {
		push(@fields, $_); push(@values,"'$params{$_}'");
	}
	my $FIELDS = join(',',@fields); my $VALUES = join(',',@values);
	
	connectDB();
	my $insertSTMT = sprintf("INSERT INTO hosts(%s) VALUES(%s)", join(",",@fields), join(",",@values));
	my $INSERT = $dbh->prepare("$insertSTMT");
	$INSERT->execute(); 
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();
	} else {
		if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }
		$getlastinsert->execute;
		($hid) = $getlastinsert->fetchrow_array();
		updateIPhistory($host,$nmapID,$hid);
	}
	$INSERT->finish();
	
	return $hid;	
}

sub updateIPhistory  { 
	my ($host,$nmapID,$hid) = @_ ;
		
	croak "nmapID not defined" unless defined($nmapID);
	croak "missing 'hid' arguement " unless $hid;
	
	croak "'ip4str' undefined" unless defined($host->ipv4_addr());
	croak "'starttime' undefined" unless (defined($host->starttime()));
	croak "'endtime' undefined" unless (defined($host->endtime()));
	
	connectDB();	
	my $INSERT = $dbh->prepare("INSERT INTO IPhistory(ip4str,firstseen,lastseen,scans,hids) VALUES(?,?,?,?,?) ON DUPLICATE KEY update lastseen = ?, scans = CONCAT_WS(',',scans, ?), hids = CONCAT_WS(',',hids, ?)");
	$INSERT->execute($host->ipv4_addr(),$host->starttime(),$host->endtime(),$nmapID,$hid,$host->endtime(),$nmapID,$hid);
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();
	} else { if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }}
		
	$INSERT->finish();

}















sub StartLogging  { 
	my ($logFile,$clobber) = @_;
	
	if (($clobber) && ( -f $logFile)) { 
		::RemoveFile($logFile); 
	} 
	 
	open(LOG, ">> nessus.log") || 
		die "failed to open logfile: $logFile\n$!\n";
	LOG->autoflush(1);
	
	printf LOG "starttime: %s [%s]\n", scalar localtime(time()), time();
	
	return 0; 
}


sub processNSEspecial {
	my ($hid,$script) = @_;
	
	my $osmatchID; 
	
	my @output; 
				
	my $scriptID; 
	my $elements = $script->elements();
	if ( ref $elements eq "HASH") { 
		my %params;
		if (defined($elements->{cpe})) { $params{cpe} = $elements->{cpe}; }
		if (defined($elements->{domain_dns})) { $params{domain} = $elements->{domain_dns}; }
		if (defined($elements->{workgroup})) { 
			$params{workgroup} = $elements->{workgroup};  
		}
		if (defined($elements->{fqdn})) { 
			  my @array = split(/\./,$elements->{fqdn}); 
			  $params{hostname} = shift(@array);
			  $params{domain} = sprintf("%s",join(".",@array)); 
		}
		if (defined($elements->{lanmanager})) { $params{lanmanager} = $elements->{lanmanager}; }
		if (defined($elements->{forest_dns})) { if (! defined ($params{domain})) { $params{domain} = $elements->{forest_dns};} }
		if (defined($elements->{server})) { $params{nbname} = $elements->{server}; }	
		if ( scalar keys %params) { updateHost(hid => $hid, %params); }	
	}
	
	return 0; 
	
}


sub updateHost { 
	my (%params) = @_ ;
	
	croak "missing 'hid' arguement " unless defined($params{hid});

	my @array; 
	foreach ( keys %{params}) {if ( $_ eq "hid" ) {next; } else {push(@array, sprintf(" %s='%s' ", $_, $params{$_}));}}
	my $SET = join(", ", @array);
	
	connectDB();
	my $UPDATE = $dbh->prepare("UPDATE hosts SET $SET WHERE hid = ?");
	$UPDATE->execute($params{hid});
	if ( $dbh->err() ) {printf STDOUT "error>$dbh->err()\n";$dbh->rollback();
	} else { if ( $Global{BatchCommits} eq "0" ) { $dbh->commit(); }}
	
	$UPDATE->finish(); 
	
}

sub RenameExistingFile { 
	my ($filename,$version) = @_; 
	if (! defined($version)) { $version = 0; }
	$version++; 
	my $newFilename = $filename . "." . $version;  
	if ( -f $newFilename ) { RenameExistingFile($filename,$version);}
	else { rename $filename, $newFilename; }
	return 0; 
}


