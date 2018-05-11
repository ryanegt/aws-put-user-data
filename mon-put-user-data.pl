#!/usr/bin/perl

BEGIN
{
  use File::Basename;
  my $script_dir   = &File::Basename::dirname($0);
  push @INC, $script_dir;
}

use strict;
use warnings;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Request;
use JSON;
use Sys::Hostname;
use Getopt::Long;
use Sys::Syslog qw(:DEFAULT setlogsock);
use Sys::Syslog qw(:standard :macros);
use CloudWatchClient;
use constant { NOW => 0 };
use Data::Dumper;

#
# For cloudwatch
#

my $version = '0.1';
my $client_name = 'CloudWatch-PutUserData';
my $enable_compression;
my $aws_credential_file;
my $aws_access_key_id;
my $aws_secret_key;
my $aws_iam_role;
my $from_cron;
my $parse_result = 1;
my $parse_error = '';
my $argv_size = @ARGV;
my $mcount = 0;
my %params = ();
my $now = time();
my $timestamp   = CloudWatchClient::get_offset_time(NOW);
my $instance_id = CloudWatchClient::get_instance_id();

#
# Set default input DS, Namespace, Dimensions
#

$params{'Input'} = {};
my $input_ref = $params{'Input'};
$input_ref->{'Namespace'}="System/Linux";
my %xdims = (("InstanceId"=>$instance_id));

#
# Adds a new metric to the request
#

sub add_single_metric
{
  my $name = shift;
  my $unit = shift;
  my $value = shift;
  my $dims = shift;
  my $metric = {};

  $metric->{"MetricName"} = $name;
  $metric->{"Timestamp"} = $timestamp;
  $metric->{"RawValue"} = $value;
  $metric->{"Unit"} = $unit;

  my $dimensions = [];
  foreach my $key (sort keys %$dims)
  {
    push(@$dimensions, {"Name" => $key, "Value" => $dims->{$key}});
  }
  $metric->{"Dimensions"} = $dimensions;
  push(@{$input_ref->{'MetricData'}},  $metric);
  ++$mcount;
}

#
# Prints out or logs an error and then exits.
#

sub exit_with_error
{
  my $message = shift;
  report_message(LOG_ERR, $message);
  exit 1;
}

#
# Prints out or logs a message
#

sub report_message
{
  my $log_level = shift;
  my $message = shift;
  chomp $message;

  if ($from_cron)
  {
    setlogsock('unix');
    openlog($client_name, 'nofatal', LOG_USER);
    syslog($log_level, $message);
    closelog;
  }
  elsif ($log_level == LOG_ERR) {
    print STDERR "\nERROR: $message\n";
  }
  elsif ($log_level == LOG_WARNING) {
    print "\nWARNING: $message\n";
  }
  elsif ($log_level == LOG_INFO) {
    print "\nINFO: $message\n";
  }
}

{
  # Capture warnings from GetOptions
  local $SIG{__WARN__} = sub { $parse_error .= $_[0]; };

  $parse_result = GetOptions(
    'from-cron' => \$from_cron,
    'aws-credential-file:s' => \$aws_credential_file,
    'aws-access-key-id:s' => \$aws_access_key_id,
    'aws-secret-key:s' => \$aws_secret_key,
    'enable-compression' => \$enable_compression,
    'aws-iam-role:s' => \$aws_iam_role,
    );
}

if (!defined($instance_id) || length($instance_id) == 0) {
  exit_with_error("Cannot obtain instance id from EC2 meta-data.");
}

#
# Params for connecting with and talking to the server API
#

my $clientId     = '';
my $clientSecret = '';
my $clientPass   = '';
my $authEndpoint = 'https://path.to.auth';
my $userEndpoint = 'https://path.to.data';
my $asaPort      = 81;

#
# Collect data from netstat command
#

my $cxns = `netstat -ant | grep $port | grep EST | wc -l`;
add_single_metric("TCP Connections","Count",$cxns,\%xdims);

#
# Get auth token from core
#

my $ua = LWP::UserAgent->new;
my $req = HTTP::Request->new(POST => $authEndpoint);

$req->header('response_type'=>'json');
$req->content_type('application/x-www-form-urlencoded');
$req->content('grant_type=client_credentials&client_id='.$clientId
   .'&client_secret='.$clientSecret);
my $res = $ua->request($req);

#
# check the authorization outcome
#
if ($res->is_success) {

   my $auth = decode_json($res->decoded_content);
   my $token= $auth->{'access_token'};

   #
   # Make the call for active user data
   #

   my $req  = HTTP::Request->new(GET => $userEndpoint);
   $req->header('Authorization'=>'Bearer '.$token);
   $req->header('response_type'=>'json');
   my $res = $ua->request($req);
   if ($res->is_success) {
      my $data = decode_json($res->decoded_content);
      my $users= $data->{'data'};
      add_single_metric("Active Users","Count", $users, \%xdims);
      $mcount++;
   }

   if($mcount > 0) {

      #
      # Attempt to send them to cloudwatch
      #

      my %opts = ();
      $opts{'aws-credential-file'} = $aws_credential_file;
      $opts{'aws-access-key-id'}   = $aws_access_key_id;
      $opts{'aws-secret-key'}      = $aws_secret_key;
      $opts{'retries'} = 2;
      $opts{'user-agent'} = "$client_name/$version";
      $opts{'enable_compression'} = 1 if ($enable_compression);
      $opts{'aws-iam-role'} = $aws_iam_role;

      my $response = CloudWatchClient::call_json('PutMetricData', \%params, \%opts);
      my $code    = $response->code;
      my $message = $response->message;

      if ($code == 200 && !$from_cron) {
        my $request_id = $response->headers->{'x-amzn-requestid'};
        print "Successfully reported metrics to CloudWatch. Reference Id: $request_id\n";
      }
      elsif ($code < 100) {
        exit_with_error($message);
      }
      elsif ($code != 200) {
        exit_with_error("Failed to call CloudWatch: HTTP $code. Message: $message");
      }

   } else {
      print "Error: " . $res->status_line . "\n";
      exit_with_error($res->status_line);
   }
}
else {
   print "Error: " . $res->status_line . "\n";
   exit_with_error($res->status_line);
}
