#!/usr/bin/env python

import re
import os
import cgi
import sys
import errno
import locale
import codecs
import socket
import urllib
import httplib
import urllib2
import datetime
import urlparse
import ConfigParser

# Keep in mind, if you use non-ASCII characters in defaults, you should change their object type from str ("") to unicode (u"") one
# Except user_agent - this should stay str object ("")
# And don't forget to specify correct source file encoding

# When current locale encoding can't be determined, fallback_encoding is used
# So it's actually better to set proper POSIX locale environment variables, instead of changing this default

ignored_hostnames = ["localhost4.localdomain4", "localhost4", "loopback4", "localhost6.localdomain6", "localhost6", "loopback6", "localhost.localdomain", "localhost", "local", "loopback", "ip6-localhost.ip6-localdomain", "ip6-localhost", "ip6-loopback"]
config_defaults = {"Url": "", "File": "", "Keep": "False", "Type": "hosts", "Encoding": ""}
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
privoxy_action = "{+block{Blocked advertisement hostname.} +handle-as-image +set-image-blocker{blank}}"
config_path = "adhosts2privoxy.conf"
actions_path = "hosts.action"
fallback_encoding = "ascii"

def SafePrint(ustr):
	print ustr.encode(sys.stdout.encoding or local_encoding, "replace")

def WriteActionPatterns(action_file, domain_tree, pattern):
	global out_count
	for domain, domain_branch in domain_tree.iteritems():
		new_pattern = u".{}{}".format(domain, pattern)
		if domain_branch:
			WriteActionPatterns(action_file, domain_branch, new_pattern)
		else:
			out_count += 1
			action_file.write(new_pattern + os.linesep)
			
def AddHostnameToDomains(domain_tree, hostname):
	domain_branch = domain_tree
	new_domain = False
	for domain in reversed(hostname.encode("idna").split(".")):
		if domain not in domain_branch:
			if not domain_tree or domain_branch or new_domain:
				domain_branch[domain] = dict() 
				new_domain = True
			else:
				break
		domain_branch = domain_branch[domain]
	domain_branch.clear()
			
def ReadHostsFile(domain_tree, hosts):
	global in_count
	prc_count = 0
	skp_count = 0
	hst_count = 0
	als_count = 0
	ign_count = 0
	for line in hosts.readlines():
		if not re.match(hosts_white_pattern, line):
			line_match = hosts_block_pattern.match(line)
			line_items = line_match and line_match.group(4) and ('_' not in line_match.group(4)) and line_match.group(4).strip().lower().split()
			if line_items:
				prc_count += 1
				for alias, hostname in enumerate(line_items):
					if hostname not in ignored_hostnames:
						in_count += 1
						if alias:
							als_count += 1
						else:
							hst_count += 1
						AddHostnameToDomains(domain_tree, hostname)
					else:
						ign_count += 1
			else:
				skp_count += 1
	SafePrint(u"Completed: {} lines processed, {} lines skipped, {} hostnames, {} aliases, {} ignored".format(prc_count, skp_count, hst_count, als_count, ign_count))

def ReadAdblockScript(domain_tree, adblock, hosts):
	global in_count
	prc_count = 0
	skp_count = 0
	hst_count = 0
	bas_count = 0
	ign_count = 0
	for line in adblock.readlines():
		if not re.match(script_white_pattern, line):
			bas = False
			line_match = script_anchored_pattern.match(line)
			if hosts and not line_match:
				bas = True
				line_match = script_basic_pattern.match(line)
			hostname = line_match and line_match.group(1) and ('_' not in line_match.group(1)) and (True if bas or not line_match.group(7) else line_match.group(7).startswith("domain=~") and line_match.group(7).count('~') == line_match.group(7).count('|') + 1) and line_match.group(1).strip().lower()
			if hostname and not script_ipv4_pattern.match(hostname):
				prc_count += 1
				if hostname not in ignored_hostnames:
					in_count += 1
					if bas:
						bas_count += 1
					else:
						hst_count += 1
					AddHostnameToDomains(domain_tree, hostname)
				else:
					ign_count += 1
			else:
				skp_count += 1
	if hosts:
		SafePrint(u"Completed: {} lines processed, {} lines skipped, {} anchored hostnames, {} basic hostnames, {} ignored".format(prc_count, skp_count, hst_count, bas_count, ign_count))
	else:
		SafePrint(u"Completed: {} lines processed, {} lines skipped, {} hostnames, {} ignored".format(prc_count, skp_count, hst_count, ign_count))

def ProcessFile(domain_tree, section, url, file, keep, type, encoding):
	global processing_error
	hosts_path = file
	hosts_encoding = encoding
	
	if url:
		processing_error = "DOWNLOAD"
		SafePrint(u"Downloading \"{}\"...".format(section))
		
		# Reasons behind converting back and forth to UTF-8:
		#   urllib2.quote and urllib.quote_plus choke on non-ASCII characters in unicode objects (any kind of str objects are ok)
		#   urllib2.urlopen choke on non-ASCII characters in unicode objects (any kind of str objects are ok)
		#   encode("idna") chokes on non-ASCII coded str objects (unicode objects are ok, but python-included IDNA specs are outdated anyway)
		
		splitted_url = urlparse.urlsplit(url.encode("utf-8").replace("\\", "/"))
		if splitted_url.port:
			punycode_netloc = "{}:{}".format(splitted_url.hostname.decode("utf-8").encode("idna"), splitted_url.port)
		else:
			punycode_netloc = splitted_url.netloc.decode("utf-8").encode("idna")
		quoted_url = urlparse.urlunsplit(splitted_url._replace(netloc=punycode_netloc, path=urllib2.quote(splitted_url.path, "/%+$!*'(),"), query=urllib.quote_plus(splitted_url.query, ":&%=+$!*'(),"), fragment=urllib.quote_plus(splitted_url.query, ":&%=+$!*'(),")))
		req = urllib2.Request(quoted_url, headers={"Accept": "*/*", "User-Agent": user_agent})
		resp = urllib2.urlopen(req, timeout=300)
		
		# In RFC 2183 it is stated that Content-Disposition filenames can only be encoded in ASCII codepage, and non-ASCII characters encoded as specified in RFC 2184
		# RFC 2184 is obsoleted by RFC 2231, which is also complemented by RFC 5987 that finally describes it's usage in HTTP headers

		if not hosts_path:
			if "Content-Disposition" in resp.info():
				cd_value, cd_params = cgi.parse_header(resp.info().getheader("Content-Disposition"))
				if "filename*" in cd_params:
					hosts_match = encoding_pattern.match(cd_params["filename*"])
					if hosts_match: hosts_path = urllib.unquote(hosts_match.group(2)).decode(hosts_match.group(1))
				elif "filename" in cd_params:
					hosts_path = cd_params["filename"].decode("ascii")
			if not hosts_path:
				hosts_path = urlparse.urlparse(url).path.strip("/").split("/")[-1] or urlparse.urlparse(url).hostname
			else:
				hosts_path = hosts_path.replace("\\", "_").replace("/", "_")
				
		if not hosts_encoding:
			if "Content-Type" in resp.info():
				ct_value, ct_params = cgi.parse_header(resp.info().getheader("Content-Type"))
				if "charset" in ct_params: 
					hosts_encoding = ct_params["charset"].decode("ascii")

		with open(hosts_path, "wb") as hosts:
			hosts.write(resp.read())
			SafePrint(u"Completed: {} ({:,} bytes)".format(hosts_path, hosts.tell()))

	if not hosts_encoding: hosts_encoding = local_encoding
	
	processing_error = "TYPE"
	if type.lower() == "hosts":
		read_function = lambda hosts : ReadHostsFile(domain_tree, hosts)
		type_name = "hosts file"
	elif type.lower() == "adblock":
		read_function = lambda hosts : ReadAdblockScript(domain_tree, hosts, False)
		type_name = "Adblock filter"
	elif type.lower() == "adblock+hosts":
		read_function = lambda hosts : ReadAdblockScript(domain_tree, hosts, True)
		type_name = "Adblock filter w/ hosts"
	else:
		type_name = ""
			
	SafePrint(u"Processing \"{}\" ({}{})...".format(section, type_name or "unknown file type", "" if codecs.lookup(local_encoding).name == codecs.lookup(hosts_encoding).name else u", {}".format(codecs.lookup(hosts_encoding).name)))
	
	if not type_name: raise IOError(errno.EINVAL, "File type \"{}\" is unsupported".format(type), hosts_path)
	
	processing_error = "FILE"	
	with codecs.open(hosts_path, "r", hosts_encoding) as hosts:
		processing_error = "READ"
		read_function(hosts)
		
	processing_error = "CLEANUP"		
	if not keep: os.remove(hosts_path)
	
def GetConfigBoolean(config, section, option):
	try:
		return bool(config.getfloat(section, option))
	except ValueError:
		return config.getboolean(section, option)
	
def GetTimestamp(dt):
	return "{0} {1.day: >2} {1:%H:%M:%S %Y}".format(rfc3164_months[dt.month - 1], dt)

local_encoding = locale.getdefaultlocale()[1] or fallback_encoding

if len(sys.argv) == 1 and not os.path.isfile(config_path):
	SafePrint(u"Usage: {} [CONFIG [ACTION_FILE [INPUT_DIR]]]".format(os.path.basename(sys.argv[0])))
	SafePrint(u"Defaults:\n\tCONFIG      = {}\n\tACTION_FILE = {}\n\INPUT_DIR   = {}\n".format(config_path, actions_path, os.getcwd()))
	SafePrint(u"Copyright (c) 2018-2019 Lcferrum");
	SafePrint(u"Licensed under BSD 2-Clause License");
	exit(1)

# Block pattern conforms (in a sane way) to RFC 4291, ID draft-main-ipaddr-text-rep-02 and RFC 1123
# Basic and anchored patterns conform (in a sane way) to RFC 1123
	
hosts_block_pattern = re.compile("^\s*(0+\.0+\.0+\.0+|127\.\d+\.\d+\.\d+|(0{0,4}:){1,7}(0{0,4}|0{0,3}1))((\s+([\w]([\w-]*[\w])?\.)*[\w]([\w-]*[\w])?)+)\s*(#.*)?$", re.UNICODE)
hosts_white_pattern = re.compile("^\s*#.*$|^\s*$")
script_basic_pattern = re.compile("^(([\w]([\w-]*[\w])?\.)*[\w]([\w-]*[\w])?)\s*$", re.UNICODE)
script_anchored_pattern = re.compile("^\|\|(([\w]([\w-]*[\w])?\.)*[\w]([\w-]*[\w])?)(\||\^)?(\$[^\$]*?(domain=.+)?|\s*)$", re.UNICODE)
script_ipv4_pattern = re.compile("^\d+\.\d+\.\d+\.\d+$")
script_white_pattern = re.compile("^\s*!.*$|^\s*$")
encoding_pattern = re.compile("^([^']+)'[\w-]*'(.+)")
rfc3164_months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
config = ConfigParser.ConfigParser(config_defaults)
dt_now = datetime.datetime.now()
root_domain_tree = dict()
delayed_write = list()
in_count = 0
out_count = 0
processing_error = ""
no_errors = True
exit_code = 1

SafePrint(u"Started on: {}".format(GetTimestamp(dt_now)))

try:
	if len(sys.argv) > 1: config_path = sys.argv[1].decode(local_encoding)
	if len(sys.argv) > 2: actions_path = sys.argv[2].decode(local_encoding)

	with codecs.open(config_path, "r", local_encoding) as config_file:
		config.readfp(config_file)
		
		if len(sys.argv) > 3:
			hosts_dir = sys.argv[3].decode(local_encoding)
			if not os.path.isdir(hosts_dir): raise IOError(errno.ENOTDIR, "The directory name is invalid", hosts_dir)
			os.chdir(hosts_dir)
			
		delayed_write.append(u"# Action file created on:")
		delayed_write.append(u"#    {}".format(GetTimestamp(dt_now)))
		delayed_write.append(u"# Included files:")

		for section in config.sections():
			try:
				ProcessFile(root_domain_tree, section, config.get(section, "Url"), config.get(section, "File"), GetConfigBoolean(config, section, "Keep"), config.get(section, "Type"), config.get(section, "Encoding"))
				delayed_write.append(u"#    [OK]: {}".format(config.get(section, "Url") or config.get(section, "File")))
			except UnicodeError as e:
				SafePrint(u"Codec error{}: {}".format(" ({})".format(e.encoding) if hasattr(e, "encoding") else "", e.message or e.reason))
			except urllib2.HTTPError as e:
				SafePrint(u"Failed to download \"{}\", HTTP error: {} ({})".format(config.get(section, "Url"), e.code, e.reason))
			except urllib2.URLError as e:
				SafePrint(u"Failed to download \"{}\", server is not reachable: {}".format(config.get(section, "Url"), e.reason))
			except httplib.HTTPException as e:
				SafePrint(u"Failed to download \"{}\": {}".format(config.get(section, "Url"), e.message))
			except socket.timeout:
				SafePrint(u"Failed to download \"{}\", timeout exceeded".format(config.get(section, "Url")))
			except socket.error as e:
				SafePrint(u"Failed to download \"{}\": {}".format(config.get(section, "Url"), e.strerror))
			except (IOError, OSError) as e:
				SafePrint(u"Error while accessing \"{}\": {}".format(e.filename, e.strerror))
			except ValueError as e:
				SafePrint(u"Processing error: {}".format(e.message))
			else:
				continue
			delayed_write.append(u"#    [{} ERROR]: {}".format(processing_error, config.get(section, "Url") or config.get(section, "File")))
			no_errors = False
			
		if not no_errors:
			delayed_write.append(u"# Due to errors some files were processed only partially or weren't processed at all.")
			
		if no_errors or root_domain_tree:
			SafePrint(u"Writing action file \"{}\"...".format(actions_path))
			with codecs.open(actions_path, "w", local_encoding) as action_file:
				for string in delayed_write: action_file.write(string + os.linesep)
				action_file.write(os.linesep)
				action_file.write(privoxy_action + os.linesep)
				WriteActionPatterns(action_file, root_domain_tree, "")
				SafePrint(u"Done!")

except ConfigParser.Error as e:
	SafePrint(u"Malformed config \"{}\"".format(e.filename))
except UnicodeError as e:
	SafePrint(u"Codec error{}: {}".format(" ({})".format(e.encoding) if hasattr(e, "encoding") else "", e.message or e.reason))
except IOError as e:
	SafePrint(u"Error while accessing \"{}\": {}".format(e.filename, e.strerror))
except:
	SafePrint(u"Unexpected error: {}".format(sys.exc_info()[0]))
else:
	exit_code = 0 if no_errors else 1
	
top_count = len([domain for domain, branch in root_domain_tree.iteritems() if not branch])

SafePrint(u"Hostnames processed: {}".format(in_count))
SafePrint(u"Resulting block patterns: {}{}".format(out_count, " (including {} top-level domains)".format(top_count) if top_count else ""))
SafePrint(u"Transfer rate: {0:.1f}%".format(float(out_count)/float(in_count)*100 if in_count else 0))

exit(exit_code)
