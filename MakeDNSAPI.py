#!/usr/bin/python3
from bs4 import BeautifulSoup
from glob import glob
from os import chmod, link, mkdir
from os.path import exists, join as pathjoin
from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import HtmlFormatter
from pygments.token import Name, Keyword
from re import compile, match, search, sub, DOTALL
from shutil import copy2
from subprocess import call
from time import strftime
from platform import system

# Define some values
DefinesArr = []
EnumType = object()
DefineType = object()

DefinesArr.append([ 300, "GETDNS_RETURN_", "Return values", EnumType,
	[ "GOOD", "MAKEVAL0#Good" ],
	[ "GENERIC_ERROR", "MAKEVAL1#Generic error" ],
	[ "BAD_DOMAIN_NAME", "Badly-formed domain name in first argument" ],
	[ "BAD_CONTEXT", "The context has internal deficiencies" ],
	[ "CONTEXT_UPDATE_FAIL", "Did not update the context" ],
	[ "UNKNOWN_TRANSACTION", "An attempt was made to cancel a callback with a transaction_id that is not recognized" ],
	[ "NO_SUCH_LIST_ITEM", "A helper function for lists had an index argument that was too high." ],
	[ "NO_SUCH_DICT_NAME", "A helper function for dicts had a name argument that for a name that is not in the dict." ],
	[ "WRONG_TYPE_REQUESTED", "A helper function was supposed to return a certain type for an item, but the wrong type was given." ],
	[ "NO_SUCH_EXTENSION", "A name in the extensions dict is not a valid extension." ],
	[ "EXTENSION_MISFORMAT", "One or more of the extensions have a bad format." ],
	[ "DNSSEC_WITH_STUB_DISALLOWED", "A query was made with a context that is using stub resolution and a DNSSEC extension specified." ],
	[ "MEMORY_ERROR", "Unable to allocate the memory required." ],
	[ "INVALID_PARAMETER", "A required parameter had an invalid value." ],
	[ "NOT_IMPLEMENTED", "The library did not have the requested API feature implemented." ]
])

DefinesArr.append([ 400, "GETDNS_DNSSEC_", "DNSSEC values", DefineType,
	[ "SECURE", "The record was determined to be secure in DNSSEC" ], 
	[ "BOGUS", "The record was determined to be bogus in DNSSEC" ], 
	[ "INDETERMINATE", "The record was not determined to be any state in DNSSEC" ], 
	[ "INSECURE", "The record was determined to be insecure in DNSSEC" ],
	[ "NOT_PERFORMED", "DNSSEC validation was not performed (only used for debugging)" ],
])

DefinesArr.append([ 500, "GETDNS_NAMESPACE_", "Namespace types", EnumType,
	[ "DNS", "See getdns_context_set_namespaces()" ],
	[ "LOCALNAMES", "See getdns_context_set_namespaces()" ],
	[ "NETBIOS", "See getdns_context_set_namespaces()" ],
	[ "MDNS", "See getdns_context_set_namespaces()" ],
	[ "NIS", "See getdns_context_set_namespaces()" ]
])

DefinesArr.append([ 520, "GETDNS_RESOLUTION_", "Resolution types", EnumType,
	[ "STUB", "See getdns_context_set_resolution_type()" ],
	[ "RECURSING", "See getdns_context_set_resolution_type()" ]
])

DefinesArr.append([ 530, "GETDNS_REDIRECTS_", "Redirect policies", EnumType,
	[ "FOLLOW", "See getdns_context_set_follow_redirects()" ],
	[ "DO_NOT_FOLLOW", "See getdns_context_set_follow_redirects()" ]
])

DefinesArr.append([ 540, "GETDNS_TRANSPORT_", "Transport arrangements", EnumType,
	[ "UDP_FIRST_AND_FALL_BACK_TO_TCP", "See getdns_context_set_dns_transport()" ],
	[ "UDP_ONLY", "See getdns_context_set_dns_transport()" ],
	[ "TCP_ONLY", "See getdns_context_set_dns_transport()" ],
	[ "TCP_ONLY_KEEP_CONNECTIONS_OPEN", "See getdns_context_set_dns_transport()" ]
])

DefinesArr.append([ 1200, "GETDNS_TRANSPORT_LIST_", "Transport list arrangements", EnumType,
	[ "UDP", "See getdns_context_set_dns_transport_list()" ],
	[ "TCP", "See getdns_context_set_dns_transport_list()" ],
	[ "TLS", "See getdns_context_set_dns_transport_list()" ],
	[ "STARTTLS", "See getdns_context_set_dns_transport_list()" ]
])

DefinesArr.append([ 550, "GETDNS_APPEND_NAME_", "Suffix appending methods", EnumType,
	[ "ALWAYS", "See getdns_context_set_append_name()" ],
	[ "ONLY_TO_SINGLE_LABEL_AFTER_FAILURE", "See getdns_context_set_append_name()" ],
	[ "ONLY_TO_MULTIPLE_LABEL_NAME_AFTER_FAILURE", "See getdns_context_set_append_name()" ],
	[ "NEVER", "See getdns_context_set_append_name()" ]
])

DefinesArr.append([ 600, "GETDNS_CONTEXT_CODE_", "Context codes", EnumType,
	[ "NAMESPACES", "Change related to <code>getdns_context_set_namespaces</code>" ],
	[ "RESOLUTION_TYPE", "Change related to <code>getdns_context_set_resolution_type</code>" ],
	[ "FOLLOW_REDIRECTS", "Change related to <code>getdns_context_set_follow_redirects</code>" ],
	[ "UPSTREAM_RECURSIVE_SERVERS", "Change related to <code>getdns_context_set_upstream_recursive_servers</code>" ],
	[ "DNS_ROOT_SERVERS", "Change related to <code>getdns_context_set_dns_root_servers</code>" ],
	[ "DNS_TRANSPORT", "Change related to <code>getdns_context_set_dns_transport</code>" ],
	[ "LIMIT_OUTSTANDING_QUERIES", "Change related to <code>getdns_context_set_limit_outstanding_queries</code>" ],
	[ "APPEND_NAME", "Change related to <code>getdns_context_set_append_name</code>" ],
	[ "SUFFIX", "Change related to <code>getdns_context_set_suffix</code>" ],
	[ "DNSSEC_TRUST_ANCHORS", "Change related to <code>getdns_context_set_dnssec_trust_anchors</code>" ],
	[ "EDNS_MAXIMUM_UDP_PAYLOAD_SIZE", "Change related to <code>getdns_context_set_edns_maximum_udp_payload_size</code>" ],
	[ "EDNS_EXTENDED_RCODE", "Change related to <code>getdns_context_set_edns_extended_rcode</code>" ],
	[ "EDNS_VERSION", "Change related to <code>getdns_context_set_edns_version</code>" ],
	[ "EDNS_DO_BIT", "Change related to <code>getdns_context_set_edns_do_bit</code>" ],
	[ "DNSSEC_ALLOWED_SKEW", "Change related to <code>getdns_context_set_dnssec_allowed_skew</code>" ],
	[ "MEMORY_FUNCTIONS", "Change related to <code>getdns_context_set_memory_functions</code>" ],
	[ "TIMEOUT", "Change related to <code>getdns_context_set_timeout</code>" ],
	[ "IDLE_TIMEOUT", "Change related to <code>getdns_context_set_idle_timeout</code>" ],
])

DefinesArr.append([ 700, "GETDNS_CALLBACK_", "Callback Type Variables", EnumType,
	[ "COMPLETE", "The response has the requested data in it" ],
	[ "CANCEL", "The calling program cancelled the callback; response is NULL" ],
	[ "TIMEOUT", "The requested action timed out; response is filled in with empty structures" ],
	[ "ERROR", "The requested action had an error; response is NULL" ],
])

DefinesArr.append([ 800, "GETDNS_NAMETYPE_", "Type Of Name Services", DefineType,
	[ "DNS", "Normal DNS (RFC 1035)" ],
	[ "WINS", "The WINS name service (some reference needed)" ],
])

DefinesArr.append([ 900, "GETDNS_RESPSTATUS_", "Status Codes for Responses", DefineType,
	[ "GOOD", "At least one response was returned" ],
	[ "NO_NAME", "Queries for the name yielded all negative responses" ],
	[ "ALL_TIMEOUT", "All queries for the name timed out" ],
	[ "NO_SECURE_ANSWERS", "The context setting for getting only secure responses was specified, and at least one DNS " \
		+ "response was received, but no DNS response was determined to be secure through DNSSEC." ],
	[ "ALL_BOGUS_ANSWERS", "The context setting for getting only secure "
	+ "responses was specified, and at least one DNS response was received, "
	+ "but all received responses for the requested name were bogus." ],
])

DefinesArr.append([ 1000, "GETDNS_EXTENSION_", "Values Associated With Extensions", DefineType,
	[ "TRUE", "Turn on the extension" ],
	[ "FALSE", "Do not turn on the extension" ],
])

DefinesArr.append([ 1100, "GETDNS_BAD_DNS_", "Values Associated With DNS Errors Found By The API", DefineType,
	[ "CNAME_IN_TARGET", "A DNS query type that does not allow a target to be a CNAME pointed to a CNAME" ],
	[ "ALL_NUMERIC_LABEL", "One or more labels in a returned domain name is all-numeric; this is not legal for a hostname" ],
	[ "CNAME_RETURNED_FOR_OTHER_TYPE", "A DNS query for a type other than CNAME returned a CNAME response" ],
])

TextForRDATADicts = '''
<p class=define>A (1)</p>
<p class=descrip><code>ipv4_address</code> (a bindata)</p>

<p class=define>NS (2)</p>
<p class=descrip><code>nsdname</code> (a bindata)</p>

<p class=define>MD (3)</p>
<p class=descrip><code>madname</code> (a bindata)</p>

<p class=define>MF (4)</p>
<p class=descrip><code>madname</code> (a bindata)</p>

<p class=define>CNAME (5)</p>
<p class=descrip><code>cname</code> (a bindata)</p>

<p class=define>SOA (6)</p>
<p class=descrip><code>mname</code> (a bindata), <code>rname</code>  (a bindata),
<code>serial</code> (an int), <code>refresh</code> (an int), <code>refresh</code> (an int),
<code>retry</code> (an int), and <code>expire</code> (an int)</p>

<p class=define>MB (7)</p>
<p class=descrip><code>madname</code> (a bindata)</p>

<p class=define>MG (8)</p>
<p class=descrip><code>mgmname</code> (a bindata)</p>

<p class=define>MR (9)</p>
<p class=descrip><code>newname</code> (a bindata)</p>

<p class=define>NULL (10)</p>
<p class=descrip><code>anything</code> (a bindata)</p>

<p class=define>WKS (11)</p>
<p class=descrip><code>address</code> (a bindata), <code>protocol</code> (an int),
and <code>bitmap</code> (a bindata)</p>

<p class=define>PTR (12)</p>
<p class=descrip><code>ptrdname</code> (a bindata)</p>

<p class=define>HINFO (13)</p>
<p class=descrip><code>cpu</code> (a bindata) and <code>os</code> (a bindata)</p>

<p class=define>MINFO (14)</p>
<p class=descrip><code>rmailbx</code> (a bindata) and <code>emailbx</code> (a bindata)</p>

<p class=define>MX (15)</p>
<p class=descrip><code>preference</code> (an int) and <code>exchange</code> (a bindata)</p>

<p class=define>TXT (16)</p>
<p class=descrip><code>txt_strings</code> (a list) which contains zero or more bindata elements
that are text strings</p>

<p class=define>RP (17)</p>
<p class=descrip><code>mbox_dname</code> (a bindata) and <code>txt_dname</code> (a bindata)</p>

<p class=define>AFSDB (18)</p>
<p class=descrip><code>subtype</code> (an int) and <code>hostname</code> (a bindata)</p>

<p class=define>X25 (19)</p>
<p class=descrip><code>psdn_address</code> (a bindata)</p>

<p class=define>ISDN (20)</p>
<p class=descrip><code>isdn_address</code> (a bindata) and <code>sa</code> (a bindata)</p>

<p class=define>RT (21)</p>
<p class=descrip><code>preference</code> (an int) and <code>intermediate_host</code> (a bindata)</p>

<p class=define>NSAP (22)</p>
<p class=descrip><code>nsap</code> (a bindata)</p>

<p class=define>SIG (24)</p>
<p class=descrip><code>sig_obsolete</code> (a bindata)</p>

<p class=define>KEY (25)</p>
<p class=descrip><code>key_obsolete</code> (a bindata)</p>

<p class=define>PX (26)</p>
<p class=descrip><code>preference</code> (an int), <code>map822</code> (a bindata), and <code>mapx400</code> (a bindata)</p>

<p class=define>GPOS (27)</p>
<p class=descrip><code>longitude</code> (a bindata), <code>latitude</code> (a bindata), and <code>altitude</code> (a bindata)</p>

<p class=define>AAAA (28)</p>
<p class=descrip><code>ipv6_address</code> (a bindata)</p>

<p class=define>LOC (29)</p>
<p class=descrip><code>loc_obsolete</code> (a bindata)</p>

<p class=define>NXT (30)</p>
<p class=descrip><code>nxt_obsolete</code> (a bindata)</p>

<p class=define>EID (31)</p>
<p class=descrip><code>eid_unknown</code> (a bindata)</p>

<p class=define>NIMLOC (32)</p>
<p class=descrip><code>nimloc_unknown</code> (a bindata)</p>

<p class=define>SRV (33)</p>
<p class=descrip><code>priority</code> (an int), <code>weight</code> (an int),
<code>port</code> (an int), and <code>target</code> (a bindata)</p>

<p class=define>ATMA (34)</p>
<p class=descrip><code>format</code> (an int) and <code>address</code> (a bindata)</p>

<p class=define>NAPTR (35)</p>
<p class=descrip><code>order</code> (an int), <code>preference</code> (an int), <code>flags</code>
(a bindata), <code>service</code> (a bindata), <code>regexp</code> (a bindata), and
<code>replacement</code> (a bindata).</p>

<p class=define>KX (36)</p>
<p class=descrip><code>preference</code> (an int) and <code>exchanger</code> (a bindata)</p>

<p class=define>CERT (37)</p>
<p class=descrip><code>type</code> (an int), <code>key_tag</code> (an int), <code>algorithm</code> (an int),
and <code>certificate_or_crl</code> (a bindata)</p>

<p class=define>A6 (38)</p>
<p class=descrip><code>a6_obsolete</code> (a bindata)</p>

<p class=define>DNAME (39)</p>
<p class=descrip><code>target</code> (a bindata)</p>

<p class=define>SINK (40)</p>
<p class=descrip><code>sink_unknown</code> (a bindata)</p>

<p class=define>OPT (41)</p>
<p class=descrip><code>options</code> (a list). Each element of the <code>options</code> list is a
dict with two names: <code>option_code</code> (an int) and <code>option_data</code> (a bindata).</p>

<p class=define>APL (42)</p>
<p class=descrip><code>apitems</code> (a list).
Each element of the <code>apitems</code> list is a dict with four names:
<code>address_family</code> (an int), <code>prefix</code> (an int),
<code>n</code> (an int), and <code>afdpart</code> (a bindata)</p>

<p class=define>DS (43)</p>
<p class=descrip><code>key_tag</code> (an int), <code>algorithm</code> (an int), <code>digest_type</code> (an int), 
and <code>digest</code> (a bindata)</p>

<p class=define>SSHFP (44)</p>
<p class=descrip><code>algorithm</code> (an int), <code>fp_type</code> (an int),
and <code>fingerprint</code> (a bindata)</p>

<p class=define>IPSECKEY (45)</p>
<p class=descrip><code>algorithm</code> (an int), <code>gateway_type</code> (an int), <code>precedence</code> (an int),
<code>gateway</code>, and <code>public_key</code> (a bindata)</p>

<p class=define>RRSIG (46)</p>
<p class=descrip> <code>type_covered</code> (an int), <code>algorithm</code> (an int),
<code>labels</code> (an int), <code>original_ttl</code> (an int), <code>signature_expiration</code>
(an int), <code>signature_inception</code> (an int), <code>key_tag</code> (an int),
<code>signers_name</code> (a bindata), and <code>signature</code> (a bindata)</p>

<p class=define>NSEC (47)</p>
<p class=descrip><code>next_domain_name</code> (a bindata) and <code>type_bit_maps</code> (a bindata)</p>

<p class=define>DNSKEY (48)</p>
<p class=descrip><code>flags</code> (an int), <code>protocol</code> (an int), <code>algorithm</code> (an int), 
and <code>public_key</code> (a bindata)</p>

<p class=define>DHCID (49)</p>
<p class=descrip><code>dhcid_opaque</code> (a bindata)</p>

<p class=define>NSEC3 (50)</p>
<p class=descrip><code>hash_algorithm</code> (an int), <code>flags</code> (an int),
<code>iterations</code> (an int), <code>salt</code> (a bindata),
<code>next_hashed_owner_name</code> (a bindata), and
<code>type_bit_maps</code> (a bindata)</p>

<p class=define>NSEC3PARAM (51)</p>
<p class=descrip><code>hash_algorithm</code> (an int), <code>flags</code> (an int),
<code>iterations</code> (an int), and
<code>salt</code> (a bindata)</p>

<p class=define>TLSA (52)</p>
<p class=descrip><code>certificate_usage</code> (an int), <code>selector</code> (an int),
<code>matching_type</code> (an int), and <code>certificate_association_data</code> (a
bindata).</p>

<p class=define>HIP (55)</p>
<p class=descrip><code>pk_algorithm</code> (an int),
<code>hit</code> (a bindata), <code>public_key</code>
(a bindata), and <code>rendezvous_servers</code> (a list) with each element a bindata with the dname of the rendezvous_server.</p>

<p class=define>NINFO (56)</p>
<p class=descrip><code>ninfo_unknown</code> (a bindata)</p>

<p class=define>RKEY (57)</p>
<p class=descrip><code>rkey_unknown</code> (a bindata)</p>

<p class=define>TALINK (58)</p>
<p class=descrip><code>talink_unknown</code> (a bindata)</p>

<p class=define>CDS (59)</p>
<p class=descrip><code>key_tag</code> (an int), <code>algorithm</code> (an int), <code>digest_type</code> (an int), 
and <code>digest</code> (a bindata)</p>

<p class=define>CDNSKEY (60)</p>
<p class=descrip><code>flags</code> (an int), <code>protocol</code> (an int), <code>algorithm</code> (an int), 
and <code>public_key</code> (a bindata)</p>

<p class=define>OPENPGPKEY (61)</p>
<p class=descrip><code>openpgpkey_unknown</code> (a bindata)</p>

<p class=define>CSYNC (62)</p>
<p class=descrip><code>serial</code> (an int), <code>flags</code> (an int), and <code>type_bit_maps</code> (a bindata)</p>

<p class=define>SPF (99)</p>
<p class=descrip><code>text</code> (a bindata)</p>

<p class=define>UINFO (100)</p>
<p class=descrip><code>uinfo_unknown</code> (a bindata)</p>

<p class=define>UID (101)</p>
<p class=descrip><code>uid_unknown</code> (a bindata)</p>

<p class=define>GID (102)</p>
<p class=descrip><code>gid_unknown</code> (a bindata)</p>

<p class=define>UNSPEC (103)</p>
<p class=descrip><code>unspec_unknown</code> (a bindata)</p>

<p class=define>NID (104)</p>
<p class=descrip><code>preference</code> (an int) and
<code>node_id</code> (a bindata)</p>

<p class=define>L32 (105)</p>
<p class=descrip><code>preference</code> (an int) and <code>locator32</code> (a bindata)</p>

<p class=define>L64 (106)</p>
<p class=descrip><code>preference</code> (an int) and <code>locator64</code> (a bindata)</p>

<p class=define>LP (107)</p>
<p class=descrip><code>preference</code> (an int) and <code>fqdn</code> (a bindata)</p>

<p class=define>EUI48 (108)</p>
<p class=descrip><code>eui48_address</code> (a bindata)</p>

<p class=define>EUI64 (109)</p>
<p class=descrip><code>eui64_address</code> (a bindata)</p>

<p class=define>TKEY (249)</p>
<p class=descrip><code>algorithm</code> (a bindata), <code>inception</code> (an int),
<code>expiration</code> (an int), <code>mode</code> (an int), <code>error</code> (an int),
<code>key_data</code> (a bindata), and <code>other_data</code> (a bindata)</p>

<p class=define>TSIG (250)</p>
<p class=descrip><code>algorithm</code> (a bindata), <code>time_signed</code> (a bindata),
<code>fudge</code> (an int), <code>mac</code> (a bindata), <code>original_id</code> (an int),
<code>error</code> (an int), and <code>other_data</code> (a bindata)</p>

<p class=define>MAILB (253)</p>
<p class=descrip><code>mailb-unknown</code> (a bindata)</p>

<p class=define>MAILA (254)</p>
<p class=descrip><code>maila-unknown</code> (a bindata)</p>

<p class=define>URI (256)</p>
<p class=descrip><code>priority</code> (an int), <code>weight</code> (an int),
and <code>target</code> (a bindata)</p>

<p class=define>CAA (257)</p>
<p class=descrip><code>flags</code> (an int), <code>tag</code> (a bindata), and <code>value</code> (a bindata)</p>

<p class=define>TA (32768)</p>
<p class=descrip><code>ta_unknown</code> (a bindata)</p>

<p class=define>DLV (32769)</p>
<p class=descrip>Identical to DS (43)</p>
'''

DefinesForRRtypes = '''
#define GETDNS_RRTYPE_A 1
#define GETDNS_RRTYPE_NS 2
#define GETDNS_RRTYPE_MD 3
#define GETDNS_RRTYPE_MF 4
#define GETDNS_RRTYPE_CNAME 5
#define GETDNS_RRTYPE_SOA 6
#define GETDNS_RRTYPE_MB 7
#define GETDNS_RRTYPE_MG 8
#define GETDNS_RRTYPE_MR 9
#define GETDNS_RRTYPE_NULL 10
#define GETDNS_RRTYPE_WKS 11
#define GETDNS_RRTYPE_PTR 12
#define GETDNS_RRTYPE_HINFO 13
#define GETDNS_RRTYPE_MINFO 14
#define GETDNS_RRTYPE_MX 15
#define GETDNS_RRTYPE_TXT 16
#define GETDNS_RRTYPE_RP 17
#define GETDNS_RRTYPE_AFSDB 18
#define GETDNS_RRTYPE_X25 19
#define GETDNS_RRTYPE_ISDN 20
#define GETDNS_RRTYPE_RT 21
#define GETDNS_RRTYPE_NSAP 22
#define GETDNS_RRTYPE_SIG 24
#define GETDNS_RRTYPE_KEY 25
#define GETDNS_RRTYPE_PX 26
#define GETDNS_RRTYPE_GPOS 27
#define GETDNS_RRTYPE_AAAA 28
#define GETDNS_RRTYPE_LOC 29
#define GETDNS_RRTYPE_NXT 30
#define GETDNS_RRTYPE_EID 31
#define GETDNS_RRTYPE_NIMLOC 32
#define GETDNS_RRTYPE_SRV 33
#define GETDNS_RRTYPE_ATMA 34
#define GETDNS_RRTYPE_NAPTR 35
#define GETDNS_RRTYPE_KX 36
#define GETDNS_RRTYPE_CERT 37
#define GETDNS_RRTYPE_A6 38
#define GETDNS_RRTYPE_DNAME 39
#define GETDNS_RRTYPE_SINK 40
#define GETDNS_RRTYPE_OPT 41
#define GETDNS_RRTYPE_APL 42
#define GETDNS_RRTYPE_DS 43
#define GETDNS_RRTYPE_SSHFP 44
#define GETDNS_RRTYPE_IPSECKEY 45
#define GETDNS_RRTYPE_RRSIG 46
#define GETDNS_RRTYPE_NSEC 47
#define GETDNS_RRTYPE_DNSKEY 48
#define GETDNS_RRTYPE_DHCID 49
#define GETDNS_RRTYPE_NSEC3 50
#define GETDNS_RRTYPE_NSEC3PARAM 51
#define GETDNS_RRTYPE_TLSA 52
#define GETDNS_RRTYPE_HIP 55
#define GETDNS_RRTYPE_NINFO 56
#define GETDNS_RRTYPE_RKEY 57
#define GETDNS_RRTYPE_TALINK 58
#define GETDNS_RRTYPE_CDS 59
#define GETDNS_RRTYPE_CDNSKEY 60
#define GETDNS_RRTYPE_OPENPGPKEY 61
#define GETDNS_RRTYPE_CSYNC 62
#define GETDNS_RRTYPE_SPF 99
#define GETDNS_RRTYPE_UINFO 100
#define GETDNS_RRTYPE_UID 101
#define GETDNS_RRTYPE_GID 102
#define GETDNS_RRTYPE_UNSPEC 103
#define GETDNS_RRTYPE_NID 104
#define GETDNS_RRTYPE_L32 105
#define GETDNS_RRTYPE_L64 106
#define GETDNS_RRTYPE_LP 107
#define GETDNS_RRTYPE_EUI48 108
#define GETDNS_RRTYPE_EUI64 109
#define GETDNS_RRTYPE_TKEY 249
#define GETDNS_RRTYPE_TSIG 250
#define GETDNS_RRTYPE_IXFR 251
#define GETDNS_RRTYPE_AXFR 252
#define GETDNS_RRTYPE_MAILB 253
#define GETDNS_RRTYPE_MAILA 254
#define GETDNS_RRTYPE_ANY 255
#define GETDNS_RRTYPE_URI 256
#define GETDNS_RRTYPE_CAA 257
#define GETDNS_RRTYPE_TA 32768
#define GETDNS_RRTYPE_DLV 32769
'''

DefinesForOpcodes= '''
#define GETDNS_OPCODE_QUERY  0
#define GETDNS_OPCODE_IQUERY 1
#define GETDNS_OPCODE_STATUS 2
#define GETDNS_OPCODE_NOTIFY 4
#define GETDNS_OPCODE_UPDATE 5
'''

DefinesForRcodes= '''
#define GETDNS_RCODE_NOERROR   0
#define GETDNS_RCODE_FORMERR   1
#define GETDNS_RCODE_SERVFAIL  2
#define GETDNS_RCODE_NXDOMAIN  3
#define GETDNS_RCODE_NOTIMP    4
#define GETDNS_RCODE_REFUSED   5
#define GETDNS_RCODE_YXDOMAIN  6
#define GETDNS_RCODE_YXRRSET   7
#define GETDNS_RCODE_NXRRSET   8
#define GETDNS_RCODE_NOTAUTH   9
#define GETDNS_RCODE_NOTZONE  10
#define GETDNS_RCODE_BADVERS  16
#define GETDNS_RCODE_BADSIG   16
#define GETDNS_RCODE_BADKEY   17
#define GETDNS_RCODE_BADTIME  18
#define GETDNS_RCODE_BADMODE  19
#define GETDNS_RCODE_BADNAME  20
#define GETDNS_RCODE_BADALG   21
#define GETDNS_RCODE_BADTRUNC 22
'''

DefinesForRRclasses= '''
#define GETDNS_RRCLASS_IN     1
#define GETDNS_RRCLASS_CH     3
#define GETDNS_RRCLASS_HS     4
#define GETDNS_RRCLASS_NONE 254
#define GETDNS_RRCLASS_ANY  255
'''

Now = strftime("%Y-%m-%d-%H-%M-%S")
APIdesc = "index.html"
APIcoreName = "getdns_core_only"
APItemplate = "APItemplate.html"
BackupDir = "NotForSVN/Backups"
VersionNumber = "0.702"
ThisTarballName = "getdns-" + VersionNumber + ".tgz"
TheExamplesToMake = [ 
	"example-all-functions",
	"example-simple-answers", 
	"example-tree", 
	"example-synchronous",
	"example-reverse",
]

# Function to replace stuff for HTML
def ReplaceForHTML(InStr):
	class MyCLexer(CLexer):
		EXTRA_TYPES = ['getdns_return_t', 'getdns_transaction_t']
		def get_tokens_unprocessed(self, text):
			for index, token, value in CLexer.get_tokens_unprocessed(self, text):
				if token is Name and value in self.EXTRA_TYPES:
					yield index, Keyword.Type, value
				else:
					yield index, token, value

	return(highlight(InStr.replace("\t", "    "), MyCLexer(), HtmlFormatter()))

## Backup the files
#FilesToBackup = ["MakeDNSAPI.py", APItemplate, APIcoreName + ".c"]
#for ThisExample in TheExamplesToMake:
#	FilesToBackup.append(ThisExample + ".c")
#for ThisFile in FilesToBackup:
#	try:
#		copy2(ThisFile, pathjoin(BackupDir, Now+ThisFile))
#	except:
#		print("Warning: Could not make a backup of '" + ThisFile + "' into the '" + BackupDir + "' directory.")

# Open the input
try:
	DescOut = open(APItemplate, mode="r").read()
except:
	exit("Could not open the template.")

# Make the examples display correctly in HTML, and reduce the tab spacing to 4
ExampleReplacements = [
	[ "EXAMPLESIMPLEANSWERS", "example-simple-answers.c" ],
	[ "EXAMPLETREE", "example-tree.c" ],
	[ "EXAMPLESYNCHRONOUS", "example-synchronous.c" ],
	[ "EXAMPLEREVERSE", "example-reverse.c" ],
]

for ThisExample in ExampleReplacements:
	try:
		ThisExampleText = open(ThisExample[1], mode="r").read()
	except:
		exit("Weird: could not read file " + ThisExample[1])
	#	ThisExampleText = "<br><pre>" + ReplaceForHTML(ThisExampleText) + "</pre>\n"
	ThisExampleText = "<br>" + ReplaceForHTML(ThisExampleText) + "\n"
	DescOut = DescOut.replace(ThisExample[0], ThisExampleText)

# Build the .h text by extracting the <div>s
ThisSoup = BeautifulSoup(DescOut)
AllForHDivs = ThisSoup.find_all("div", "forh")
FromDivs = ""
getdnsDef = ""
for ThisHDiv in AllForHDivs:
	# Don't put the getdns() or getdns_tlv or Typedefs into the main section of definitions
	if ThisHDiv.get("id") == None:
		if ThisHDiv.string.startswith("\n") == False:
			FromDivs += "\n"
		FromDivs += ThisHDiv.string
		if ThisHDiv.string.endswith("\n") == False:
			FromDivs += "\n"
		continue
	if ThisHDiv["id"].startswith("getdnsfunc"):
		getdnsDef += ThisHDiv.string
	elif ThisHDiv["id"] == "Various":
		VariousDefs = ThisHDiv.string
	elif ThisHDiv["id"] == "getdns_callback_t":
		CallbackDef = ThisHDiv.string
	elif ThisHDiv["id"] == "ParseData":
		ParseDataDef = ThisHDiv.string
	elif ThisHDiv["id"] == "datagetters":
		DataGettersDef = ThisHDiv.string
	elif ThisHDiv["id"] == "datasetters":
		DataSettersDef = ThisHDiv.string
	else:
		exit("Weird: found an id in a div that was unexpected: " + ThisHDiv["id"] + ". Exiting.")

# Define the things that go in the .h
hEnums = ""
hDefines = ""
HexPat = compile(r'MAKEVAL(\d+)#')
for ThisArr in DefinesArr:
	# The first four fields in each element are descriptive
	ThisCode = ThisArr[0]  # Number to start defines at
	DefineForCodes = ThisArr[1]  # Prefix, such as GETDNS_SOMETHING_
	ThisSectionTitle = ThisArr[2]  # Title for the definitions in the .h
	IsEnumType = ThisArr[3] is EnumType
	ThisSectionItems = ThisArr[4:]  # Array of items for this list
	ThisSectionID = ThisSectionTitle.replace(" ", "_")

	ThisDefineText = ""
	hEnums += "\n/* " + ThisSectionTitle + " */\n"
	hEnumTexts = ""
	if IsEnumType:
		EnumName = DefineForCodes.lower() + "t"
		if DefineForCodes == 'GETDNS_TRANSPORT_LIST_':
			DefineForCodes = 'GETDNS_TRANSPORT_'
		if EnumName in ( "getdns_callback_t",):
			EnumName += "ype_t"
		hEnums += "typedef enum " + EnumName + " {\n"
		enum_elements = list()
		prev = -2

	# After the first four fields, the rest are arrays of name/string pairs
	for ThisPair in ThisSectionItems:
		# See if the second field in this pair starts with "MAKEVALnnn#";
		#   if so, set it as the value and remove that string from the text
		HexObj = HexPat.match(ThisPair[1])
		if HexObj:
			TheNum = HexObj.expand(r'\1')
			ThisPair[1] = ThisPair[1].replace("MAKEVAL" + TheNum + "#", "")
		else:
			TheNum = str(ThisCode)
			ThisCode += 1
		ThisDefine = DefineForCodes + ThisPair[0]
		ThisText = ThisPair[1].replace("<code>", "").replace("</code>", "")
		ThisDefineText += "<p class=define>%s</p>\n<p class=descrip>%s</p>\n" % (ThisDefine, ThisPair[1])
		if IsEnumType:
			enum_elements.append("\t" + ThisDefine + 
			    (" = " + TheNum if int(TheNum) != prev + 1 or True else ""))
			prev = int(TheNum) 
			hEnumTexts += "#define " + ThisDefine + "_TEXT \"" + ThisText + "\"\n"
		else:
			hEnumTexts += "#define " + ThisDefine + " " + TheNum + "\n"
			hEnumTexts += "#define " + ThisDefine + "_TEXT \"" + ThisText + "\"\n"
	if IsEnumType:
		hEnums += ",\n".join(enum_elements)
		hEnums += "\n} " + EnumName + ";\n\n"
	hEnums += hEnumTexts
	DescOut = DescOut.replace("<!--TABLE_FOR_CODE_" + DefineForCodes + "-->", ThisDefineText)
# Add the RRtypes list to the defines list
hDefines += "\n/* Defines for RRtypes (from 2014-02) */" + DefinesForRRtypes
hDefines += "\n/* Defines for RRclasses (from 2014-02) */" + DefinesForRRclasses
hDefines += "\n/* Defines for Opcodes (from 2014-02) */" + DefinesForOpcodes
hDefines += "\n/* Defines for Rcodes (from 2014-02) */" + DefinesForRcodes

# Do the rest of the replacements
CommentRepacements = [
	[ "<!--VERSIONNUMBER-->", VersionNumber ],
	[ "<!--TARBALL-->", ThisTarballName ],
	[ "<!--LIST_FOR_RDATA_DICTS-->", TextForRDATADicts ],
]
for ThisReplacement in CommentRepacements:
	DescOut = DescOut.replace(ThisReplacement[0], ThisReplacement[1])

StuffForLibevent = "#include <event2/event.h>\n#include <" + APIcoreName + '''.h>

/* For libevent, which we are using for these examples */
getdns_return_t
getdns_extension_set_libevent_base(
  getdns_context     *context,
  struct event_base  *this_event_base
);
'''

try:
	libeventf = open("getdns_libevent.h", mode="w")
	libeventf.write(StuffForLibevent)
	libeventf.close()
except:
	exit("Failed to write out the libevent stuff. Exiting.")	

# Add section numbers to <h1> and <h2>
#   This does not use Beautiful Soup output because that breaks divs
HPat = compile(r'<h(\d)>(.*)</h\d>')
StartPos = 0
H1lev = 0
H2lev = 0
while True:
	ThisHeadObj = HPat.search(DescOut, pos=StartPos)
	if ThisHeadObj == None:
		break
	(ThisStart, ThisEnd) = ThisHeadObj.span()
	ThisHeadLevel = ThisHeadObj.expand(r'\1')
	if ThisHeadLevel == "1":
		H1lev += 1
		H2lev = 0
		NumberedHead = "<h" + ThisHeadLevel + ">" + str(H1lev) + ". " + ThisHeadObj.expand(r'\2') + "</h" + ThisHeadLevel + ">"
	elif ThisHeadLevel == "2":
		H2lev += 1
		NumberedHead = "<h" + ThisHeadLevel + ">" + str(H1lev) + "." + str(H2lev) + " " + ThisHeadObj.expand(r'\2') + "</h" + ThisHeadLevel + ">"
	else:
		exit("Weird: found a heading level of '" + ThisHeadLevel + "'. Exiting.")
	DescOut = DescOut[:ThisStart] + NumberedHead + DescOut[ThisEnd:]
	StartPos = ThisEnd

# Write out the HTML
try:
	outf = open(APIdesc, mode="w")
except:
	exit("Weird, could not open " + APIdesc + " for writing.")
outf.write(DescOut)
outf.close()

# Write out the .h in the proper order
HContents = "/* Created at " + Now + "*/\n" \
	+ "#ifndef GETDNS_H\n#define GETDNS_H\n\n" \
	+ "#include <stdint.h>\n#include <stdlib.h>\n#include <time.h>\n\n" \
	+ "#ifdef __cplusplus\n" \
	+ "extern \"C\" {\n" \
	+ "#endif\n\n" \
	+ "#define GETDNS_COMPILATION_COMMENT The API implementation should fill in something here, "\
	+ "such as a compilation version string and date, and change it each time the API is compiled.\n" \
	+ hEnums + "\n" \
	+ hDefines + "\n" \
	+ "/* Various typedefs  */\n" + VariousDefs + "\n" \
	+ "/* Helper functions for data structures */\n" + DataGettersDef + "\n" + DataSettersDef + "\n" \
	+ "/* Callback arguments */" + CallbackDef + "\n" \
	+ "/* Function definitions */\n" + "\n" + getdnsDef + FromDivs \
	+ "\n#ifdef __cplusplus\n" \
	+ "}\n" \
	+ "#endif\n" \
	+ "#endif /* GETDNS_H */\n"
try:
	houtf = open(APIcoreName + ".h", mode="w")
except:
	exit("Weird, could not open " + APIcoreName + ".h for writing.")
houtf.write(HContents)
houtf.close()

# Sanity check that all the GETDNS_ things in the HTML are also in the .h
GETDNS_Pat = compile(r'(GETDNS_\w*)')
AllDefinesFound = GETDNS_Pat.findall(DescOut)
DefinesToIgnore = [ "GETDNS_COMPILATION_COMMENT" ]  # Use this if you later have defines that need to be ignored
for ThisDefine in sorted(AllDefinesFound):
	if ThisDefine not in hDefines and ThisDefine not in hEnums:
		if (ThisDefine in DefinesToIgnore) == False:
			print("Found " + ThisDefine + " in HTML, but not in .h")

BuildStyle = {}
BuildStyle["mac"] = { "sharing-style": "-dynamiclib", "sharing-extension": "dylib" }
BuildStyle["linux"] = { "sharing-style": "-shared", "sharing-extension": "so" }

for ThisStyle in BuildStyle.keys():
	# Make everything
	Sharing = BuildStyle[ThisStyle]["sharing-style"]
	Extension = BuildStyle[ThisStyle]["sharing-extension"]
	MakeFileName = "make-examples-" + ThisStyle + ".sh"
	MakeCleanAll = "rm -rf *.o *.dylib\n"
	MakeC = "%(compiler)s -std=c%(stdyr)s -c -fPIC -pedantic -g -I./ -Werror -Wall -Wextra -c %(inname)s.c\n"
	MakeGetdns = "%(compiler)s -std=c%(stdyr)s " + Sharing + " -fPIC -levent_core -o libgetdns." + Extension + " " + APIcoreName + ".o\n"
	MakeExampleExe = "%(compiler)s -std=c%(stdyr)s -fPIC -L./ %(inname)s.o -levent_core -lgetdns -lgetdns_ext_event -lssl -lcrypto -o %(inname)s \n"

	makef = open(MakeFileName, mode="w")
	for ThisCompiler in ("gcc", "clang"):
		makef.write(MakeCleanAll)
		makef.write(MakeC % {"compiler": ThisCompiler, "inname": APIcoreName, "stdyr": "89"})
		makef.write(MakeGetdns % {"compiler": ThisCompiler, "stdyr": "89"})
		for ThisName in TheExamplesToMake:
			if (ThisName == "example-all-functions"):
				ThisYear = "89"
			else:
				ThisYear = "99"
			makef.write(MakeC % {"compiler": ThisCompiler, "inname": ThisName, "stdyr": ThisYear})
			makef.write(MakeExampleExe % {"compiler": ThisCompiler, "inname": ThisName, "stdyr": ThisYear})
	makef.close()
	call("chmod 0744 " + MakeFileName, shell=True)

# Make the tarball
print("Making tarball")
ThisVersionName = "getdns-" + VersionNumber
# Delete the current tar directory if it exists
call("rm -rf " + ThisVersionName, shell=True)
try:
	mkdir(ThisVersionName)
except:
	exit("Could not create directory " + ThisVersionName + ". Exiting.")
ToTar = []
ToTar.extend(glob("index.html"))
ToTar.extend(glob("*.c"))
ToTar.extend(glob("*.h"))
ToTar.extend(glob("*.sh"))
for ThisFile in ToTar:
	try:
		link(ThisFile, pathjoin(ThisVersionName, ThisFile))
	except:
		exit("Failed to link " + ThisFile + " in new directory. Exiting.")
call("tar -czf getdns-" + VersionNumber + ".tgz " + ThisVersionName, shell=True)
# Delete the current tar directory if it exists
call("rm -rf " + ThisVersionName, shell=True)

if system() == 'Linux':
	# Run the Linux version
	print("Running Linux making")
	MakingLines = open("make-examples-linux.sh", mode="r").readlines()
else:
	# Run the Mac version
	print("Running Mac making")
	MakingLines = open("make-examples-mac.sh", mode="r").readlines()

for ThisLine in MakingLines:
	print(ThisLine, end="")
	call(ThisLine, shell=True)
