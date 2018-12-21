/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  externally blocked detection routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

// Define maximum number of IPs we accept for each individual IP type
#define maxIPs 12
char** blocked_IP_v4 = NULL;
char** blocked_IP_v6 = NULL;

void init_blocked_IP()
{
	// Initialize memory
	blocked_IP_v4 = calloc(maxIPs, sizeof(char*));
	blocked_IP_v6 = calloc(maxIPs, sizeof(char*));

	// If upstream replied with 0.0.0.0 or ::,
	// we assume that it filtered the reply as
	// nothing is reachable under these addresses
	add_blocked_IP("0.0.0.0", 4);
	add_blocked_IP("::", 6);

	// OpenDNS (Cisco Umbrella):
	// See https://support.opendns.com/hc/en-us/articles/227986927-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses- for a full list of these IP addresses
	// Domain List Block Page
	add_blocked_IP("146.112.61.104", 4);
	add_blocked_IP("::ffff:146.112.61.104", 6);
	// Command and Control Callback Block Page
	add_blocked_IP("146.112.61.105", 4);
	add_blocked_IP("::ffff:146.112.61.105", 6);
	// Content Category Block Page
	add_blocked_IP("146.112.61.106", 4);
	add_blocked_IP("::ffff:146.112.61.106", 6);
	// Malware Block Page
	add_blocked_IP("146.112.61.107", 4);
	add_blocked_IP("::ffff:146.112.61.107", 6);
	// Phishing Block Page
	add_blocked_IP("146.112.61.108", 4);
	add_blocked_IP("::ffff:146.112.61.108", 6);
	// Suspicious Response Block Page
	add_blocked_IP("146.112.61.109", 4);
	add_blocked_IP("::ffff:146.112.61.109", 6);
	// Security Integrations Block Page
	add_blocked_IP("146.112.61.110", 4);
	add_blocked_IP("::ffff:146.112.61.110", 6);
}

bool add_blocked_IP(const char* addr, unsigned char type)
{
	char** list = NULL;
	switch(type)
	{
		case 4: // IPv4 address
			list = blocked_IP_v4;
			struct in_addr addr4;
			if(inet_pton(AF_INET, addr, &addr4) != 1)
			{
				logg("Provided IP %s is not a valid IPv4 address", addr);
				return false;
			}
			break;
		case 6: // IPv6 address
			list = blocked_IP_v6;
			struct in6_addr addr6;
			if(inet_pton(AF_INET6, addr, &addr6) != 1)
			{
				logg("Provided IP %s is not a valid IPv6 address", addr);
				return false;
			}
			break;
		default:
			logg("Provided invalid IP type to add_blocked_IP()");
			return false;
	}
	// Loop over all IPs in the list to find the last one
	for(int i=0; i < maxIPs; i++)
	{
		// Stop if reached end of list
		if(list[i] == NULL)
		{
			list[i] = strdup(addr);
			return (list[i] != NULL);
		}
	}
	// If reached this point, then the list is already full
	return false;
}

// Compare IP to list of known blocking IPs
bool is_blocked_IP(const char* addr, unsigned char type)
{
	// Verify validity of input
	if(addr == NULL)
		return false;

	char** list = NULL;
	switch(type)
	{
		case 4: // IPv4 address
			list = blocked_IP_v4;
			break;
		case 6: // IPv6 address
			list = blocked_IP_v6;
		default:
			logg("Provided invalid IP type (%u) to is_blocked_IP()", type);
			return false;
	}
	// Loop over all IPs in the list
	for(int i=0; i < maxIPs; i++)
	{
		// Stop if reached end of list
		if(list[i] == NULL)
			break;

		// Compare addr against list entry
		if(strcmp(addr, list[i]) == 0)
			return true;
	}
	// Not found:
	return false;
}
