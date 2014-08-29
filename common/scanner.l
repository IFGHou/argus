%{
/* Argus Software
 * Copyright (c) 2000-2012 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: //depot/argus/argus/common/scanner.l#28 $
 * $DateTime: 2012/03/15 01:01:31 $
 * $Change: 2333 $
 */

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994
 *   The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if defined(HAVE_FEATURES_H)
#define _GNU_SOURCE
#undef _FEATURES_H
#include <features.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#include <ctype.h>
#include <string.h>

#include <argus_compat.h>

#include <sys/time.h>
#include <netinet/in.h>

#include <argus_namedb.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>
#include <argus_filter.h>

#include <tokdefs.h>
#include <syslog.h>

extern void ArgusLog (int, char *, ...);

#ifndef __GNUC__
#define inline
#endif

int argus_lex(void);
int stoi(char *);
static inline int xdtoi(int);

#ifdef FLEX_SCANNER
int argus_get_lineno (void);
FILE *argus_get_in (void);
FILE *argus_get_out (void);

static YY_BUFFER_STATE in_buffer;
#else
static char *in_buffer;
 
#undef getc
#define getc(fp)  (*in_buffer == 0 ? EOF : *in_buffer++)
#endif
 
#define yylval argus_lval
extern YYSTYPE yylval;
%}

%option noinput
%option nounput

N        ([0-9]+|(0X|0x)[0-9A-Fa-f]+)
B        ([0-9A-Fa-f][0-9A-Fa-f]?)
ISD      [0-9A-Fa-f]{4}
V6       ((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|(([0-9A-Fa-f]{1,4}:){0,5}:((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|(::([0-9A-Fa-f]{1,4}:){0,5}((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:))
                         
%%
start    return START;
init     return START;
stop     return STOP;
status   return STATUS;
shut     return SHUTDOWN;
error    return ERROR;

man      return MAN;
far      return FAR;
event    return EVENT;
index    return INDEX;

dst      return DST;
src      return SRC;

seq      return SEQ;

auth     return AUTH;
recurs   return RECURS;
req      return REQ;
rsp      return RSP;

link|ppp|slip  return LINK;
fddi     return LINK;
ether    return LINK;
arp      return ARP;
rarp     return RARP;
ip       return IP;
ipv4     return IPV4;
ipv6     return IPV6;
tcp      return TCP;
udp      return UDP;
udt      return UDT;
rtp      return RTP;
rtcp     return RTCP;
icmp     return ICMP;
igmp     return IGMP;
mpls     return MPLS;
vlan     return VLAN;
vid      return VID;
vpri     return VPRI;
mid      return MPLSID;
ipid     return IPID;
anon     return ANON;
isis     return ISIS;
psnp     return PSNP;
csnp     return CSNP;
lsp      return LSP;
hello    return HELLO;
svc      return SVC;
spi      return SPI;

host     return HOST;
srcid    return SRCID;
inode    return INODE;
net      return NET;
mask     return AMASK;
port     return PORT;
proto    return PROTO;
encaps   return ENCAPS;

ttl      return TTL;
tos      return TOS;
dsb      return DSB;
dsbyte   return DSB;

co       return CO;
cocode   return COCODE;

as       return ASN;
asn      return ASN;

trans    return TRANS;
pkt      return PKT;
pkts     return PKT;
byte     return BYTE;
bytes    return BYTE;
data     return APPBYTE;
appbyte  return APPBYTE;
appbytes return APPBYTE;

nstroke  return NSTROKE;
nstrokes return NSTROKE;

tcpb     return TCPBASE;
base     return TCPBASE;
tcprtt   return TCPRTT;

rate     return RATE;
load     return LOAD;
inter    return INTER;
jitter   return JITTER;
dur      return DUR;
avgdur   return AVGDUR;
deldur   return DELTADUR;
delstime return DELTALAST;
delltime return DELTALAST;
loss     return LOSS;
ploss    return PLOSS;

gateway  return GATEWAY;

eq       return EQUAL;
equal    return EQUAL;
lt       return LESS;
lte      return LEQ;
less     return LESS;
gt       return GREATER;
gte      return GEQ;
greater  return GREATER;

broadcast return TK_BROADCAST;
multicast return TK_MULTICAST;

and|"&&"  return AND;
or|"||"   return OR;
not       return '!';

len|length   return LEN;
inbound      return INBOUND;
outbound     return OUTBOUND;

syn          return SYN;
synack       return SYNACK;
fin          return FIN;
finack       return FINACK;
rst          return RESET;
ack          return ACK;
urg          return URGENT;
ece          return ECE;
cwr          return CWR;
push         return PUSH;
reset        return RESET;

rtr          return RTR;
mbr          return MBR;
lvg          return LVG;

normal       return NORMAL;
wait         return WAIT;
timeout      return TIMEDOUT;
est          return ESTABLISHED;
con          return CONNECTED;
avail        return CONNECTED;
cor          return CORRELATED;
corolated    return CORRELATED;

ecn          return ECN;
drop         return RETRANS;
retrans      return RETRANS;
outoforder   return OUTOFORDER;
ooo          return OUTOFORDER;
multipath    return MULTIPATH;
mpath        return MULTIPATH;
winshut      return WINSHUT;
frag         return FRAG;
fragonly     return FRAG_ONLY;

icmpmap      return ICMPMAP;
echo         return ICMPECHO;
unreach      return UNREACH;
redirect     return REDIRECT;
timexed      return TIMEXED;

[ \n\t]         ;
[+\-*/:\[\]!<>()&|=]   return yytext[0];
">="         return GEQ;
"<="         return LEQ;
"!="         return NEQ;
"=="         return '=';
"<<"         return LSH;
">>"         return RSH;
{N}         { yylval.i  = stoi((char *)yytext); return NUM; }
(\.{N})      { yylval.f  = strtof((char *)yytext, NULL); return FLOAT; }
({N}\.{N})  { yylval.f  = strtof((char *)yytext, NULL); return FLOAT; }
({N}\.{N}\.{N}\.{N})   { yylval.s = Argussdup((char *)yytext); return HIDV4; }
{B}:{B}:{B}:{B}:{B}:{B} { yylval.e = argus_ether_aton((char *)yytext); return EID; }
{V6}	{ yylval.s = Argussdup((char *)yytext); return HIDV6; }

\"[^\*\n]*\"  { yylval.s = Argussdup((char *)yytext); return STRING; }

[A-Za-z0-9][-_.A-Za-z0-9]*[.A-Za-z0-9] { yylval.s = Argussdup((char *)yytext); return ID; }
"\\"[^ !()\n\t]+   { yylval.s = Argussdup((char *)yytext + 1); return ID; }
[^ \[\]\t\n\-_.A-Za-z0-9!<>()&|=]+i { ArgusLog(LOG_ERR, "illegal token: %s\n", yytext); }
.         { ArgusLog (LOG_ERR, "illegal char '%c'", *yytext); }

%%
void
argus_lex_init(char *buf)
{
#ifdef FLEX_SCANNER
   in_buffer = yy_scan_string(buf);
#else 
   in_buffer = buf;
#endif 
}

/*
 * Also define a yywrap.  Note that if we're using flex, it will
 * define a macro to map this identifier to pcap_wrap.
 */
int
yywrap()
{
   return 1;
}

/* Hex digit to integer. */
static inline int
xdtoi(c)
int c;
{
   if (isdigit(c))
      return c - '0';
   else if (islower(c))
      return c - 'a' + 10;
   else
      return c - 'A' + 10;
}

/*
 * Convert string to integer.  Just like atoi(), but checks for
 * preceding 0x or 0 and uses hex or octal instead of decimal.
 */
int
stoi(s)
char *s;
{
   int base = 10;
   int n = 0;

   if (*s == '0') {
      if (s[1] == 'x' || s[1] == 'X') {
         s += 2;
         base = 16;
      }
      else {
         base = 8;
         s += 1;
      }
   }
   while (*s)
      n = n * base + xdtoi(*s++);

   return n;
}

