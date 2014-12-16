/*
 * snif.c
 *
 *  Created on: Dec 16, 2014
 *      Author: ivan
 */


#include <iostream>
#include <iomanip>

#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include <netinet/in.h>
extern "C" {
  #include <linux/netfilter.h>  /* Defines verdicts (NF_ACCEPT, etc) */
  #include <libnetfilter_queue/libnetfilter_queue.h>
}

using namespace std;

//----------------------------------------------------------------------
//------------------------------------------------------

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 32) {
		gap = 32 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}


void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 32;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}



static int Callback(nfq_q_handle *myQueue, struct nfgenmsg *msg,
                    nfq_data *pkt, void *cbData) {
  uint32_t id = 0;
  nfqnl_msg_packet_hdr *header;

  cout << "pkt recvd: ";
  if ((header = nfq_get_msg_packet_hdr(pkt))) {
    id = ntohl(header->packet_id);
    cout << "id " << id << "; hw_protocol " << setfill('0') << setw(4) <<
      hex << ntohs(header->hw_protocol) << "; hook " << ('0'+header->hook)
         << " ; ";
  }

  // The HW address is only fetchable at certain hook points
  nfqnl_msg_packet_hw *macAddr = nfq_get_packet_hw(pkt);
  if (macAddr) {
    cout << "mac len " << ntohs(macAddr->hw_addrlen) << " addr ";
    for (int i = 0; i < 8; i++) {
    	printf("%02x :", macAddr->hw_addr[i]);macAddr->hw_addr;
    }
    // end if macAddr
  } else {
    cout << "no MAC addr";
  }

  timeval tv;
  if (!nfq_get_timestamp(pkt, &tv)) {
    cout << "; tstamp " << tv.tv_sec << "." << tv.tv_usec;
  } else {
    cout << "; no tstamp";
  }

  cout << "; mark " << nfq_get_nfmark(pkt);

  // Note that you can also get the physical devices
  cout << "; indev " << nfq_get_indev(pkt);
  cout << "; outdev " << nfq_get_outdev(pkt);

  cout << endl;

  // Print the payload; in copy meta mode, only headers will be included;
  // in copy packet mode, whole packet will be returned.
  char *pktData;
  int len = nfq_get_payload(pkt, &pktData);
  cout<<"Payload ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;
  printf("%d\n",len);
  cout<<"Payload ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"<<endl;

  print_payload((u_char *)pktData,len);
    // end data found

  // For this program we'll always accept the packet...
  return nfq_set_verdict(myQueue, id, NF_ACCEPT, 0, NULL);

  // end Callback
}

//----------------------------------------------------------------------
//------------------------------------------------------
int main(int argc, char **argv) {
  struct nfq_handle *nfqHandle;

  struct nfq_q_handle *myQueue;
  struct nfnl_handle *netlinkHandle;

  int fd, res;
  char buf[4096];

  // Get a queue connection handle from the module
  if (!(nfqHandle = nfq_open())) {
    cerr << "Error in nfq_open()" << endl;
    exit(-1);
  }

  // Unbind the handler from processing any IP packets
  // Not totally sure why this is done, or if it's necessary...
  if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
    cerr << "Error in nfq_unbind_pf()" << endl;
    exit(1);
  }

  // Bind this handler to process IP packets...
  if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
    cerr << "Error in nfq_bind_pf()" << endl;
    exit(1);
  }

  // Install a callback on queue 0
  if (!(myQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
    cerr << "Error in nfq_create_queue()" << endl;
    exit(1);
  }

  // Turn on packet copy mode
  if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
    cerr << "Could not set packet copy mode" << endl;
    exit(1);
  }

  netlinkHandle = nfq_nfnlh(nfqHandle);
  fd = nfnl_fd(netlinkHandle);

  while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
    // I am not totally sure why a callback mechanism is used
    // rather than just handling it directly here, but that
    // seems to be the convention...
    nfq_handle_packet(nfqHandle, buf, res);
    // end while receiving traffic
  }

  nfq_destroy_queue(myQueue);

  nfq_close(nfqHandle);

  return 0;

  // end main
}



