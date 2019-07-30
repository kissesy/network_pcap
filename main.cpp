#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

typedef struct _Ethernet{
	u_char dest_mac[6];
	u_char src_mac[6];
	u_short type;
}Ethernet;

typedef struct _IPv4{
	u_char Version_HeaderLength; //4bit & 4bit need for bit mask
	u_char TypeOfService;
	u_short TotalPacketLength;
	u_short Fragment_Identifier;
	u_short FragmentationFlag_Offset; // umm... 4bit + 12bit? bit mask
	u_char TTL;
	u_char Protocol;
	u_short Header_Checksum;
	u_char Source_IP_Address[4];
	u_char Destion_IP_Address[4];
}IPv4;

typedef struct _TCP_Header{
	u_short SourcePort;
	u_short DestinationPort;
	u_char Sequence_Number[4];
	u_char Acknowledgement[4];
	u_short Header_Reserved_Flag;
	u_short Windows_size;
	u_short CheckSum;
	u_short UrgentPointer;
	u_char Option[12];
}TCP_Header;

typedef struct _ARP_Header{
	/**/
}ARP_Header;

/*print dest mac & src mac & Type*/
int CheckMacAddress(Ethernet* ethernet);
int Hander_Manager(const u_char* packet);
int IPv4_Parse(const u_char* packet);
int TCP_Parse(const u_char* packet);
int TCP_Data_Parse(int tcp_data_offset, const u_char* packet);
int CheckMacAddress(Ethernet* ethernet)
{
	printf("Source Mac : %x:%x:%x:%x:%x:%x\n", ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);
	printf("Dest Mac : %x:%x:%x:%x:%x:%x\n",ethernet->dest_mac[0],ethernet->dest_mac[1],ethernet->dest_mac[2],ethernet->dest_mac[3],ethernet->dest_mac[4],ethernet->dest_mac[5]);
	return htons(ethernet->type);
}

int IPv4_Parse(const u_char* packet)
{
	IPv4* ipv4 = (IPv4*)(packet + sizeof(Ethernet));
	printf("Source IP : %d.%d.%d.%d\n", ipv4->Source_IP_Address[0],ipv4->Source_IP_Address[1],ipv4->Source_IP_Address[2],ipv4->Source_IP_Address[3]);
	printf("Dest IP : %d.%d.%d.%d\n", ipv4->Destion_IP_Address[0],ipv4->Destion_IP_Address[1],ipv4->Destion_IP_Address[2],ipv4->Destion_IP_Address[3]);
	return ipv4->Protocol;
}

int TCP_Parse(const u_char* packet)
{
	TCP_Header* tcp_header = (TCP_Header*)(packet + sizeof(Ethernet) + sizeof(IPv4));
	printf("Source Port : %d\n", htons(tcp_header->SourcePort));
	printf("Dest Port : %d\n", htons(tcp_header->DestinationPort));
}
int TCP_Data_Parse(int tcp_data_offset, const u_char* packet)
{
	printf("TCP Data : ");
	for(int i=0;i<10;i++)
	{
		printf("%x ", packet[tcp_data_offset+i]);
	}
	printf("\n");
}
int Handler_Manager(const u_char* packet)
{
	int tcp_data_offset=0;
	Ethernet* ethernet = (Ethernet*)packet;
	int Ethernet_Protocol_Type = CheckMacAddress(ethernet);
	switch (Ethernet_Protocol_Type) {
		case 0x800: /*IPv4*/
			if(IPv4_Parse(packet) == 0x06){
				TCP_Parse(packet);
				TCP_Data_Parse(sizeof(Ethernet) + sizeof(IPv4) + sizeof(TCP_Header), packet);
			}
			else{
				printf("Ahh.... UDP\n");
			}
			break;
		case 0x86DD: /*IPv6*/
			printf("IPv6 setting...\n");
			break;
		case 0x806:  /*IPv6*/
			printf("ARP setting...\n");
		default:
			printf("setting....\n");
			break;

	}
}


void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("\n\n%u bytes captured\n\n", header->caplen);
		Handler_Manager(packet);
	}
	pcap_close(handle);
	return 0;
}
