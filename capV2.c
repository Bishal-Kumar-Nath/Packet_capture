/* lets catch some packets */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>
#include <math.h>
static clock_t start_t;

int loop=1;
int cou=0;
FILE *logfile;
void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 	
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            //printf(" %02X",(unsigned int)data[i]);
              printf(" %d",(unsigned int)data[i]);   
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   "); //extra spaces
            }
             
            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  printf("%c",(unsigned char)data[j]);
                }
                else
                {
                  printf(".");
                }
            }
             
            printf("\n" );
        }
    }
	printf("\n\n\t***soure ip == ");
	for(i=12;i<16;i++)
	{
	printf("%d",(unsigned int)data[i]);
	if(i!=15)
		printf(".");
	}
	printf("\n\n\t***Destination ip == ");
	for(i=16;i<20;i++)
	{
		printf("%d",(unsigned int)data[i]);
		if(i!=19)
			printf(".");
	}

	printf("\n");
	return;

}


void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
		packet)
{

	//static clock_t start_t;
	clock_t end_t;
	double total_t,diff;
	static    int i;
	static unsigned int lg,k;
	int size = pkthdr->len;
	int sum1=0;
	double add;
	static int count = 1;
	struct ethhdr *eth = (struct ethhdr *)packet;
	char fname[20];
	cou++;
	i++;
	printf("\n i= %d\n",i);
	if(count==1)
	{
		start_t =clock();
		sprintf(fname,"log%d.txt",lg);
		logfile=fopen(fname,"a+");
		lg++;
	}
	fprintf(logfile,"\n%d) ",count);
	fprintf(logfile,"\tsoure ip == ");
	for(k=12;k<16;k++)
	{
	fprintf(logfile,"%d",(unsigned int)packet[k]);
	if(k!=15)
		fprintf(logfile,".");
	sum1=sum1*10+(unsigned int)packet[k];
	}
	add=(log10f(sum1)*1000);//tokenized
	fprintf(logfile,"\tunique id == %lf ",add);

	fprintf(logfile,"\tDestination ip == ");
	for(k=16;k<20;k++)
	{	
		fprintf(logfile,"%d",(unsigned int)packet[k]);
		if(k!=19)
			fprintf(logfile,".");

	}

	//   start_t = clock();
	printf("Starting of the program, start_t = %ld\n", start_t);

	end_t = clock();
	printf("End of the big loop, end_t = %ld\n", end_t);

	total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
	printf("Total time taken by CPU: %f\n", total_t  );
	//total_t= difftime(end_t,start_t);
	// printf("Total time taken by CPU: %f\n", total_t  );

	//diff=end_t-start_t;
	//printf("\n\n diff == %ld \n",diff);

	if(total_t>=1)
	{
		printf("\nstops here\n");
		start_t=end_t;
		fclose(logfile);
		sprintf(fname,"log%d.txt",lg);
		logfile=fopen(fname,"a+");
		lg++;
		//fprintf(logfile,"there= %d\n",count);

		//exit(0);
	}


	printf("callback\n");
	printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );


	PrintData(packet , size);


	printf("\nPacket number [%d], length of this packet is: %d\n\n", count++, pkthdr->len);


}

int main(int argc,char *argv[])
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp;        
	bpf_u_int32 pMask;            
	bpf_u_int32 pNet;             
	pcap_if_t *alldevs, *d;
	char dev_buff[64] = {0};
	int i =0;
	struct pcap_pkthdr header;
	const u_char *packet;


	printf("argc is %d",argc);
	

	// list of all the devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	printf("\nHere is a list of available devices on your system:\n\n");
	for(d=alldevs; d; d=d->next)		//	****** may be the alldevice is a node or pointer *****	
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (Sorry, No description available for this device)\n");
	}
	printf("\nEnter the interface name on which you want to run the packet sniffer : ");//This is the maximum number of characters to be read 
	fgets(dev_buff, sizeof(dev_buff)-1, stdin);		// ******* here might be a problem ******

	// clear off the trailing newline that fgets sets
	dev_buff[strlen(dev_buff)-1] = '\0';		// ***** or the problem is here *****
	
	if(strlen(dev_buff))
	{
		dev = dev_buff;
		printf("\n ---You opted for device [%s] to capture [%d] packets---\n\n Starting capture...",dev, (atoi)(argv[2]));
	}     

	if(dev == NULL)
	{
		printf("\n[%s]\n", errbuf);
		return -1;
	}

	pcap_lookupnet(dev, &pNet, &pMask, errbuf);
	//printf("mask = %s \n",pMask);
	descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		return -1;
	}
	if(pcap_compile(descr, &fp, argv[1], 0, pNet) == -1)
	{
		printf("\npcap_compile() failed\n");
		return -1;
	}
	if(pcap_setfilter(descr, &fp) == -1)
	{
		printf("\npcap_setfilter() failed\n");
		exit(1);
	}

	// call the callback function. max limit on number of packets is specified by user.

	logfile=fopen("log.txt","w");
	if(logfile==NULL) 
	{
		printf("Unable to create file.");
	}
	pcap_loop(descr,atoi(argv[2]), callback, NULL);
	printf("the arg 0 is %s",argv[0]);
	//	packet = pcap_next(descr, &header);
	//	printf("Jacked a packet with length of [%d]\n", header.len);
	printf("\nDone with packet sniffing!\n");



	return 0;
}
