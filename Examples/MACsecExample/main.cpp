#if !defined(WIN32) && !defined(WINx64)
#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "MACsecLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PayloadLayer.h"
#include "PcapFileDevice.h"

#include <string>

int MACsecEdit(void);
void MACsecCreate(uint8_t *randomData, size_t dataLen);

uint8_t createTCI_AN(uint8_t tci, uint8_t an);
void createICV(uint8_t *ICV);

int main(int argc, char* argv[])
{
	size_t payloadLen = 100;
	uint8_t *payloadData = new uint8_t[payloadLen];
	
	MACsecCreate(payloadData, payloadLen);
	MACsecEdit();
	return 0;
}

int MACsecEdit(void) 
{

	// Packet Editing
	// ~~~~~~~~~~~~~~

	// use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
	// and create an interface instance that both readers implement
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("1_created_macsec_frame.pcap");

	// verify that a reader interface was indeed created
	if (reader == NULL)
	{
		printf("Cannot determine reader for file type\n");
		exit(1);
	}

	// open the reader for reading
	if (!reader->open())
	{
		printf("Cannot open input.pcap for reading\n");
		exit(1);
	}

	// read the first (and only) packet from the file
	pcpp::RawPacket rawPacket;
	if (!reader->getNextPacket(rawPacket))
	{
		printf("Couldn't read the first packet in the file\n");
		return 1;
	}

	// close the file reader, we don't need it anymore
	reader->close();

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);

	// now let's get the Ethernet layer
	pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	// change the source dest MAC address
	ethernetLayer->setDestMac(pcpp::MacAddress("aa:bb:cc:dd:ee:ff"));

	pcpp::MACsecLayer* macsecLayer = parsedPacket.getLayerOfType<pcpp::MACsecLayer>();
	if(macsecLayer == NULL) {
		std::cout << "nullptr to MACsec Layer" << std::endl;
	}
	macsecLayer->setPN(100);	

	// compute all calculated fields
	parsedPacket.computeCalculateFields();

	// write the modified packet to a pcap file
	pcpp::PcapFileWriterDevice writer("1_macsec_modified_frame.pcap");
	writer.open();
	writer.writePacket(*(parsedPacket.getRawPacket()));
	writer.close();

	return 0;

}

void MACsecCreate(uint8_t *randomData, size_t dataLen)
{

	// Packet Creation
	// ~~~~~~~~~~~~~~~
	std::cout << "Creating a MACsec Frame." << std::endl;

	// create a new Ethernet layer
	pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:50:43:11:22:33"), pcpp::MacAddress("aa:bb:cc:dd:ee"));

	uint8_t SCI[8] = { 0x00, 0x50, 0x43, 0x11, 0x22, 0x33, 0x00, 0x00 };

	// create a new MACsec layer
	pcpp::MACsecLayer newMACsecLayer(createTCI_AN(0x0b, 0x00), 0, 10, &SCI[0]);

	// create a new Payload layer, add the ICV to it.
	createICV(randomData+dataLen-16);
	pcpp::PayloadLayer newPayloadLayer(randomData, dataLen, true);

	// create a packet with initial capacity of 100 bytes (will grow automatically if needed)
	pcpp::Packet newPacket(100);

	// add all the layers we created
	newPacket.addLayer(&newEthernetLayer);
	newPacket.addLayer(&newMACsecLayer);
	newPacket.addLayer(&newPayloadLayer);

	// compute all calculated fields
	newPacket.computeCalculateFields();

	// write the new packet to a pcap file
	pcpp::PcapFileWriterDevice writer("1_created_macsec_frame.pcap");
	writer.open();
	writer.writePacket(*(newPacket.getRawPacket()));
	writer.close();

	std::cout << "Done creating MACsec Frame -> written to 1_created_macsec_frame.pcap" << std::endl;

}

uint8_t createTCI_AN(uint8_t tci, uint8_t an) {
	tci <<= 2;
	an &= 0x03;
	tci |= an;
	return (tci);
}

void createICV(uint8_t *ICV) {
	for(uint8_t i = 0; i < 16; i++) {
		*(ICV+i) = i+1;
	}
}

