#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "EthLayer.h"
#include "MACsecLayer.h"
#include "PayloadLayer.h"
#include "Packet.h"
#include "SystemUtils.h"

PTF_TEST_CASE(MACsecFrameCreation)
{
	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_MACSEC);

	uint8_t tci = 0x0d;
	uint8_t an = 0x00;
	uint8_t tci_an = (tci << 2) | an;
	uint8_t sl = 0x55;
	uint32_t pn = 0xdeadbeef;
	uint8_t SCI[8] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00 };	
	pcpp::MACsecLayer macsecLayer(tci_an, sl, pn, &SCI[0]);

	// ICV must be added to payload and is then appended as trailer
	uint8_t payload[] = { 0xc0, 0xca, 0xc0, 0x1a, 		// payload data
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,	// ICV
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
	 };

	pcpp::PayloadLayer payloadLayer(payload, 20, true);

	pcpp::Packet MACsecFrame(1);
	PTF_ASSERT_TRUE(MACsecFrame.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(MACsecFrame.addLayer(&macsecLayer));
	PTF_ASSERT_TRUE(MACsecFrame.addLayer(&payloadLayer));

	PTF_ASSERT_TRUE(MACsecFrame.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(MACsecFrame.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(MACsecFrame.getLayerOfType<pcpp::EthLayer>() == &ethLayer);
	PTF_ASSERT_EQUAL(MACsecFrame.getLayerOfType<pcpp::EthLayer>()->getDestMac(), dstMac, object);
	PTF_ASSERT_EQUAL(MACsecFrame.getLayerOfType<pcpp::EthLayer>()->getSourceMac(), srcMac, object);
	PTF_ASSERT_EQUAL(MACsecFrame.getLayerOfType<pcpp::EthLayer>()->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_MACSEC), u16);

	PTF_ASSERT_NOT_NULL(MACsecFrame.getLayerOfType<pcpp::MACsecLayer>());
	PTF_ASSERT_TRUE(MACsecFrame.getLayerOfType<pcpp::MACsecLayer>() == &macsecLayer);
	PTF_ASSERT_EQUAL(MACsecFrame.getLayerOfType<pcpp::MACsecLayer>()->getMACsecTCI(), tci, object);
	PTF_ASSERT_EQUAL(MACsecFrame.getLayerOfType<pcpp::MACsecLayer>()->getMACsecAN(), an, object);
	PTF_ASSERT_EQUAL(MACsecFrame.getLayerOfType<pcpp::MACsecLayer>()->getMACsecSL(), sl, object);
	PTF_ASSERT_EQUAL(MACsecFrame.getLayerOfType<pcpp::MACsecLayer>()->getMACsecPN(), pn, object);
	PTF_ASSERT_BUF_COMPARE(MACsecFrame.getLayerOfType<pcpp::MACsecLayer>()->getMACsecSCI(), SCI, 8);

	pcpp::RawPacket* rawFrame = MACsecFrame.getRawPacket();
	PTF_ASSERT_NOT_NULL(rawFrame);
	PTF_ASSERT_EQUAL(rawFrame->getRawDataLen(), 48, int);

	uint8_t expectedBuffer[48] = {
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 			// dstMAC
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,				// srcMAC
		0x88, 0xE5, 									// EtherType
		0x34, 0x55, 0xde, 0xad, 0xbe, 0xef, 			// TCI, SL, PN,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0x00, 0x00, // SCI
		0xc0, 0xca, 0xc0, 0x1a, 						// payload data
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,	// ICV
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb
	 };

	PTF_ASSERT_BUF_COMPARE(rawFrame->getRawData(), expectedBuffer, 48);	

} // MACsecFrameCreation

PTF_TEST_CASE(MACsecFramePointerCreation) {

	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer* ethLayer = new pcpp::EthLayer(srcMac, dstMac, PCPP_ETHERTYPE_MACSEC);

	uint8_t tci = 0x0d;
	uint8_t an = 0x00;
	uint8_t tci_an = (tci << 2) | an;
	uint8_t sl = 0x55;
	uint32_t pn = 0xdeadbeef;
	uint8_t SCI[8] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00 };	
	pcpp::MACsecLayer* macsecLayer = new pcpp::MACsecLayer(tci_an, sl, pn, &SCI[0]);

	// ICV must be added to payload and is then appended as trailer
	uint8_t payload[] = { 0xc0, 0xca, 0xc0, 0x1a, 		// payload data
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,	// ICV
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
	 };
	pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, 20, true);

	pcpp::Packet *MACsecFrame = new pcpp::Packet(1);
	PTF_ASSERT_TRUE(MACsecFrame->addLayer(ethLayer, true));
	PTF_ASSERT_TRUE(MACsecFrame->addLayer(macsecLayer, true));
	PTF_ASSERT_TRUE(MACsecFrame->addLayer(payloadLayer, true));

	PTF_ASSERT_TRUE(MACsecFrame->isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(MACsecFrame->getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(MACsecFrame->getLayerOfType<pcpp::EthLayer>() == ethLayer);
	PTF_ASSERT_EQUAL(MACsecFrame->getLayerOfType<pcpp::EthLayer>()->getDestMac(), dstMac, object);
	PTF_ASSERT_EQUAL(MACsecFrame->getLayerOfType<pcpp::EthLayer>()->getSourceMac(), srcMac, object);
	PTF_ASSERT_EQUAL(MACsecFrame->getLayerOfType<pcpp::EthLayer>()->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_MACSEC), u16);

	PTF_ASSERT_NOT_NULL(MACsecFrame->getLayerOfType<pcpp::MACsecLayer>());
	PTF_ASSERT_TRUE(MACsecFrame->getLayerOfType<pcpp::MACsecLayer>() == macsecLayer);
	PTF_ASSERT_EQUAL(MACsecFrame->getLayerOfType<pcpp::MACsecLayer>()->getMACsecTCI(), tci, object);
	PTF_ASSERT_EQUAL(MACsecFrame->getLayerOfType<pcpp::MACsecLayer>()->getMACsecAN(), an, object);
	PTF_ASSERT_EQUAL(MACsecFrame->getLayerOfType<pcpp::MACsecLayer>()->getMACsecSL(), sl, object);
	PTF_ASSERT_EQUAL(MACsecFrame->getLayerOfType<pcpp::MACsecLayer>()->getMACsecPN(), pn, object);
	PTF_ASSERT_BUF_COMPARE(MACsecFrame->getLayerOfType<pcpp::MACsecLayer>()->getMACsecSCI(), SCI, 8);

	pcpp::RawPacket* rawFrame = MACsecFrame->getRawPacket();
	PTF_ASSERT_NOT_NULL(rawFrame);
	PTF_ASSERT_EQUAL(rawFrame->getRawDataLen(), 48, int);

	uint8_t expectedBuffer[48] = {
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 			// dstMAC
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,				// srcMAC
		0x88, 0xE5, 									// EtherType
		0x34, 0x55, 0xde, 0xad, 0xbe, 0xef, 			// TCI, SL, PN,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,	0x00, 0x00, // SCI
		0xc0, 0xca, 0xc0, 0x1a, 						// payload data
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,	// ICV
		0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb
	 };

	PTF_ASSERT_BUF_COMPARE(rawFrame->getRawData(), expectedBuffer, 48);	
	delete(MACsecFrame);

}

/*
PTF_TEST_CASE(EthPacketPointerCreation)
{
	pcpp::MacAddress srcMac("aa:aa:aa:aa:aa:aa");
	pcpp::MacAddress dstMac("bb:bb:bb:bb:bb:bb");
	pcpp::EthLayer* ethLayer = new pcpp::EthLayer(srcMac, dstMac, PCPP_ETHERTYPE_IP);

	uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
	pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, 4, true);

	pcpp::Packet* ethPacket = new pcpp::Packet(1);
	PTF_ASSERT_TRUE(ethPacket->addLayer(ethLayer, true));
	PTF_ASSERT_TRUE(ethPacket->addLayer(payloadLayer, true));

	PTF_ASSERT_TRUE(ethPacket->isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(ethPacket->getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(ethPacket->getLayerOfType<pcpp::EthLayer>() == ethLayer);
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getDestMac(), dstMac, object);
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getSourceMac(), srcMac, object);
	PTF_ASSERT_EQUAL(ethPacket->getLayerOfType<pcpp::EthLayer>()->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_IP), u16);

	pcpp::RawPacket* rawPacket = ethPacket->getRawPacket();
	PTF_ASSERT_NOT_NULL(rawPacket);
	PTF_ASSERT_EQUAL(rawPacket->getRawDataLen(), 18, int);

	uint8_t expectedBuffer[18] = { 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04 };
	PTF_ASSERT_BUF_COMPARE(rawPacket->getRawData(), expectedBuffer, 18);
	delete(ethPacket);
} // EthPacketPointerCreation


PTF_TEST_CASE(EthAndArpPacketParsing)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/ArpResponsePacket.dat");

	pcpp::Packet ethPacket(&rawPacket1);
	PTF_ASSERT_TRUE(ethPacket.isPacketOfType(pcpp::Ethernet));
	PTF_ASSERT_NOT_NULL(ethPacket.getLayerOfType<pcpp::EthLayer>());

	pcpp::MacAddress expectedSrcMac(0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa);
	pcpp::MacAddress expectedDstMac(0x6c, 0xf0, 0x49, 0xb2, 0xde, 0x6e);
	pcpp::EthLayer* ethLayer = ethPacket.getLayerOfType<pcpp::EthLayer>();
	PTF_ASSERT_EQUAL(ethLayer->getDestMac(), expectedDstMac, object);
	PTF_ASSERT_EQUAL(ethLayer->getSourceMac(), expectedSrcMac, object);
	PTF_ASSERT_EQUAL(ethLayer->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_ARP), hex);

	PTF_ASSERT_EQUAL(ethLayer->getNextLayer()->getProtocol(), pcpp::ARP, enum);
	pcpp::ArpLayer* arpLayer = (pcpp::ArpLayer*)ethLayer->getNextLayer();
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->hardwareType, htobe16(1), u16);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->protocolType, htobe16(PCPP_ETHERTYPE_IP), hex);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->hardwareSize, 6, u8);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->protocolSize, 4, u8);
	PTF_ASSERT_EQUAL(arpLayer->getArpHeader()->opcode, htobe16(pcpp::ARP_REPLY), u16);
	PTF_ASSERT_EQUAL(arpLayer->getSenderIpAddr(), pcpp::IPv4Address(std::string("10.0.0.138")), object);
	PTF_ASSERT_EQUAL(arpLayer->getTargetMacAddress(), pcpp::MacAddress("6c:f0:49:b2:de:6e"), object);
} // EthAndArpPacketParsing


PTF_TEST_CASE(ArpPacketCreation)
{
	pcpp::MacAddress srcMac("6c:f0:49:b2:de:6e");
	pcpp::MacAddress dstMac("ff:ff:ff:ff:ff:ff:");
	pcpp::EthLayer ethLayer(srcMac, dstMac, PCPP_ETHERTYPE_ARP);

	pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, srcMac, srcMac, pcpp::IPv4Address(std::string("10.0.0.1")), pcpp::IPv4Address(std::string("10.0.0.138")));

	pcpp::Packet arpRequestPacket(1);
	PTF_ASSERT_TRUE(arpRequestPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(arpRequestPacket.addLayer(&arpLayer));
	arpRequestPacket.computeCalculateFields();
	PTF_ASSERT_EQUAL(arpRequestPacket.getRawPacket()->getRawDataLen(), 42, int);

	pcpp::ArpLayer* pArpLayer = arpRequestPacket.getLayerOfType<pcpp::ArpLayer>();
	PTF_ASSERT_NOT_NULL(pArpLayer);

	pcpp::arphdr* arpHeader = pArpLayer->getArpHeader();
	PTF_ASSERT_EQUAL(arpHeader->hardwareSize, 6, u8);
	PTF_ASSERT_EQUAL(arpHeader->protocolType, htobe16(PCPP_ETHERTYPE_IP), u16);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/ArpRequestPacket.dat");

	PTF_ASSERT_EQUAL(bufferLength1, arpRequestPacket.getRawPacket()->getRawDataLen(), int);
	PTF_ASSERT_BUF_COMPARE(arpRequestPacket.getRawPacket()->getRawData(), buffer1, bufferLength1);

	delete [] buffer1;
} // ArpPacketCreation


PTF_TEST_CASE(EthDot3LayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/EthDot3.dat");
	pcpp::Packet ethDot3Packet(&rawPacket1);

	PTF_ASSERT_TRUE(ethDot3Packet.isPacketOfType(pcpp::EthernetDot3));
	pcpp::EthDot3Layer* ethDot3Layer = ethDot3Packet.getLayerOfType<pcpp::EthDot3Layer>();
	PTF_ASSERT_NOT_NULL(ethDot3Layer);
	PTF_ASSERT_EQUAL(ethDot3Layer->getHeaderLen(), 14, size);
	PTF_ASSERT_EQUAL(ethDot3Layer->getSourceMac(), pcpp::MacAddress("00:13:f7:11:5e:db"), object);
	PTF_ASSERT_EQUAL(ethDot3Layer->getDestMac(), pcpp::MacAddress("01:80:c2:00:00:00"), object);
	PTF_ASSERT_EQUAL(be16toh(ethDot3Layer->getEthHeader()->length), 38, u16);

	PTF_ASSERT_NOT_NULL(ethDot3Layer->getNextLayer());
	PTF_ASSERT_EQUAL(ethDot3Layer->getNextLayer()->getProtocol(), pcpp::GenericPayload, enum);
	pcpp::PayloadLayer* payloadLayer = (pcpp::PayloadLayer*)ethDot3Layer->getNextLayer();
	PTF_ASSERT_NOT_NULL(payloadLayer);
	PTF_ASSERT_EQUAL(payloadLayer->getDataLen(), 46, size);

	PTF_ASSERT_NULL(payloadLayer->getNextLayer());
} // EthDot3LayerParsingTest


PTF_TEST_CASE(EthDot3LayerCreateEditTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_INTO_BUFFER(1, "PacketExamples/EthDot3.dat");
	READ_FILE_INTO_BUFFER(2, "PacketExamples/EthDot3_2.dat");

	// create a new EthDot3 packet

	pcpp::MacAddress srcAddr("00:13:f7:11:5e:db");
	pcpp::MacAddress dstAddr("01:80:c2:00:00:00");
	pcpp::EthDot3Layer ethDot3NewLayer(srcAddr, dstAddr, 38);

	pcpp::PayloadLayer newPayloadLayer("424203000000000000000013f71edff00000271080000013f7115ec0801b0100140002000f000000000000000000");
	PTF_ASSERT_EQUAL(newPayloadLayer.getDataLen(), 46, size);

	pcpp::Packet newEthDot3Packet;
	PTF_ASSERT_TRUE(newEthDot3Packet.addLayer(&ethDot3NewLayer));
	PTF_ASSERT_TRUE(newEthDot3Packet.addLayer(&newPayloadLayer));
	newEthDot3Packet.computeCalculateFields();

	PTF_ASSERT_BUF_COMPARE(newEthDot3Packet.getRawPacket()->getRawData(), buffer1, bufferLength1);


	// edit an EthDot3 packet

	ethDot3NewLayer.setSourceMac(pcpp::MacAddress("00:1a:a1:97:d1:85"));
	ethDot3NewLayer.getEthHeader()->length = htobe16(121);

	pcpp::PayloadLayer newPayloadLayer2("424203000003027c8000000c305dd100000000008000000c305dd10080050000140002000f000000500000000"
			"00000000000000000000000000000000000000000000000000000000000000055bf4e8a44b25d442868549c1bf7720f00030d408000001a"
			"a197d180137c8005000c305dd10000030d40808013");

	PTF_ASSERT_TRUE(newEthDot3Packet.detachLayer(&newPayloadLayer));
	PTF_ASSERT_TRUE(newEthDot3Packet.addLayer(&newPayloadLayer2));
	newEthDot3Packet.computeCalculateFields();

	PTF_ASSERT_BUF_COMPARE(newEthDot3Packet.getRawPacket()->getRawData(), buffer2, bufferLength2);

	delete [] buffer1;
	delete [] buffer2;

} // EthDot3LayerCreateEditTest

*/
