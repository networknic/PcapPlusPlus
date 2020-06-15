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

PTF_TEST_CASE(MACsecFramePointerCreation) 
{

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

PTF_TEST_CASE(MACsecFrameParsing) {

	uint8_t expectedTCI_AN = 0x2c;	
	uint8_t expectedTCI = 0x0b;
	uint8_t expectedAN = 0x00;
	uint8_t expectedSL = 0x00;
	uint32_t expectedPN = 0x0d;
	uint8_t expectedSCI[8] = { 0xbc, 0x16, 0x65, 0x2b, 0x75, 0x0d, 0x00, 0x00 };
	
	pcpp::MacAddress expectedDstMac(0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd);
	pcpp::MacAddress expectedSrcMac(0xbc, 0x16, 0x65, 0x2b, 0x75, 0x0d);

	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/MACsecFrame.dat");
	pcpp::Packet ethPacket(&rawPacket1);

	pcpp::EthLayer* ethLayer = ethPacket.getLayerOfType<pcpp::EthLayer>();
	PTF_ASSERT_EQUAL(ethLayer->getDestMac(), expectedDstMac, object);
	PTF_ASSERT_EQUAL(ethLayer->getSourceMac(), expectedSrcMac, object);
	PTF_ASSERT_EQUAL(ethLayer->getEthHeader()->etherType, be16toh(PCPP_ETHERTYPE_MACSEC), hex);

	PTF_ASSERT_EQUAL(ethLayer->getNextLayer()->getProtocol(), pcpp::MACsec, enum);
	pcpp::MACsecLayer* macsecLayer = (pcpp::MACsecLayer*)ethLayer->getNextLayer();

	PTF_ASSERT_EQUAL(macsecLayer->getMACsecHeader()->TCI_AN, expectedTCI_AN, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecTCI(), expectedTCI, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecAN(), expectedAN, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecHeader()->SL, expectedSL, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecHeader()->PN, htobe32(expectedPN), u32);
	PTF_ASSERT_BUF_COMPARE(macsecLayer->getMACsecHeader()->SCI, expectedSCI, 8);	

}

PTF_TEST_CASE(MACsecFrameEdit)
{

	uint8_t newTCI = 0x0d;
	uint8_t newAN = 0x01;
	uint8_t newSL = 0x02;
	uint8_t newTCI_AN = (newTCI << 2) | (newAN);
	uint32_t newPN = 0xdeadbeef;
	uint8_t newSCI[8] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x5, 0x6, 0x7 };

	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/MACsecFrame.dat");
	pcpp::Packet ethPacket(&rawPacket1);
	pcpp::EthLayer* ethLayer = ethPacket.getLayerOfType<pcpp::EthLayer>();

	pcpp::MACsecLayer* macsecLayer = (pcpp::MACsecLayer*)ethLayer->getNextLayer();

	macsecLayer->setTCI_AN(newTCI_AN);
	macsecLayer->setSL(newSL);
	macsecLayer->setPN(newPN);
	macsecLayer->setSCI(&newSCI[0]);

	PTF_ASSERT_EQUAL(macsecLayer->getMACsecHeader()->TCI_AN, newTCI_AN, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecHeader()->SL, newSL, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecHeader()->PN, htobe32(newPN), u32);
	PTF_ASSERT_BUF_COMPARE(macsecLayer->getMACsecHeader()->SCI, newSCI, 8);	

	PTF_ASSERT_EQUAL(macsecLayer->getMACsecTCI(), newTCI, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecAN(), newAN, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecSL(), newSL, u8);
	PTF_ASSERT_EQUAL(macsecLayer->getMACsecPN(), newPN, u32);
	PTF_ASSERT_BUF_COMPARE(macsecLayer->getMACsecSCI(), newSCI, 8);	


} // MACsecFrameEdit
