//#nmt# check the log module for this!
#define LOG_MODULE PacketLogModuleMACsecLayer

#include <iostream>	// #nmt# for debugging

#include "MACsecLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "ArpLayer.h"
#include "PPPoELayer.h"
#include "MplsLayer.h"
#include <string.h>
#include <sstream>
#include "EndianPortable.h"

namespace pcpp
{

MACsecLayer::MACsecLayer(uint8_t TCI_AN, uint8_t SL, uint32_t PN, uint8_t *SCI)
{
	// layer class data 
	const size_t headerLen = sizeof(macsec_header);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);
	m_Protocol = MACsec;	

	setTCI_AN(TCI_AN);
	setSL(SL);
	setPN(PN);
	setSCI(SCI);

}

uint8_t MACsecLayer::getMACsecTCI() const 
{
	return (getMACsecHeader()->TCI_AN >> 2);	
}

uint8_t MACsecLayer::getMACsecAN() const 
{
	return (getMACsecHeader()->TCI_AN & 0x03);	
}

uint8_t MACsecLayer::getMACsecSL() const 
{
	return getMACsecHeader()->SL;	
}

uint32_t MACsecLayer::getMACsecPN() const 
{
	return htobe32(getMACsecHeader()->PN);	
}

uint8_t* MACsecLayer::getMACsecSCI() const 
{
	return &getMACsecHeader()->SCI[0];	
}

std::string MACsecLayer::parseMACsecTCI() const 
{

	/**
	 * 1 Octet TCI Field
	 * | V | ES | SC | SCB | E | C | 2-bit AN |
	 *   1   1    1    1     1   1      2	
	 */
	std::ostringstream streamTCIDetails;
	
	streamTCIDetails << " TCI details: ";

	/** 
	 * version is always zero in the 
	 * current versions of the standard
	 */	
	
	/**
	 * If the SCI bit is set, the SCI is 
	 * explicitly encoded in the SecTAG
	 */
	
	/**
	 * The ES bit concerns the port identifier,
	 * however, as nothing is done with the port
	 * identifier here, it is not relevant	
	 */

	/**
	 * The E bit indicates if encryption is active
	 * this is interesting.
	 */
	if(getMACsecHeader()->TCI_AN & (1 << 3)) 
	{
		streamTCIDetails << "Encryption On ";
	} 
	else 
	{
		streamTCIDetails << "Encryption Off ";
	}

	/** 
	 * A cleared C bit indicates that the secure data
	 * is exactly the same as the user data with appended
	 * ICV
	 */
	if(!(getMACsecHeader()->TCI_AN & (1 << 2))) 
	{
		streamTCIDetails << "Secure Data == User Data ";
	}

	return streamTCIDetails.str();
	
}

void MACsecLayer::setTCI_AN(uint8_t tci_an) 
{
	getMACsecHeader()->TCI_AN = tci_an;
}

void MACsecLayer::setSL(uint8_t sl) 
{
	getMACsecHeader()->SL = sl;
}

void MACsecLayer::setPN(uint32_t pn) 
{
	getMACsecHeader()->PN = htobe32(pn);
}

void MACsecLayer::setSCI(uint8_t *sci) 
{
	memcpy(getMACsecHeader()->SCI, sci, sizeof(uint8_t)*8);
}

void MACsecLayer::parseNextLayer()
{
	
	if (m_DataLen <= sizeof(macsec_header)) 
	{
		return;
	}

	/* skip the ICV when advancing the data pointer */
	uint8_t* payload = m_Data + sizeof(macsec_header);
	size_t payloadLen = m_DataLen - sizeof(macsec_header) - MACsecICVLength;

	/** 
	 * #nmt# can extract the ethertype of the next layer if encryption is not
	 * activated in the TCI
	 */
	m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);

	/*
	switch (be16toh(hdr->etherType))
	{
	case PCPP_ETHERTYPE_IP:
		m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PCPP_ETHERTYPE_IPV6:
		m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			: static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
		break;
	case PCPP_ETHERTYPE_ARP:
		m_NextLayer = new ArpLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_VLAN:
		m_NextLayer = new VlanLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOES:
		m_NextLayer = new PPPoESessionLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_PPPOED:
		m_NextLayer = new PPPoEDiscoveryLayer(payload, payloadLen, this, m_Packet);
		break;
	case PCPP_ETHERTYPE_MPLS:
		m_NextLayer = new MplsLayer(payload, payloadLen, this, m_Packet);
		break;
	default:
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
	*/

}

std::string MACsecLayer::toString() const
{

	std::ostringstream tciStream;
	tciStream << std::hex <<(int)getMACsecTCI();

	std::ostringstream anStream;
	anStream << (int)getMACsecAN();

	std::ostringstream slStream;
	slStream << (int)getMACsecSL();

	std::ostringstream pnStream;
	pnStream << (uint32_t)getMACsecPN();

	std::ostringstream sciStream;
	for(int i = 0; i < 8; i++) {
		sciStream << std::hex << (int)*(getMACsecSCI()+i);
	}

	return "MACsec Layer, TCI: " + tciStream.str() + ", AN: " + anStream.str() + parseMACsecTCI() +", SL: " + slStream.str() + ", PN: " + pnStream.str() + ", SCI: " + sciStream.str() + ", ICV in Trailer... ";

}

} // namespace pcpp
