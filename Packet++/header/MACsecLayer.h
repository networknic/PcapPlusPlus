#ifndef PACKETPP_MACSEC_LAYER
#define PACKETPP_MACSEC_LAYER

#include <iostream>

#include "Layer.h"
#include "EthLayer.h"
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#endif

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct macsec_header
	 * Represents a macsec header
	 */
#pragma pack(push, 1)
	struct macsec_header {
		/**
		   @verbatim
		   octet
		   0         1        2	   8     16          n-8     n
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |TCI | AN | SL     | PN | SCI | PAYLOAD   |  ICV  |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   @endverbatim
		 */


		uint8_t TCI_AN;
		uint8_t SL;
		uint32_t PN;
		uint8_t SCI[8];
	};
#pragma pack(pop)

	/**
	 * @class MACsecLayer
	 * Represents a MACsec layer 
	 */
	class MACsecLayer : public Layer
	{
	public:

		const uint8_t MACsecICVLength = 16; // the 16 byte MACsec ICV 

		 /** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		MACsecLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = MACsec; } 

		/**
		 * A constructor that allocates a new MACsec header
		 * @param[in] TCI_AN the MACsec Tag Control Information and Association Number
		 * @param[in] SL the MACsec Short Length
		 * @param[in] PN the MACsec Packet Number
		 * @param[in] SCI the MACsec Secure Channel Identifier
		 */
		MACsecLayer(uint8_t TCI_AN, uint8_t SL, uint32_t PN, uint8_t *SCI);

		~MACsecLayer() {}

		/**
		 * Get a pointer to the MACsec header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the macsec_header
		 */
		macsec_header* getMACsecHeader() const { return (macsec_header*)m_Data; }

		/**
		 * extracts the TCI value of the MACsec SecTAG
		 * @return TCI value
		 */
		uint8_t getMACsecTCI() const;

		/**
		 * extracts the AN value of the MACsec SecTAG
		 * @return AN value
		 */
		uint8_t getMACsecAN() const;

		/**
		 * extracts the SL value of the MACsec SecTAG
		 * @return SL value
		 */
		uint8_t getMACsecSL() const;

		/**
		 * extracts the PN value of the MACsec SecTAG
		 * @return PN value
		 */
		uint32_t getMACsecPN() const;

		/**
		 * extracts the SCI value of the MACsec SecTAG
		 * @return SCI value
		 */
		uint8_t* getMACsecSCI() const;

		/**
		 * parses the TCI of the SecTAG
		 * @return string with TCI details
		 */
		std::string parseMACsecTCI() const;

		/**
		 * Set TCI field containing the AN. 
		 * @param[in] tci The TCI value to set, with the AN
		 */
		void setTCI_AN(uint8_t tci_an);

		/**
		 * Set SL field. 
		 * @param[in] sl The SL value to set
		 */
		void setSL(uint8_t sl);

		/**
		 * Set PN field. 
		 * @param[in] pn The PN value to set
		 */
		void setPN(uint32_t pn);

		/**
		 * Set SCI field. 
		 * @param[in] sci The SCI value to set
		 */
		void setSCI(uint8_t *sci);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, MACsecLayer, MplsLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of macsec_header
		 */
		size_t getHeaderLen() const { return sizeof(macsec_header); }

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelDataLinkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_MACSEC_LAYER */
