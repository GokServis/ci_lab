/************************************************************************
 * CI_LAB: detect Rust bridge wire format (CCSDS primary + payload + CRC-16 BE)
 * and wrap it in a cFE Software Bus message. SB MsgId is chosen from the wire APID
 * (see bridge_reader_mission_ids.h).
 ************************************************************************/
#ifndef CI_LAB_BRIDGE_INGEST_H
#define CI_LAB_BRIDGE_INGEST_H

#include "common_types.h"
#include "cfe_sb_api_typedefs.h"

#include "bridge_reader_mission_ids.h"

bool CI_LAB_IsBridgeWireFormat(const void *source, size_t source_size);

/** CCSDS APID from bridge wire (11 bits), or 0 if buffer too short. */
uint16_t CI_LAB_BridgeWireGetApid(const void *source, size_t source_size);

/**
 * Repacks in place: SourceBuffer must be a SB-allocated buffer large enough.
 * After success, the message is cFE primary header + raw bridge wire bytes.
 */
CFE_Status_t CI_LAB_WrapBridgeWireInPlace(void *source_buffer, size_t source_size);

/**
 * Rust bridge APID 0x008: CCSDS TC + 16-byte dest_IP payload + CRC → TO_LAB_EnableOutputCmd on SB.
 * Allocates a new SB buffer; caller must transmit and not use WrapBridgeWireInPlace for this APID.
 */
CFE_Status_t CI_LAB_DecodeBridgeWireToToLabEnableOutput(const void *source_buffer, size_t source_size,
                                                        CFE_SB_Buffer_t **dest_out);

#endif /* CI_LAB_BRIDGE_INGEST_H */
