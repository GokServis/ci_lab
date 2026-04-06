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

/**
 * Repacks in place: SourceBuffer must be a SB-allocated buffer large enough.
 * After success, the message is cFE primary header + raw bridge wire bytes.
 */
CFE_Status_t CI_LAB_WrapBridgeWireInPlace(void *source_buffer, size_t source_size);

#endif /* CI_LAB_BRIDGE_INGEST_H */
