/************************************************************************
 * CI_LAB bridge ingest: Rust CCSDS + CRC-16 BE datagram → SB message.
 ************************************************************************/

#include "cfe.h"

#include "ci_lab_bridge_ingest.h"

/*
 * CCSDS Packet Data Length field semantics match rust-bridge/src/lib.rs:
 * 0xFFFF => zero-byte payload; else payload length = field + 1.
 */
static size_t bridge_payload_len_from_w2(uint16_t w2)
{
    if (w2 == 0xFFFFu)
    {
        return 0;
    }
    return (size_t)w2 + 1u;
}

bool CI_LAB_IsBridgeWireFormat(const void *source, size_t source_size)
{
    const uint8_t *p = source;

    if (source_size < 8u)
    {
        return false;
    }

    uint16_t w0 = ((uint16_t)p[0] << 8) | p[1];
    uint16_t w2 = ((uint16_t)p[4] << 8) | p[5];

    size_t payload_len = bridge_payload_len_from_w2(w2);
    size_t expected    = 6u + payload_len + 2u;
    if (source_size != expected)
    {
        return false;
    }

    /* Match rust-bridge defaults: version 0, TC (packet type 1), APID 0x006. */
    uint16_t apid = w0 & 0x07FFu;
    if (apid != BRIDGE_WIRE_CCSDS_APID)
    {
        return false;
    }
    if (((w0 >> 13) & 0x7u) != 0u)
    {
        return false;
    }
    if (((w0 >> 12) & 0x1u) != 1u)
    {
        return false;
    }

    return true;
}

CFE_Status_t CI_LAB_WrapBridgeWireInPlace(void *source_buffer, size_t source_size)
{
    CFE_SB_Buffer_t *Buf = (CFE_SB_Buffer_t *)source_buffer;
    uint8_t          tmp[768];
    CFE_MSG_Size_t   total_size;

    if (source_size > sizeof(tmp))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    memcpy(tmp, source_buffer, source_size);

    total_size = sizeof(CFE_MSG_Message_t) + source_size;
    if (CFE_MSG_Init(&Buf->Msg, CFE_SB_ValueToMsgId(BRIDGE_SB_MSGID_RAW_VALUE), total_size) != CFE_SUCCESS)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    memcpy((uint8_t *)&Buf->Msg + sizeof(CFE_MSG_Message_t), tmp, source_size);

    return CFE_SUCCESS;
}
