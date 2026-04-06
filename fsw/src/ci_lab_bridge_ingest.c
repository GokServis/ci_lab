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

static bool bridge_wire_apid_is_allowed(uint16_t apid)
{
    return (apid == BRIDGE_WIRE_CCSDS_APID_HEARTBEAT) || (apid == BRIDGE_WIRE_CCSDS_APID_PING);
}

static uint16_t bridge_wire_apid_to_sb_msgid(uint16_t apid)
{
    if (apid == BRIDGE_WIRE_CCSDS_APID_HEARTBEAT)
    {
        return BRIDGE_SB_MSGID_HEARTBEAT;
    }
    if (apid == BRIDGE_WIRE_CCSDS_APID_PING)
    {
        return BRIDGE_SB_MSGID_PING;
    }
    return 0u;
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

    /* Match rust-bridge: version 0, TC (packet type 1), allowlisted APID. */
    uint16_t apid = w0 & 0x07FFu;
    if (!bridge_wire_apid_is_allowed(apid))
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
    uint16_t         w0;
    uint16_t         apid;
    uint16_t         sb_msg_value;

    if (source_size > sizeof(tmp))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    memcpy(tmp, source_buffer, source_size);

    w0  = ((uint16_t)tmp[0] << 8) | tmp[1];
    apid = w0 & 0x07FFu;
    if (!bridge_wire_apid_is_allowed(apid))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    sb_msg_value = bridge_wire_apid_to_sb_msgid(apid);
    if (sb_msg_value == 0u)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    total_size = sizeof(CFE_MSG_Message_t) + source_size;
    if (CFE_MSG_Init(&Buf->Msg, CFE_SB_ValueToMsgId(sb_msg_value), total_size) != CFE_SUCCESS)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    memcpy((uint8_t *)&Buf->Msg + sizeof(CFE_MSG_Message_t), tmp, source_size);

    return CFE_SUCCESS;
}
