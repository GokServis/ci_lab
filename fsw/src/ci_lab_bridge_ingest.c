/************************************************************************
 * CI_LAB bridge ingest: Rust CCSDS + CRC-16 BE datagram → SB message.
 ************************************************************************/

#include "cfe.h"

#include "cfe_msg.h"

#include "ci_lab_bridge_ingest.h"
#include "to_lab_fcncodes.h"
#include "cfe_tbl_fcncodes.h"
#include "cfe_tbl_msgids.h"
#include "cfe_tbl_msgstruct.h"

/*
 * Must match TO_LAB_CMD_MID from TO_LAB mission topic ID 0x80:
 * CFE_PLATFORM_CMD_TOPICID_TO_MIDV(TO_LAB_MISSION_CMD_TOPICID) == 0x1800 | 0x80
 */
#define CI_LAB_BRIDGE_TO_LAB_CMD_MIDVAL (0x1800u | 0x80u)

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
    return (apid == BRIDGE_WIRE_CCSDS_APID_HEARTBEAT) || (apid == BRIDGE_WIRE_CCSDS_APID_PING) ||
           (apid == BRIDGE_WIRE_CCSDS_APID_TO_LAB_ENABLE_OUTPUT) ||
           (apid == BRIDGE_WIRE_CCSDS_APID_TO_LAB_DISABLE_OUTPUT) ||
           (apid == BRIDGE_WIRE_CCSDS_APID_CFE_TBL_LOAD_FILE) ||
           (apid == BRIDGE_WIRE_CCSDS_APID_CFE_TBL_ACTIVATE);
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

uint16_t CI_LAB_BridgeWireGetApid(const void *source, size_t source_size)
{
    const uint8_t *p = source;

    if (source_size < 2u)
    {
        return 0u;
    }

    uint16_t w0 = ((uint16_t)p[0] << 8) | p[1];
    return w0 & 0x07FFu;
}

/** Layout matches TO_LAB_EnableOutputCmd_t (CommandHeader + 16-byte IP string). */
typedef struct
{
    CFE_MSG_CommandHeader_t CommandHeader;
    struct
    {
        char dest_IP[16];
    } Payload;
} CI_LAB_ToLabEnableOutputCmd_t;

/** Layout matches TO_LAB_DisableOutputCmd_t (command header only). */
typedef struct
{
    CFE_MSG_CommandHeader_t CommandHeader;
} CI_LAB_ToLabDisableOutputCmd_t;

CFE_Status_t CI_LAB_DecodeBridgeWireToCfeTblLoadFile(const void *source_buffer, size_t source_size,
                                                     CFE_SB_Buffer_t **dest_out)
{
    const uint8_t *p = source_buffer;
    CFE_SB_Buffer_t *Buf;
    CFE_TBL_LoadCmd_t *cmd;
    uint16_t w0;
    uint16_t w2;
    size_t payload_len;

    *dest_out = NULL;

    if (!CI_LAB_IsBridgeWireFormat(source_buffer, source_size))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    w0 = ((uint16_t)p[0] << 8) | p[1];
    w2 = ((uint16_t)p[4] << 8) | p[5];
    if ((w0 & 0x07FFu) != BRIDGE_WIRE_CCSDS_APID_CFE_TBL_LOAD_FILE)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    if (w2 == 0xFFFFu)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    payload_len = (size_t)w2 + 1u;
    if (payload_len != sizeof(cmd->Payload.LoadFilename))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    Buf = CFE_SB_AllocateMessageBuffer(sizeof(CFE_TBL_LoadCmd_t));
    if (Buf == NULL)
    {
        return CFE_SB_BUF_ALOC_ERR;
    }
    cmd = (CFE_TBL_LoadCmd_t *)&Buf->Msg;
    memset(cmd, 0, sizeof(*cmd));

    if (CFE_MSG_Init(CFE_MSG_PTR(cmd->CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID),
                     sizeof(CFE_TBL_LoadCmd_t)) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(Buf);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    if (CFE_MSG_SetFcnCode(CFE_MSG_PTR(cmd->CommandHeader), CFE_TBL_LOAD_CC) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(Buf);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    memcpy(cmd->Payload.LoadFilename, &p[6], payload_len);
    *dest_out = Buf;
    return CFE_SUCCESS;
}

CFE_Status_t CI_LAB_DecodeBridgeWireToCfeTblActivate(const void *source_buffer, size_t source_size,
                                                     CFE_SB_Buffer_t **dest_out)
{
    const uint8_t *p = source_buffer;
    CFE_SB_Buffer_t *Buf;
    CFE_TBL_ActivateCmd_t *cmd;
    uint16_t w0;
    uint16_t w2;
    size_t payload_len;

    *dest_out = NULL;

    if (!CI_LAB_IsBridgeWireFormat(source_buffer, source_size))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    w0 = ((uint16_t)p[0] << 8) | p[1];
    w2 = ((uint16_t)p[4] << 8) | p[5];
    if ((w0 & 0x07FFu) != BRIDGE_WIRE_CCSDS_APID_CFE_TBL_ACTIVATE)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    if (w2 == 0xFFFFu)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    payload_len = (size_t)w2 + 1u;
    if (payload_len != sizeof(cmd->Payload.TableName))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    Buf = CFE_SB_AllocateMessageBuffer(sizeof(CFE_TBL_ActivateCmd_t));
    if (Buf == NULL)
    {
        return CFE_SB_BUF_ALOC_ERR;
    }
    cmd = (CFE_TBL_ActivateCmd_t *)&Buf->Msg;
    memset(cmd, 0, sizeof(*cmd));

    if (CFE_MSG_Init(CFE_MSG_PTR(cmd->CommandHeader), CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID),
                     sizeof(CFE_TBL_ActivateCmd_t)) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(Buf);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    if (CFE_MSG_SetFcnCode(CFE_MSG_PTR(cmd->CommandHeader), CFE_TBL_ACTIVATE_CC) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(Buf);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    memcpy(cmd->Payload.TableName, &p[6], payload_len);
    *dest_out = Buf;
    return CFE_SUCCESS;
}

CFE_Status_t CI_LAB_DecodeBridgeWireToToLabDisableOutput(const void *source_buffer, size_t source_size,
                                                        CFE_SB_Buffer_t **dest_out)
{
    const uint8_t *p = source_buffer;
    CFE_SB_Buffer_t *Buf;
    CI_LAB_ToLabDisableOutputCmd_t *cmd;
    uint16_t w0;
    uint16_t w2;

    *dest_out = NULL;

    if (!CI_LAB_IsBridgeWireFormat(source_buffer, source_size))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    w0 = ((uint16_t)p[0] << 8) | p[1];
    w2 = ((uint16_t)p[4] << 8) | p[5];
    if ((w0 & 0x07FFu) != BRIDGE_WIRE_CCSDS_APID_TO_LAB_DISABLE_OUTPUT)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    /* Zero-byte payload => CCSDS length field 0xFFFF (matches rust-bridge semantics). */
    if (w2 != 0xFFFFu)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    Buf = CFE_SB_AllocateMessageBuffer(sizeof(CI_LAB_ToLabDisableOutputCmd_t));
    if (Buf == NULL)
    {
        return CFE_SB_BUF_ALOC_ERR;
    }
    cmd = (CI_LAB_ToLabDisableOutputCmd_t *)&Buf->Msg;
    memset(cmd, 0, sizeof(*cmd));

    if (CFE_MSG_Init(CFE_MSG_PTR(cmd->CommandHeader), CFE_SB_ValueToMsgId(CI_LAB_BRIDGE_TO_LAB_CMD_MIDVAL),
                     sizeof(CI_LAB_ToLabDisableOutputCmd_t)) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(Buf);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    if (CFE_MSG_SetFcnCode(CFE_MSG_PTR(cmd->CommandHeader), TO_LAB_OUTPUT_DISABLE_CC) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(Buf);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    *dest_out = Buf;
    return CFE_SUCCESS;
}

CFE_Status_t CI_LAB_DecodeBridgeWireToToLabEnableOutput(const void *source_buffer, size_t source_size,
                                                        CFE_SB_Buffer_t **dest_out)
{
    const uint8_t *                    p = source_buffer;
    CI_LAB_ToLabEnableOutputCmd_t *    cmd;
    CFE_SB_Buffer_t *                    Buf;
    uint16_t                           w0;
    uint16_t                           w2;
    size_t                             payload_len;

    *dest_out = NULL;

    if (!CI_LAB_IsBridgeWireFormat(source_buffer, source_size))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    w0 = ((uint16_t)p[0] << 8) | p[1];
    w2 = ((uint16_t)p[4] << 8) | p[5];
    if ((w0 & 0x07FFu) != BRIDGE_WIRE_CCSDS_APID_TO_LAB_ENABLE_OUTPUT)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    if (w2 == 0xFFFFu)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    payload_len = (size_t)w2 + 1u;
    if (payload_len != 16u)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    Buf = CFE_SB_AllocateMessageBuffer(sizeof(CI_LAB_ToLabEnableOutputCmd_t));
    if (Buf == NULL)
    {
        return CFE_SB_BUF_ALOC_ERR;
    }

    cmd = (CI_LAB_ToLabEnableOutputCmd_t *)&Buf->Msg;

    memset(cmd, 0, sizeof(*cmd));

    if (CFE_MSG_Init(CFE_MSG_PTR(cmd->CommandHeader), CFE_SB_ValueToMsgId(CI_LAB_BRIDGE_TO_LAB_CMD_MIDVAL),
                     sizeof(CI_LAB_ToLabEnableOutputCmd_t)) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(Buf);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    if (CFE_MSG_SetFcnCode(CFE_MSG_PTR(cmd->CommandHeader), TO_LAB_OUTPUT_ENABLE_CC) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(Buf);
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }

    memcpy(cmd->Payload.dest_IP, &p[6], 16);

    *dest_out = Buf;
    return CFE_SUCCESS;
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

    w0   = ((uint16_t)tmp[0] << 8) | tmp[1];
    apid = w0 & 0x07FFu;
    if (!bridge_wire_apid_is_allowed(apid))
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    if (apid == BRIDGE_WIRE_CCSDS_APID_TO_LAB_ENABLE_OUTPUT)
    {
        return CFE_STATUS_WRONG_MSG_LENGTH;
    }
    if (apid == BRIDGE_WIRE_CCSDS_APID_TO_LAB_DISABLE_OUTPUT)
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
