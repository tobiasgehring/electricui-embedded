#include "eui_serial_transport.h"

void
crc16(uint8_t data, uint16_t *crc)
{
  *crc  = (uint8_t)(*crc >> 8) | (*crc << 8);
  *crc ^= data;
  *crc ^= (uint8_t)(*crc & 0xff) >> 4;
  *crc ^= (*crc << 8) << 4;
  *crc ^= ((*crc & 0xff) << 4) << 1;
}

euiHeader_t *
generate_header(uint8_t internal, uint8_t ack, uint8_t query, uint8_t offset_packet, uint8_t data_type, uint8_t msgID_len, uint8_t data_length, uint8_t sequence_num)
{
  euiHeader_t temp_header; 

  temp_header.internal   = internal;
  temp_header.ack        = ack;
  temp_header.query      = query;
  temp_header.offset     = offset_packet;
  temp_header.type       = data_type;
  temp_header.id_len     = msgID_len;
  temp_header.data_len   = data_length;
  temp_header.seq        = sequence_num;

  return &temp_header;
}

uint8_t
form_packet_simple(CallBackwithUINT8 output_function, euiPacketSettings_t *settings, const char * msg_id, uint8_t payload_len, void* payload)
{
  //just call the full one with default seq# and offset values
  return form_packet_full(output_function, settings, 0, msg_id, 0x00, payload_len, payload);
}

uint8_t
form_packet_full(CallBackwithUINT8 output_function, euiPacketSettings_t *settings, uint8_t sequence_num, const char * msg_id, uint16_t offset_addr, uint8_t payload_len, void* payload)
{
  euiHeader_t temp_header;

  temp_header.internal   = settings->internal;
  temp_header.ack        = settings->ack;
  temp_header.query      = settings->query;
  temp_header.offset     = (offset_addr) ? MSG_OFFSET_PACKET : MSG_STANDARD_PACKET;
  temp_header.type       = settings->type;
  temp_header.id_len     = strlen(msg_id);
  temp_header.data_len   = payload_len;
  temp_header.seq        = sequence_num;  //todo implement this properly

  return encode_packet(output_function, &temp_header, msg_id, offset_addr, payload);
}

uint8_t
encode_packet(CallBackwithUINT8 output_function, euiHeader_t * header, const char * msg_id, uint16_t offset, void* payload)
{
  if(output_function)  //todo ASSERT if not valid?
  {  
    //preamble
    output_function( stHeader );
    
    uint16_t outbound_crc = 0xffff;

    //header
    uint16_t header_buffer = 0;
    header_buffer |= header->internal << 0;
    header_buffer |= header->ack      << 1;
    header_buffer |= header->query    << 2;
    header_buffer |= header->offset   << 3;
    header_buffer |= header->type     << 4;
    output_function( header_buffer );
    crc16(header_buffer, &outbound_crc); 

    header_buffer = 0;  //reuse the buffer for the remaining 2-bytes
    header_buffer |= header->seq << 14;
    header_buffer |= header->id_len  << 10;
    header_buffer |= (header->data_len);
    output_function( header_buffer & 0xFF );
    crc16(header_buffer & 0xFF , &outbound_crc); 
    output_function( header_buffer >> 8 );
    crc16(header_buffer >> 8 , &outbound_crc); 

    //message identifier
    for(int i = 0; i < header->id_len; i++)
    {
      output_function( msg_id[i] );
      crc16(msg_id[i], &outbound_crc); 
    }

    //data offset if used
    if(header->offset)
    {
      output_function( offset & 0xFF );
      crc16(offset & 0xFF, &outbound_crc); 

      output_function( offset >> 8 );
      crc16(offset >> 8, &outbound_crc); 
    }
    
    //payload data
    for(int i = 0; i < header->data_len; i++)
    {
      output_function( *((uint8_t *)payload + i) );
      crc16(*((uint8_t *)payload + i), &outbound_crc); 
    }

    //checksum between the preamble and CRC
    output_function( outbound_crc & 0xFF );
    output_function( outbound_crc >> 8 );

    //packet terminator
    output_function( enTransmission );
  }

  return 0;
}

uint8_t
decode_packet(uint8_t inbound_byte, struct eui_interface *active_interface)
{
  if(active_interface->state.parser_s < exp_crc_b1)    //only CRC the data between preamble and the CRC (exclusive)
  {
    crc16(inbound_byte, &(active_interface->runningCRC)); 
  }

  switch(active_interface->state.parser_s)
  {
    case find_preamble:
    case exp_reset:
      //Ignore random bytes prior to preamble
      if(inbound_byte == stHeader)
      {
        active_interface->runningCRC = 0xFFFF;
        active_interface->state.parser_s = exp_header_b1;
      }
      else if(exp_reset)
      {
        //wipe out the array
      }
    break;

    case exp_header_b1:
      //populate the header bitfield from recieved byte
      active_interface->inboundHeader.internal  = (inbound_byte >> 0) & 1;
      active_interface->inboundHeader.ack       = (inbound_byte >> 1) & 1;
      active_interface->inboundHeader.query     = (inbound_byte >> 2) & 1;
      active_interface->inboundHeader.offset    = (inbound_byte >> 3) & 1;
      active_interface->inboundHeader.type      = inbound_byte >> 4;

      active_interface->state.parser_s = exp_header_b2;
    break;

   case exp_header_b2:
      active_interface->inboundHeader.data_len = inbound_byte;
      
      active_interface->state.parser_s = exp_header_b3;
    break;

    case exp_header_b3:
      active_interface->inboundHeader.seq       = (inbound_byte >> 6);         //read last two bits
      active_interface->inboundHeader.id_len    = (inbound_byte >> 2) & 0x0F;  //shift 2-bits, mask lowest 4
      active_interface->inboundHeader.data_len |= ((uint16_t)inbound_byte << 8) & 0x0300; //the 'last' two length bits = first 2b of this byte
      
      active_interface->state.parser_s = exp_message_id;
    break;   
    
    case exp_message_id:
      //Bytes are messageID until we hit the length specified in the header
      active_interface->inboundID[active_interface->state.id_bytes_in] = inbound_byte;
      active_interface->state.id_bytes_in++;

      //we've read the number of bytes specified by the header count OR
      //we've ingested the maximum allowable length of the message ID
      if(active_interface->state.id_bytes_in >= active_interface->inboundHeader.id_len || active_interface->state.id_bytes_in >= MESSAGEID_SIZE)
      {
        //terminate msgID string if shorter than max size
        if(active_interface->state.id_bytes_in < MESSAGEID_SIZE)
        {
          active_interface->inboundID[active_interface->state.id_bytes_in + 1] = '\0';
        }

        //start reading in the offset or data based on header guide
        if(active_interface->inboundHeader.offset)
        {
          active_interface->state.parser_s = exp_offset_b1;
        }
        else
        {
          if(active_interface->inboundHeader.data_len)
          {
            active_interface->state.parser_s = exp_data;            
          }
          else
          {
            active_interface->state.parser_s = exp_crc_b1;            
          }
        }
      }
    break;

    case exp_offset_b1:
      active_interface->inboundOffset = inbound_byte;
      active_interface->inboundOffset << 8;

      active_interface->state.parser_s = exp_offset_b2;
    break;

    case exp_offset_b2:
      //ingest second offset byte as the MSB
      active_interface->inboundOffset |= inbound_byte;
      active_interface->state.parser_s = exp_data;
    break;
    
    case exp_data:
      //we know the payload length, parse until we've eaten those bytes
      active_interface->inboundData[active_interface->state.data_bytes_in] = inbound_byte;
      active_interface->state.data_bytes_in++;

      //prepare for the crc data
      if(active_interface->state.data_bytes_in >= active_interface->inboundHeader.data_len)
      {
        active_interface->state.parser_s = exp_crc_b1;
      }
    break;
    
    case exp_crc_b1:
      //check the inbound byte against the corresponding CRC byte
      if(inbound_byte == (active_interface->runningCRC & 0xFF) )
      {
        active_interface->state.parser_s = exp_crc_b2;        
      }
      else  //first byte didn't match CRC, fail early
      {
        active_interface->state.parser_s = exp_reset;
        return packet_error_generic;
      }
    break;

    case exp_crc_b2:
      if(inbound_byte == (active_interface->runningCRC >> 8) )  //CRC is correct 
      {
        active_interface->state.parser_s = exp_eot;  
      }
      else  //second byte didn't match CRC
      {
        active_interface->state.parser_s = exp_reset;
        return packet_error_generic;
      }
    break;

    case exp_eot:
      active_interface->state.parser_s = exp_reset;

      //we've recieved the end of packet indication
      if(inbound_byte == enTransmission)
      {
        return packet_valid; //signal to the application layer that a valid packet is waiting
      }
    break;  
  }
  
  return parser_idle;
}