/* Software-Based Trusted Platform Module (TPM) Emulator for Linux
 * Copyright (C) 2004 Mario Strasser <mast@gmx.net>,
 *                    Swiss Federal Institute of Technology (ETH) Zurich
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id$
 */

#include "tpm_emulator.h"
#include "tpm_commands.h"

/*
 * GPIO ([TPM_Part3], Section 27)
 * The GPIO capability allows platform software to send and receive 
 * data from general-purpose IO pins on the TPM device.
 */

TPM_RESULT TPM_GPIO_AuthChannel(  
  TPM_ENCAUTH *ioAuth,
  UINT32 sizeChannel,
  TPM_GPIO_CHANNEL *channel,
  TPM_AUTH *auth1,  
  TPM_GPIO_AUTHORIZE *channelAuth 
)
{
  info("TPM_GPIO_AuthChannel() not implemented yet");
  /* TODO: implement TPM_GPIO_AuthChannel() */
  return TPM_FAIL;
}

TPM_RESULT TPM_GPIO_ReadWrite(  
  UINT32 channelAuthSize,
  UINT32 readBytes,
  UINT32 writeBytes,
  BYTE *writeData,
  TPM_AUTH *auth1,  
  TPM_COMMAND_CODE *ordinal,
  UINT32 *readDataSize,
  BYTE **readData  
)
{
  info("TPM_GPIO_ReadWrite() not implemented yet");
  /* TODO: implement TPM_GPIO_ReadWrite() */
  return TPM_FAIL;
}

