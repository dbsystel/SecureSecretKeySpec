/*
 * Copyright (c) 2022, DB Systel GmbH
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes:
 *     2021-05-28: V1.0.0: Created. fhs
 *     2021-09-01: V1.0.1: Some small refactoring. fhs
 *     2022-11-07: V1.1.0: Better mixing of bytes from and to buffers. fhs
 */
package de.db.bcm.crypto;

import de.db.bcm.arrays.ArrayHelper;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Class to get masks for array indices
 *
 * @author Frank Schwab, DB Systel
 * @version 1.1.0
 */
public class MaskedIndex {
   //******************************************************************
   // Private constants
   //******************************************************************
   static final byte BUFFER_PRIMER = (byte) 0x5a;

   static final int MAX_INTEGER_MASK = 0x07ffffff;

   //******************************************************************
   // Instance variables
   //******************************************************************
   private Cipher m_Encryptor;

   private final byte[] m_SourceBuffer = new byte[16];
   private final byte[] m_MaskBuffer   = new byte[16];

   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * The constructor for an instance of MaskedIndex
    */
   public MaskedIndex() {
      initializeCipher();
   }

   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Get an integer mask for an index
    *
    * @param forIndex The index to use
    * @return The int mask for the given index
    */
   public synchronized int getIntMask(final int forIndex) {
      final int sanitizedIndex = forIndex & MAX_INTEGER_MASK;

      getMaskBuffer(sanitizedIndex);

      final int result = getMaskIntFromArray(m_MaskBuffer, (7 * (sanitizedIndex % 13) + 3) % 13);

      ArrayHelper.clear(m_MaskBuffer);

      return result;
   }

   /**
    * Get a byte mask for an index
    *
    * @param forIndex The index to use
    * @return The byte mask for the given index
    */
   public synchronized byte getByteMask(final int forIndex) {
      final int sanitizedIndex = forIndex & MAX_INTEGER_MASK;

      getMaskBuffer(sanitizedIndex);

      final byte result = m_MaskBuffer[(13 * (sanitizedIndex & 0xf) + 5) & 0xf];

      ArrayHelper.clear(m_MaskBuffer);

      return result;
   }

   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Calculate a buffer full of mask bytes
    *
    * @param sanitizedIndex Sanitized index to use for the mask calculation
    */
   private void getMaskBuffer(final int sanitizedIndex) {
      Arrays.fill(m_SourceBuffer, BUFFER_PRIMER);

      final int offset = ((11 * sanitizedIndex) + 2) % 13;
      storeIntInArray(sanitizedIndex, m_SourceBuffer, offset);

      try {
         m_Encryptor.doFinal(m_SourceBuffer, 0, m_SourceBuffer.length, m_MaskBuffer, 0);
      } catch (Exception ex) {
         // BadPaddingException, IllegalBlockSizeException and ShortBufferException can never happen
      } finally {
         ArrayHelper.clear(m_SourceBuffer);
      }
   }

   /**
    * Initialize the cipher
    */
   private void initializeCipher() {
      final byte[] key = new byte[16];

      final SecureRandom sprng = SecureRandomFactory.getSensibleSingleton();

      sprng.nextBytes(key);

      try {
         // ECB is an insecure mode but that is not a problem as
         // the cipher is only used for generating an obfuscation mask.
         m_Encryptor = Cipher.getInstance("AES/ECB/NoPadding");

         // This has to be "SecretKeySpec" and not "SecureSecretKeySpec".
         // Otherwise, we would have an infinite loop here.
         SecretKeySpec maskKey = new SecretKeySpec(key, "AES");

         m_Encryptor.init(Cipher.ENCRYPT_MODE, maskKey);
      } catch (Exception ex) {
         // InvalidKeyException, NoSuchAlgorithmException and NoSuchPaddingException can never happen
      } finally {
         ArrayHelper.clear(key);
      }
   }

   /**
    * Stores the bytes of an integer in an existing array
    *
    * @param sourceInt Integer to convert
    * @param destArray Destination byte array
    * @param startPos Start position in the byte array
    */
   private void storeIntInArray(final int sourceInt, final byte[] destArray, final int startPos) {
      int toPos = startPos;
      int work = sourceInt;

      destArray[toPos] = (byte) (work & 0xff);
      toPos = (toPos + 3) & 0x0f; work >>>= 8;
      destArray[toPos] = (byte) (work & 0xff);
      toPos = (toPos + 3) & 0x0f;  work >>>= 8;
      destArray[toPos] = (byte) (work & 0xff);
      toPos = (toPos + 3) & 0x0f;  work >>>= 8;
      destArray[toPos] = (byte) (work & 0xff);
   }

   /**
    * Get a mask integer from the bytes in an array
    *
    * @param sourceArray Byte array to get the integer from
    * @param startPos Start position in the byte array
    * @return Mask integer
    */
   private int getMaskIntFromArray(final byte[] sourceArray, final int startPos) {
      int result = 0;
      int fromPos = startPos;

      result = (sourceArray[fromPos] & 0xff);  // This stupid Java sign extension!!!!
      result <<= 8; fromPos = (fromPos + 3) & 0x0f;
      result |= (sourceArray[fromPos] & 0xff);
      result <<= 8; fromPos = (fromPos + 3) & 0x0f;
      result |= (sourceArray[fromPos] & 0xff);
      result <<= 8; fromPos = (fromPos + 3) & 0x0f;
      result |= (sourceArray[fromPos] & 0xff);

      return result;
   }
}
