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
 *     2022-11-08: V1.2.0: Name all constants. fhs
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
 * @version 1.2.0
 */
public class MaskedIndex {
   //******************************************************************
   // Private constants
   //******************************************************************

   /***
    * Key size
    */
   static final int KEY_SIZE = 16;  // I.e. 128 bits

   /***
    * Buffer size
    */
   static final int BUFFER_SIZE = 16;

   /***
    * Mask for additions modulo buffer size
    */
   static final int BUFFER_SIZE_MASK = BUFFER_SIZE - 1;

   /***
    * Modulo value for the offset of an integer in a buffer
    */
   static final int MOD_BUFFER_SIZE_FOR_INTEGER = BUFFER_SIZE - 3;

   /***
    * Byte value to prime buffer with
    */
   static final byte BUFFER_PRIMER = (byte) 0x5a;

   /***
    * Step size for setting and getting bytes in the buffer
    */
   static final int STEP_SIZE = 3;

   /***
    * Number of bits to shift for a byte shift
    */
   static final int BYTE_SHIFT = 8;

   /***
    * Byte mask for integers
    */
   static final int INT_BYTE_MASK = 0xff;

   /***
    * Maximum allowed integer mask
    */
   static final int MAX_INTEGER_MASK = 0x7fffffff;

   //******************************************************************
   // Instance variables
   //******************************************************************

   /***
    * Encryptor to use
    */
   private Cipher m_Encryptor;

   /***
    * Source buffer for mask generation
    */
   private final byte[] m_SourceBuffer = new byte[BUFFER_SIZE];

   /***
    * Buffer for encryption result
    */
   private final byte[] m_MaskBuffer   = new byte[BUFFER_SIZE];

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

      final int result = getMaskIntFromArray(m_MaskBuffer,
            (7 * (sanitizedIndex % MOD_BUFFER_SIZE_FOR_INTEGER) + 3) % MOD_BUFFER_SIZE_FOR_INTEGER);

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

      final byte result = m_MaskBuffer[(13 * (sanitizedIndex & BUFFER_SIZE_MASK) + 5) & BUFFER_SIZE_MASK];

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

      final int offset = (11 * (sanitizedIndex % MOD_BUFFER_SIZE_FOR_INTEGER) + 2) % MOD_BUFFER_SIZE_FOR_INTEGER;
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
      final byte[] key = new byte[KEY_SIZE];

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

      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos = (toPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos = (toPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);

      toPos = (toPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      work >>>= BYTE_SHIFT;
      destArray[toPos] = (byte) (work & INT_BYTE_MASK);
   }

   /**
    * Get a mask integer from the bytes in an array
    *
    * @param sourceArray Byte array to get the integer from
    * @param startPos Start position in the byte array
    * @return Mask integer
    */
   private int getMaskIntFromArray(final byte[] sourceArray, final int startPos) {
      int result;
      int fromPos = startPos;

      result = (sourceArray[fromPos] & INT_BYTE_MASK);  // This stupid Java sign extension!!!!

      result <<= BYTE_SHIFT;
      fromPos = (fromPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      result <<= BYTE_SHIFT;
      fromPos = (fromPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      result <<= BYTE_SHIFT;
      fromPos = (fromPos + STEP_SIZE) & BUFFER_SIZE_MASK;
      result |= (sourceArray[fromPos] & INT_BYTE_MASK);

      return result;
   }
}
