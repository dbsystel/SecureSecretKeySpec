/*
 * Copyright (c) 2021, DB Systel GmbH
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
 */
package de.db.bcm.tupw.crypto;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Class to get masks for array indices
 */
public class MaskedIndex {
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
   public synchronized int getIntMask(int forIndex) {
      getMaskBuffer(forIndex);

      final int result = bytesToInt(m_MaskBuffer, (7 * (Math.abs(forIndex) % 13) + 3) % 13);

      Arrays.fill(m_MaskBuffer, (byte) 0);

      return result;
   }

   /**
    * Get a byte mask for an index
    *
    * @param forIndex The index to use
    * @return The byte mask for the given index
    */
   public synchronized byte getByteMask(final int forIndex) {
      getMaskBuffer(forIndex);

      final byte result = m_MaskBuffer[(13 * (forIndex & 0xf) + 5) & 0xf];

      Arrays.fill(m_MaskBuffer, (byte) 0);

      return result;
   }

   //******************************************************************
   // Private methods
   //******************************************************************

   /**
    * Calculate a buffer full of mask bytes
    *
    * @param forIndex The index to use for the mask calculation
    */
   private void getMaskBuffer(final int forIndex) {
      Arrays.fill(m_SourceBuffer, (byte) 0x5a);

      intToBytes(forIndex, m_SourceBuffer, 6);

      try {
         m_Encryptor.doFinal(m_SourceBuffer, 0, m_SourceBuffer.length, m_MaskBuffer, 0);
      } catch (Exception ex) {
         // BadPaddingException, IllegalBlockSizeException and ShortBufferException can never happen
      }

      Arrays.fill(m_SourceBuffer, (byte) 0);
   }

   /**
    * Initialize the cipher
    */
   private void initializeCipher() {
      final byte[] key = new byte[16];

      final SecureRandom sprng = SecureRandomFactory.getSensibleSingleton();

      sprng.nextBytes(key);

      try {
         m_Encryptor = Cipher.getInstance("AES/ECB/NoPadding");
         SecretKeySpec maskKey = new SecretKeySpec(key, "AES");

         m_Encryptor.init(Cipher.ENCRYPT_MODE, maskKey);
      } catch (Exception ex) {
         // InvalidKeyException, NoSuchAlgorithmException and NoSuchPaddingException can never happen
      }

      Arrays.fill(key, (byte) 0);
   }

   /**
    * Converts an int to a byte array
    *
    * @param i Integer to convert
    * @param destArray Destination byte array
    * @param startPos Start position in the byte array
    */
   private void intToBytes(final int i, final byte[] destArray, final int startPos) {
      destArray[startPos] = (byte) ((i >> 24) & 0xff);
      destArray[startPos + 1] = (byte) ((i >> 16) & 0xff);
      destArray[startPos + 2] = (byte) ((i >> 8) & 0xff);
      destArray[startPos + 3] = (byte) (i & 0xff);
   }

   /**
    * Converts a byte array to an int
    *
    * @param b Byte array to convert
    * @param startPos Start position in the byte array
    * @return The byte array as an integer
    */
   private int bytesToInt(final byte[] b, int startPos) {
      return (0xff000000 & (b[startPos] << 24))
            | (0xff0000 & (b[startPos + 1] << 16))
            | (0xff00 & (b[startPos + 2] << 8))
            | (0xff & b[startPos + 3]);
   }
}
