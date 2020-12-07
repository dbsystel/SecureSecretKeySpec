/*
 * Copyright (c) 2020, DB Systel GmbH
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
 *     2016-09-26: V4.1.0: Created. fhs
 *     2016-11-24: V4.2.0: Make "isValid" property of underlying array publicly available. fhs
 *     2017-12-21: V4.2.1: Added "throws" tags. fhs
 *     2018-08-15: V4.2.2: Added a few "finals". fhs
 *     2020-03-10: V4.3.0: Use "SecureRandomFactory". fhs
 *     2020-03-10: V4.4.0: Added "length" method and checks of state. fhs
 *     2020-03-13: V4.5.0: Added checks for null. fhs
 *     2020-03-23: V4.6.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V4.7.0: Corrected several SonarLint findings and made class serializable. fhs
 */
package de.db.bcm.tupw.crypto;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Stores a byte array in a protected form where "protection" means that 1. the
 * data are only stored in an obfuscated form and 2. the data are cleared from
 * memory when "close" is called.
 *
 * <p>Note: The content of the byte array can not be changed after it has been set
 * with the constructor.</p>
 *
 * @author Frank Schwab
 * @version 4.7.0
 */
public final class ProtectedByteArray implements AutoCloseable, Serializable {
   /**
    * Serial version UID for Serializable interface
    */
   private static final long serialVersionUID = -491054792691223953L;

   //******************************************************************
   // Instance variables
   //******************************************************************

   private final ShuffledByteArray protectedArray;
   private final ShuffledByteArray obfuscation;


   //******************************************************************
   // Constructors
   //******************************************************************

   /**
    * Creates a new {@code ProtectedByteArray} for the specified data.
    *
    * @param arrayToProtect The byte array to protect.
    * @throws NullPointerException if {@code arrayToProtect} is null
    */
   public ProtectedByteArray(final byte[] arrayToProtect) {
      Objects.requireNonNull(arrayToProtect, "Array to protect is null");

      this.protectedArray = new ShuffledByteArray(arrayToProtect);

      this.obfuscation = createNewObfuscationArray(arrayToProtect.length);

      storeInObfuscatedArray(arrayToProtect);
   }

   /**
    * Creates a new {@code ProtectedByteArray} for the specified data
    * starting from {@code offset} with length {@code len}.
    *
    * @param arrayToProtect The byte array to protect.
    * @param offset         The offset of the data in the byte array.
    * @param len            The length of the data in the byte array.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} are less than 0.
    * @throws IllegalArgumentException       if {@code arrayToProtect} is not long enough to get
    *                                        {@code len} bytes from position {@code offset} in
    *                                        array {@code arrayToProtect}.
    * @throws NullPointerException           if {@code arrayToProtect} is null
    */
   public ProtectedByteArray(final byte[] arrayToProtect, final int offset, final int len) {
      Objects.requireNonNull(arrayToProtect, "Array to protect is null");

      checkOffsetAndLength(arrayToProtect, offset, len);

      final byte[] intermediateArray = new byte[len];
      System.arraycopy(arrayToProtect, offset, intermediateArray, 0, len);

      this.protectedArray = new ShuffledByteArray(intermediateArray);

      this.obfuscation = createNewObfuscationArray(len);

      storeInObfuscatedArray(intermediateArray);

      Arrays.fill(intermediateArray, (byte) 0); // Clear sensitive data
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Returns the data of the byte array in the clear.
    *
    * @return the data in the byte array.
    * @throws IllegalStateException if the protected array has already been destroyed.
    */
   public byte[] getData() {
      checkState();

      return getDeObfuscatedArray();
   }

   /**
    * Returns the hash code of this {@code ProtectedByteArray} instance.
    *
    * @return The hash code.
    * @throws IllegalStateException if the protected array has already been
    *                               destroyed.
    */
   @Override
   public int hashCode() {
      checkState();

      return this.protectedArray.hashCode();
   }

   /**
    * Compares the specified object with this {@code ProtectedByteArray}
    * instance.
    *
    * @param obj The object to compare.
    * @return true if byte arrays of both object are equal, otherwise false.
    * @throws IllegalStateException if the protected array has already been  destroyed.
    */
   @Override
   public boolean equals(final Object obj) {
      checkState();

      if (obj == null)
         return false;

      if (getClass() != obj.getClass())
         return false;

      final ProtectedByteArray other = (ProtectedByteArray) obj;
      final byte[] thisClearKey = this.getData();
      final byte[] otherClearKey = other.getData();

      final boolean result = Arrays.equals(thisClearKey, otherClearKey);

      Arrays.fill(thisClearKey, (byte) 0);
      Arrays.fill(otherClearKey, (byte) 0);

      return result;
   }

   /**
    * Gets the array length
    *
    * @return Real length of stored array
    * @throws IllegalStateException if the protected array has already been destroyed
    */
   public int length() {
      checkState();

      return this.protectedArray.length();
   }

   /**
    * Check whether this {@code ProtectedByteArray} contains valid data
    *
    * @return {@code true}: Data are valid. {@code false}: Data are not valid.
    */
   public boolean isValid() {
      return this.protectedArray.isValid();
   }

   /*
    * Method for AutoCloseable interface
    */

   /**
    * Secure deletion of byte array.
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public void close() {
      this.protectedArray.close();
      this.obfuscation.close();
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /*
    * Check methods
    */

   /**
    * Checks whether offset and length are valid for the array
    *
    * @param arrayToProtect Key as byte array
    * @param offset         The offset of the data in the byte array.
    * @param len            The length of the data in the byte array.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} are less than 0.
    * @throws IllegalArgumentException       if {@code arrayToProtect} is not long enough to get {@code len} bytes from position
    *                                        {@code offset} in array {@code arrayToProtect}.
    */
   private void checkOffsetAndLength(final byte[] arrayToProtect, final int offset, final int len) {
      if ((offset < 0) || (len < 0))
         throw new ArrayIndexOutOfBoundsException("offset < 0 || len < 0");

      if ((arrayToProtect.length - offset) < len)
         throw new IllegalArgumentException("arrayToProtect too short for offset and length");
   }

   /**
    * Checks whether the protected byte array is in a valid state
    *
    * @throws IllegalStateException if the shuffled array has already been
    *                               destroyed
    */
   private void checkState() {
      if (!this.protectedArray.isValid())
         throw new IllegalStateException("ProtectedByteArray has already been destroyed");
   }

   /*
    * Methods for obfuscation and deobfuscation
    */

   /**
    * Creates a new obfuscation array
    *
    * @param arrayLength Length of the new obfuscation array
    * @return New obfuscation array as ShuffledByteArray
    */
   private ShuffledByteArray createNewObfuscationArray(final int arrayLength) {
      final byte[] obfuscationSource = new byte[arrayLength];
      final SecureRandom sprng = SecureRandomFactory.getSensibleSingleton();

      sprng.nextBytes(obfuscationSource);

      final ShuffledByteArray result = new ShuffledByteArray(obfuscationSource);

      Arrays.fill(obfuscationSource, (byte) 0); // Clear sensitive data

      return result;
   }

   /**
    * Stores the source xored with the obfuscation bytes in the protected array.
    */
   private void storeInObfuscatedArray(final byte[] source) {
      // Need to cast a byte xor to a byte as Java does not define an
      // xor operation on bytes but silently converts the bytes to
      // ints before doing the xor. One more Java stupidity.
      for (int i = 0; i < source.length; i++)
         this.protectedArray.setAt(i, (byte) (source[i] ^ this.obfuscation.getAt(i)));
   }

   /**
    * Xors the obfuscated array to get the clear data
    *
    * @return Byte array of clear data
    * @throws IllegalStateException if protectedArray has already been destroyed
    */
   private byte[] getDeObfuscatedArray() {
      final byte[] result = new byte[this.protectedArray.length()];

      // Need to cast a byte xor to a byte as Java does not define an
      // xor operation on bytes but silently converts the bytes to
      // ints before doing the xor. One more Java stupidity.
      for (int i = 0; i < this.protectedArray.length(); i++)
         result[i] = (byte) (this.protectedArray.getAt(i) ^ this.obfuscation.getAt(i));

      return result;
   }
}
