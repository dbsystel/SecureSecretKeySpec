/*
 * Copyright (c) 2018, DB Systel GmbH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Frank Schwab, DB Systel GmbH
 *
 * Changes:
 *     2016-09-26: V4.1.0: Created. fhs
 *     2016-11-24: V4.2.0: Make "isValid" property of underlying array publicly available. fhs
 *     2017-12-21: V4.2.1: Added "throws" tags. fhs
 *     2018-08-15: V4.2.2: Added a few "finals". fhs
 *     2020-03-10: V4.3.0: Use "SecureRandomFactory". fhs
 */
package dbscryptolib;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Stores a byte array in a protected form where "protection" means that 1. the
 * data are only stored in an obfuscated form and 2. the data are cleared from
 * memory when "close" is called.
 * <p>
 * Note: The content of the byte array can not be changed after it has been set
 * with the constructor.
 *
 * @author Frank Schwab
 * @version 4.3.0
 */
public final class ProtectedByteArray implements AutoCloseable {

   private final ShuffledByteArray protectedArray;
   private final ShuffledByteArray obfuscation;

   /**
    * Creates a new <code>ProtectedByteArray</code> for the specified data.
    *
    * @param arrayToProtect The byte array to protect.
    * @throws IllegalArgumentException if <code>arrayToProtect</code> is null.
    */
   public ProtectedByteArray(final byte[] arrayToProtect) throws IllegalArgumentException {
      this.protectedArray = new ShuffledByteArray(arrayToProtect);

      this.obfuscation = createNewObfuscationArray(arrayToProtect.length);

      storeInObfuscatedArray(arrayToProtect);
   }

   /**
    * Creates a new <code>ProtectedByteArray</code> for the specified data
    * starting from <code>offset</code> with length <code>len</code>.
    *
    * @param arrayToProtect The byte array to protect.
    * @param offset         The offset of the data in the byte array.
    * @param len            The length of the data in the byte array.
    * @throws ArrayIndexOutOfBoundsException if <code>offset</code> or
    *                                        <code>len</code> are less than 0.
    * @throws IllegalArgumentException       if <code>arrayToProtect</code> is not
    *                                        long enough to get <code>len</code> bytes from position
    *                                        <code>offset</code> in array <code>arrayToProtect</code>.
    */
   public ProtectedByteArray(final byte[] arrayToProtect, final int offset, final int len) throws ArrayIndexOutOfBoundsException, IllegalArgumentException {
      checkArray(arrayToProtect);

      checkOffsetAndLength(arrayToProtect, offset, len);

      final byte[] intermediateArray = new byte[len];
      System.arraycopy(arrayToProtect, offset, intermediateArray, 0, len);

      this.protectedArray = new ShuffledByteArray(intermediateArray);

      this.obfuscation = createNewObfuscationArray(len);

      storeInObfuscatedArray(intermediateArray);

      Arrays.fill(intermediateArray, (byte) 0); // Clear sensitive data
   }

   /*
    * Check methods
    */

   /**
    * Checks whether array is valid
    *
    * Note: An array length of 0 is allowed
    *
    * @param arrayToProtect Key as byte array
    * @throws IllegalArgumentException if <code>arrayToProtect</code> is null
    */
   private void checkArray(final byte[] arrayToProtect) throws IllegalArgumentException {
      if (arrayToProtect == null)
         throw new IllegalArgumentException("arrayToProtect is null");
   }

   /**
    * Checks whether offset and length are valid for the array
    *
    * @param arrayToProtect Key as byte array
    * @param offset         The offset of the data in the byte array.
    * @param len            The length of the data in the byte array.
    * @throws ArrayIndexOutOfBoundsException if <code>offset</code> or <code>len</code> are less than 0.
    * @throws IllegalArgumentException       if <code>arrayToProtect</code> is not long enough to get <code>len</code> bytes from position
    *                                        <code>offset</code> in array <code>arrayToProtect</code>.
    */
   private void checkOffsetAndLength(final byte[] arrayToProtect, final int offset, final int len) throws IllegalArgumentException {
      if ((offset < 0) || (len < 0))
         throw new ArrayIndexOutOfBoundsException("offset < 0 || len < 0");

      if ((arrayToProtect.length - offset) < len)
         throw new IllegalArgumentException("arrayToProtect too short for offset and length");
   }

   /**
    * Checks whether the protected byte array is in a valid state
    *
    * @throws IllegalStateException if the shuffled array has already been
    * destroyed
    */
   private void checkState() throws IllegalStateException {
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
    * @throws IllegalStateException if protectedArray has alreqady been destroyed
    */
   private byte[] getDeObfuscatedArray() throws IllegalStateException {
      final byte[] result = new byte[this.protectedArray.length()];

      // Need to cast a byte xor to a byte as Java does not define an
      // xor operation on bytes but silently converts the bytes to
      // ints before doing the xor. One more Java stupidity.
      for (int i = 0; i < this.protectedArray.length(); i++)
         result[i] = (byte) (this.protectedArray.getAt(i) ^ this.obfuscation.getAt(i));

      return result;
   }

   /*
    * Access methods
    */

   /**
    * Returns the data of the byte array in the clear.
    *
    * @return the data in the byte array.
    * @throws IllegalStateException if the protected array has already been destroyed.
    */
   public byte[] getData() throws IllegalStateException {
      checkState();

      return getDeObfuscatedArray();
   }

   /**
    * Returns the hash code of this <code>ProtectedByteArray</code> instance.
    *
    * @return The hash code.
    * @throws IllegalStateException if the protected array has already been
    *                               destroyed.
    */
   @Override
   public int hashCode() throws IllegalStateException {
      checkState();

      return this.protectedArray.hashCode();
   }

   /**
    * Compares the specified object with this <code>ProtectedByteArray</code>
    * instance.
    *
    * @param obj The object to compare.
    * @return true if byte arrays of both object are equal, otherwise false.
    * @throws IllegalStateException if the protected array has already been  destroyed.
    */
   @Override
   public boolean equals(final Object obj) throws IllegalStateException {
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
   public int length() throws IllegalStateException {
      checkState();

      return this.protectedArray.length();
   }

   /**
    * Check whether this <code>ProtectedByteArray</code> contains valid data
    *
    * @return <code>true</code>: Data are valid. <code>false</code>: Data are
    * not valid.
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
    * This method is idempotent and never throws an exception.
    */
   @Override
   public void close() {
      this.protectedArray.close();
      this.obfuscation.close();
   }
}
