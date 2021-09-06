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
 *     2015-09-26: V1.0.0: Created. fhs
 *     2018-08-15: V1.0.1: Added a few more "finals". fhs
 *     2018-08-16: V1.0.2: Made name of SPRNG variable conform to class visible variable name. fhs
 *     2019-03-06: V1.1.0: Store array length in an obfuscated form. fhs
 *     2019-05-17: V1.1.1: Clear data first and then set flag that it is cleared. fhs
 *     2019-08-06: V1.1.2: Use SecureRandomFactory. fhs
 *     2019-08-23: V1.1.3: Use SecureRandom singleton. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V1.3.0: Corrected several SonarLint findings and made class serializable. fhs
 *     2020-12-29: V1.4.0: Made thread safe. fhs
 *     2021-05-21: V1.5.0: More store size variation for small source sizes, check max source size. fhs
 *     2021-05-27: V2.0.0: Byte array is protected by an index dependent masker now, no more need for an obfuscation array. fhs
 *     2021-06-09: V2.0.1: Simplified constructors. fhs
 *     2021-09-01: V2.0.2: Some refactoring. fhs
 */
package de.db.bcm.crypto;

import de.db.bcm.arrays.ArrayHelper;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Stores a byte array in a protected form.
 *
 * <p>
 * The array is stored shuffled and masked.
 * </p>
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 2.0.2
 */
public final class ProtectedByteArray implements AutoCloseable {
   //******************************************************************
   // Private constants
   //******************************************************************

   /**
    * Indices and data are stored in arrays which are multiples of this block size
    */
   private static final int INDEX_BLOCK_SIZE = 50;

   /**
    * This class can store at most this many data
    */
   private static final int MAX_SOURCE_ARRAY_LENGTH = (Integer.MAX_VALUE / INDEX_BLOCK_SIZE) * INDEX_BLOCK_SIZE;

   // Pro forma indices for special data.
   // They can have any negative value.

   /**
    * Pro forma index value for the data length
    */
   private static final int INDEX_LENGTH =  -3;

   /**
    * Pro forma index value for the start index
    */
   private static final int INDEX_START  = -97;

   //******************************************************************
   // Instance variables
   //******************************************************************

   /**
    * Byte array to store the data in
    */
   private byte[] m_ByteArray;

   /**
    * Index array into {@code byteArray}
    */
   private int[] m_IndexArray;

   /**
    * Length of data in {@code byteArray} in obfuscated form
    */
   private int m_StoredArrayLength;

   /**
    * Start position in index array
    */
   private int m_IndexStart;

   /**
    * Hash code of data in {@code byteArray}
    */
   private int m_HashCode;

   /**
    * Indicator whether the bytes of the source array have changed
    */
   private boolean m_HasChanged;

   /**
    * Is data valid?
    */
   private boolean m_IsValid;

   /**
    * Index masker
    */
   private MaskedIndex m_IndexMasker;


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Constructor for the protected byte array with a source array
    *
    * @param sourceArray Source byte array.
    * @throws NullPointerException if {@code sourceArray} is {@code null}.
    * @throws IllegalArgumentException if {@code sourceArray} is too large.
    */
   public ProtectedByteArray(final byte[] sourceArray) {
      this(sourceArray, 0);
   }

   public ProtectedByteArray(final byte[] sourceArray, final int offset) {
      Objects.requireNonNull(sourceArray, "Source array is null");

      initializeInstance(sourceArray, offset, sourceArray.length - offset);
   }

   /**
    * Creates a new {@code ProtectedByteArray} for the specified data
    * starting from {@code offset} with length {@code len}.
    *
    * @param sourceArray Source byte array.
    * @param offset      The offset of the data in the byte array.
    * @param len         The length of the data in the byte array.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} are less than 0.
    * @throws IllegalArgumentException       if {@code arrayToProtect} is not long enough to get
    *                                        {@code len} bytes from position {@code offset} in
    *                                        array {@code arrayToProtect}.
    * @throws NullPointerException           if {@code arrayToProtect} is null
    */
   public ProtectedByteArray(final byte[] sourceArray, final int offset, final int len) {
      Objects.requireNonNull(sourceArray, "Source array is null");

      initializeInstance(sourceArray, offset, len);
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /*
    * Access methods
    */

   /**
    * Gets the original array content
    *
    * @return Original array content
    * @throws IllegalStateException if the protected array has already been destroyed
    */
   public synchronized byte[] getData() {
      checkState();

      return getValues();
   }

   /**
    * Gets an array element at a given position
    *
    * @param externalIndex Index of the array element
    * @return Value of the array element at the given position
    * @throws ArrayIndexOutOfBoundsException if index is outside of allowed bounds
    * @throws IllegalStateException          if array has already been destroyed
    */
   public synchronized byte getAt(final int externalIndex) {
      checkStateAndExternalIndex(externalIndex);

      return (byte) (this.m_IndexMasker.getByteMask(externalIndex) ^ this.m_ByteArray[getArrayIndex(externalIndex)]);
   }

   /**
    * Sets the array element at a given position to a given value
    *
    * @param externalIndex Index of the array element
    * @param newValue      New value of the array element
    * @throws ArrayIndexOutOfBoundsException if index is outside of allowed bounds
    * @throws IllegalStateException          if array has already been destroyed
    */
   public synchronized void setAt(final int externalIndex, final byte newValue) {
      checkStateAndExternalIndex(externalIndex);

      this.m_ByteArray[getArrayIndex(externalIndex)] = (byte) (this.m_IndexMasker.getByteMask(externalIndex) ^ newValue);

      this.m_HasChanged = true;
   }

   /**
    * Gets the real array length
    *
    * @return Real length of stored array
    * @throws IllegalStateException if the protected array has already been destroyed
    */
   public synchronized int length() {
      checkState();

      return getRealLength();
   }

   /**
    * Checks whether this ProtectedByteArray is valid
    *
    * @return {@code True}, if this ProtectedByteArray is valid.
    * {@code False}, if it has been deleted
    */
   public synchronized boolean isValid() {
      return this.m_IsValid;
   }

   /**
    * Returns the hash code of this {@code ProtectedByteArray} instance.
    *
    * @return The hash code.
    * @throws IllegalStateException if this protected byte array has already been destroyed.
    */
   @Override
   public synchronized int hashCode() {
      checkState();

      if (this.m_HasChanged)
         calculateHashCode();

      return this.m_HashCode;
   }

   /**
    * Compares the specified object with this {@code ProtectedByteArray} instance.
    *
    * @param obj The object to compare.
    * @return {@code true} if byte arrays of both object are equal, otherwise {@code false}.
    * @throws IllegalStateException if the protected array has already been destroyed.
    */
   @Override
   public synchronized boolean equals(final Object obj) {
      if (obj == null)
         return false;

      if (getClass() != obj.getClass())
         return false;

      boolean result;

      byte[] thisClearArray = null;
      byte[] otherClearArray = null;

      try {
         final ProtectedByteArray other = (ProtectedByteArray) obj;
         thisClearArray = this.getData();
         otherClearArray = other.getData();
         result = Arrays.equals(thisClearArray, otherClearArray);
      } finally {
         // Clear sensitive data
         ArrayHelper.safeClear(thisClearArray);
         ArrayHelper.safeClear(otherClearArray);
      }

      return result;
   }

   /*
    * Method for AutoCloseable interface
    */

   /**
    * Secure deletion of protected array.
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public synchronized void close() {
      if (this.m_IsValid)
         clearData();
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /*
    * Initialization methods
    */

   /**
    * Initialize this instance from a source array
    *
    * @param sourceArray Array to use as source
    * @param offset      The offset of the data in the byte array.
    * @param len         The length of the data in the byte array.
    */
   private void initializeInstance(final byte[] sourceArray, final int offset, final int len) {
      checkOffsetAndLength(sourceArray, offset, len);

      initializeDataStructures(len);

      setValues(sourceArray, offset, len);

      calculateHashCode();
   }


   /*
    * Check methods
    */

   /**
    * Checks whether offset and length are valid for the array
    *
    * @param sourceArray Source byte array.
    * @param offset      The offset of the data in the byte array.
    * @param len         The length of the data in the byte array.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} are less than 0.
    * @throws IllegalArgumentException       if {@code sourceArray} is not long enough to get {@code len} bytes from position
    *                                        {@code offset} in array {@code sourceArray}.
    */
   private void checkOffsetAndLength(final byte[] sourceArray, final int offset, final int len) {
      if (len > MAX_SOURCE_ARRAY_LENGTH)
         throw new IllegalArgumentException("Source array is too large");

      if ((offset < 0) || (len < 0))
         throw new ArrayIndexOutOfBoundsException("offset or length less than zero");

      if ((sourceArray.length - offset) < len)
         throw new IllegalArgumentException("sourceArray too short for offset and length");
   }

   /**
    * Checks whether the protected byte array is in a valid state
    *
    * @throws IllegalStateException if the protected array has already been destroyed
    */
   private void checkState() {
      if (!this.m_IsValid)
         throw new IllegalStateException("ProtectedByteArray has already been destroyed");
   }

   /**
    * Checks whether a given external index is valid
    *
    * @param externalIndex Index value to be checked
    * @throws ArrayIndexOutOfBoundsException if index is out of array bounds
    */
   private void checkExternalIndex(final int externalIndex) {
      if ((externalIndex < 0) || (externalIndex >= getRealLength()))
         throw new ArrayIndexOutOfBoundsException("Illegal index " + externalIndex);
   }

   /**
    * Checks the state and then the validity of the given external index
    *
    * @param externalIndex Index value to be checked
    * @throws ArrayIndexOutOfBoundsException if index is out of array bounds
    * @throws IllegalStateException          if the protected array has already been destroyed
    */
   private void checkStateAndExternalIndex(final int externalIndex) {
      checkState();
      checkExternalIndex(externalIndex);
   }

   /*
    * Methods for data structure initialization and maintenance
    */

   /**
    * Calculates the array size required for storing the data.
    *
    * @param forSize Original size
    * @return Size of protected array
    */
   private int getStoreLength(final int forSize) {
      final int padLength = INDEX_BLOCK_SIZE - (forSize % INDEX_BLOCK_SIZE);

      return forSize + padLength;
   }

   /**
    * Initializes the index array.
    */
   private void initializeIndexArray() {
      for (int i = 0; i < this.m_IndexArray.length; i++)
         this.m_IndexArray[i] = i;
   }

   /**
    * Shuffles the positions in the index array.
    */
   private void shuffleIndexArray(final SecureRandom sprng) {
      int i1;
      int i2;
      int swap;

      int count = 0;

      final int arrayLength = this.m_IndexArray.length;

      do {
         i1 = sprng.nextInt(arrayLength);
         i2 = sprng.nextInt(arrayLength);

         // Swapping is inlined for performance
         if (i1 != i2) {
            swap = this.m_IndexArray[i1];
            this.m_IndexArray[i1] = this.m_IndexArray[i2];
            this.m_IndexArray[i2] = swap;

            count++;
         }
      } while (count < arrayLength);

      // These seemingly unnecessary assignments clear the indices
      // so one can not see their values in a memory dump
      i1 = 0;
      i2 = 0;
   }

   /**
    * Masks the index array.
    */
   private void maskIndexArray() {
      for (int i = 0; i < this.m_IndexArray.length; i++)
         this.m_IndexArray[i] ^= this.m_IndexMasker.getIntMask(i);
   }

   /**
    * Sets up the index array by initializing and shuffling it
    */
   private void setUpIndexArray(final SecureRandom sprng) {
      initializeIndexArray();
      shuffleIndexArray(sprng);
      maskIndexArray();
   }

   /**
    * Allocates and initializes all necessary arrays
    *
    * @param sourceLength Length of source array
    */
   private void initializeDataStructures(final int sourceLength) {
      this.m_IndexMasker = new MaskedIndex();

      final int storeLength = getStoreLength(sourceLength);

      this.m_ByteArray = new byte[storeLength];

      SecureRandom sprng = SecureRandomFactory.getSensibleSingleton();

      sprng.nextBytes(this.m_ByteArray);   // Initialize the data with random values

      this.m_IndexArray = new int[storeLength];

      setUpIndexArray(sprng);

      this.m_IndexStart = convertIndex(getStartIndex(sourceLength, storeLength, sprng), INDEX_START);
      this.m_StoredArrayLength = convertIndex(sourceLength, INDEX_LENGTH);

      this.m_IsValid = true;
   }

   /**
    * Calculate start index
    *
    * @param sourceLength Length of source
    * @param storeLength  Length of store
    * @param sprng        Secure pseudo random number generator
    * @return             Start index in index array
    */
   private int getStartIndex(final int sourceLength, final int storeLength, final SecureRandom sprng) {
      final int supStart = storeLength - sourceLength + 1;

      if (supStart > 1)
         return sprng.nextInt(supStart);
      else
         return 0;
   }

   /**
    * Clears all data
    */
   private void clearData() {
      this.m_HashCode = 0;

      this.m_StoredArrayLength = 0;

      this.m_IndexStart = 0;

      this.m_HasChanged = false;

      this.m_IsValid = false;

      ArrayHelper.clear(this.m_ByteArray);
      this.m_ByteArray = null;

      ArrayHelper.clear(this.m_IndexArray);
      this.m_IndexArray = null;

      this.m_IndexMasker = null;
   }

   /**
    * Convert between real index and masked index
    *
    * @param sourceIndex The index value to convert
    * @param forPosition The position of the index value
    * @return Converted index
    */
   private int convertIndex(final int sourceIndex, final int forPosition) {
      return this.m_IndexMasker.getIntMask(forPosition) ^ sourceIndex;
   }

   /**
    * Gets the array index from the external index
    *
    * @param externalIndex External index
    * @return The index into the byte array
    */
   private int getArrayIndex(final int externalIndex) {
      final int position = externalIndex + convertIndex(this.m_IndexStart, INDEX_START);

      return convertIndex(this.m_IndexArray[position], position);
   }

   /*
    * Methods for accessing data from or to byte array
    */

   /** Gets the real array length without a state check
    *
    * @return Real length
    */
   private int getRealLength() {
      return convertIndex(this.m_StoredArrayLength, INDEX_LENGTH);
   }

   /**
    * Sets the destination array to the values in the source array.
    *
    * @param sourceArray Source byte array
    * @param offset      The offset of the data in the byte array.
    * @param len         The length of the data in the byte array.
    */
   private void setValues(final byte[] sourceArray, final int offset, final int len) {
      int sourceIndex = offset;

      for (int i = 0; i < len; i++) {
         this.m_ByteArray[getArrayIndex(i)] = (byte) (this.m_IndexMasker.getByteMask(i) ^ sourceArray[sourceIndex]);

         sourceIndex++;
      }
   }

   /**
    * Gets the values from the protected array.
    *
    * @return Values stored in protected byte array
    */
   private byte[] getValues() {
      final byte[] result = new byte[getRealLength()];

      for (int i = 0; i < result.length; i++)
         result[i] = (byte) (this.m_IndexMasker.getByteMask(i) ^ this.m_ByteArray[getArrayIndex(i)]);

      return result;
   }

   /**
    * Calculates the hash code of the content
    */
   private void calculateHashCode() {
      final byte[] content = getValues();

      this.m_HashCode = Arrays.hashCode(content);

      ArrayHelper.clear(content);  // Clear sensitive data

      this.m_HasChanged = false;
   }
}
