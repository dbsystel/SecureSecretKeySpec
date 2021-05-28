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
 */
package de.db.bcm.tupw.crypto;

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
 * @author Frank Schwab
 * @version 2.0.0
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

   /**
    * Bytes to fill arrays with for security reasons
    */
   private static final byte FILL_BYTE = (byte) 0;

   //******************************************************************
   // Instance variables
   //******************************************************************

   /**
    * Byte array to store the data in
    */
   private byte[] byteArray;

   /**
    * Index array into {@code byteArray}
    */
   private int[] indexArray;

   /**
    * Length of data in {@code byteArray} in obfuscated form
    */
   private int storedArrayLength;

   /**
    * Start position in index array
    */
   private int indexStart;

   /**
    * Hash code of data in {@code byteArray}
    */
   private int hashCode;

   /**
    * Indicator whether the bytes of the source array have changed
    */
   private boolean hasChanged;

   /**
    * Is data valid?
    */
   private boolean isValid;

   /**
    * Index masker
    */
   private MaskedIndex indexMasker;


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
      Objects.requireNonNull(sourceArray, "Source array is null");

      if (sourceArray.length > MAX_SOURCE_ARRAY_LENGTH)
         throw new IllegalArgumentException("Source array is too large");

      initializeInstance(sourceArray);
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

      if (len > MAX_SOURCE_ARRAY_LENGTH)
         throw new IllegalArgumentException("Length is too large");

      checkOffsetAndLength(sourceArray, offset, len);

      final byte[] intermediateArray = new byte[len];
      System.arraycopy(sourceArray, offset, intermediateArray, 0, len);

      initializeInstance(intermediateArray);

      Arrays.fill(intermediateArray, FILL_BYTE); // Clear sensitive data
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

      return (byte) (this.indexMasker.getByteMask(externalIndex) ^ this.byteArray[getArrayIndex(externalIndex)]);
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

      this.byteArray[getArrayIndex(externalIndex)] = (byte) (this.indexMasker.getByteMask(externalIndex) ^ newValue);

      this.hasChanged = true;
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
    * @return {@code True}, if this ProtecedByteArray is valid.
    * {@code False}, if it has been deleted
    */
   public synchronized boolean isValid() {
      return this.isValid;
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

      if (this.hasChanged)
         calculateHashCode();

      return this.hashCode;
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

      final ProtectedByteArray other = (ProtectedByteArray) obj;
      final byte[] thisClearArray = this.getData();
      final byte[] otherClearArray = other.getData();
      final boolean result = Arrays.equals(thisClearArray, otherClearArray);

      Arrays.fill(thisClearArray, FILL_BYTE); // Clear sensitive data
      Arrays.fill(otherClearArray, FILL_BYTE); // Clear sensitive data

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
      if (this.isValid)
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
    */
   private void initializeInstance(byte[] sourceArray) {
      this.hashCode = Arrays.hashCode(sourceArray);   // Calculate hash code of source once

      this.indexMasker = new MaskedIndex();

      initializeDataStructures(sourceArray.length);

      setValues(sourceArray);

      this.hasChanged = false;
      this.isValid = true;
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
      if (!this.isValid)
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
      for (int i = 0; i < this.indexArray.length; i++)
         this.indexArray[i] = i;
   }

   /**
    * Shuffles the positions in the index array.
    */
   private void shuffleIndexArray(final SecureRandom sprng) {
      int i1;
      int i2;
      int swap;

      int count = 0;

      final int arrayLength = this.indexArray.length;

      do {
         i1 = sprng.nextInt(arrayLength);
         i2 = sprng.nextInt(arrayLength);

         // Swapping is inlined for performance
         if (i1 != i2) {
            swap = this.indexArray[i1];
            this.indexArray[i1] = this.indexArray[i2];
            this.indexArray[i2] = swap;

            count++;
         }
      } while (count < arrayLength);

      i1 = 0;
      i2 = 0;
   }

   /**
    * Masks the index array.
    */
   private void maskIndexArray() {
      for (int i = 0; i < this.indexArray.length; i++)
         this.indexArray[i] ^= this.indexMasker.getIntMask(i);
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
      final int storeLength = getStoreLength(sourceLength);

      this.byteArray = new byte[storeLength];

      SecureRandom sprng = SecureRandomFactory.getSensibleSingleton();

      sprng.nextBytes(this.byteArray);   // Initialize the data with random values

      this.indexArray = new int[storeLength];

      setUpIndexArray(sprng);

      this.indexStart = convertIndex(getStartIndex(sourceLength, storeLength, sprng), INDEX_START);
      this.storedArrayLength = convertIndex(sourceLength, INDEX_LENGTH);
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
      Arrays.fill(this.byteArray, FILL_BYTE); // Clear sensitive data

      Arrays.fill(this.indexArray, 0);

      this.hashCode = 0;

      this.storedArrayLength = 0;

      this.indexStart = 0;

      this.hasChanged = false;

      this.isValid = false;
   }

   /**
    * Convert between real index and masked index
    *
    * @param sourceIndex The index value to convert
    * @param forPosition The position of the index value
    * @return Converted index
    */
   private int convertIndex(final int sourceIndex, final int forPosition) {
      return this.indexMasker.getIntMask(forPosition) ^ sourceIndex;
   }

   /**
    * Gets the array index from the external index
    *
    * @param externalIndex External index
    * @return The index into the byte array
    */
   private int getArrayIndex(final int externalIndex) {
      final int position = externalIndex + convertIndex(this.indexStart, INDEX_START);

      return convertIndex(this.indexArray[position], position);
   }

   /*
    * Methods for accessing data from or to byte array
    */

   /** Gets the real array length without a state check
    *
    * @return Real length
    */
   private int getRealLength() {
      return convertIndex(this.storedArrayLength, INDEX_LENGTH);
   }

   /**
    * Sets the destination array to the values in the source array.
    *
    * @param sourceArray Source byte array
    */
   private void setValues(final byte[] sourceArray) {
      for (int i = 0; i < sourceArray.length; i++)
         this.byteArray[getArrayIndex(i)] = (byte) (this.indexMasker.getByteMask(i) ^ sourceArray[i]);
   }

   /**
    * Gets the values from the protected array.
    *
    * @return Values stored in protected byte array
    */
   private byte[] getValues() {
      final byte[] result = new byte[this.length()];

      for (int i = 0; i < result.length; i++)
         result[i] = (byte) (this.indexMasker.getByteMask(i) ^ this.byteArray[getArrayIndex(i)]);

      return result;
   }

   /**
    * Calculates the hash code of the content
    */
   private void calculateHashCode() {
      byte[] content = getValues();

      this.hashCode = Arrays.hashCode(content);   // Calculate hash code of source once

      Arrays.fill(content, FILL_BYTE);  // Clear sensitive data

      this.hasChanged = false;
   }
}
