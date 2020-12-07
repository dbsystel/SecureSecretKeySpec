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
 *     2015-09-26: V1.0.0: Created. fhs
 *     2018-08-15: V1.0.1: Added a few more "finals". fhs
 *     2018-08-16: V1.0.2: Made name of SPRNG variable conform to class visible variable name. fhs
 *     2019-03-06: V1.1.0: Store array length in an obfuscated form. fhs
 *     2019-05-17: V1.1.1: Clear data first and then set flag that it is cleared. fhs
 *     2019-08-06: V1.1.2: Use SecureRandomFactory. fhs
 *     2019-08-23: V1.1.3: Use SecureRandom singleton. fhs
 *     2020-03-23: V1.2.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V1.3.0: Corrected several SonarLint findings and made class serializable. fhs
 */
package de.db.bcm.tupw.crypto;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Stores a byte array in a shuffled form.
 *
 * @author Frank Schwab
 * @version 1.3.0
 */
public final class ShuffledByteArray implements AutoCloseable, Serializable {
   /**
    * Serial version UID for Serializable interface
    */
   private static final long serialVersionUID = 7824599800903260500L;

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
   private int indexOffset;
   private int indexFactor;
   private int indexStart;

   /**
    * Length of data in {@code byteArray} in obfuscated form
    */
   private int storedArrayLength;

   /**
    * Hash code of data in {@code byteArray}
    */
   private int hashCode;

   /**
    * Is data in {@code byteArray} valid?
    */
   private boolean isValid;

   /*
    * Random numbers are needed in several places so the PRNG is instantiated
    * once at the class level.
    */
   private final SecureRandom SECURE_PRNG = SecureRandomFactory.getSensibleSingleton();


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Constructor for the shuffled byte array with a source array
    *
    * @param sourceArray Source byte array
    * @throws IllegalArgumentException if {@code sourceArray} is {@code null}
    */
   public ShuffledByteArray(final byte[] sourceArray) {
      Objects.requireNonNull(sourceArray, "Source array is null");

      initializeDataStructures(sourceArray.length);
      setValues(sourceArray);

      this.hashCode = Arrays.hashCode(sourceArray);   // Calculate hash code of source only once

      this.isValid = true;
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
    * @throws IllegalStateException if the shuffled array has already been destroyed
    */
   public byte[] getData() {
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
   public byte getAt(final int externalIndex) {
      checkStateAndExternalIndex(externalIndex);

      return this.byteArray[getArrayIndex(externalIndex)];
   }

   /**
    * Sets the array element at a given position to a given value
    *
    * @param externalIndex Index of the array element
    * @param newValue      New value of the array element
    * @throws ArrayIndexOutOfBoundsException if index is outside of allowed bounds
    * @throws IllegalStateException          if array has already been destroyed
    */
   public void setAt(final int externalIndex, final byte newValue) {
      checkStateAndExternalIndex(externalIndex);

      this.byteArray[getArrayIndex(externalIndex)] = newValue;
   }

   /**
    * Gets the real array length
    *
    * @return Real length of stored array
    * @throws IllegalStateException if the shuffled array has already been
    *                               destroyed
    */
   public int length() {
      checkState();

      return getRealIndex(this.storedArrayLength);
   }

   /**
    * Checks whether this ShuffledByteArray is valid
    *
    * @return {@code True}, if this ShuffledByteArray is valid.
    * {@code False}, if it has been deleted
    */
   public boolean isValid() {
      return this.isValid;
   }

   /**
    * Returns the hash code of this {@code ShuffledByteArray} instance.
    *
    * @return The hash code.
    * @throws IllegalStateException if this shuffled byte array has already been destroyed.
    */
   @Override
   public int hashCode() {
      checkState();

      return this.hashCode;
   }

   /**
    * Compares the specified object with this {@code ShuffledByteArray} instance.
    *
    * @param obj The object to compare.
    * @return {@code true} if byte arrays of both object are equal, otherwise {@code false}.
    * @throws IllegalStateException if the protected array has already been destroyed.
    */
   @Override
   public boolean equals(final Object obj) {
      if (obj == null)
         return false;

      if (getClass() != obj.getClass())
         return false;

      final ShuffledByteArray other = (ShuffledByteArray) obj;
      final byte[] thisClearArray = this.getData();
      final byte[] otherClearArray = other.getData();
      final boolean result = Arrays.equals(thisClearArray, otherClearArray);

      Arrays.fill(thisClearArray, (byte) 0); // Clear sensitive data
      Arrays.fill(otherClearArray, (byte) 0); // Clear sensitive data

      return result;
   }

   /*
    * Method for AutoCloseable interface
    */

   /**
    * Secure deletion of shuffled array.
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public void close() {
      if (this.isValid) {
         clearData();

         this.isValid = false;
      }
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /*
    * Check methods
    */

   /**
    * Checks whether the shuffled byte array is in a valid state
    *
    * @throws IllegalStateException if the shuffled array has already been destroyed
    */
   private void checkState() {
      if (!this.isValid)
         throw new IllegalStateException("ShuffledByteArray has already been destroyed");
   }

   /**
    * Checks whether a given external index is valid
    *
    * @param externalIndex Index value to be checked
    * @throws ArrayIndexOutOfBoundsException if index is out of array bounds
    */
   private void checkExternalIndex(final int externalIndex) {
      if ((externalIndex < 0) || (externalIndex >= getRealIndex(this.storedArrayLength)))
         throw new ArrayIndexOutOfBoundsException("Illegal index " + externalIndex);
   }

   /**
    * Checks the state and then the validity of the given external index
    *
    * @param externalIndex Index value to be checked
    * @throws ArrayIndexOutOfBoundsException if index is out of array bounds
    * @throws IllegalStateException          if the shuffled array has already been destroyed
    */
   private void checkStateAndExternalIndex(final int externalIndex) {
      checkState();
      checkExternalIndex(externalIndex);
   }

   /*
    * Methods for data structure initialization and maintenance
    */

   /**
    * Calculates the array size required for storing the data. The stored array
    * has at least twice the size of the original array to be able to set a
    * random start point in the index reorder array.
    *
    * @param forSize Original size
    * @return Size of shuffled array
    */
   private int getStoreLength(final int forSize) {
      final int calcSize = forSize + forSize + 7;

      return this.SECURE_PRNG.nextInt(calcSize) + calcSize;
   }

   /**
    * Gets the offset for index obfuscation
    *
    * @param arrayLength Length of the array
    * @return Offset for indices
    */
   private int getIndexOffset(final int arrayLength) {
      return this.SECURE_PRNG.nextInt(100000) + arrayLength + arrayLength + 1;
   }

   /**
    * Gets the factor for index obfuscation
    *
    * @param offset      Offset for indices
    * @param arrayLength Length of the array
    * @return Factor for indices
    */
   private int getIndexFactor(final int offset, final int arrayLength) {
      return (5 * offset) / (3 * arrayLength);
   }

   /**
    * Initializes the index array with each position holding it's own index in
    * store index form.
    */
   private void initializeIndexArray() {
      for (int i = 0; i < this.indexArray.length; i++)
         this.indexArray[i] = getStoreIndex(i);
   }

   /**
    * Shuffles the positions in the index array.
    */
   private void shuffleIndexArray() {
      int i1;
      int i2;
      int swap;

      int count = 0;

      final int arrayLength = this.indexArray.length;

      do {
         i1 = this.SECURE_PRNG.nextInt(arrayLength);
         i2 = this.SECURE_PRNG.nextInt(arrayLength);

         // Swapping is inlined for performance
         if (i1 != i2) {
            swap = this.indexArray[i1];
            this.indexArray[i1] = this.indexArray[i2];
            this.indexArray[i2] = swap;

            count++;
         }
      } while (count < arrayLength);
   }

   /**
    * Gets the start position in an array
    *
    * @param arrayLength Length of the array to get the start position for
    * @return Start position in the array
    */
   private int getStartPosition(final int arrayLength) {
      // "+1" because the max. start position is at the half size of
      // the array.
      return this.SECURE_PRNG.nextInt((arrayLength >> 1) + 1);
   }

   /**
    * Reorganizes the index array for reordering of the byte array.
    *
    * <p>This includes setting a random start position in the index array.</p>
    */
   private void reorganizeIndexArray() {
      shuffleIndexArray();

      this.indexStart = getStartPosition(this.indexArray.length);
   }

   /**
    * Sets up the index array by initializing and shuffling it
    */
   private void setUpIndexArray() {
      initializeIndexArray();
      reorganizeIndexArray();
   }

   /**
    * Allocates and initializes all necessary arrays
    *
    * @param sourceLength Length of source array
    */
   private void initializeDataStructures(final int sourceLength) {
      final int storeLength = getStoreLength(sourceLength);

      this.byteArray = new byte[storeLength];
      this.SECURE_PRNG.nextBytes(this.byteArray);   // Initialize the data with random values

      this.indexArray = new int[storeLength];

      this.indexOffset = getIndexOffset(storeLength);
      this.indexFactor = getIndexFactor(this.indexOffset, storeLength);
      setUpIndexArray();

      this.storedArrayLength = getStoreIndex(sourceLength);
   }

   /**
    * Clears all data
    */
   private void clearData() {
      Arrays.fill(this.byteArray, (byte) 0); // Clear sensitive data

      Arrays.fill(this.indexArray, 0);

      this.indexStart = 0;
      this.indexOffset = 0;
      this.indexFactor = 0;

      this.hashCode = 0;

      this.storedArrayLength = 0;
   }

   /**
    * Gets the store index from the real index
    *
    * @param realIndex Real index
    * @return Store index
    */
   private int getStoreIndex(final int realIndex) {
      // 2 is added so that the indexOffset is not put out for a realIndex of 0
      // and neither is the difference of indexOffset and indexFactor.
      return (this.indexFactor * (realIndex + 2)) - this.indexOffset;
   }

   /**
    * Gets the real index from the store index
    *
    * @param storeIndex Store index
    * @return Real index
    */
   private int getRealIndex(final int storeIndex) {
      return ((storeIndex + this.indexOffset) / this.indexFactor) - 2;
   }

   /**
    * Gets the array index from the external index
    *
    * @param externalIndex External index
    * @return The index into the byte array
    */
   private int getArrayIndex(final int externalIndex) {
      return getRealIndex(this.indexArray[externalIndex + this.indexStart]);
   }

   /*
    * Methods for accessing data from or to byte array
    */

   /**
    * Sets the destination array to the values in the source array.
    *
    * @param sourceArray Source byte array
    */
   private void setValues(final byte[] sourceArray) {
      for (int i = 0; i < sourceArray.length; i++)
         this.byteArray[getArrayIndex(i)] = sourceArray[i];
   }

   /**
    * Gets the values from the shuffled array.
    *
    * @return Values stored in shuffled byte array
    */
   private byte[] getValues() {
      final byte[] result = new byte[getRealIndex(this.storedArrayLength)];

      for (int i = 0; i < result.length; i++)
         result[i] = this.byteArray[getArrayIndex(i)];

      return result;
   }
}
