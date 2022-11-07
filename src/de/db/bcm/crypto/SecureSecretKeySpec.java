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
 *     2016-09-26: V2.0.0: Use ProtectedByteArray. fhs
 *     2016-11-24: V2.1.0: Implement "javax.security.auth.Destroyable" interface. fhs
 *     2018-08-15: V2.1.1: Added a few "finals". fhs
 *     2020-03-10: V2.2.0: Make comparable with {@code SecretKeySpec}, constructor argument checks,
 *                         throw IllegalStateExceptions when instance has been closed or destroyed. fhs
 *     2020-03-11: V2.2.1: Added some "throws" statements. fhs
 *     2020-03-13: V2.3.0: Added checks for null. fhs
 *     2020-03-23: V2.4.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V2.5.0: Corrected several SonarLint findings and made class serializable. fhs
 *     2020-12-29: V2.6.0: Made thread safe. fhs
 *     2021-05-26: V2.7.0: This class is no longer serializable. It never should have been. fhs
 *     2021-09-03: V2.7.1: Correct signatures of Serializable methods. fhs
 *     2021-09-28: V2.7.2: Ensure "equals" clears sensitive array data. fhs
 */
package de.db.bcm.tupw.crypto;

import de.db.bcm.tupw.arrays.ArrayHelper;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;
import java.io.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * A key specification for a {@code SecretKey} and also a secret key
 * implementation that is provider-independent. It can be used for raw secret
 * keys that can be specified as {@code byte[]}.
 *
 * <p>It is intended to be used as a drop-in replacement for {@code SecretKeySpec}.</p>
 *
 * @author Frank Schwab
 * @version 2.7.2
 */
public class SecureSecretKeySpec implements KeySpec, SecretKey, Destroyable, AutoCloseable {
   /*
    * This class implements the Serialization interface because it is inherited from SecretKey
    * but throws an exception whenever a serialization or deserialization is attempted.
    * A secret key must *never* be serializable as this leads to security vulnerabilities.
    */

   /**
    * Serial version UID for Serializable interface that is inherited from {@code javax.crypto.SecretKey}
    * which inherits it from {@code java.secjurity.Key}
    */
   private static final long serialVersionUID = -6754161938847519344L;


   //******************************************************************
   // Private constants
   //******************************************************************

   /*
    * Helper variables for compatible class check
    */
   private final Class thisClass = this.getClass();
   private Class compatibleClass;


   //******************************************************************
   // Instance variables
   //******************************************************************

   private final transient ProtectedByteArray key;
   private final transient ProtectedByteArray algorithm;


   //******************************************************************
   // Constructors
   //******************************************************************

   /**
    * Creates a new {@code SecureSecretKeySpec} for the specified {@code key}
    * and {@code algorithm}.
    *
    * @param key       the key data.
    * @param algorithm the algorithm name.
    * @throws IllegalArgumentException if the key data or the algorithm name is null.
    */
   public SecureSecretKeySpec(final byte[] key, final String algorithm) {
      // All the functionality of the other constructor has to be duplicated here
      // just because of the Java strangeness that a call to another constructor
      // *must* be the first statement in a constructor. This does not make sense,
      // at all! Real object oriented languages do not have this limitation.

      checkKeyAndAlgorithm(key, algorithm);

      this.key = new ProtectedByteArray(key);

      this.algorithm = createNewAlgorithmArray(algorithm);

      setCompatibleClass();
   }

   /**
    * Creates a new {@code SecureSecretKeySpec} for the key data from the
    * specified buffer {@code key} starting at {@code offset} with
    * length {@code len} and the specified {@code algorithm} name.
    *
    * @param key       the key data.
    * @param offset    the offset.
    * @param len       the size of the key data.
    * @param algorithm the algorithm name.
    * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} is negative.
    * @throws IllegalArgumentException       if {@code key} or {@code algorithm} is empty or {@code offset} and {@code len}
    *                                        do not specify a valid chunk in the {@code key}.
    * @throws NullPointerException           if {@code algorithm} or {@code key} is null
    */
   public SecureSecretKeySpec(final byte[] key, final int offset, final int len, final String algorithm) {
      checkKeyAndAlgorithm(key, algorithm);

      this.key = new ProtectedByteArray(key, offset, len);

      this.algorithm = createNewAlgorithmArray(algorithm);

      setCompatibleClass();
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /*
    * Interface methods
    */

   /**
    * Returns the algorithm name.
    *
    * @return the algorithm name.
    * @throws IllegalStateException if the SecureSecretKeySpec has already been destroyed.
    */
   @Override
   public synchronized String getAlgorithm() {
      checkState();

      return new String(algorithm.getData());
   }

   /**
    * Returns the name of the format used to encode the key.
    *
    * @return the format name "RAW".
    * @throws IllegalStateException if the SecureSecretKeySpec has already been destroyed.
    */
   @Override
   public synchronized String getFormat() {
      checkState();

      return "RAW";
   }

   /**
    * Returns the encoded form of this secret key.
    *
    * @return the encoded form of this secret key.
    * @throws IllegalStateException if the SecureSecretKeySpec has already been destroyed.
    */
   @Override
   public synchronized byte[] getEncoded() {
      checkState();

      return this.key.getData();
   }

   /**
    * Returns the hash code of this {@code SecureSecretKeySpec} instance.
    *
    * @return the hash code.
    * @throws IllegalStateException if the SecureSecretKeySpec has already been destroyed.
    */
   @Override
   public synchronized int hashCode() {
      checkState();

      // Java does not indicate an over- or underflow, so it is safe
      // to multiply with a number that will overflow on multiplication
      return this.key.hashCode() * 79 + this.algorithm.hashCode();
   }

   /**
    * Compares the specified object with this {@code SecureSecretKeySpec} instance.
    *
    * @param obj the object to compare.
    * @return {@code true} if the algorithm name and key of both object are equal, otherwise {@code false}.
    * @throws IllegalStateException if the SecureSecretKeySpec has already been destroyed.
    */
   @Override
   public synchronized boolean equals(final Object obj) {
      checkState();

      if (obj == null)
         return false;

      final Class objectClass = obj.getClass();

      if ((objectClass != thisClass) &&
            (objectClass != compatibleClass))
         return false;

      final SecretKey other = (SecretKey) obj;

      boolean result = this.getAlgorithm().equalsIgnoreCase(other.getAlgorithm());

      if (result) {
         byte[] thisKey = null;
         byte[] otherKey = null;

         try {
            thisKey = this.getEncoded();
            otherKey = other.getEncoded();

            result = Arrays.equals(thisKey, otherKey);
         } finally {
            ArrayHelper.safeClear(thisKey);
            ArrayHelper.safeClear(otherKey);
         }
      }

      return result;
   }

   /*
    * Method for AutoCloseable interface
    */

   /**
    * Secure deletion of key and algorithm
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public synchronized void close() {
      this.key.close();
      this.algorithm.close();
   }

   /*
    * Methods for Destroyable interface
    */

   /**
    * Secure destruction of secret key spec
    *
    * <p>This method is idempotent and never throws an exception.</p>
    */
   @Override
   public synchronized void destroy() {
      this.close();
   }

   /**
    * Check whether secret key spec is destroyed
    */
   @Override
   public synchronized boolean isDestroyed() {
      return !this.key.isValid();
   }

   /**
    * Checks whether this SecureSecretKeySpec is valid
    *
    * @return {@code True}, if this instance is valid. {@code False}, if it has been deleted.
    */
   public synchronized boolean isValid() {
      return this.key.isValid();
   }


   //******************************************************************
   // Private methods
   //******************************************************************

   /*
    * Check methods
    */

   /**
    * Checks whether the key and the algorithm are valid
    *
    * @param key       Key array
    * @param algorithm algorithm name as string
    * @throws IllegalArgumentException if {@code algorithm} or {@code key} is empty
    * @throws NullPointerException     if {@code algorithm} or {@code key} is null
    */
   private void checkKeyAndAlgorithm(final byte[] key, final String algorithm) {
      checkKey(key);
      checkAlgorithm(algorithm);
   }

   /**
    * Checks whether algorithm is valid
    *
    * @param algorithm algorithm name as string
    * @throws IllegalArgumentException if {@code algorithm} is empty
    * @throws NullPointerException     if {@code algorithm} is null
    */
   private void checkAlgorithm(final String algorithm) {
      Objects.requireNonNull(algorithm, "Algorithm is null");

      if (algorithm.length() == 0)
         throw new IllegalArgumentException("Algorithm is empty");
   }

   /**
    * Checks whether algorithm is valid
    *
    * @param key Key array
    * @throws IllegalArgumentException if {@code key} is empty
    * @throws NullPointerException     if {@code key} is null
    */
   private void checkKey(final byte[] key) {
      Objects.requireNonNull(key, "Key is null");

      if (key.length == 0)
         throw new IllegalArgumentException("Key is empty");
   }

   /**
    * Checks whether the shuffled byte array is in a valid state
    *
    * @throws IllegalStateException if the SecureSecretKeySpec has already been destroyed
    */
   private void checkState() {
      if (!this.key.isValid())
         throw new IllegalStateException("SecureSecretKeySpec has already been destroyed");
   }

   /**
    * Set the compatible class {@code SecretKeySpec} for use in the {@code equals} method
    */
   private void setCompatibleClass() {
      compatibleClass = SecretKeySpec.class;
   }

   /*
    * Implementation
    */

   /**
    * Creates a new ProtectedByteArray for the algorithm name
    *
    * @param algorithm Name of the algorithm as String
    * @return ProtectedByteArray that hides the algorithm name
    */
   private ProtectedByteArray createNewAlgorithmArray(final String algorithm) {
      final byte[] algorithmBytes = algorithm.getBytes();

      final ProtectedByteArray result = new ProtectedByteArray(algorithmBytes);

      ArrayHelper.clear(algorithmBytes); // Clear sensitive data

      return result;
   }

   //******************************************************************
   // Serializable-Methods
   //******************************************************************

   // We do not serialize a secret key

   private void writeObject(ObjectOutputStream out) throws IOException {
      throw new NotSerializableException("Secret keys must not be serialized");
   }

   private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      throw new NotSerializableException("Secret keys must not be deserialized");
   }

   private void readObjectNoData() throws ObjectStreamException {
      throw new NotSerializableException("Secret keys must not be deserialized");
   }
}
