/*
 * Copyright (c) 2020, DB Systel GmbH
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
 *     2016-09-26: V2.0.0: Use ProtectedByteArray. fhs
 *     2016-11-24: V2.1.0: Implement "javax.security.auth.Destroyable" interface. fhs
 *     2018-08-15: V2.1.1: Added a few "finals". fhs
 *     2020-03-10: V2.2.0: Make comparable with {@code SecretkeySpec}, constructor argument checks,
 *                         throw IllegalStateExcpetions when instance has been closed or destroyed. fhs
 *     2020-03-11: V2.2.1: Added some "throws" statements. fhs
 *     2020-03-13: V2.3.0: Added checks for null. fhs
 *     2020-03-23: V2.4.0: Restructured source code according to DBS programming guidelines. fhs
 */
package dbscryptolib;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;
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
 * @version 2.4.0
 */
public class SecureSecretKeySpec implements SecretKey, KeySpec, Destroyable, AutoCloseable {
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

   private final ProtectedByteArray key;
   private final ProtectedByteArray algorithm;


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
   public SecureSecretKeySpec(final byte[] key, final int offset, final int len, final String algorithm) throws ArrayIndexOutOfBoundsException, IllegalArgumentException {
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
   public String getAlgorithm() throws IllegalStateException {
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
   public String getFormat() throws IllegalStateException {
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
   public byte[] getEncoded() throws IllegalStateException {
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
   public int hashCode() throws IllegalStateException {
      checkState();

      // Java does not indicate an over- or underflow so it is safe
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
   public boolean equals(final Object obj) throws IllegalStateException {
      checkState();

      if (obj == null)
         return false;

      final Class objectClass = obj.getClass();

      if ((objectClass != thisClass) &&
               (objectClass != compatibleClass))
         return false;

      final SecretKey other = (SecretKey) obj;
      final byte[] thisKey = this.getEncoded();
      final byte[] otherKey = other.getEncoded();

      final boolean result = Arrays.equals(thisKey, otherKey);

      Arrays.fill(thisKey, (byte) 0);
      Arrays.fill(otherKey, (byte) 0);

      return (result & this.getAlgorithm().equalsIgnoreCase(other.getAlgorithm()));
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
   public void close() {
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
   public void destroy() {
      this.close();
   }

   /**
    * Check whether secret key spec is destroyed
    */
   @Override
   public boolean isDestroyed() {
      return !this.key.isValid();
   }

   /**
    * Checks whether this SecureSecretKeySpec is valid
    *
    * @return {@code True}, if this ShuffledByteArray is valid. {@code False}, if it has been deleted.
    */
   public boolean isValid() {
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
   private void checkKeyAndAlgorithm(final byte[] key, final String algorithm) throws IllegalArgumentException, NullPointerException {
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
   private void checkAlgorithm(final String algorithm) throws IllegalArgumentException, NullPointerException {
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
   private void checkKey(final byte[] key) throws IllegalArgumentException, NullPointerException {
      Objects.requireNonNull(key, "Key is null");

      if (key.length == 0)
         throw new IllegalArgumentException("Key is empty");
   }

   /**
    * Checks whether the shuffled byte array is in a valid state
    *
    * @throws IllegalStateException if the SecureSecretKeySpec has already been destroyed
    */
   private void checkState() throws IllegalStateException {
      if (!this.key.isValid())
         throw new IllegalStateException("SecureSecretKeySpec has already been destroyed");
   }

   /**
    * Set the compatible class {@code SecretKeySpec} for use in the {@code equals} method
    */
   private void setCompatibleClass() {
      // This is instantiated to get the class object without having to call "Class.forName()"}" which
      // needs handling of a "ClassNotFound" exception.
      final SecretKeySpec tempSpec = new SecretKeySpec(new byte[1], "");

      compatibleClass = tempSpec.getClass();
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

      Arrays.fill(algorithmBytes, (byte) 0); // Clear sensitive data

      return result;
   }
}
