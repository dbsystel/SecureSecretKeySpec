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
 *     2016-09-26: V2.0.0: Use ProtectedByteArray.
 *     2016-11-24: V2.1.0: Implement "javax.security.auth.Destroyable" interface.
 */
package dbscryptolib;

import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * A key specification for a <code>SecretKey</code> and also a secret key
 * implementation that is provider-independent. It can be used for raw secret
 * keys that can be specified as <code>byte[]</code>.
 * 
 * It is intended to be used as a drop-in replacement for <code>SecretKeySpec</code>.
 *
 * @author Frank Schwab
 * @version 2.1.0
 */
public class SecureSecretKeySpec implements SecretKey, KeySpec, Destroyable, AutoCloseable {
   private final ProtectedByteArray key;
   private final ProtectedByteArray algorithm;


   /**
    * Creates a new <code>SecureSecretKeySpec</code> for the specified key data
    * and algorithm name.
    *
    * @param key the key data.
    * @param algorithm the algorithm name.
    * @throws IllegalArgumentException if the key data or the algorithm name is
    * null.
    */
   public SecureSecretKeySpec(byte[] key, String algorithm) {
      checkAlgorithm(algorithm);

      this.key = new ProtectedByteArray(key);

      this.algorithm = createNewAlgorithmArray(algorithm);
   }

   /**
    * Creates a new <code>SecureSecretKeySpec</code> for the key data from the
    * specified buffer <code>key</code> starting at <code>offset</code> with
    * length <code>len</code> and the specified <code>algorithm</code> name.
    *
    * @param key the key data.
    * @param offset the offset.
    * @param len the size of the key data.
    * @param algorithm the algorithm name.
    * @throws IllegalArgumentException if the key data or the algorithm name is
    * null, or <code>offset</code> and <code>len</code> do not specify a valid
    * chunk in the buffer <code>key</code>.
    * @throws ArrayIndexOutOfBoundsException if <code>offset</code> or
    * <code>len</code> is negative.
    */
   public SecureSecretKeySpec(byte[] key, int offset, int len, String algorithm) {
      checkAlgorithm(algorithm);

      this.key = new ProtectedByteArray(key, offset, len);

      this.algorithm = createNewAlgorithmArray(algorithm);
   }

   /**
    * Checks whether algorithm is valid
    *
    * @param algorithm Algorithm name as string
    * @throws IllegalArgumentException if <code>key</code> is null or
    * <code>algorithm</code> is null
    */
   private void checkAlgorithm(String algorithm) throws IllegalArgumentException {
      if (algorithm == null) {
         throw new IllegalArgumentException("algorithm == null");
      }
   }

   /*
    * Private methods
    */
   
   /**
    * Creates a new ProtectedByteArray for the algorithm name
    * 
    * @param algorithm Name of the algorithm as String
    * @return ProtectedByteArray that hides the algorithm name
    */
   private ProtectedByteArray createNewAlgorithmArray(String algorithm) {
      ProtectedByteArray result;
      
      final byte[] algorithmBytes = algorithm.getBytes();
      result = new ProtectedByteArray(algorithmBytes);
      Arrays.fill(algorithmBytes, (byte) 0); // Clear sensitive data
   
      return result;
   }
   
   /*
    * Interface methods
    */
   /**
    * Returns the algorithm name.
    *
    * @return the algorithm name.
    */
   @Override
   public String getAlgorithm() {
      return new String(algorithm.getData());
   }

   /**
    * Returns the name of the format used to encode the key.
    *
    * @return the format name "RAW".
    */
   @Override
   public String getFormat() {
      return "RAW";
   }

   /**
    * Returns the encoded form of this secret key.
    *
    * @return the encoded form of this secret key.
    */
   @Override
   public byte[] getEncoded() {
      byte[] result = this.key.getData();

      return result;
   }

   /**
    * Returns the hash code of this <code>SecureSecretKeySpec</code> instance.
    *
    * @return the hash code.
    */
   @Override
   public int hashCode() {
      // Java does not indicate an over- or underflow so it is safe
      // to multiply with a number that will overflow on multiplication
      return this.key.hashCode() * 79 + this.algorithm.hashCode();
   }

   /**
    * Compares the specified object with this <code>SecureSecretKeySpec</code>
    * instance.
    *
    * @param obj the object to compare.
    * @return true if the algorithm name and key of both object are equal,
    * otherwise false.
    */
   @Override
   public boolean equals(Object obj) {
      if (obj == null) {
         return false;
      }
      
      if (getClass() != obj.getClass()) {
         return false;
      }
      
      final SecureSecretKeySpec other = (SecureSecretKeySpec) obj;
      if (!this.key.equals(other.key)) {
         return false;
      }

      return this.getAlgorithm().equalsIgnoreCase(other.getAlgorithm());
   }
   
   /*
    * Method for AutoCloseable interface
    */
   /**
    * Secure deletion of key and algorithm
    *
    * This method is idempotent and never throws an exception.
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
    * This method is idempotent and never throws an exception.
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
}
