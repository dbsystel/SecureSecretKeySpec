/*
 * Copyright (c) 2019, DB Systel GmbH
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
 *     2019-08-03: V1.0.0: Created. fhs
 *     2019-08-05: V1.1.0: Cache SecureRandom algorithm name. Change method name. fhs
 *     2019-08-23: V1.2.0: Make it possible to use a SecureRandom singleton. fhs
 */
package dbscryptolib;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

/**
 * A class to get the most secure SecureRandom instance
 *
 * @author Frank Schwab
 * @version 1.2.0
 */
@SuppressWarnings("ConstantConditions")
public class SecureRandomFactory {
   private static String m_SecureRandomAlgorithmName;
   private static SecureRandom m_Singleton;

   /**
    * Get optimal SecureRandom provider
    *
    * <p>
    * Choose a non-blocking SecureRandom provider. On Windows this is the "WINDOWS-PRNG" provider.
    * On *ux this is the "NATIVEPRNGNONBLOCKING" provider. If there is no non-blocking provider
    * look for just "NATIVEPRNG" as this is non-blocking for the .nextBytes method, as well.
    * </p>
    *
    * @return Name of optimal SecureRandom provider, or an empty string if none is found
    */
   private static String getOptimalSecureRandomAlgorithmName() {
      String result = "";

      // Scan through the list of SecureRandom algorithms
      final Set<String> algorithms = Security.getAlgorithms("SecureRandom");

      for (String algorithm : algorithms) {
         // Use the native windows SPRNG on Windows
         if (algorithm.startsWith("WINDOWS-")) {
            result = algorithm;
            break;
         }

         // Use native non-blocking SPRNG on *ux, if it exists
         if (algorithm.startsWith("NATIVE")) {
            if (algorithm.endsWith("NONBLOCKING")) {
               result = algorithm;
               break;
            } else if (!algorithm.endsWith("BLOCKING"))  // Never use the BLOCKING provider
               if (result.length() == 0) {
                  // Choose NATIVEPRNG if there is one
                  result = algorithm;
                  break;
               }
         }
      }

      return result;
   }

   /**
    * Get optimal SecureRandom instance depending on the platform.
    *
    * <p>
    * This method retuns the default SecureRandom instance, if there is no optimal one.
    * </p>
    * @return Optimal SecureRandom instance
    */
   public static SecureRandom getSensibleInstance() {
      SecureRandom result;

      // Only get the name of the SecureRandom algorithm if it has not been determined, yet.
      if (m_SecureRandomAlgorithmName == null)
         m_SecureRandomAlgorithmName = getOptimalSecureRandomAlgorithmName();

      // Use the optimal algorithm, if there is one
      if (m_SecureRandomAlgorithmName.length() > 0)
         try {
            result = SecureRandom.getInstance(m_SecureRandomAlgorithmName);
         } catch (NoSuchAlgorithmException e) {
            // The chosen algorithm was not present, so use the default, which is guaranteed to work
            result = new SecureRandom();
         }
      else {
         // Choose the default if there could no optimal algorithm be found
         result = new SecureRandom();
      }

      return result;
   }

   /**
    * Get optimal SecureRandom singleton instance depending on the platform.
    *
    * <p>
    * This method retuns the default SecureRandom instance, if there is no optimal one.
    * </p>
    * @return Optimal SecureRandom singleton instance
    */
   public static SecureRandom getSensibleSingleton() {
      if (m_Singleton == null)
         m_Singleton = getSensibleInstance();

      return m_Singleton;
   }
}
