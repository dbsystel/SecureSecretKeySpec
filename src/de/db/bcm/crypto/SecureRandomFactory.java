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
 *     2019-08-03: V1.0.0: Created. fhs
 *     2019-08-05: V1.1.0: Cache SecureRandom algorithm name. Change method name. fhs
 *     2019-08-23: V1.2.0: Make it possible to use a SecureRandom singleton. fhs
 *     2020-03-23: V1.3.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V1.3.1: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.4.0: Made thread safe. fhs
 *     2021-08-13: V1.5.0: Make algorithm to find SecureRandom algorithm more robust. fhs
 *     2021-08-31: V1.6.0: Pick strong default instance, if necessary. fhs
 *     2021-08-31: V1.6.1: Corrected variable names. fhs
 */
package de.db.bcm.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

/**
 * A class to get the most secure SecureRandom instance
 *
 * @author Frank Schwab
 * @version 1.6.1
 */
public class SecureRandomFactory {
   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instantiated.</p>
    */
   private SecureRandomFactory() {
      throw new IllegalStateException("Utility class");
   }

   //******************************************************************
   // Instance variables
   //******************************************************************

   private static String m_SecureAlgorithmName;
   private static SecureRandom m_SecureRandomSingleton;


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Get optimal SecureRandom instance depending on the platform.
    *
    * <p>This method returns the default SecureRandom instance, if there is no optimal one.</p>
    *
    * @return Optimal SecureRandom instance
    */
   public static synchronized SecureRandom getSensibleInstance() {
      SecureRandom result;

      // Only get the name of the SecureRandom algorithm if it has not been determined, yet.
      if (m_SecureAlgorithmName == null)
         m_SecureAlgorithmName = getOptimalSecureRandomAlgorithmName();

      // Use the optimal algorithm, if there is one
      if (m_SecureAlgorithmName.length() > 0)
         try {
            result = SecureRandom.getInstance(m_SecureAlgorithmName);
         } catch (NoSuchAlgorithmException e) {
            // The chosen algorithm was not present, so use the default, which is guaranteed to work
            result = getDefaultInstance();
         }
      else {
         // Choose the default if there could no optimal algorithm be found
         result = getDefaultInstance();
      }

      return result;
   }

   /**
    * Get optimal SecureRandom singleton instance depending on the platform.
    *
    * <p>This method returns the default SecureRandom instance, if there is no optimal one.</p>
    *
    * @return Optimal SecureRandom singleton instance
    */
   public static synchronized SecureRandom getSensibleSingleton() {
      if (m_SecureRandomSingleton == null)
         m_SecureRandomSingleton = getSensibleInstance();

      return m_SecureRandomSingleton;
   }


   //******************************************************************
   // Private methods
   //******************************************************************

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

      // These are the algorithms we are looking for
      boolean foundWindows = false;
      boolean foundNativeNonBlocking = false;
      boolean foundNativeOther = false;

      String windowsAlgorithm = "";
      String nativeNonBlockingAlgorithm = "";
      String nativeOtherAlgorithm = "";

      // Scan through the list of SecureRandom algorithms
      final Set<String> algorithms = Security.getAlgorithms("SecureRandom");

      // The order of the entries is not defined so loop through all entries
      // and remember what we found
      for (String algorithm : algorithms) {
         // Use the native windows SPRNG on Windows
         if (algorithm.startsWith("WINDOWS-")) {
            foundWindows = true;
            windowsAlgorithm = algorithm;
         }

         // Use a nonblocking native SPRNG on other OSes.
         // Nonblocking SPRNGs are no less secure than blocking SPRNGs, except for the first
         // few seconds after system start.
         // Blocking must be avoided. On systems with heavy usage of SPRNG
         // blocks can last for minutes. See https://lwn.net/Articles/808575/,
         // https://unix.stackexchange.com/questions/324209/when-to-use-dev-random-vs-dev-urandom,
         // or https://words.filippo.io/dispatches/linux-csprng/
         if (algorithm.startsWith("NATIVE")) {
            if (algorithm.endsWith("NONBLOCKING")) {
               foundNativeNonBlocking = true;
               nativeNonBlockingAlgorithm = algorithm;
            } else if (!algorithm.endsWith("BLOCKING")) {
               foundNativeOther = true;
               nativeOtherAlgorithm = algorithm;
            }
         }
      }

      // Now choose the appropriate algorithm
      if (foundWindows)
         result = windowsAlgorithm;
      else if (foundNativeNonBlocking)
         result = nativeNonBlockingAlgorithm;
      else if (foundNativeOther)
         result = nativeOtherAlgorithm;

      // If none of the "good" algorithms was found return an empty string
      return result;
   }

   /**
    * Get the default SecureRandom instance
    *
    * @return Default SecureRandom instance
    */
   private static SecureRandom getDefaultInstance() {
      SecureRandom result;

      try {
         result = SecureRandom.getInstanceStrong();
      } catch (NoSuchAlgorithmException ex) {
         result = new SecureRandom();
      }

      m_SecureAlgorithmName = result.getAlgorithm();

      return result;
   }
}
