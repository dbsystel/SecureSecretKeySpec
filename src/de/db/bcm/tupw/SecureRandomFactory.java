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
 */
package de.db.bcm.tupw.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

/**
 * A class to get the most secure SecureRandom instance
 *
 * @author Frank Schwab
 * @version 1.3.0
 */
public class SecureRandomFactory {
   //******************************************************************
   // Instance variables
   //******************************************************************

   private static String m_SecureRandomAlgorithmName;
   private static SecureRandom m_Singleton;


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
    * <p>This method returns the default SecureRandom instance, if there is no optimal one.</p>
    *
    * @return Optimal SecureRandom singleton instance
    */
   public static SecureRandom getSensibleSingleton() {
      if (m_Singleton == null)
         m_Singleton = getSensibleInstance();

      return m_Singleton;
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

      // Scan through the list of SecureRandom algorithms
      final Set<String> algorithms = Security.getAlgorithms("SecureRandom");

      for (String algorithm : algorithms) {
         // Use the native windows SPRNG on Windows
         if (algorithm.startsWith("WINDOWS-")) {
            result = algorithm;
            break;
         }

         if (algorithm.startsWith("NATIVE")) {
            if (algorithm.endsWith("NONBLOCKING")) {
               // Use native non-blocking SPRNG on *ux, if it exists
               result = algorithm;
               break;
            } else if (!algorithm.endsWith("BLOCKING"))  { // Never use the BLOCKING provider
               // This is probably "NATIVEPRNG"
               result = algorithm;
               break;
            }
         }
      }

      return result;
   }
}
