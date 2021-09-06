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
 *     2021-08-30: V1.0.0: Created. fhs
 *     2021-09-01: V1.0.1: Added clear methods for integer arrays. fhs
 */
package de.db.bcm.arrays;

import java.util.Arrays;

/**
 * Helper class for array operations that need a simpler interface
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.1
 */
public class ArrayHelper {
   //******************************************************************
   // Private constants
   //******************************************************************

   // Fill values for clear methods

   private static final byte CLEAR_BYTE = (byte) 0;
   private static final char CLEAR_CHAR = '\0';
   private static final byte CLEAR_INT = 0;

   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instantiated.</p>
    */
   private ArrayHelper() {
      throw new IllegalStateException("Utility class");
   }

   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Clear a byte array
    *
    * @param a Byte array to clear
    */
   public static void clear(final byte[] a) {
      Arrays.fill(a, CLEAR_BYTE);
   }

   /**
    * Clear a character array
    *
    * @param a Character array to clear
    */
   public static void clear(final char[] a) {
      Arrays.fill(a, CLEAR_CHAR);
   }

   /**
    * Clear an integer array
    *
    * @param a Integer array to clear
    */
   public static void clear(final int[] a) {
      Arrays.fill(a, CLEAR_INT);
   }

   /**
    * Clear a byte array and do not throw an exception if it is null
    *
    * @param a Byte array to clear
    */
   public static void safeClear(final byte[] a) {
      if (a != null)
         Arrays.fill(a, CLEAR_BYTE);
   }

   /**
    * Clear a character array and do not throw an exception if it is null
    *
    * @param a Character array to clear
    */
   public static void safeClear(final char[] a) {
      if (a != null)
         Arrays.fill(a, CLEAR_CHAR);
   }

   /**
    * Clear an integer array and do not throw an exception if it is null
    *
    * @param a Integer array to clear
    */
   public static void safeClear(final int[] a) {
      if (a != null)
         Arrays.fill(a, CLEAR_INT);
   }
}
