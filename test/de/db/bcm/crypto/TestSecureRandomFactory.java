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
    *     2021-08-13: V1.0.0: Created. fhs
    */
   package de.db.bcm.crypto;

   import org.junit.*;

   import static org.junit.Assert.*;

   /**
    * Test case for SecureRandomFactory
    *
    * @author Frank Schwab, DB Systel GmbH
    * @version 1.0.0
    */
   public class TestSecureRandomFactory {
      private static final String LINUX_NAME = "Linux";
      private static final String NATIVE_NAME = "Native";
      private static final String NONBLOCKING_NAME = "Nonblocking";
      private static final String WINDOWS_NAME = "Windows";
      private static final String END_QUOTE = "'";

      /*
       * Private constants
       */
      public TestSecureRandomFactory() {
      }

      @BeforeClass
      public static void setUpClass() {
      }

      @AfterClass
      public static void tearDownClass() {
      }

      @Before
      public void setUp() {
      }

      @After
      public void tearDown() {
      }

      @Test
      public void TestOSMatch() {
         final String optimalAlgorithm = SecureRandomFactory.getSensibleInstance().getAlgorithm();

         final String thisOS = getOsName();

         final String errorMessagePrefix = "OS is '" + thisOS + "' but optimal algorithm '" + optimalAlgorithm + "' does not start with '";

         if (startsWithIgnoreCase(thisOS, WINDOWS_NAME)) {
            assertTrue(errorMessagePrefix + WINDOWS_NAME + END_QUOTE, startsWithIgnoreCase(optimalAlgorithm, WINDOWS_NAME));
         } else if (startsWithIgnoreCase(thisOS, LINUX_NAME)) {
            assertTrue(errorMessagePrefix + NATIVE_NAME + END_QUOTE, startsWithIgnoreCase(optimalAlgorithm, NATIVE_NAME));
            assertTrue(errorMessagePrefix + NONBLOCKING_NAME + END_QUOTE, startsWithIgnoreCase(optimalAlgorithm, NONBLOCKING_NAME));
         }
      }

      // Private methods

      /***
       * Gets the name of the operating system this program is running on
       *
       * @return Name of the operating system
       */
      private static String getOsName() {
         return System.getProperty("os.name");
      }

      /***
       * Tests if this string starts with the specified prefix ignoring the case.
       *
       * @param testString String to test
       * @param prefix The prefix to look for
       * @return true: The string starts with the specified prefix,
       * false: The string does not start with the specified prefix
       */
      private static boolean startsWithIgnoreCase(final String testString, final String prefix) {
         if (testString == null || prefix == null) {
            return (testString == null && prefix == null);
         }

         if (prefix.length() > testString.length()) {
            return false;
         }

         return testString.regionMatches(true, 0, prefix, 0, prefix.length());
      }
   }
