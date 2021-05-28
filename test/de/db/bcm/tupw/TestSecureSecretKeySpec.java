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
 *     2020-03-10: V1.0.0: Created. fhs
 */
package de.db.bcm.tupw.crypto;

import org.junit.*;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Test cases for SecureSecretKeySpec
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class TestSecureSecretKeySpec {

   /*
    * Private constants
    */
   static final String ALGORITHM_NAME = "AES";
   static final String OTHER_ALGORITHM_NAME = "BLA";

   static final String EXPECTED_EXCEPTION = "Expected exception not thrown";

   public TestSecureSecretKeySpec() {
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
   public void TestNullKeyAndAlgorithm() {
      try {
         final SecureSecretKeySpec spec = new SecureSecretKeySpec(null, null);

         fail(EXPECTED_EXCEPTION);
      }
      catch (NullPointerException e) {
         assertEquals("Exception: " + e.toString(), "Key is null", e.getMessage());
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestNullKey() {
      try {
         final SecureSecretKeySpec spec = new SecureSecretKeySpec(null, ALGORITHM_NAME);

         fail(EXPECTED_EXCEPTION);
      }
      catch (NullPointerException e) {
         assertEquals("Exception: " + e.toString(), "Key is null", e.getMessage());
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestNullAlgorithm() {
      try {
         final SecureSecretKeySpec spec = new SecureSecretKeySpec(new byte[1], null);

         fail(EXPECTED_EXCEPTION);
      }
      catch (NullPointerException e) {
      assertEquals("Exception: " + e.toString(), "Algorithm is null", e.getMessage());
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestEmptyAlgorithm() {
      try {
         final SecureSecretKeySpec spec = new SecureSecretKeySpec(new byte[1], "");

         fail(EXPECTED_EXCEPTION);
      }
      catch (IllegalArgumentException e) {
         assertEquals("Exception: " + e.toString(), "Algorithm is empty", e.getMessage());
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestBase() {
      final byte[] key = new byte[32];

      Arrays.fill(key, (byte) 0x55);

      final SecureSecretKeySpec spec = new SecureSecretKeySpec(key, ALGORITHM_NAME);

      assertArrayEquals("Key was not correctly retrieved", key, spec.getEncoded());
      assertEquals("Algorithm name not correctly retrieved", ALGORITHM_NAME, spec.getAlgorithm());
      assertEquals("Format is not 'RAW'", "RAW", spec.getFormat());
   }

   @Test
   public void TestClose() {
      final byte[] key = new byte[32];

      Arrays.fill(key, (byte) 0x55);

      final SecureSecretKeySpec spec = new SecureSecretKeySpec(key, ALGORITHM_NAME);

      spec.close();
      assertTrue("SecureSecretKeySpec still valid after close", spec.isDestroyed());

      try {
         spec.getAlgorithm();

         fail(EXPECTED_EXCEPTION);
      }
      catch (IllegalStateException e) {
         final String message = e.getMessage();

         assertEquals("IllegalStateException with wrong message: " + message, "SecureSecretKeySpec has already been destroyed", message);
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestEquals() {
      final byte[] key = new byte[32];

      Arrays.fill(key, (byte) 0x55);

      final SecureSecretKeySpec spec1 = new SecureSecretKeySpec(key, ALGORITHM_NAME);
      final SecureSecretKeySpec spec2 = new SecureSecretKeySpec(key, ALGORITHM_NAME);
      final SecureSecretKeySpec spec3 = new SecureSecretKeySpec(new byte[1], ALGORITHM_NAME);
      final SecureSecretKeySpec spec4 = new SecureSecretKeySpec(key, OTHER_ALGORITHM_NAME);

      assertEquals("SecureSecretsKeySpecs are not equal when they should be", spec1, spec2);
      assertEquals("SecureSecretsKeySpecs do not have identical hash codes", spec1.hashCode(), spec2.hashCode());
      assertNotEquals("SecureSecretsKeySpecs are equal when they should not be (different keys)", spec1, spec3);
      assertNotEquals("SecureSecretsKeySpecs are equal when they should not be (different algorithms)", spec1, spec4);
   }

   @Test
   public void TestCompatibleEquals() {
      final byte[] key = new byte[32];

      Arrays.fill(key, (byte) 0x55);

      final SecureSecretKeySpec spec1 = new SecureSecretKeySpec(key, ALGORITHM_NAME);
      final SecretKeySpec spec2 = new SecretKeySpec(key, ALGORITHM_NAME);
      final SecretKeySpec spec3 = new SecretKeySpec(new byte[1], ALGORITHM_NAME);
      final SecretKeySpec spec4 = new SecretKeySpec(key, OTHER_ALGORITHM_NAME);

      assertEquals("SecureSecretsKeySpecs are not equal when they should be", spec1, spec2);
      assertNotEquals("SecureSecretsKeySpecs are equal when they should not be (different keys)", spec1, spec3);
      assertNotEquals("SecureSecretsKeySpecs are equal when they should not be (different algorithms)", spec1, spec4);
   }
}
