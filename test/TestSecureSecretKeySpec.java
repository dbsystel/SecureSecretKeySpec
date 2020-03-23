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
 *     2020-03-10: V1.0.0: Created. fhs
 */
package dbscryptolib;

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
