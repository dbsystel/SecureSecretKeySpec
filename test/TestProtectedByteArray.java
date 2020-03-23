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
 *     2020-03-11: V1.0.0: Created. fhs
 */
package dbscryptolib;

import org.junit.*;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Test cases for SecureSecretKeySpec
 *
 * @author Frank Schwab, DB Systel GmbH
 * @version 1.0.0
 */
public class TestProtectedByteArray {

   /*
    * Private constants
    */
   static final byte FILL_VALUE = (byte) 0x55;
   static final byte OTHER_VALUE = (byte) 0xAA;
   static final int CHANGE_INDEX = 7;

   static final String EXPECTED_EXCEPTION = "Expected exception not thrown";

   public TestProtectedByteArray() {
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
   public void TestNullArgument() {
      try {
         ProtectedByteArray pba = new ProtectedByteArray(null);

         fail(EXPECTED_EXCEPTION);
      }
      catch (NullPointerException e) {
         assertEquals("Exception: " + e.toString(), "Array to protect is null", e.getMessage());
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestEmptyArgument() {
      ProtectedByteArray pba = new ProtectedByteArray(new byte[0]);

      byte[] result = pba.getData();

      assertEquals("Empty byte array is retrieved with wrong length", 0, result.length);
   }

   @Test
   public void TestBase() {
      final byte[] ba = new byte[32];

      Arrays.fill(ba, FILL_VALUE);

      ProtectedByteArray pba = new ProtectedByteArray(ba);

      assertArrayEquals("Data was not correctly retrieved", ba, pba.getData());
      assertEquals("Retrieved data has different length from stored data", ba.length, pba.length());
   }

   @Test
   public void TestClose() {
      final byte[] ba = new byte[32];

      Arrays.fill(ba, FILL_VALUE);

      ProtectedByteArray pba = new ProtectedByteArray(ba);

      pba.close();
      assertFalse("ProtectedByteArray still valid after close", pba.isValid());

      try {
         pba.getData();

         fail(EXPECTED_EXCEPTION);
      }
      catch (IllegalStateException e) {
         final String message = e.getMessage();

         assertEquals("IllegalStateException with wrong message: " + message, "ProtectedByteArray has already been destroyed", message);
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestEquals() {
      final byte[] ba = new byte[32];

      Arrays.fill(ba, FILL_VALUE);

      final ProtectedByteArray pba1 = new ProtectedByteArray(ba);
      final ProtectedByteArray pba2 = new ProtectedByteArray(ba);

      assertEquals("ProtectedByteArray are not equal when they should be", pba1, pba2);
      assertEquals("ProtectedByteArray do not have identical hash codes", pba1.hashCode(), pba2.hashCode());

      final ProtectedByteArray pba3 = new ProtectedByteArray(new byte[32]);
      assertNotEquals("ProtectedByteArray are equal when they should not be (different keys)", pba1, pba3);
   }
}
