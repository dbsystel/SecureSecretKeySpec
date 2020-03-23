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
public class TestShuffledByteArray {

   /*
    * Private constants
    */
   static final byte FILL_VALUE = (byte) 0x55;
   static final byte OTHER_VALUE = (byte) 0xAA;
   static final int CHANGE_INDEX = 7;

   static final String EXPECTED_EXCEPTION = "Expected exception not thrown";

   public TestShuffledByteArray() {
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
         ShuffledByteArray sba = new ShuffledByteArray(null);

         fail(EXPECTED_EXCEPTION);
      }
      catch (NullPointerException e) {
         assertEquals("Exception: " + e.toString(), "Source array is null", e.getMessage());
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestEmptyArgument() {
      ShuffledByteArray sba = new ShuffledByteArray(new byte[0]);

      byte[] result = sba.getData();

      assertEquals("Empty byte array is retrieved with wrong length", 0, result.length);

      try {
         final byte notExistent = sba.getAt(1);

         fail(EXPECTED_EXCEPTION);
      }
      catch (ArrayIndexOutOfBoundsException e) {
         assertTrue("Exception: " + e.toString(), e.getMessage().contains("Illegal index"));
      }
      catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   @Test
   public void TestBase() {
      final byte[] ba = new byte[32];

      Arrays.fill(ba, FILL_VALUE);

      ShuffledByteArray sba = new ShuffledByteArray(ba);

      assertArrayEquals("Data was not correctly retrieved", ba, sba.getData());
      assertEquals("Retrieved data has different length from stored data", ba.length, sba.length());
      assertEquals("Retrieved data at index 0 has different value from stored data", ba[0], sba.getAt(0));

      sba.setAt(CHANGE_INDEX, OTHER_VALUE);
      assertEquals("Retrieved data with 'getAt' has different value from what was set", OTHER_VALUE, sba.getAt(CHANGE_INDEX));

      final byte[] retrievedBa = sba.getData();
      assertEquals("Retrieved data with 'getData' has different value from what was set", OTHER_VALUE, retrievedBa[CHANGE_INDEX]);
   }

   @Test
   public void TestClose() {
      final byte[] ba = new byte[32];

      Arrays.fill(ba, FILL_VALUE);

      ShuffledByteArray sba = new ShuffledByteArray(ba);

      sba.close();
      assertFalse("ShuffledByteArray still valid after close", sba.isValid());

      try {
         sba.getData();

         fail(EXPECTED_EXCEPTION);
      }
      catch (IllegalStateException e) {
         final String message = e.getMessage();

         assertEquals("IllegalStateException with wrong message: " + message, "ShuffledByteArray has already been destroyed", message);
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

      final ShuffledByteArray sba1 = new ShuffledByteArray(ba);
      final ShuffledByteArray sba2 = new ShuffledByteArray(ba);

      assertEquals("ShuffledByteArray are not equal when they should be", sba1, sba2);
      assertEquals("ShuffledByteArray do not have identical hash codes", sba1.hashCode(), sba2.hashCode());

      final ShuffledByteArray sba3 = new ShuffledByteArray(new byte[32]);
      assertNotEquals("ShuffledByteArray are equal when they should not be (different keys)", sba1, sba3);
   }
}
