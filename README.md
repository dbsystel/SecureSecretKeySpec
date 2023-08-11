# SecureSecretKeySpec

> 💡 This repository is no longer actively maintained by DB Systel GmbH. Its development will continue here: https://github.com/xformerfhs/SecureSecretKeySpec

Java's `SecretKeySpec` implementation is unsafe. It stores the key bytes in its original form and does not automatically delete them when the key is no longer in use, so it is still visible in memory until the next garbage collection.

This makes it possible to easily find keys in a memory dump. One just has to search for the algorithm names and the keys are stored right next to them.

`SecureSecretKeySpec` is a drop-in replacement for Java's SecretKeySpec. It does multiple things to enhance the security of the stored key:

* Implements the `AutoCloseable` interface so the key is automatically destroyed when the key is closed
* Implements the `Destroyable` interface (unlike the original `SecretKeySpec`, this class has a working `destroy` method)
* Stores the key and the algorithm name in an obfuscated form, so they never appear in the clear
* Stores the key and the algorithm name in a shuffled form, so the order is changed in memory

A typical usage would be something like this:

    ...
    // Get the key in variable "theKey"
    ...
    // Use it here
    try (SecureSecretKeySpec mySecretKey = new SecureSecretKeySpec(theKey, "AES")) {
       Arrays.fill(theKey, (byte) 0);  // Delete the key from memory. Now it is safely stored in the SecureSecretKeySpec
       ...
       // Use the SecureSecretKeySpec
       Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
       aesCipher.init(Cipher.ENCRYPT_MODE, mySecretKey);
       ...
    } // Here the SecureSecretKeySpec is automatically destroyed due to the AutoClosable interface

Note that this is security by obscurity. It does not make it impossible to get at the key. It just makes it harder and there are no visible clues within the memory dump any more. However, if an attacker analyzes the memory dump he will be able to extract the key (with quite a bit of effort, though). One could make this a bit more secure if one uses an Java code obfuscator so the class names will be random.

## Contributing

Feel free to submit a pull request with new features, improvements on tests or documentation and bug fixes.

## Contact

Frank Schwab ([Mail](mailto:frank.schwab@deutschebahn.com "Mail"))

## License

SecureSecretKeySpec is released under the Apache license, V2.0. See "LICENSE" for details.
