
# NaCl Swift wrapper fo keys pair only

This library wraps `crypto_scalarmult_curve25519_tweet_base` and `crypto_box_curve25519xsalsa20poly1305_tweet_beforenm`. Nothing more.

### Warning:  
Developed and compiled with Swift 5. Mai have side effects in different Swift versions. 

## In action

- Create keypair

```swift
    let keyPair = NaclBox.keyPair() 
```

- Send public key to the server. Server should respond with it's publick key made with same NaCl algo.
- Use server public key to create shared key. Server will do the same with your public key.

```swift
let sharedKey = NaclBox.before(publicKey: serverPublicKey, secretKey: keyPair.secretKey)
```

- Done. You and server now has identical shared keys which can be used for data encription. 

Example

```swift
    public typealias Bytes = Array<UInt8>

    extension Data {
        var bytesArray: Bytes {
            Bytes(self)
        }
    }
    
    guard let key = sharedKey else {
        fatalError("Missing shared key")
    }

    var iv = Data(repeating: 0, count: 12).bytesArray
    guard SecRandomCopyBytes(kSecRandomDefault, 12, &iv) == 0 else {
        fatalError("Can not create iv. SecRandomCopyBytes non zero return")
    }

    let bytes = data.bytes
    let gcm = GCM(iv: iv, mode: .combined)

    do {
        let aes = try AES(key: key.bytesArray, blockMode: gcm, padding: .noPadding)
        let encrypted = try aes.encrypt(bytes)
        
        let iv_encrypted = iv + encrypted
        
        print("iv", iv)
        print("encrypted", encrypted)
        print("iv_encrypted", iv_encrypted)
        
        ws.send(iv_encrypted)
        
    } catch let e {
        fatalError(e.localizedDescription)
    }
```
