//
//  Nacl.swift
//  Nacl
//
//  Created by George Romas on 25/09/2019.
//  Copyright © 2019 madgeorge. All rights reserved.
//

import Foundation

public typealias Bytes = Array<UInt8>

extension Data {
    var bytesArray: Bytes {
        Bytes(self)
    }
}

let crypto_box_PUBLICKEYBYTES = 32
let crypto_box_SECRETKEYBYTES = 32
let crypto_box_BEFORENMBYTES = 32

class NaclUtil {
    
    enum NaclUtilError: Error {
        case badPublicKeySize
        case badSecretKeySize
        case internalError
    }
    
    static func checkBoxLength(publicKey: Data, secretKey: Data) throws {
        if publicKey.count != crypto_box_PUBLICKEYBYTES {
            throw(NaclUtilError.badPublicKeySize)
        }
        
        if secretKey.count != crypto_box_SECRETKEYBYTES {
            throw(NaclUtilError.badSecretKeySize)
        }
    }
}

fileprivate class NaclWrapper {
    enum NaclWrapperError: Error {
        case creationFailed
    }
    
    fileprivate static func crypto_box_keypair(pk: inout Data, sk: inout Data) throws -> Int32 {
        var skb = sk.bytesArray
        let result = SecRandomCopyBytes(kSecRandomDefault, sk.count, &skb)
        
        if result != 0 {
            throw(NaclWrapperError.creationFailed)
        }
        
        var pkb = pk.bytesArray
        
        let r = crypto_scalarmult_curve25519_tweet_base(&pkb, &skb)
        
        pk = Data(bytes: &pkb, count: 32)
        sk = Data(bytes: &skb, count: 32)
        
        return r
    }
}

public class NaclBox {
    
    enum NaclBoxError: Error {
        case invalidParameters
        case internalError
        case creationFailed
    }
    
    public static func before(publicKey: Data, secretKey: Data) throws -> Data {
        try NaclUtil.checkBoxLength(publicKey: publicKey, secretKey: secretKey)
        
        let k = Data(repeating: 0, count: crypto_box_BEFORENMBYTES)
        var kb = k.bytesArray
        
        var pkb = publicKey.bytesArray
        var skb = secretKey.bytesArray
        
        _ = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(&kb, &pkb, &skb)
        
        return Data(bytes: &kb, count: 32)
    }

    public static func keyPair() throws -> (publicKey: Data, secretKey: Data) {
        var pk = Data(repeating: 0, count: crypto_box_PUBLICKEYBYTES)
        var sk = Data(repeating: 0, count: crypto_box_SECRETKEYBYTES)

        let r = try NaclWrapper.crypto_box_keypair(pk: &pk, sk: &sk)

        if r != 0 {
            throw(NaclBoxError.creationFailed)
        }

        return (pk, sk)
    }
    
    public static func keyPair(fromSecretKey secretKey: Data) throws -> (publicKey: Data, secretKey: Data) {
        if secretKey.count != crypto_box_SECRETKEYBYTES {
            throw(NaclBoxError.invalidParameters)
        }
        
        let pk = Data(repeating: 0, count: crypto_box_PUBLICKEYBYTES)
        var pkb = pk.bytesArray
        let skb = secretKey.bytesArray
        
        _ = crypto_scalarmult_curve25519_tweet_base(&pkb, skb)
        
        let pkk = Data(bytes: &pkb, count: 32)
        
        return (pkk, secretKey)
    }
}

