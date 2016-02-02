//
//  main.swift
//  IdeaCipher
//
//  A port of this java version of the IDEA algorithm:
//  http://web.mit.edu/javadev/packages/Acme/Crypto/IdeaCipher.java
//
//  to swift
//
//  by Matthew Whiteside on 1/29/16.



//example usage
let clearText:[UInt8] = [0x20,0x82,0x2C,0x11,0x09,0x51,0x08,0x40]

let keyBytes:[UInt8] = [0x78, 0x02, 0xC4, 0x51,
                        0x44, 0x63, 0x4A, 0x43,
                        0xFA, 0x10, 0xA1, 0x5C,
                        0x40, 0x5A, 0x4A, 0x42]


let ideaCipher = IDEACipher(key: keyBytes)
let utf16clearText = [UInt16](clearText)
let cipherText = ideaCipher.encrypt(utf16clearText)
let decipheredText = ideaCipher.decrypt(cipherText)
print("clear text:")
for utf16Char in utf16clearText{
	print("  0x\(String(utf16Char,radix:16))")
}

print("cipher text:")
for utf16Char in cipherText{
	print("  0x\(String(utf16Char,radix:16))")
}

print("deciphered text:")
for utf16Char in decipheredText{
	print("  0x\(String(utf16Char,radix:16))")
}