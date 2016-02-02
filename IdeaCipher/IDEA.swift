//
//  IDEA.swift
//
//  A port of this java version of the IDEA algorithm:
//  http://web.mit.edu/javadev/packages/Acme/Crypto/IdeaCipher.java
//
//  to swift
//
//  by Matthew Whiteside on 1/29/16.


import Darwin

extension Array where Element:IntegerType{
	init(_ bytes:[UInt8]) {
		let s = sizeof(Element)
		assert(bytes.count % s == 0, "byte array size must be a multiple of " +
																	"the target type size")
		self = [Element](count: bytes.count/s, repeatedValue: 0)
		for i in 0.stride(through: bytes.count - s, by: s){
			let slice = bytes[i...i+s-1].reverse()
			let bytes = [UInt8](slice)
			let u16 = UnsafePointer<Element>(bytes).memory
			self[i/s] = u16
		}
	}
}


prefix operator ⩪{}
prefix func ⩪(operand: UInt32) -> UInt32{
	return operand.inverseWRTMultiplicationMod65537()
}


//operator for multiplication modulo 65537
infix operator ⊙{ associativity left precedence 160 }
func ⊙( a:UInt32, b:UInt32 ) -> UInt32
{
	let ab = a &* b;
	if ( ab != 0 )
	{
		let lo = ab & 0xffff;
		let hi = ab >> 16;
		return ( ( lo &- hi ) + ( lo < hi ? 1 : 0 ) ) & 0xffff;
	}
	if ( a != 0 ){
		return ( 1 &- a ) & 0xffff;
	}
	return ( 1 &- b ) & 0xffff;
}

prefix func -(rhs:UInt32) -> UInt32{
  return UInt32(bitPattern: -Int32(rhs))
}

extension UInt32{
	
	func inverseWRTMultiplicationMod65537() -> UInt32{
		var x = self
		var t0, t1, q, y:UInt32
		if self <= 1{
			return self // 0 and 1 are self-inverse
		}
		t0 = 1;
		t1 = 0x10001 / x // since x >= 2, this fits into 16 bits
		y = (0x10001 % x) & 0xffff;
		
		repeat {
			if  y == 1 {
				return ( 1 &- t1 ) & 0xffff
			}
			q = x / y;
			x = x % y;
			t0 = ( t0 &+ q &* t1 ) & 0xffff;
			if x == 1{
				return t0
			}
			
			q = y / x
			y = y % x
			t1 = ( t1 &+ q &* t0 ) & 0xffff;
		} while true
		
	}
}


struct IDEACipher {

	var encryptionKeys = [UInt32](count: 52, repeatedValue: 0)
	var decryptionKeys = [UInt32](count:52, repeatedValue: 0)
	init(key:[UInt8]){
		
		// initialize the encryption keys.  The first 8 key values come from the 16
		// user-supplied key bytes.
		for  i in 0...7{
			encryptionKeys[i] =
				(UInt32( key[2 * i] & 0xff ) << 8 ) | UInt32( key[ 2 * i + 1] & 0xff );
		}
		
		// Subsequent key values are the previous values rotated to the
		// left by 25 bits.
		for i in 8...51{
			encryptionKeys[i] =
			( ( encryptionKeys[i - 8] << 9 ) |
			( encryptionKeys[i - 7] >> 7 ) ) & 0xffff;
		}
		
		// initialize the decryption keys, i.e., the encryption keys, inverted and
		// in reverse order.
		func setDecryptionKeys(startIndex lower:Int, endIndex upper:Int) -> Void{
			let t1 = ⩪self.encryptionKeys[lower]
			let t2 = -self.encryptionKeys[lower + 1]
			let t3 = -self.encryptionKeys[lower + 2]
			self.decryptionKeys[upper] =
				⩪self.encryptionKeys[lower + 3]
			if upper < 48 && upper > 3{
				self.decryptionKeys[upper - 1] = t2;
				self.decryptionKeys[upper - 2] = t3;
			} else {
				self.decryptionKeys[upper - 1] = t3;
				self.decryptionKeys[upper - 2] = t2;
			}
			self.decryptionKeys[upper - 3] = t1;
		}
		
		setDecryptionKeys(startIndex:51, endIndex:0)
		
		for round in 0...7
		{
			let upper = 51 - (6*round) - 4
			let lower = 6*round + 4
			let t1 = encryptionKeys[lower];
			decryptionKeys[upper] = encryptionKeys[lower + 1];
			decryptionKeys[upper - 1] = t1;
			setDecryptionKeys(startIndex:upper - 2, endIndex: lower + 2)
		}
	}
	
	
	func encrypt(clearText:[UInt16]) -> [UInt16]{
		return IDEA(clearText, keys: encryptionKeys)
	}
	
	func decrypt(cipherText:[UInt16]) -> [UInt16]{
		return IDEA(cipherText, keys: decryptionKeys)
	}
	
	func IDEA(input:[UInt16], keys:[UInt32]) -> [UInt16]{
		
		var x1 = UInt32(input[0]);
		var x2 = UInt32(input[1]);
		var x3 = UInt32(input[2]);
		var x4 = UInt32(input[3]);
		
		for round in 0...7{
			let base = round * 6
			x1 =  (x1 & 0xffff) ⊙ keys[base]
			x2 = x2 &+ keys[base + 1];
			x3 = x3 &+ keys[base + 2];
			x4 = ( x4 & 0xffff) ⊙ keys[base + 3]
			var t2 = x1 ^ x3;
			t2 = ( t2 & 0xffff) ⊙ keys[base + 4]
			var t1 = t2 &+ ( x2 ^ x4 );
			t1 = ( t1 & 0xffff) ⊙ keys[base + 5]
			t2 = t1 &+ t2;
			x1 ^= t1;
			x4 ^= t2;
			t2 ^= x2;
			x2 = x3 ^ t1;
			x3 = t2;
		}
		
		return [
			UInt16(truncatingBitPattern: ( x1 & 0xffff) ⊙  keys[48] ),
			UInt16(truncatingBitPattern: x3 &+ keys[49] ),
			UInt16(truncatingBitPattern: x2 &+ keys[50] ),
			UInt16(truncatingBitPattern: (x4 & 0xffff) ⊙ keys[51] )
		]
	}
}