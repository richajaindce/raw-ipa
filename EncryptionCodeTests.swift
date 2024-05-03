@testable import EncryptionCode
import XCTest
import CryptoKit

@available(macOS 14.0, *)
typealias IPAShare = IPAEncryptedMatchKey.IPAShare

@available(macOS 14.0, *)
extension IPAShare {
  static func fromData(_ data: Data) -> IPAShare {
    
    let leftData = data.subdata(in: 0..<8)
    let left = leftData.withUnsafeBytes { $0.load(as: UInt64.self) }
    let rightData = data.subdata(in: 8..<16)
    let right = rightData.withUnsafeBytes { $0.load(as: UInt64.self) }
    
    return IPAShare(left: left, right: right)
  }
}



@available(macOS 14.0, *)

class InteroperablePrivateAttributionTests: XCTestCase {
  
  typealias MatchKeyEncryption = IPAEncryptedMatchKey.MatchKeyEncryption
  typealias EventType = IPAEncryptedMatchKey.EventType
  typealias HelperNumber = IPAEncryptedMatchKey.HelperNumber
  
  @available(iOS 17.0, *)
  func decryptShare(_ encryptedShare: MatchKeyEncryption, privateKey: String) throws -> IPAShare {
    let ciphersuite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
    let privateKeydata = try IPAEncryptedMatchKey.hexStringToBytes(privateKey)
    
    let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeydata)
    
    var recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: ciphersuite, info: encryptedShare.info, encapsulatedKey: encryptedShare.encapsulatedKey)
    let shareData = try recipient.open(encryptedShare.matchKeyCiphertextAndTag, authenticating: encryptedShare.info)
    return IPAShare.fromData(shareData)
  }
  
  func testEncryptDecryptShare() throws {
    let encryptedMatchKey = IPAEncryptedMatchKey()
    
    let share = IPAEncryptedMatchKey.IPAShare(left: 1, right: 2)
    let metaDomain = "www.meta.com"
    let privateKeyOne = "53d58e022981f2edbf55fec1b45dbabd08a3442cb7b7c598839de5d7a5888bff"
    
    guard let matchKeyBlob = try encryptedMatchKey.encryptShare(share, eventType: EventType.source, siteDomain: metaDomain, whichHelper: HelperNumber.One) else {
      XCTFail("Failed to generate encrypted share")
      return
    }
    
    print("info size = \(matchKeyBlob.info.count)")

    let keyId: UInt8 = 0;
    let keyIdData = withUnsafeBytes(of: keyId) { Data($0) }

    let epoch: UInt16 = 0;
    let epochData = withUnsafeBytes(of: epoch) { Data($0) }

    let fileManager = FileManager.default
    let temporaryDirectory = fileManager.temporaryDirectory
    let temporaryFile = temporaryDirectory.appendingPathComponent("temp.txt")

    // Create the temporary file
    try fileManager.createFile(atPath: temporaryFile.path, contents: nil, attributes: nil)

    print("Temporary file path: \(temporaryFile.path)")
    //     Define the file URL where you want to write the blob
    let fileURL = URL(fileURLWithPath: temporaryFile.path)
    let fileHandle = try FileHandle(forWritingTo: fileURL)
    fileHandle.write(matchKeyBlob.encapsulatedKey)
      var total = 0
    print("encapsulated key offset = \(total) value = \([UInt8](matchKeyBlob.encapsulatedKey))")
      total += matchKeyBlob.encapsulatedKey.count

      fileHandle.write(matchKeyBlob.matchKeyCiphertextAndTag)
      print("matchKeyCiphertextAndTag offset = \(total) value = \([UInt8](matchKeyBlob.matchKeyCiphertextAndTag))")
      total += matchKeyBlob.matchKeyCiphertextAndTag.count

      fileHandle.write(EventType.source.toData())
      print("EventType offset = \(total) value = \([UInt8](EventType.source.toData()))")
      total += EventType.source.toData().count

      fileHandle.write(keyIdData)
      print("keyId offset = \(total) value = \([UInt8](keyIdData))")
      total += keyIdData.count
      
      fileHandle.write(epochData)
      print("epoch offset = \(total) value = \([UInt8](epochData))")
      total += epochData.count
    
      fileHandle.write(metaDomain.data(using: .utf8)!)
      print("metaDomain offset = \(total) value = \([UInt8](metaDomain.data(using: .utf8)!))")
      total += metaDomain.data(using: .utf8)!.count

//      print("Blob data written to file successfully at \(fileURL.absoluteString)")
      fileHandle.closeFile()
    
    let decryptedShare = try decryptShare(matchKeyBlob, privateKey: privateKeyOne)
    XCTAssertEqual(share.left, decryptedShare.left)
    XCTAssertEqual(share.right, decryptedShare.right)
  }
}
