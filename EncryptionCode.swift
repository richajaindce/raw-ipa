// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

import CryptoKit
import Foundation

@available(macOS 14.0, *)
public final class IPAEncryptedMatchKey {
  
  var matchKey: UInt64
  
  public init() {
    matchKey = UInt64.random(in: UInt64.min...UInt64.max)
  }
  
  public enum IPAErrorInternal: Error {
    case encryptSharesFailed
    case hexDecodeFailed
    case mobileConfigError
  }
  public enum EventType: Int {
    case trigger = 1
    case source = 0
    
    func toData() -> Data {
      let number: UInt8
      switch self {
      case .trigger: number = 1
      case .source: number = 0
      }
      let binaryData = withUnsafeBytes(of: number) { Data($0) }
      
      return binaryData
    }
  }
  
  enum HelperNumber {
    case One
    case Two
    case Three
  }
  
  public struct MatchKeyEncryption {
    var matchKeyCiphertextAndTag: Data
    var encapsulatedKey: Data
    var info: Data
  }
  
  struct IPAShare {
    var left: UInt64
    var right: UInt64
    
    public init(left: UInt64, right: UInt64) {
      self.left = left
      self.right = right
    }
    
    func toData() -> Data {
      var data = Data()
      
      withUnsafeBytes(of: left.littleEndian) { data.append(contentsOf: $0) }
      withUnsafeBytes(of: right.littleEndian) { data.append(contentsOf: $0) }
      
      return data
    }
  }
  
  struct IPAReportInfo {
    var keyId: UInt8
    var epoch: UInt16
    var eventType: EventType
    var helperDomain: String
    var siteDomain: String
    
    public func count() -> Int{
      return MemoryLayout.size(ofValue: keyId) + MemoryLayout.size(ofValue: epoch) + MemoryLayout.size(ofValue: eventType) + helperDomain.count + siteDomain.count
    }
    
    public func toData() -> Data {
      let DOMAIN = "private-attribution"
      var data = Data()
      
      data.append(DOMAIN.data(using: .utf8)!)
      data.append(0)
      data.append(helperDomain.data(using: .utf8)!)
      data.append(0)
      data.append(siteDomain.data(using: .utf8)!)
      data.append(0)
      withUnsafeBytes(of: keyId) { data.append(Data($0)) }
      withUnsafeBytes(of: epoch) { data.append(Data($0)) }
      withUnsafeBytes(of: eventType) { data.append(Data($0)) }
      
      return data
      
    }
  }
  
  /* This is the main function to get the encrypted shares of the match key. It does the following:
   1. Create 3 shares of the match key
   2. Encrypt each share with a different helper
   3. Return the encrypted shares */
  @available(iOS 17.0, *)
  public func getEncryptedMatchKey(eventType: EventType, siteDomain: String) throws -> (MatchKeyEncryption, MatchKeyEncryption, MatchKeyEncryption)? {
    let shares = createSharesOfMatchKey(matchKey)
    
    return try getEncryptedShares(eventType: eventType, siteDomain: siteDomain, shares: shares)
  }
  
  func createSharesOfMatchKey(_ matchKey: UInt64) -> (IPAShare, IPAShare, IPAShare) {
    let firstShare = UInt64.random(in: UInt64.min...UInt64.max)
    let secondShare = UInt64.random(in: UInt64.min...UInt64.max)
    let thirdShare = firstShare ^ secondShare ^ matchKey
    
    return (IPAShare(left: firstShare, right: secondShare),
            IPAShare(left: secondShare, right: thirdShare),
            IPAShare(left: thirdShare, right: firstShare))
  }
  
  @available(iOS 17.0, *)
  func getEncryptedShares(eventType: EventType, siteDomain: String, shares: (IPAShare, IPAShare, IPAShare)) throws -> (MatchKeyEncryption, MatchKeyEncryption, MatchKeyEncryption)? {
    
    let blob1 = try encryptShare(shares.0, eventType: eventType, siteDomain: siteDomain, whichHelper: HelperNumber.One)
    let blob2 = try encryptShare(shares.1, eventType: eventType, siteDomain: siteDomain, whichHelper: HelperNumber.Two)
    let blob3 = try encryptShare(shares.2, eventType: eventType, siteDomain: siteDomain, whichHelper: HelperNumber.Three)
    
    if let blob1, let blob2, let blob3 {
      return (blob1, blob2, blob3)
    } else {
      throw IPAErrorInternal.encryptSharesFailed
    }
  }
  
  /* This function encrypts a share of the match key towards a specific helper using its public key
   The public key is a Curve25519 used for HPKE
   For the info data, we use key id, epoch, event type, specific helper domain and site where the match key is being used
   key id and epoch are hard coded for now. These will be used in future when the usage is more scaled e.g. multiple key ids per helper and
   IPA queries running across many epochs.
   */
  
  @available(iOS 17.0, *)
  func encryptShare(_ share: IPAShare, eventType: EventType, siteDomain: String, whichHelper: HelperNumber) throws -> MatchKeyEncryption? {
    let (publicKeyString, helperDomain) = try getHelperPublicKeyAndDomain(whichHelper)
    
    let rawPublicKey = try IPAEncryptedMatchKey.hexStringToBytes(publicKeyString)
    
    let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey)
    let ciphersuite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
    
    let reportInfo = IPAReportInfo(keyId: 0, epoch: 0, eventType: eventType, helperDomain: helperDomain, siteDomain: siteDomain)
    let reportInfoData = reportInfo.toData()
    
    var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: ciphersuite, info: reportInfoData)
    let shareData = share.toData()
    let ciphertextAndTag = try sender.seal(shareData, authenticating: reportInfoData)
    
    return MatchKeyEncryption(matchKeyCiphertextAndTag: ciphertextAndTag, encapsulatedKey: sender.encapsulatedKey, info: reportInfoData)
  }
  
  // TODO(T186863032) memoize mobile config values
  func getHelperPublicKeyAndDomain(_ whichHelper: HelperNumber) throws -> (String, String) {
    var publicKeyString: String?
    var helperDomain: String?
    
    switch whichHelper {
    case .One:
      publicKeyString = "92a6fb666c37c008defd74abf3204ebea685742eab8347b08e2f7c759893947a"
      helperDomain = "github.com/private-attribution"
    case .Two:
      publicKeyString = "cfdbaaff16b30aa8a4ab07eaad2cdd80458208a1317aefbb807e46dce596617e"
      helperDomain = "github.com/private-attribution"
    case .Three:
      publicKeyString = "b900be35da06106a83ed73c33f733e03e4ea5888b7ea4c912ab270b0b0f8381e"
      helperDomain = "github.com/private-attribution"
    }
    
    if let publicKeyString, !publicKeyString.isEmpty, let helperDomain, !helperDomain.isEmpty {
      return (publicKeyString, helperDomain)
    } else {
      throw IPAErrorInternal.mobileConfigError
    }
  }
  
  // This is a helper function to convert a hex string to bytes
  static func hexStringToBytes(_ hexString: String) throws -> [UInt8] {
    var bytes = [UInt8]()
    let hexChars = Array(hexString)
    for i in stride(from: 0, to: hexChars.count, by: 2) {
      let hexByte = String(hexChars[i..<i + 2])
      if let byte = UInt8(hexByte, radix: 16) {
        bytes.append(byte)
      } else {
        throw IPAErrorInternal.hexDecodeFailed
      }
    }
    return bytes
  }
}
