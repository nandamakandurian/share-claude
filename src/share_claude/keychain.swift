import Foundation
import Security

let service = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : ""
let operation = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
let account = NSUserName()

guard !service.isEmpty else {
    fputs("Missing Keychain service.\n", stderr)
    exit(2)
}

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account,
]

switch operation {
case "read":
    var result: CFTypeRef?
    var readQuery = query
    readQuery[kSecReturnData as String] = true
    readQuery[kSecMatchLimit as String] = kSecMatchLimitOne
    let status = SecItemCopyMatching(readQuery as CFDictionary, &result)
    if status == errSecItemNotFound { exit(3) }
    guard status == errSecSuccess, let data = result as? Data else {
        fputs("Keychain read failed (OSStatus \(status)).\n", stderr)
        exit(1)
    }
    FileHandle.standardOutput.write(data)

case "write":
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard !data.isEmpty else {
        fputs("Empty Keychain value.\n", stderr)
        exit(2)
    }
    let update: [String: Any] = [kSecValueData as String: data]
    var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
    if status == errSecItemNotFound {
        var add = query
        add[kSecValueData as String] = data
        status = SecItemAdd(add as CFDictionary, nil)
    }
    guard status == errSecSuccess else {
        fputs("Keychain write failed (OSStatus \(status)).\n", stderr)
        exit(1)
    }

case "delete":
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        fputs("Keychain delete failed (OSStatus \(status)).\n", stderr)
        exit(1)
    }

default:
    fputs("Expected read, write, or delete.\n", stderr)
    exit(2)
}
