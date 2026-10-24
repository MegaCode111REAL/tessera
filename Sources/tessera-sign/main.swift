import Foundation
import TesseraCore

// Developer/CI tool: ad-hoc signs an extracted .app with Tessera's signing engine and verifies it.
// Usage: tessera-sign Payload/Foo.app
guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: tessera-sign <path/to/App.app>\n".utf8))
    exit(2)
}
let app = URL(fileURLWithPath: CommandLine.arguments[1])
do {
    let metadata = try BundleInspector().inspect(appBundle: app)
    let plan = SigningPlanner.makePlan(metadata: metadata)
    let engine = BundleSigner()
    let request = SigningRequest(appBundle: app, plan: plan, identityID: nil, profile: nil, profileData: nil)
    try await engine.sign(request) { step in print("signed \(step.displayName)") }
    let issues = SignatureVerifier.verify(appBundle: app, plan: plan)
    for issue in issues { print("\(issue.severity.rawValue): \(issue.message)") }
    exit(issues.contains { $0.severity == .error } ? 1 : 0)
} catch {
    FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
    exit(1)
}
