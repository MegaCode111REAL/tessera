// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TesseraCore",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "TesseraCore", targets: ["TesseraCore"]),
        .executable(name: "tessera-sign", targets: ["tessera-sign"]),
    ],
    dependencies: [
        // MIT-licensed ZIP reader/writer used behind ArchiveEngine / FormatAdapter.
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", from: "0.9.19"),
    ],
    targets: [
        .target(
            name: "TesseraCore",
            dependencies: [
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
            ],
            path: "Sources/TesseraCore"
        ),
        .executableTarget(
            name: "tessera-sign",
            dependencies: ["TesseraCore"],
            path: "Sources/tessera-sign"
        ),
        .testTarget(
            name: "TesseraCoreTests",
            dependencies: ["TesseraCore"],
            path: "Tests/TesseraCoreTests"
        ),
    ],
    swiftLanguageVersions: [.v5]
)
