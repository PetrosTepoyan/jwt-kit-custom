// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.2.0")
    ],
    targets: [
        .target(
            name: "JWTKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates")
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "JWTKitTests",
            dependencies: [
                "JWTKit",
            ],
            resources: [
                .copy("TestVectors"),
                .copy("TestCertificates"),
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .enableUpcomingFeature("ConciseMagicFile"),
            ]
        ),
    ]
)
