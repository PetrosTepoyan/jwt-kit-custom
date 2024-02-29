struct JWKSigner: Sendable {
    let jwk: JWK
    
    let parser: any JWTParser
    let serializer: any JWTSerializer

    init(jwk: JWK, parser: some JWTParser, serializer: some JWTSerializer) {
        self.jwk = jwk
        self.parser = parser
        self.serializer = serializer
    }

    func signer(for algorithm: JWK.Algorithm? = nil) -> JWTSigner? {
        switch jwk.keyType.backing {
        case .ecdsa:
            guard let x = self.jwk.x else {
                return nil
            }
            guard let y = self.jwk.y else {
                return nil
            }

            guard let algorithm = algorithm ?? self.jwk.algorithm else {
                return nil
            }

            do {
                switch algorithm {
                case .es256:
                    if let privateExponent = self.jwk.privateExponent {
                        return try .init(algorithm: ECDSASigner(
                            key: ES256PrivateKey(key: privateExponent),
                            algorithm: .sha256,
                            name: "ES256"
                        ))
                    } else {
                        return try .init(algorithm: ECDSASigner(
                            key: ES256PublicKey(parameters: (x, y)),
                            algorithm: .sha256,
                            name: "ES256"
                        ))
                    }

                case .es384:
                    if let privateExponent = self.jwk.privateExponent {
                        return try .init(algorithm: ECDSASigner(
                            key: ES384PrivateKey(key: privateExponent),
                            algorithm: .sha384,
                            name: "ES384"
                        ))
                    } else {
                        return try .init(algorithm: ECDSASigner(
                            key: ES384PublicKey(parameters: (x, y)),
                            algorithm: .sha384,
                            name: "ES384"
                        ))
                    }
                case .es512:
                    if let privateExponent = self.jwk.privateExponent {
                        return try .init(algorithm: ECDSASigner(
                            key: ES512PrivateKey(key: privateExponent),
                            algorithm: .sha512,
                            name: "ES512"
                        ))
                    } else {
                        return try .init(algorithm: ECDSASigner(
                            key: ES512PublicKey(parameters: (x, y)),
                            algorithm: .sha512,
                            name: "ES512"
                        ))
                    }
                default:
                    return nil
                }
            } catch {
                return nil
            }
        case .octetKeyPair:
            guard let algorithm = algorithm ?? self.jwk.algorithm else {
                return nil
            }

            guard let curve = self.jwk.curve.flatMap({ EdDSACurve(rawValue: $0.rawValue) }) else {
                return nil
            }

            switch (algorithm, self.jwk.x, self.jwk.privateExponent) {
            case let (.eddsa, .some(x), .some(d)):
                let key = try? EdDSA.PrivateKey(x: x, d: d, curve: curve)
                return key.map { .init(algorithm: EdDSASigner(key: $0)) }

            case let (.eddsa, .some(x), .none):
                let key = try? EdDSA.PublicKey(x: x, curve: curve)
                return key.map { .init(algorithm: EdDSASigner(key: $0)) }

            default:
                return nil
            }
        }
    }
}
