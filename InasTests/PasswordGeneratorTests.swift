import XCTest
@testable import Inas

final class PasswordGeneratorTests: XCTestCase {
    func testShape() {
        for _ in 0..<200 {
            let password = PasswordGenerator.generate()
            XCTAssertEqual(password.count, 12)
            XCTAssertTrue(PasswordGenerator.isGeneratedShape(password), password)
            XCTAssertTrue(password.prefix(8).contains { $0.isUppercase } || password.prefix(8).contains { $0.isLowercase })
        }
    }

    func testUniqueness() {
        let samples = Set((0..<80).map { _ in PasswordGenerator.generate() })
        XCTAssertGreaterThan(samples.count, 70)
    }
}
