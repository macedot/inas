import XCTest
@testable import Inas

final class DialectPolicyTests: XCTestCase {
    func testAllowsSMB3Only() {
        XCTAssertFalse(DialectPolicy.accepts(0x0202))
        XCTAssertFalse(DialectPolicy.accepts(0x0210))
        XCTAssertFalse(DialectPolicy.accepts(0x0300))
        XCTAssertTrue(DialectPolicy.accepts(0x0302))
        XCTAssertTrue(DialectPolicy.accepts(0x0311))
        XCTAssertFalse(DialectPolicy.accepts(0x0100))
    }
}
