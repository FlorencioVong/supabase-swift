//
//  SessionManagerTests.swift
//
//
//  Created by Guilherme Souza on 23/10/23.
//

import ConcurrencyExtras
import CustomDump
import InlineSnapshotTesting
import TestHelpers
import XCTest
import XCTestDynamicOverlay

@testable import Auth

final class SessionManagerTests: XCTestCase {
  var http: HTTPClientMock!

  let clientID = AuthClientID()

  var sut: SessionManager {
    Dependencies[clientID].sessionManager
  }

  override func setUp() {
    super.setUp()

    http = HTTPClientMock()

    Dependencies[clientID] = .init(
      configuration: .init(
        url: clientURL,
        localStorage: InMemoryLocalStorage(),
        autoRefreshToken: false
      ),
      http: http,
      api: APIClient(clientID: clientID),
      codeVerifierStorage: .mock,
      sessionStorage: SessionStorage.live(clientID: clientID),
      sessionManager: SessionManager.live(clientID: clientID)
    )
  }

  #if !os(Windows) && !os(Linux) && !os(Android)
    override func invokeTest() {
      withMainSerialExecutor {
        super.invokeTest()
      }
    }
  #endif

  func testSession_shouldFailWithSessionNotFound() async {
    do {
      _ = try await sut.session()
      XCTFail("Expected a \(AuthError.sessionMissing) failure")
    } catch {
      assertInlineSnapshot(of: error, as: .dump) {
        """
        - AuthError.sessionMissing

        """
      }
    }
  }

  func testSession_shouldReturnValidSession() async throws {
    let session = Session.validSession
    Dependencies[clientID].sessionStorage.store(session)

    let returnedSession = try await sut.session()
    expectNoDifference(returnedSession, session)
  }

  func testSession_shouldRefreshSession_whenCurrentSessionExpired() async throws {
    let currentSession = Session.expiredSession
    Dependencies[clientID].sessionStorage.store(currentSession)

    let validSession = Session.validSession

    let refreshSessionCallCount = LockIsolated(0)

    let (refreshSessionStream, refreshSessionContinuation) = AsyncStream<Session>.makeStream()

    await http.when(
      { $0.url.path.contains("/token") },
      return: { _ in
        refreshSessionCallCount.withValue { $0 += 1 }
        let session = await refreshSessionStream.first(where: { _ in true })!
        return .stub(session)
      }
    )

    // Fire N tasks and call sut.session()
    let tasks = (0..<10).map { _ in
      Task { [weak self] in
        try await self?.sut.session()
      }
    }

    await Task.yield()

    refreshSessionContinuation.yield(validSession)
    refreshSessionContinuation.finish()

    // Await for all tasks to complete.
    var result: [Result<Session?, Error>] = []
    for task in tasks {
      let value = await task.result
      result.append(value)
    }

    // Verify that refresher and storage was called only once.
    expectNoDifference(refreshSessionCallCount.value, 1)
    expectNoDifference(
      try result.map { try $0.get()?.accessToken },
      (0..<10).map { _ in validSession.accessToken }
    )
  }

  // MARK: - Commit guard (SDK-1882)

  /// A session with tokens derived from `name`, so two sessions in one test are distinguishable.
  private func session(_ name: String) -> Session {
    Session(
      accessToken: "\(name)-access",
      tokenType: "bearer",
      expiresIn: 120,
      expiresAt: Date().addingTimeInterval(120).timeIntervalSince1970,
      refreshToken: "\(name)-refresh",
      user: User(fromMockNamed: "user")
    )
  }

  /// Holds the `/token` response until `release()` is called, so a sign-out can interleave.
  private func heldTokenResponse(
    _ response: @escaping @Sendable () throws -> HTTPResponse
  ) async -> (requestSeen: LockIsolated<Bool>, release: @Sendable () -> Void) {
    let (gate, continuation) = AsyncStream<Void>.makeStream()
    let requestSeen = LockIsolated(false)

    await http.when(
      { $0.url.path.contains("/token") },
      return: { _ in
        requestSeen.setValue(true)
        _ = await gate.first(where: { _ in true })
        return try response()
      }
    )

    return (
      requestSeen,
      {
        continuation.yield(())
        continuation.finish()
      }
    )
  }

  private func collectAuthEvents() -> (events: LockIsolated<[AuthChangeEvent]>, stop: () -> Void) {
    let events = LockIsolated<[AuthChangeEvent]>([])
    let token = Dependencies[clientID].eventEmitter.attach { event, _ in
      events.withValue { $0.append(event) }
    }
    return (events, { token.cancel() })
  }

  func testStaleRefreshDoesNotOverwriteANewerStoredSession() async throws {
    let userA = session("A")
    let userB = session("B")
    let refreshedA = session("A2")

    Dependencies[clientID].sessionStorage.store(userA)
    let (requestSeen, release) = await heldTokenResponse {
      .stub(refreshedA)
    }
    let (events, stopCollecting) = collectAuthEvents()
    defer { stopCollecting() }

    let refresh = Task { try await sut.refreshSession(userA.refreshToken) }
    let sawRequest = await waitUntil { requestSeen.value }
    XCTAssertTrue(sawRequest)

    // User A signs out, then user B signs in — both land while A's refresh is in flight.
    await sut.remove()
    await sut.update(userB)

    release()
    let result = await refresh.result

    expectNoDifference(
      Dependencies[clientID].sessionStorage.get()?.refreshToken, userB.refreshToken)
    XCTAssertTrue(!events.value.contains(.tokenRefreshed))
    if case .failure(let error) = result {
      expectNoDifference(error as? AuthError, .refreshDiscarded)
    } else { XCTFail("Expected refreshDiscarded") }
  }

  func testStaleRefreshDoesNotDeleteANewerStoredSessionOnACleanupError() async throws {
    let userA = session("A")
    let userB = session("B")

    Dependencies[clientID].sessionStorage.store(userA)
    // `/logout` has already revoked A's refresh token by the time this answer arrives.
    let (requestSeen, release) = await heldTokenResponse {
      .stub(
        #"{"code":"refresh_token_not_found","message":"Refresh Token Not Found"}"#,
        code: 400,
        headers: ["X-Supabase-Api-Version": "2024-01-01"]
      )
    }
    let (events, stopCollecting) = collectAuthEvents()
    defer { stopCollecting() }

    let refresh = Task { try await sut.refreshSession(userA.refreshToken) }
    let sawRequest = await waitUntil { requestSeen.value }
    XCTAssertTrue(sawRequest)

    await sut.remove()
    await sut.update(userB)

    release()
    let result = await refresh.result

    expectNoDifference(
      Dependencies[clientID].sessionStorage.get()?.refreshToken, userB.refreshToken)
    XCTAssertTrue(!events.value.contains(.signedOut))
    // A's caller still learns its own session is gone — the server did reject A's refresh token.
    // What must not happen is B being signed out along with it.
    if case .failure(let error) = result {
      expectNoDifference(error as? AuthError, .sessionMissing)
    } else { XCTFail("Expected sessionMissing") }
  }

  func testRefreshForADifferentTokenDoesNotJoinAnInFlightRefresh() async throws {
    let userA = session("A")
    let userB = session("B")
    let refreshedA = session("A2")
    let refreshedB = session("B2")

    Dependencies[clientID].sessionStorage.store(userA)

    let tokensRequested = LockIsolated<[String]>([])
    let (gate, continuation) = AsyncStream<Void>.makeStream()

    struct RefreshBody: Decodable { let refreshToken: String }

    // Answers each token with its own rotated session, so joining the wrong task is visible in
    // the result and not only in the request count.
    await http.when(
      { $0.url.path.contains("/token") },
      return: { request in
        let refreshToken = try AuthClient.Configuration.jsonDecoder.decode(
          RefreshBody.self, from: request.body ?? Data()
        ).refreshToken
        tokensRequested.withValue { $0.append(refreshToken) }

        // Hold A's request only, so B's refresh is requested while A's is still in flight.
        if refreshToken == userA.refreshToken {
          _ = await gate.first(where: { _ in true })
        }
        return .stub(refreshToken == userA.refreshToken ? refreshedA : refreshedB)
      }
    )

    let refreshA = Task { try await sut.refreshSession(userA.refreshToken) }
    let sawRequest = await waitUntil { tokensRequested.value.contains(userA.refreshToken) }
    XCTAssertTrue(sawRequest)

    await sut.update(userB)
    // Started as a task, not awaited inline: while the bug is present B joins A's gated task, and
    // awaiting inline would deadlock against the release below instead of failing.
    let refreshB = Task { try await sut.refreshSession(userB.refreshToken) }
    _ = await waitUntil { tokensRequested.value.count == 2 }

    continuation.yield(())
    continuation.finish()
    _ = await refreshA.result
    let resultB = await refreshB.result

    // B asked to refresh its own token, so it must not be served A's in-flight task.
    expectNoDifference(try resultB.get().refreshToken, refreshedB.refreshToken)
    expectNoDifference(tokensRequested.value.sorted(), [userA, userB].map(\.refreshToken).sorted())
  }

  func testRefreshForTheSameTokenJoinsTheInFlightRefreshAfterAnotherTokenIntervened() async throws {
    let userA = session("A")
    let userB = session("B")

    Dependencies[clientID].sessionStorage.store(userA)

    let tokensRequested = LockIsolated<[String]>([])
    let (gate, continuation) = AsyncStream<Void>.makeStream()

    struct RefreshBody: Decodable { let refreshToken: String }

    await http.when(
      { $0.url.path.contains("/token") },
      return: { request in
        let refreshToken = try AuthClient.Configuration.jsonDecoder.decode(
          RefreshBody.self, from: request.body ?? Data()
        ).refreshToken
        tokensRequested.withValue { $0.append(refreshToken) }

        if refreshToken == userA.refreshToken {
          _ = await gate.first(where: { _ in true })
        }
        return .stub(userA)
      }
    )

    let firstA = Task { try await sut.refreshSession(userA.refreshToken) }
    let sawFirstA = await waitUntil { tokensRequested.value.contains(userA.refreshToken) }
    XCTAssertTrue(sawFirstA)

    // B's refresh must not evict A's in-flight task, so this second A joins the first rather than
    // redeeming A's refresh token a second time.
    let refreshB = Task { try await sut.refreshSession(userB.refreshToken) }
    _ = await waitUntil { tokensRequested.value.contains(userB.refreshToken) }
    let secondA = Task { try await sut.refreshSession(userA.refreshToken) }
    // A short window: while the bug is present the third request is issued as soon as the join
    // check misses, so this only has to outlast that — not wait out a full timeout.
    _ = await waitUntil(timeout: 0.5) { tokensRequested.value.count > 2 }

    continuation.yield(())
    continuation.finish()
    _ = await firstA.result
    _ = await refreshB.result
    _ = await secondA.result

    expectNoDifference(tokensRequested.value.filter { $0 == userA.refreshToken }.count, 1)
  }

  func testRefreshCommitsWhenStorageStartsEmpty() async throws {
    // `setSession(accessToken:refreshToken:)` refreshes an externally-sourced token with nothing
    // stored yet. The guard must not mistake that for a session replaced under it.
    let hydrated = session("hydrated")

    await http.when(
      { $0.url.path.contains("/token") },
      return: { _ in .stub(hydrated) }
    )

    let result = try await sut.refreshSession("externally-sourced-refresh")

    expectNoDifference(result.refreshToken, hydrated.refreshToken)
    expectNoDifference(
      Dependencies[clientID].sessionStorage.get()?.refreshToken, hydrated.refreshToken)
  }
}

/// Polls `condition` until it returns `true` or `timeout` elapses.
///
/// Swift Testing has no direct equivalent of `XCTestExpectation` + `fulfillment(of:timeout:)` for
/// "wait for an async condition driven by a concurrently-running task".
@discardableResult
private func waitUntil(
  timeout: TimeInterval = 10.0,
  pollInterval: UInt64 = 10_000_000,
  condition: @escaping @Sendable () -> Bool
) async -> Bool {
  let deadline = Date().addingTimeInterval(timeout)
  while Date() < deadline {
    if condition() { return true }
    try? await Task.sleep(nanoseconds: pollInterval)
  }
  return condition()
}

extension SessionManagerTests {
  func testReviewRefreshCannotRestoreSignedOutSession() async throws {
    let before = Session.expiredSession
    let refreshed = Session.validSession
    Dependencies[clientID].sessionStorage.store(before)
    let (responses, continuation) = AsyncStream<Session>.makeStream()
    let requestSeen = LockIsolated(false)
    await http.when({ $0.url.path.contains("/token") }, return: { _ in
      requestSeen.setValue(true)
      return .stub(await responses.first(where: { _ in true })!)
    })
    let refresh = Task { try await sut.refreshSession(before.refreshToken) }
    for _ in 0..<1000 {
      if requestSeen.value { break }
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    XCTAssertTrue(requestSeen.value)
    await sut.remove()
    XCTAssertNil(Dependencies[clientID].sessionStorage.get())
    continuation.yield(refreshed)
    continuation.finish()
    _ = await refresh.result
    XCTAssertNil(Dependencies[clientID].sessionStorage.get(), "a refresh must not restore a signed-out session")
  }
}

extension SessionManagerTests {
  func testReviewLateRefreshCannotReplaceNextLogin() async throws {
    let before = Session.expiredSession
    let refreshed = Session.validSession
    var nextUser = Session.validSession
    nextUser.accessToken = "next-user-access"
    nextUser.refreshToken = "next-user-refresh"
    Dependencies[clientID].sessionStorage.store(before)
    let (responses, continuation) = AsyncStream<Session>.makeStream()
    let requestSeen = LockIsolated(false)
    await http.when({ $0.url.path.contains("/token") }, return: { _ in
      requestSeen.setValue(true)
      return .stub(await responses.first(where: { _ in true })!)
    })
    let refresh = Task { try await sut.refreshSession(before.refreshToken) }
    for _ in 0..<1000 {
      if requestSeen.value { break }
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    XCTAssertTrue(requestSeen.value)
    await sut.remove()
    XCTAssertNil(Dependencies[clientID].sessionStorage.get())
    // AuthClient.signIn stores the new login through this same SessionManager update.
    await sut.update(nextUser)
    continuation.yield(refreshed)
    continuation.finish()
    _ = await refresh.result
    let sessionForNextRequest = try await sut.session()
    XCTAssertEqual(sessionForNextRequest.accessToken, nextUser.accessToken)
    XCTAssertEqual(Dependencies[clientID].sessionStorage.get()?.refreshToken, nextUser.refreshToken)
  }
}
