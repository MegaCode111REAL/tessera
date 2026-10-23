import Foundation

public enum DownloadError: Error, LocalizedError, Equatable {
    case httpsRequired
    case insecureRedirect
    case badStatus(Int)
    case tooLarge(UInt64)
    case failed(String)

    public var errorDescription: String? {
        switch self {
        case .httpsRequired: return "Only HTTPS downloads are allowed."
        case .insecureRedirect: return "The server tried to redirect the download to an insecure address."
        case .badStatus(let code): return "The server responded with status \(code)."
        case .tooLarge(let limit): return "The download is larger than the \(limit / 1_048_576) MB limit."
        case .failed(let message): return "The download failed: \(message)"
        }
    }
}

/// Downloads one file over HTTPS. This is Tessera's only network code, and it runs only after the
/// user confirms a specific URL. It sends no cookies or credentials, refuses redirects to anything
/// but HTTPS, and stops once the size limit is exceeded.
public struct DownloadService: Sendable {
    public static let defaultMaxBytes: UInt64 = 8 * 1024 * 1024 * 1024

    public let maxBytes: UInt64

    public init(maxBytes: UInt64 = DownloadService.defaultMaxBytes) {
        self.maxBytes = maxBytes
    }

    /// A safe local file name for a download, always ending in `.ipa` or `.tipa`.
    static func fileName(for url: URL) -> String {
        let last = url.lastPathComponent
        let lower = last.lowercased()
        if lower.hasSuffix(".ipa") || lower.hasSuffix(".tipa"), last.count <= 120,
           !last.contains("/"), !last.hasPrefix(".") {
            return last
        }
        return "download.ipa"
    }

    /// Downloads `url` into `directory` and returns the file's location.
    public func download(
        _ url: URL,
        into directory: URL,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> URL {
        guard url.scheme?.lowercased() == "https" else { throw DownloadError.httpsRequired }

        let destination = directory.appendingPathComponent(Self.fileName(for: url))
        let delegate = DownloadDelegate(destination: destination, maxBytes: maxBytes, progress: progress)

        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 30
        configuration.waitsForConnectivity = false

        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                delegate.start(session: session, url: url, continuation: continuation)
            }
        } onCancel: {
            delegate.cancel()
        }
    }
}

/// Bridges `URLSessionDownloadDelegate` callbacks to a single async result.
private final class DownloadDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let destination: URL
    private let maxBytes: UInt64
    private let progress: (@Sendable (Double) -> Void)?

    private let lock = NSLock()
    private var continuation: CheckedContinuation<URL, Error>?
    private var task: URLSessionDownloadTask?
    private var recordedError: Error?
    private var moved = false
    private var cancelled = false
    private var finished = false

    init(destination: URL, maxBytes: UInt64, progress: (@Sendable (Double) -> Void)?) {
        self.destination = destination
        self.maxBytes = maxBytes
        self.progress = progress
    }

    func start(session: URLSession, url: URL, continuation: CheckedContinuation<URL, Error>) {
        lock.lock()
        if cancelled {
            finished = true
            lock.unlock()
            continuation.resume(throwing: CancellationError())
            return
        }
        self.continuation = continuation
        var request = URLRequest(url: url)
        request.httpShouldHandleCookies = false
        let task = session.downloadTask(with: request)
        self.task = task
        lock.unlock()
        task.resume()
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let task = self.task
        lock.unlock()
        task?.cancel()
    }

    private func record(_ error: Error) {
        lock.lock()
        if recordedError == nil { recordedError = error }
        lock.unlock()
    }

    private func finish(_ result: Result<URL, Error>) {
        lock.lock()
        guard !finished, let continuation else {
            lock.unlock()
            return
        }
        finished = true
        self.continuation = nil
        lock.unlock()
        continuation.resume(with: result)
    }

    // MARK: URLSessionTaskDelegate

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        if request.url?.scheme?.lowercased() == "https" {
            completionHandler(request)
        } else {
            record(DownloadError.insecureRedirect)
            completionHandler(nil)
            task.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let wasCancelled = cancelled
        let recorded = recordedError
        let didMove = moved
        lock.unlock()

        if let recorded {
            finish(.failure(recorded))
        } else if wasCancelled {
            finish(.failure(CancellationError()))
        } else if let error {
            finish(.failure(DownloadError.failed(error.localizedDescription)))
        } else if didMove {
            finish(.success(destination))
        } else {
            finish(.failure(DownloadError.failed("No data was received.")))
        }
    }

    // MARK: URLSessionDownloadDelegate

    func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didWriteData bytesWritten: Int64,
        totalBytesWritten: Int64,
        totalBytesExpectedToWrite: Int64
    ) {
        if UInt64(max(totalBytesWritten, 0)) > maxBytes {
            record(DownloadError.tooLarge(maxBytes))
            downloadTask.cancel()
            return
        }
        if totalBytesExpectedToWrite > 0 {
            progress?(Double(totalBytesWritten) / Double(totalBytesExpectedToWrite))
        }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        if let http = downloadTask.response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            record(DownloadError.badStatus(http.statusCode))
            return
        }
        // The temporary file is deleted when this method returns, so move it now.
        do {
            let fm = FileManager.default
            try? fm.removeItem(at: destination)
            try fm.moveItem(at: location, to: destination)
            lock.lock()
            moved = true
            lock.unlock()
        } catch {
            record(DownloadError.failed(error.localizedDescription))
        }
    }
}
