import ExpoModulesCore
import UIKit
import WebKit

/// Signs in to an environment behind an identity proxy. The proxy and T3 Code session cookies
/// land in the web view's store, so they are copied into `HTTPCookieStorage.shared`, which
/// React Native's fetch and the T3WebSocket session send with every request.
final class T3EnvironmentSignIn: NSObject, WKNavigationDelegate, UIAdaptivePresentationControllerDelegate {
  private static let pollInterval: TimeInterval = 1.5

  let origin: URL
  private var promises: [Promise] = []
  private var webView: WKWebView?
  private var navigation: UINavigationController?
  private var timer: Timer?
  private var checking = false
  private var finished = false
  private let onFinish: () -> Void

  init(origin: URL, onFinish: @escaping () -> Void) {
    self.origin = origin
    self.onFinish = onFinish
  }

  func join(_ promise: Promise) {
    promises.append(promise)
  }

  /// Shows the sheet only when the cookies already saved do not give a session.
  func start(from presenter: UIViewController) {
    copyCookies(from: WKWebsiteDataStore.default()) { [weak self] in
      guard let self else { return }
      Self.hasSession(origin: self.origin) { signedIn in
        DispatchQueue.main.async {
          if signedIn { self.finish("ready", dismiss: false) } else if !self.finished { self.present(from: presenter) }
        }
      }
    }
  }

  private func copyCookies(from store: WKWebsiteDataStore, completion: @escaping () -> Void) {
    store.httpCookieStore.getAllCookies { [weak self] cookies in
      guard let self else { return }
      let host = self.origin.host ?? ""
      for cookie in cookies where Self.domainMatches(host: host, domain: cookie.domain) {
        HTTPCookieStorage.shared.setCookie(cookie)
      }
      completion()
    }
  }

  private func present(from presenter: UIViewController) {
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .default()
    let webView = WKWebView(frame: .zero, configuration: configuration)
    webView.navigationDelegate = self
    self.webView = webView

    let controller = UIViewController()
    controller.view = webView
    controller.title = origin.host
    controller.navigationItem.leftBarButtonItem = UIBarButtonItem(
      systemItem: .cancel,
      primaryAction: UIAction { [weak self] _ in self?.finish("cancelled") }
    )
    let navigation = UINavigationController(rootViewController: controller)
    navigation.presentationController?.delegate = self
    self.navigation = navigation
    presenter.present(navigation, animated: true)

    webView.load(URLRequest(url: origin))
    timer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
      self?.check()
    }
  }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    check()
  }

  func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
    finish("cancelled", dismiss: false)
  }

  func dismiss() {
    finish("cancelled")
  }

  /// Checks only once the web view is back on the environment, after the proxy's own pages.
  private func check() {
    guard !finished, !checking, let webView, let url = webView.url, Self.sameOrigin(url, origin)
    else { return }
    checking = true
    copyCookies(from: webView.configuration.websiteDataStore) { [weak self] in
      guard let self else { return }
      Self.hasSession(origin: self.origin) { signedIn in
        DispatchQueue.main.async {
          self.checking = false
          if signedIn { self.finish("ready") }
        }
      }
    }
  }

  private func finish(_ result: String, dismiss: Bool = true) {
    guard !finished else { return }
    finished = true
    timer?.invalidate()
    timer = nil
    webView?.stopLoading()
    if dismiss { navigation?.presentingViewController?.dismiss(animated: true) }
    for promise in promises { promise.resolve(result) }
    promises = []
    onFinish()
  }

  /// A redirect back to the proxy's sign-in page ends in HTML, which reads as signed out.
  private static func hasSession(origin: URL, completion: @escaping (Bool) -> Void) {
    var request = URLRequest(url: origin.appendingPathComponent("api/auth/session"))
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    request.cachePolicy = .reloadIgnoringLocalCacheData
    URLSession.shared.dataTask(with: request) { data, response, _ in
      guard let data, let response = response as? HTTPURLResponse, response.statusCode == 200,
        let url = response.url, sameOrigin(url, origin),
        let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
      else { return completion(false) }
      completion(body["authenticated"] as? Bool == true)
    }.resume()
  }

  static func sameOrigin(_ a: URL, _ b: URL) -> Bool {
    a.scheme?.lowercased() == b.scheme?.lowercased() && a.host?.lowercased() == b.host?.lowercased()
      && effectivePort(a) == effectivePort(b)
  }

  private static func effectivePort(_ url: URL) -> Int? {
    url.port ?? (url.scheme?.lowercased() == "https" ? 443 : url.scheme?.lowercased() == "http" ? 80 : nil)
  }

  private static func domainMatches(host: String, domain: String) -> Bool {
    let host = host.lowercased()
    let domain = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    return host == domain || host.hasSuffix("." + domain)
  }
}
