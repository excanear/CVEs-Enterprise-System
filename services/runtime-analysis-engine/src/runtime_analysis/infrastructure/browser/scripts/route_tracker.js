/**
 * route_tracker.js
 * Wraps history.pushState, history.replaceState, and listens to popstate
 * to capture SPA client-side navigation events.
 * Reports via window.__onRouteChange({ path, method, timestamp }).
 */
(function () {
  "use strict";

  function report(method, path) {
    if (window.__onRouteChange) {
      window.__onRouteChange({
        path: path,
        method: method,
        timestamp: Date.now(),
      });
    }
  }

  const _pushState = history.pushState.bind(history);
  history.pushState = function (state, title, url) {
    _pushState(state, title, url);
    if (url) report("pushState", String(url));
  };

  const _replaceState = history.replaceState.bind(history);
  history.replaceState = function (state, title, url) {
    _replaceState(state, title, url);
    if (url) report("replaceState", String(url));
  };

  window.addEventListener("popstate", function () {
    report("popstate", window.location.pathname + window.location.search);
  });
})();
