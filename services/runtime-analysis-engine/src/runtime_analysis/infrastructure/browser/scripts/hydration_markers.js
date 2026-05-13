/**
 * hydration_markers.js
 * Reads all well-known SSR hydration markers BEFORE re-render and exposes
 * them as window.__hydrationMarkers = { ... }.
 *
 * This script must run at document start (via page.addInitScript) so it
 * captures markers before the framework's client-side runtime removes them.
 */
(function () {
  "use strict";

  function safeGet(fn) {
    try { return fn(); } catch (_) { return undefined; }
  }

  function collectMarkers() {
    var markers = {};

    // Next.js
    markers.nextData = safeGet(function () { return window.__NEXT_DATA__ ? JSON.stringify(window.__NEXT_DATA__).slice(0, 512) : undefined; });

    // Nuxt
    markers.nuxtData = safeGet(function () { return window.__NUXT__ ? JSON.stringify(window.__NUXT__).slice(0, 512) : undefined; });

    // React SSR (data-reactroot)
    markers.dataReactRoot = safeGet(function () {
      var el = document.querySelector("[data-reactroot]");
      return el ? true : undefined;
    });

    // Generic server-rendered attribute (Vue / Nuxt / etc.)
    markers.dataServerRendered = safeGet(function () {
      var el = document.querySelector("[data-server-rendered]");
      return el ? el.getAttribute("data-server-rendered") : undefined;
    });

    // Angular
    markers.ngVersion = safeGet(function () {
      var el = document.querySelector("[ng-version]");
      return el ? el.getAttribute("ng-version") : undefined;
    });

    // Inertia.js
    markers.inertia = safeGet(function () {
      var el = document.querySelector("[data-page]");
      return el ? true : undefined;
    });

    // Redux / generic initial state bags
    markers.initialState = safeGet(function () {
      return window.__INITIAL_STATE__ ? JSON.stringify(window.__INITIAL_STATE__).slice(0, 256) : undefined;
    });
    markers.reduxState = safeGet(function () {
      return window.__REDUX_STATE__ ? JSON.stringify(window.__REDUX_STATE__).slice(0, 256) : undefined;
    });
    markers.apolloState = safeGet(function () {
      return window.__APOLLO_STATE__ ? JSON.stringify(window.__APOLLO_STATE__).slice(0, 256) : undefined;
    });

    // Remove undefined keys
    Object.keys(markers).forEach(function (k) {
      if (markers[k] === undefined) delete markers[k];
    });

    return markers;
  }

  // Capture immediately at script evaluation time
  window.__hydrationMarkers = collectMarkers();

  // Re-capture after DOMContentLoaded in case inline <script> sets them later
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      var late = collectMarkers();
      Object.assign(window.__hydrationMarkers, late);
    });
  }
})();
