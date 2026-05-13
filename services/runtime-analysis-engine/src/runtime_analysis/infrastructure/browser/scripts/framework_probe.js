/**
 * framework_probe.js
 * Probes well-known global variables and DOM attributes to fingerprint the
 * frontend framework. Fires window.__onFrameworkSignal(...) for each signal.
 *
 * Runs after DOMContentLoaded to allow SSR markers to appear.
 */
(function () {
  "use strict";

  function emit(framework, version, confidence, evidence) {
    if (window.__onFrameworkSignal) {
      window.__onFrameworkSignal({ framework, version, confidence, evidence });
    }
  }

  function probe() {
    // --- React ---
    if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      const renderers = window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers;
      let version = null;
      if (renderers && renderers.size > 0) {
        const first = renderers.values().next().value;
        version = (first && first.version) || null;
      }
      emit("REACT", version, 0.95, "__REACT_DEVTOOLS_GLOBAL_HOOK__");
    } else {
      // Fallback: check data-reactroot attribute
      const reactRoot = document.querySelector("[data-reactroot]");
      if (reactRoot) emit("REACT", null, 0.7, "data-reactroot");
    }

    // --- Next.js ---
    if (window.__NEXT_DATA__) {
      const version = (window.__NEXT_DATA__.buildId && null) || null; // version not directly exposed
      emit("NEXT", version, 0.98, "__NEXT_DATA__");
    }
    if (window.__NEXT_LOADED_PAGES__) {
      emit("NEXT", null, 0.85, "__NEXT_LOADED_PAGES__");
    }

    // --- Vue 3 ---
    if (window.__VUE__) {
      emit("VUE", null, 0.95, "window.__VUE__");
    }
    const vueApp = document.querySelector("[data-v-app]");
    if (vueApp) {
      const instance = vueApp.__vue_app__;
      const version = (instance && instance.version) || null;
      emit("VUE", version, 0.9, "data-v-app");
    }

    // --- Vue 2 ---
    if (window.Vue && window.Vue.version) {
      emit("VUE", window.Vue.version, 0.9, "window.Vue");
    }

    // --- Angular ---
    const ngEl = document.querySelector("[ng-version]");
    if (ngEl) {
      emit("ANGULAR", ngEl.getAttribute("ng-version"), 0.98, "ng-version");
    }

    // --- Nuxt ---
    if (window.__NUXT__) {
      emit("NUXT", null, 0.97, "window.__NUXT__");
    }
    if (window.$nuxt) {
      const version = (window.$nuxt.$root && window.$nuxt.$root.$options._base && window.$nuxt.$root.$options._base.version) || null;
      emit("NUXT", version, 0.9, "window.$nuxt");
    }

    // --- Svelte ---
    if (window.__svelte) {
      emit("SVELTE", null, 0.9, "window.__svelte");
    }
    // SvelteKit hydration marker
    const svelteEl = document.querySelector("[data-svelte]");
    if (svelteEl) {
      emit("SVELTE", null, 0.8, "data-svelte");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", probe);
  } else {
    probe();
  }
})();
