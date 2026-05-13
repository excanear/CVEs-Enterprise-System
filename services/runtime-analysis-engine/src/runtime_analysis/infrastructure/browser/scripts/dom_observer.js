/**
 * dom_observer.js
 * Installs a MutationObserver on document.documentElement and reports
 * debounced summaries (500 ms quiet window) via window.__onMutation(summary).
 *
 * Tracks: node additions/removals, attribute changes, newly added <script>
 * and <form> elements.
 */
(function () {
  "use strict";

  let _addedNodes = 0;
  let _removedNodes = 0;
  let _attrChanges = 0;
  const _addedScripts = [];
  const _addedForms = [];
  let _debounceTimer = null;

  function flush() {
    if (!window.__onMutation) return;
    window.__onMutation({
      nodeAdditions: _addedNodes,
      nodeRemovals: _removedNodes,
      attrChanges: _attrChanges,
      addedScripts: _addedScripts.slice(),
      addedForms: _addedForms.slice(),
      timestamp: Date.now(),
    });
    // Reset counters so subsequent flushes are incremental
    _addedNodes = 0;
    _removedNodes = 0;
    _attrChanges = 0;
    _addedScripts.length = 0;
    _addedForms.length = 0;
  }

  function schedule() {
    if (_debounceTimer !== null) clearTimeout(_debounceTimer);
    _debounceTimer = setTimeout(function () {
      _debounceTimer = null;
      flush();
    }, 500);
  }

  const observer = new MutationObserver(function (mutations) {
    mutations.forEach(function (mutation) {
      if (mutation.type === "attributes") {
        _attrChanges++;
      } else if (mutation.type === "childList") {
        _addedNodes += mutation.addedNodes.length;
        _removedNodes += mutation.removedNodes.length;

        mutation.addedNodes.forEach(function (node) {
          if (node.nodeType !== Node.ELEMENT_NODE) return;
          if (node.tagName === "SCRIPT") {
            _addedScripts.push(node.src || node.textContent.slice(0, 200));
          } else if (node.tagName === "FORM") {
            _addedForms.push(node.action || node.id || "");
          }
          // Recurse into subtrees
          node.querySelectorAll && node.querySelectorAll("script, form").forEach(function (child) {
            if (child.tagName === "SCRIPT") {
              _addedScripts.push(child.src || child.textContent.slice(0, 200));
            } else if (child.tagName === "FORM") {
              _addedForms.push(child.action || child.id || "");
            }
          });
        });
      }
    });
    schedule();
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    characterData: false,
  });
})();
