/**
 * network_hooks.js
 * Patches window.fetch, XMLHttpRequest, and WebSocket to capture all
 * outbound network calls. Invokes Python-exposed callbacks:
 *   window.__onNetworkCall(data)  — for fetch / XHR
 *   window.__onWSEvent(data)      — for WebSocket connect + messages
 *
 * Body samples are truncated to 4 KB to prevent memory bloat.
 */
(function () {
  "use strict";

  const MAX_BODY = 4096;

  function truncate(str) {
    if (!str) return "";
    return typeof str === "string" ? str.slice(0, MAX_BODY) : String(str).slice(0, MAX_BODY);
  }

  // ------------------------------------------------------------------ fetch
  const _originalFetch = window.fetch;
  window.fetch = async function (input, init) {
    const url = typeof input === "string" ? input : input.url;
    const method = (init && init.method) || "GET";
    let reqBody = "";
    try {
      if (init && init.body) reqBody = truncate(init.body);
    } catch (_) {}

    let response;
    let status = null;
    let resBody = "";
    try {
      response = await _originalFetch.apply(this, arguments);
      status = response.status;
      try {
        const clone = response.clone();
        resBody = truncate(await clone.text());
      } catch (_) {}
    } catch (err) {
      if (window.__onNetworkCall) {
        window.__onNetworkCall({
          url,
          method,
          status: null,
          requestBody: reqBody,
          responseBody: "",
          source: "fetch",
          timestamp: Date.now(),
        });
      }
      throw err;
    }

    if (window.__onNetworkCall) {
      window.__onNetworkCall({
        url,
        method,
        status,
        requestBody: reqBody,
        responseBody: resBody,
        source: "fetch",
        timestamp: Date.now(),
      });
    }
    return response;
  };

  // --------------------------------------------------------------- XMLHttpRequest
  const _open = XMLHttpRequest.prototype.open;
  const _send = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__rae_method = method;
    this.__rae_url = url;
    return _open.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const xhr = this;
    const method = xhr.__rae_method || "GET";
    const url = xhr.__rae_url || "";
    const reqBody = truncate(body);

    xhr.addEventListener("loadend", function () {
      if (window.__onNetworkCall) {
        window.__onNetworkCall({
          url,
          method,
          status: xhr.status || null,
          requestBody: reqBody,
          responseBody: truncate(xhr.responseText),
          source: "xhr",
          timestamp: Date.now(),
        });
      }
    });
    return _send.apply(this, arguments);
  };

  // --------------------------------------------------------------- WebSocket
  const _WS = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    const ws = new _WS(url, protocols);
    const protoList = Array.isArray(protocols) ? protocols : protocols ? [protocols] : [];

    if (window.__onWSEvent) {
      window.__onWSEvent({
        event: "connect",
        url: url,
        protocols: protoList,
        timestamp: Date.now(),
      });
    }

    const _origSend = ws.send.bind(ws);
    ws.send = function (data) {
      if (window.__onWSEvent) {
        window.__onWSEvent({
          event: "message_sent",
          url: url,
          data: truncate(data),
          timestamp: Date.now(),
        });
      }
      return _origSend(data);
    };

    ws.addEventListener("message", function (evt) {
      if (window.__onWSEvent) {
        window.__onWSEvent({
          event: "message_received",
          url: url,
          data: truncate(evt.data),
          timestamp: Date.now(),
        });
      }
    });

    return ws;
  };
  window.WebSocket.prototype = _WS.prototype;
  Object.defineProperty(window.WebSocket, "CONNECTING", { value: _WS.CONNECTING });
  Object.defineProperty(window.WebSocket, "OPEN", { value: _WS.OPEN });
  Object.defineProperty(window.WebSocket, "CLOSING", { value: _WS.CLOSING });
  Object.defineProperty(window.WebSocket, "CLOSED", { value: _WS.CLOSED });
})();
