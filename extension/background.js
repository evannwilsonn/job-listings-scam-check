// Right-click selected text -> "Check this with LureCheck". The selection goes to session storage (memory only,
// cleared when the browser closes) and a small window opens the checker on it. No network access is requested.
"use strict";
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({id: "lurecheck", title: "Check this with LureCheck", contexts: ["selection"]});
});
chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== "lurecheck" || !info.selectionText) return;
  await chrome.storage.session.set({pending: info.selectionText.slice(0, 8000)});
  chrome.windows.create({url: "popup.html?from=menu", type: "popup", width: 460, height: 640});
});
