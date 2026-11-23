chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "airlock-scrub-selection",
      title: "AirlockAI: Scrub & Audit Selection",
      contexts: ["selection"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== "airlock-scrub-selection") return;

  // Must invoke sidePanel.open synchronously in the user gesture handler
  if (tab?.id !== undefined) {
    chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
  }

  if (info.selectionText) {
    chrome.storage.session.set({
      pendingSelection: {
        text: info.selectionText,
        sourceUrl: tab?.url ?? "active-tab",
        capturedAt: Date.now(),
      },
    });
  }
});
