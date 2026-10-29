chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "analyze-ip-context",
    title: "🛡️ Analizar IP '%s' con IP Threat Radar",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "analyze-ip-context" && info.selectionText) {
    const selectedText = info.selectionText.trim();
    const match = selectedText.match(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/);

    if (match) {
      const validIp = match[0];
      chrome.storage.local.set({ pendingIpScan: validIp }, () => {
        chrome.action.openPopup();
      });
    } else {
      chrome.storage.local.set({ pendingIpScanError: "invalid_ip" }, () => {
        chrome.action.openPopup();
      });
    }
  }
});
