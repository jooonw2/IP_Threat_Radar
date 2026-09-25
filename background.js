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
    // Validar con expresiones regulares que sea estrictamente una IP IPv4 (cuatro bloques de 0-255)
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    // Si la selección contiene una IP válida dentro del texto
    const match = selectedText.match(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/);

    if (match) {
      const validIp = match[0];
      chrome.storage.local.set({ pendingIpScan: validIp }, () => {
        chrome.action.openPopup();
      });
    } else {
      // Si no es una IP válida, guardamos un flag de IP inválida
      chrome.storage.local.set({ pendingIpScanError: "invalid_ip" }, () => {
        chrome.action.openPopup();
      });
    }
  }
});
