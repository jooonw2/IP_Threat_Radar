document.addEventListener("DOMContentLoaded", () => {
  const tabScan = document.getElementById("tab-scan");
  const tabHistory = document.getElementById("tab-history");
  const tabSettings = document.getElementById("tab-settings");

  const viewScan = document.getElementById("view-scan");
  const viewHistory = document.getElementById("view-history");
  const viewSettings = document.getElementById("view-settings");

  tabScan.addEventListener("click", () => {
    switchTab("scan");
  });

  tabHistory.addEventListener("click", () => {
    switchTab("history");
    renderHistory();
  });

  tabSettings.addEventListener("click", () => {
    switchTab("settings");
  });

  function switchTab(tab) {
    tabScan.classList.toggle("active", tab === "scan");
    tabHistory.classList.toggle("active", tab === "history");
    tabSettings.classList.toggle("active", tab === "settings");

    viewScan.classList.toggle("hidden", tab !== "scan");
    viewHistory.classList.toggle("hidden", tab !== "history");
    viewSettings.classList.toggle("hidden", tab !== "settings");
  }

  if (chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["vtApiKey", "pendingIpScan", "pendingIpScanError"], (result) => {
      if (result.vtApiKey) {
        document.getElementById("vt-api-key").value = result.vtApiKey;
      }
      
      if (result.pendingIpScanError) {
        document.getElementById("error-msg").classList.remove("hidden");
        document.getElementById("results").classList.add("hidden");
        chrome.storage.local.remove("pendingIpScanError");
      } else if (result.pendingIpScan) {
        document.getElementById("error-msg").classList.add("hidden");
        const ip = result.pendingIpScan;
        document.getElementById("ip-input").value = ip;
        chrome.storage.local.remove("pendingIpScan");
        analyzeIP(ip);
      }
    });
  }

  document.getElementById("btn-save-key").addEventListener("click", () => {
    const key = document.getElementById("vt-api-key").value.trim();
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ vtApiKey: key }, () => {
        const msg = document.getElementById("save-msg");
        msg.classList.remove("hidden");
        setTimeout(() => msg.classList.add("hidden"), 2000);
      });
    }
  });

  document.getElementById("btn-clear-history").addEventListener("click", () => {
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.remove("scanHistory", () => {
        renderHistory();
      });
    }
  });

  document.getElementById("btn-my-ip").addEventListener("click", async () => {
    try {
      const res = await fetch("https://api.ipify.org?format=json");
      const data = await res.json();
      document.getElementById("ip-input").value = data.ip;
      document.getElementById("error-msg").classList.add("hidden");
      analyzeIP(data.ip);
    } catch (e) {
      alert("Error al obtener la IP local.");
    }
  });

  document.getElementById("btn-analyze").addEventListener("click", () => {
    const ip = document.getElementById("ip-input").value.trim();
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    if (ipRegex.test(ip)) {
      document.getElementById("error-msg").classList.add("hidden");
      analyzeIP(ip);
    } else {
      document.getElementById("error-msg").classList.remove("hidden");
      document.getElementById("results").classList.add("hidden");
    }
  });

  let currentAnalysisData = null;

  // Helper function to check if an IP is private or local
  function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return "Loopback / Localhost";
    // 10.0.0.0/8 (Private)
    if (parts[0] === 10) return "Red Privada (Clase A)";
    // 172.16.0.0 - 172.31.255.255 (Private)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return "Red Privada (Clase B)";
    // 192.168.0.0/16 (Private)
    if (parts[0] === 192 && parts[1] == 168) return "Red Privada (Clase C)";
    // 169.254.0.0/16 (Link-local)
    if (parts[0] === 169 && parts[1] === 254) return "Dirección de Enlace Local";
    return null;
  }

  async function analyzeIP(ip) {
    const privateType = isPrivateIP(ip);
    
    let geoData = { country: "N/A (IP Interna)", city: "Red Local", isp: "LAN / Intranet", asn: "Privada" };
    let vtData = { status: "private", ratio: "No escaneable (IP Privada)", maliciousCount: 0 };

    if (privateType) {
      geoData.country = `🏠 ${privateType}`;
      geoData.city = "Red Privada Local";
      geoData.isp = "Red Interna / Router";
      geoData.asn = "N/A (Intranet)";
      vtData = {
        status: "private",
        ratio: "Omitido (IP Privada)",
        maliciousCount: 0
      };
    } else {
      let vtKey = "";
      if (chrome.storage && chrome.storage.local) {
        const stored = await new Promise(r => chrome.storage.local.get(["vtApiKey"], r));
        vtKey = stored.vtApiKey || "";
      }

      // Geo lookup for public IPs
      try {
        const geoRes = await fetch(`https://ipwho.is/${ip}`);
        const geoJson = await geoRes.json();
        if (geoJson.success) {
          geoData = {
            country: `${geoJson.country_flag || ''} ${geoJson.country || 'N/A'}`,
            city: geoJson.city || 'N/A',
            isp: geoJson.connection?.isp || geoJson.isp || 'N/A',
            asn: geoJson.connection?.asn ? `AS${geoJson.connection.asn}` : 'N/A'
          };
        }
      } catch (e) {
        console.warn("Geo API failure:", e);
      }

      if (vtKey) {
        try {
          const vtRes = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: { "x-apikey": vtKey }
          });
          if (vtRes.ok) {
            const vtJson = await vtRes.json();
            const stats = vtJson.data?.attributes?.last_analysis_stats || {};
            const mal = stats.malicious || 0;
            const sus = stats.suspicious || 0;
            const total = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0);
            
            let status = "clean";
            if (mal > 3) status = "malicious";
            else if (mal > 0 || sus > 0) status = "suspicious";

            vtData = {
              status,
              ratio: `${mal} / ${total || 93}`,
              maliciousCount: mal
            };
          } else {
            vtData = {
              status: "noapi",
              ratio: "API Key inválida o límite alcanzado",
              maliciousCount: 0
            };
          }
        } catch (e) {
          console.warn("VT API failure:", e);
        }
      } else {
        vtData = {
          status: "noapi",
          ratio: "Introduce la API de VirusTotal",
          maliciousCount: 0
        };
      }
    }

    currentAnalysisData = { ip, ...geoData, ...vtData };

    // Save to history
    saveToHistory(currentAnalysisData);

    // Render results
    document.getElementById("results").classList.remove("hidden");
    document.getElementById("geo-location").textContent = geoData.country;
    document.getElementById("geo-city").textContent = geoData.city;
    document.getElementById("geo-isp").textContent = geoData.isp;
    document.getElementById("geo-asn").textContent = geoData.asn;
    
    const vtRatioElem = document.getElementById("vt-ratio");
    vtRatioElem.textContent = vtData.ratio;

    const badge = document.getElementById("badge-status");
    badge.className = "status-badge";
    if (vtData.status === "malicious") {
      badge.classList.add("status-malicious");
      badge.textContent = "Maliciosa";
      vtRatioElem.classList.remove("api-warning-msg");
    } else if (vtData.status === "suspicious") {
      badge.classList.add("status-suspicious");
      badge.textContent = "Sospechosa";
      vtRatioElem.classList.remove("api-warning-msg");
    } else if (vtData.status === "clean") {
      badge.classList.add("status-clean");
      badge.textContent = "Limpia";
      vtRatioElem.classList.remove("api-warning-msg");
    } else if (vtData.status === "private") {
      badge.classList.add("status-private");
      badge.textContent = "IP Privada";
      vtRatioElem.classList.remove("api-warning-msg");
    } else {
      badge.classList.add("status-noapi");
      badge.textContent = "Sin API";
      vtRatioElem.classList.add("api-warning-msg");
    }
  }

  function saveToHistory(data) {
    if (!chrome.storage || !chrome.storage.local) return;
    chrome.storage.local.get(["scanHistory"], (result) => {
      let history = result.scanHistory || [];
      // Remove duplicates
      history = history.filter(item => item.ip !== data.ip);
      // Add to start
      history.unshift({
        ip: data.ip,
        status: data.status,
        ratio: data.ratio,
        country: data.country,
        time: new Date().toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' })
      });
      // Limit to 20
      if (history.length > 20) history = history.slice(0, 20);
      chrome.storage.local.set({ scanHistory: history });
    });
  }

  function renderHistory() {
    if (!chrome.storage || !chrome.storage.local) return;
    chrome.storage.local.get(["scanHistory"], (result) => {
      const historyList = document.getElementById("history-list");
      const history = result.scanHistory || [];

      if (history.length === 0) {
        historyList.innerHTML = '<div class="history-empty">No hay búsquedas guardadas.</div>';
        return;
      }

      historyList.innerHTML = history.map(item => `
        <div class="history-item" data-ip="${item.ip}">
          <div>
            <div class="history-ip">${item.ip}</div>
            <div style="font-size: 10px; color: #8b949e;">${item.country}</div>
          </div>
          <div style="text-align: right;">
            <span class="status-badge status-${item.status}">${item.status.toUpperCase()}</span>
            <div class="history-time">${item.time}</div>
          </div>
        </div>
      `).join('');

      // Add click listener to re-analyze IP from history
      document.querySelectorAll(".history-item").forEach(elem => {
        elem.addEventListener("click", () => {
          const ip = elem.getAttribute("data-ip");
          document.getElementById("ip-input").value = ip;
          switchTab("scan");
          analyzeIP(ip);
        });
      });
    });
  }

  document.getElementById("btn-open-vt").addEventListener("click", () => {
    const ip = document.getElementById("ip-input").value.trim();
    if (ip) {
      window.open(`https://www.virustotal.com/gui/ip-address/${ip}`, "_blank");
    }
  });

  // Fixed PDF generation using window.jspdf or loaded jsPDF constructor
  document.getElementById("btn-pdf").addEventListener("click", () => {
    if (!currentAnalysisData) return;
    
    // Check jsPDF availability properly
    let jsPDFClass = null;
    if (window.jspdf && window.jspdf.jsPDF) {
      jsPDFClass = window.jspdf.jsPDF;
    } else if (typeof window.jsPDF === 'function') {
      jsPDFClass = window.jsPDF;
    }

    if (!jsPDFClass) {
      alert("Error: No se pudo cargar la librería jsPDF correctamente.");
      return;
    }

    try {
      const doc = new jsPDFClass();
      const d = currentAnalysisData;

      doc.setFillColor(13, 17, 23);
      doc.rect(0, 0, 210, 297, 'F');

      doc.setTextColor(88, 166, 255);
      doc.setFontSize(20);
      doc.text("IP Threat Radar - Informe Técnico", 15, 20);

      doc.setFontSize(10);
      doc.setTextColor(139, 148, 158);
      doc.text(`Fecha del Análisis: ${new Date().toLocaleString('es-ES')}`, 15, 28);

      doc.setDrawColor(48, 54, 61);
      doc.line(15, 32, 195, 32);

      doc.setFontSize(14);
      doc.setTextColor(240, 246, 252);
      doc.text(`Dirección IP Analizada: ${d.ip}`, 15, 45);

      doc.setFillColor(22, 27, 34);
      doc.roundedRect(15, 52, 180, 85, 3, 3, 'F');

      doc.setFontSize(12);
      doc.setTextColor(201, 209, 217);

      doc.text(`Estado / Tipo: ${d.status.toUpperCase()}`, 25, 65);
      doc.text(`Detección VT: ${d.ratio}`, 25, 75);
      doc.text(`País / Red: ${d.country}`, 25, 85);
      doc.text(`Ciudad: ${d.city}`, 25, 95);
      doc.text(`ISP: ${d.isp}`, 25, 105);
      doc.text(`ASN: ${d.asn}`, 25, 115);

      doc.setFontSize(10);
      doc.setTextColor(139, 148, 158);
      doc.text("Generado por la extensión IP Threat Radar", 15, 150);

      doc.save(`IP_Reporte_${d.ip}.pdf`);
    } catch (err) {
      alert("Error generando el archivo PDF: " + err.message);
    }
  });
});
