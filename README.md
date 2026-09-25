# 🛡️ IP Threat Radar & Geolocation (v1.0.0)

**IP Threat Radar** es una extensión de navegador ligera y moderna desarrollada bajo la especificación **Manifest V3**. Permite analizar direcciones IP al instante integrando la API de **VirusTotal v3** y geolocalización IP en tiempo real, con soporte para menú contextual al hacer clic derecho sobre cualquier texto e impresión de reportes en PDF.

---

## ✨ Características Principales

* **🔍 Análisis en Tiempo Real:** Integración directa con la API v3 de VirusTotal para verificar la reputación de direcciones IPv4.
* **📍 Geolocalización Completa:** Consulta datos sobre el país, ciudad, Proveedor de Servicios de Internet (ISP) y Número de Sistema Autónomo (ASN) con la API de `ipwho.is`.
* **🖱️ Menú Contextual (Clic Derecho):** Selecciona cualquier dirección IP en una página web, haz clic derecho y envíala directamente a la extensión para un análisis instantáneo.
* **🛡️ Validación de Entrada:** Detección y filtrado estricto para procesar únicamente direcciones IPv4 válidas.
* **📄 Exportación a PDF:** Generación de informes técnicos de ciberseguridad en PDF con un solo clic (usando `jsPDF`).
* **⚙️ Persistencia de Configuración:** Guarda de manera segura tu clave API de VirusTotal utilizando `chrome.storage.local`.

---

## 🚀 Instalación Local (Modo Desarrollador)

1. **Clona o descarga este repositorio:**
   ```bash
   git clone [https://github.com/TU_USUARIO/IP-Threat-Radar.git](https://github.com/TU_USUARIO/IP-Threat-Radar.git)
