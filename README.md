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
   `git clone https://github.com/TU_USUARIO/IP-Threat-Radar.git`
2. Abre tu navegador basado en Chromium (Google Chrome, Microsoft Edge, Brave).
3. Dirígete a la gestión de extensiones escribiendo en la barra de direcciones:
   `chrome://extensions/`
4. Activa el **Modo de desarrollador** en la esquina superior derecha.
5. Haz clic en el botón **Cargar descomprimida** (*Load unpacked*) y selecciona la carpeta raíz del proyecto.

---

## 🛠️ Estructura del Proyecto

* `manifest.json`: Configuración del Manifest V3 de la extensión
* `background.js`: Service worker para la gestión del menú contextual
* `popup.html`: Interfaz de usuario (Escáner y Ajustes)
* `popup.js`: Lógica principal, peticiones API y exportación a PDF
* `styles.css`: Estilos visuales en modo oscuro
* `jspdf.umd.min.js`: Librería ligera para generación de reportes PDF
* `icon16.png`: Icono de extensión (16x16)
* `icon48.png`: Icono de extensión (48x48)
* `icon128.png`: Icono de extensión (128x128)

---

## 🔑 Configuración de VirusTotal

Para habilitar el escaneo contra los motores antivirus de VirusTotal:
1. Abre el menú flotante de la extensión.
2. Ve a la pestaña **Ajustes**.
3. Pega tu clave **API Key de VirusTotal v3** (puedes obtener una gratuita registrándote en VirusTotal).
4. Haz clic en **Guardar Configuración**.

---

## 📄 Licencia

Este proyecto está distribuido bajo la licencia **MIT**.
