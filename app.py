import os
import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="Dashboard de Vulnerabilidades - Banco Refassil",
    page_icon="🛡️",
    layout="wide"
)

# ------------------------------------------------------------------------------
# DATOS DE VULNERABILIDADES
# ------------------------------------------------------------------------------
vulnerabilidades = [
    {
        "id": 1,
        "titulo": "Ejecución Remota de Código — MS17-010 (EternalBlue)",
        "cvss": 9.8,
        "nivel": "CRÍTICO",
        "puerto": "445/tcp",
        "servicio": "SMB",
        "nombre": "MS17-010 / EternalBlue — CVE-2017-0143, CVE-2017-0144, CVE-2017-0145 (servicio SMB, puerto 445/tcp).",
        "impacto": "Permite ejecución de código remoto con privilegios de sistema (SYSTEM), sin autenticación, a través de SMBv1. Conlleva el compromiso total del host: pérdida de confidencialidad, integridad y disponibilidad.",
        "mitigacion": "Aplicar el parche de seguridad de Microsoft (MS17-010); deshabilitar SMBv1 y migrar a SMBv2/SMBv3; bloquear el puerto 445/tcp en el firewall si el servicio no es necesario; habilitar el firmado SMB (SMB Signing).",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "poc": "Verificación con el script smb-vuln-ms17-010 de Nmap sobre el objetivo y confirmación del estado VULNERABLE.",
        "imagen": "poc_ms17010.png"
    },
    {
        "id": 2,
        "titulo": "Ejecución de Comandos Backdoor — vsftpd 2.3.4",
        "cvss": 9.8,
        "nivel": "CRÍTICO",
        "puerto": "21/tcp",
        "servicio": "FTP",
        "nombre": "vsftpd 2.3.4 Backdoor — CVE-2011-2523 (servicio FTP, puerto 21/tcp).",
        "impacto": "Permite la apertura de una shell con privilegios de root en el puerto 6200/tcp al enviar la secuencia ':) ' en el usuario FTP, permitiendo el control completo del servidor.",
        "mitigacion": "Actualizar la versión de vsftpd a una versión corregida no vulnerable o reemplazar el servicio por alternativas seguras como SFTP.",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "poc": "Identificación de la versión vulnerable vsftpd 2.3.4 durante el escaneo de servicios con Nmap y verificación de la respuesta del servicio FTP.",
        "imagen": "poc_vsftpd.png"
    },
    {
        "id": 3,
        "titulo": "Ejecución Remota de Código — Tomcat Manager Interface",
        "cvss": 8.1,
        "nivel": "ALTO",
        "puerto": "8080/tcp",
        "servicio": "HTTP",
        "nombre": "Apache Tomcat RCE via Manager Interface — CVE-2017-12617 (servicio HTTP, puerto 8080/tcp).",
        "impacto": "Permite la carga remota de archivos JSP maliciosos mediante solicitudes HTTP PUT cuando el parámetro readonly está deshabilitado, ejecutando código arbitrario.",
        "mitigacion": "Actualizar Apache Tomcat a una versión parcheada y configurar el parámetro readonly en true dentro del archivo de configuración web.xml.",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "poc": "Detección de la versión Apache Tomcat 7.0.52 mediante escaneo de cabeceras HTTP de Nmap y análisis de vulnerabilidades del directorio manager.",
        "imagen": "poc_tomcat.png"
    },
    {
        "id": 4,
        "titulo": "Escalada de Privilegios / Auth Bypass — MySQL",
        "cvss": 7.5,
        "nivel": "ALTO",
        "puerto": "3306/tcp",
        "servicio": "MySQL",
        "nombre": "MySQL Privilege Escalation — CVE-2016-6662 (servicio MySQL, puerto 3306/tcp).",
        "impacto": "Permite a atacantes inyectar configuraciones maliciosas en archivos de inicio de MySQL (my.cnf), conduciendo a la ejecución de código con privilegios elevados del sistema.",
        "mitigacion": "Aplicar parches de actualización de MySQL, restringir los permisos de escritura sobre los archivos de configuración my.cnf y restringir el acceso a la base de datos.",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "poc": "Comprobación del servicio MySQL 5.5.54 y evaluación del estado de autenticación mediante scripts NSE de Nmap.",
        "imagen": "poc_mysql.png"
    },
    {
        "id": 5,
        "titulo": "Denegación de Servicio — Apache Byterange Filter",
        "cvss": 7.5,
        "nivel": "ALTO",
        "puerto": "8081/tcp",
        "servicio": "HTTP (Nginx)",
        "nombre": "Apache byterange filter DoS — CVE-2011-3192 (servicio HTTP / nginx, puerto 8081/tcp - Objetivo 142.93.12.42).",
        "impacto": "Permite agotamiento de recursos de memoria y procesador en el servidor objetivo mediante el envío de solicitudes HTTP con cabeceras Range con múltiples sub-rangos superpuestos.",
        "mitigacion": "Configurar el proxy o servidor web para limitar/ignorar el número de rangos en la cabecera HTTP Range o aplicar parches de seguridad del proveedor.",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "poc": "Ejecución del comando 'nmap -sV --script vuln -p 8081 142.93.12.42' e identificación de la falla mediante el script http-vuln-cve2011-3192.",
        "imagen": "poc_8081.png"
    }
]

# ------------------------------------------------------------------------------
# BARRA LATERAL (FILTROS)
# ------------------------------------------------------------------------------
st.sidebar.title("🔍 Filtros del Reporte")
nivel_filtro = st.sidebar.multiselect(
    "Filtrar por Severidad:",
    options=["CRÍTICO", "ALTO"],
    default=["CRÍTICO", "ALTO"]
)

busqueda = st.sidebar.text_input("Buscar por palabra clave / CVE:", "")

st.sidebar.markdown("---")
st.sidebar.info("💡 **Tip:** Utiliza el menú desplegable para filtrar los resultados y exportar el informe.")

# ------------------------------------------------------------------------------
# ENCABEZADO Y MÉTRICAS DYNAMICAS
# ------------------------------------------------------------------------------
st.title("🛡️ Dashboard de Análisis de Vulnerabilidades")
st.subheader("Banco Refassil S.A. — Auditoría de Seguridad con IA")
st.caption("Fecha de entrega: 9 de octubre de 2026 | Objetivo evaluado: 142.93.12.42:8081")

st.markdown("---")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Vulnerabilidades", len(vulnerabilidades))
col2.metric("Nivel Crítico", sum(1 for v in vulnerabilidades if v["nivel"] == "CRÍTICO"))
col3.metric("Nivel Alto", sum(1 for v in vulnerabilidades if v["nivel"] == "ALTO"))
col4.metric("Puntuación Máxima", "9.8 (CRÍTICO)")

# ------------------------------------------------------------------------------
# GRÁFICO DE DISTRIBUCIÓN
# ------------------------------------------------------------------------------
df_summary = pd.DataFrame(vulnerabilidades)
st.markdown("### 📊 Distribución de Severidad")
st.bar_chart(df_summary["nivel"].value_counts(), color="#0f2b5c")

st.markdown("---")

# ------------------------------------------------------------------------------
# APLICACIÓN DE FILTROS
# ------------------------------------------------------------------------------
vulns_filtradas = [
    v for v in vulnerabilidades 
    if v["nivel"] in nivel_filtro and (busqueda.lower() in v["titulo"].lower() or busqueda.lower() in v["nombre"].lower())
]

st.markdown(f"### 📋 Fichas de Vulnerabilidad Identificadas ({len(vulns_filtradas)})")

def render_ficha(v):
    badge_color = "#dc3545" if v["nivel"] in ["CRÍTICO", "ALTO"] else "#ffc107"
    
    st.markdown(f"""
    <div style="border: 2px solid #0f2b5c; border-radius: 8px; margin-top: 15px; background-color: #ffffff; font-family: sans-serif; overflow: hidden;">
        <div style="background-color: #0f2b5c; color: white; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center;">
            <span style="font-weight: bold; font-size: 16px; color: white;">{v['titulo']}</span>
            <span style="background-color: {badge_color}; color: white; padding: 4px 12px; border-radius: 15px; font-weight: bold; font-size: 13px;">
                CVSS {v['cvss']} · {v['nivel']}
            </span>
        </div>
        <div style="padding: 15px; color: #212529;">
            <p style="margin-top: 0; font-size: 14px;"><strong>Nombre:</strong> {v['nombre']}</p>
            <div style="display: flex; gap: 15px; margin-bottom: 15px;">
                <div style="flex: 1; background-color: #fde8e8; border-left: 4px solid #dc3545; padding: 10px; border-radius: 4px;">
                    <strong style="color: #9b1c1c; font-size: 13px;">Impacto</strong><br>
                    <span style="font-size: 12px; color: #333333;">{v['impacto']}</span>
                </div>
                <div style="flex: 1; background-color: #eef8f1; border-left: 4px solid #198754; padding: 10px; border-radius: 4px;">
                    <strong style="color: #0f5132; font-size: 13px;">Mitigación</strong><br>
                    <span style="font-size: 12px; color: #333333;">{v['mitigacion']}</span>
                </div>
            </div>
            <div style="font-size: 13px; font-weight: bold; margin-bottom: 5px; color: #0f2b5c;">Nivel de riesgo — Vector CVSS 3.1</div>
            <div style="background-color: #f1f3f9; border-radius: 6px; padding: 8px 12px; font-family: monospace; font-size: 13px; color: #333333; margin-bottom: 15px;">
                {v['vector']} &rarr; <span style="color: #0f2b5c; font-weight: bold;">Puntuación base {v['cvss']} ({v['nivel']})</span>
            </div>
            <div style="border: 1px dashed #b0b8c5; border-radius: 6px; padding: 12px; background-color: #fafbfc;">
                <strong style="font-size: 13px; color: #0f2b5c;">Prueba de concepto (PoC)</strong><br>
                <p style="font-size: 12px; color: #444444; margin: 5px 0 10px 0;">
                    <strong>(a) Pasos:</strong> {v['poc']}
                </p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if os.path.exists(v["imagen"]):
        st.image(v["imagen"], caption=f"Figura {v['id']}. Evidencia de la validación.", use_container_width=True)
    else:
        st.info(f"📷 (b) [Inserta aquí tu imagen '{v['imagen']}'] — Pie de figura: Figura {v['id']}. Evidencia de la validación.")

    st.markdown("<div style='margin-bottom: 25px;'></div>", unsafe_allow_html=True)

for v in vulns_filtradas:
    render_ficha(v)

# ------------------------------------------------------------------------------
# EXPORTAR DATOS
# ------------------------------------------------------------------------------
st.markdown("---")
st.markdown("### 📥 Exportar Resultados")

csv_data = df_summary[["id", "titulo", "cvss", "nivel", "puerto", "servicio"]].to_csv(index=False)
st.download_button(
    label="Download Resumen Ejecutivo (CSV)",
    data=csv_data,
    file_name="resumen_vulnerabilidades_banco_refassil.csv",
    mime="text/csv"
)
