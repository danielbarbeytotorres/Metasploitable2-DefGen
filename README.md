# Metasploitable2-DefGen
**Metasploitable2-Agent** es un agente en lenguaje Python que genera scripts de seguridad con IA (LLM) para mitigar vulnerabilidades en **Metasploitable 2** (Ubuntu 8.04).

En concreto, se usa el modelo de lenguaje de OpenAI. Como entrada se le proporciona una descripción de una vulnerabilidad en formato JSON (o un directorio con varias descripciones), y como salida obtenemos un script (o scripts) de seguridad que mitigan la vulnerabilidad descrita.

Para la generación del script de seguridad usamos la API de OpenAI para interpretar descripciones de vulnerabilidades en formato JSON, siguiendo un estricto conjunto de reglas de seguridad y compatibilidad

## ⚠️ Importante

El **prompt del agente** ha sido diseñado y optimizado *exclusivamente* para generar comandos compatibles con **Metasploitable 2** (Ubuntu 8.04 LTS, que utiliza SysV init e `iptables`).
- **Si planeas usar este agente en otro sistema operativo**, es **OBLIGATORIO** modificar la variable `SYSTEM_PROMPT` dentro de `agent.py` para adaptar los comandos que los scripts de seguridad podrán usar. El incumplimiento de esto podrá resultar en la generación de scripts de seguridad inválidos.

## 🚀 Requisitos
1. **Python3**.
2. Las librerías Python `openai` y `rich`.
3. La **clave API de OpenAI**, que debe estar configurada como variable de entorno.

## ⚙️ Instalación y ejecución
1. **Clonación del Repositorio**:
```bash
    git clone [https://github.com/tu-usuario/Metasploitable2-DefGen.git](https://github.com/tu-usuario/Metasploitable2-DefGen.git)
    cd Metasploitable2-DefGen
```

2. **Creación y Activación de un Entorno Virtual**:
```bash
    python3 -m venv venv
    source venv/bin/activate
```

3. **Instalación de las dependencias**:
```bash
    pip install openai rich
```

4. **Configuración de la Clave API de OpenAI**:
```bash
    export OPENAI_API_KEY="TU_CLAVE_API_DE_OPENAI"
```

5. **Ejecución del agente**:
El agente se ejecuta con el comando:
```bash
python3 agent.py
```

A continuación, se detallan las **opciones** que se pueden indicar:

| Opción | Descripción | Ejemplo |
| :--- | :--- | :--- |
| **`[PATH_JSON]`** | Archivo JSON único o directorio con JSONs de vulnerabilidades. (**Obligatorio**) | `./vulnerabilidades.json` o `./vulnerabilidades_dir` |
| **`[--out DIR]`** | Directorio de salida para los scripts generados. (Por defecto: `./out_scripts`) | `--out ./defensa_scripts` |
| **`[--workers N]`**| Número de hilos (workers) para el procesamiento concurrente. (Por defecto: 5) | `--workers 10` |

**Ejemplos de ejecución**:

- Procesar un único archivo JSON: `python3 agent.py ./data/ftp_anon_rce.json`
- Procesar todos los JSON de un directorio, con 8 workers: `python3 agent.py ./datos_vulnerabilidades/ --workers 8`
- Especificar un direcotrio de salida diferente: `python3 agent.py ./datos_vulnerabilidades/ --out /tmp/mitigaciones`

## 📝 Formato del Archivo de Entrada
La herramienta espera archivos JSON que contengan la información de la vulnerabilidad (**no es condición obligatoria, pero si recomendable**). A continuación, unos ejemplos del formato del archivo de entrada

Archivo **possible_Backdoor_Ingreslock.json**:

```bash
{
  "target": "Target1",
  "result": {
    "name": "Possible Backdoor: Ingreslock",
    "host": "127.0.0.1",
    "port": "1524/tcp",
    "threat": "High",
    "severity": "10.0",
    "family": "Gain a shell remotely",
    "cvss": "10.0",
    "cvss_base_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "summary": "A backdoor is installed on the remote host.",
    "impact": "Attackers can exploit this issue to execute arbitrary commands in the\n  context of the application. Successful attacks will compromise the affected isystem.",
    "solution": "A whole cleanup of the infected system is recommended.",
    "solution_type": "Workaround"
  }
}
```

Archivo **phpinfo_output_reporting_http.json**:

```bash
{
  "target": "Target1",
  "result": {
    "name": "phpinfo() Output Reporting (HTTP)",
    "host": "127.0.0.1",
    "port": "80/tcp",
    "threat": "Medium",
    "severity": "5.3",
    "family": "Web application abuses",
    "cvss": "5.3",
    "cve": [
      "CVE-2008-0149",
      "CVE-2023-49282",
      "CVE-2023-49283",
      "CVE-2024-10486"
    ],
    "cvss_base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "summary": "Reporting of files containing the output of the phpinfo() PHP\n  function previously detected via HTTP.",
    "insight": "Many PHP installation tutorials instruct the user to create a\n  file called phpinfo.php or similar containing the phpinfo() statement. Such a file is often left\n  back in the webserver directory.",
    "affected": "All systems exposing a file containing the output of the\n  phpinfo() PHP function.\n\n  This VT is also reporting if an affected endpoint for the following products have been identified:\n\n  - CVE-2008-0149: TUTOS\n\n  - CVE-2023-49282, CVE-2023-49283: Microsoft Graph PHP SDK\n\n  - CVE-2024-10486: Google for WooCommerce plugin for WordPress",
    "impact": "Some of the information that can be gathered from this file\n  includes:\n\n  The username of the user running the PHP process, if it is a sudo user, the IP address of the\n  host, the web server version, the system version (Unix, Linux, Windows, ...), and the root\n  directory of the web server.",
    "solution": "Delete the listed files or restrict access to them.",
    "vuldetect": "This script reports files identified by the following separate\n  VT: 'phpinfo() Output Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.108474).",
    "solution_type": "Workaround"
  }
}
```

## 📂 Estructura de Salida
Los scripts generados se guardarán en un directorio estructurado por fecha dentro del directorio de salida (`out_scripts` por defecto):
```bash
out_scripts/
└── 2025-11-27/
    ├── 150001_vsftpd_backdoor.sh
    ├── 150005_samba_usermap.sh
    └── ...
```
Cada script generado será un fichero ejecutable de Bash (`.sh`) con permisos `755`.

## 🧠 Lógica de Mitigación en el Prompt
* **Idempotencia:** Los cambios se realizan de forma que ejecutar el script varias veces no cause problemas (ej. usando `iptables -C` o *backups* de configuración).
* **Acceso SSH (TCP/22):** Bajo ninguna circunstancia se debe bloquear o deshabilitar el servicio SSH. El script inserta una regla `ACCEPT` para SSH antes de cualquier regla `DROP` general.
* **Interacción Manual:** Si la solución requiere una contraseña o *input* interactivo (`vncpasswd`, `passwd`), el LLM no inventa nada. En su lugar, aísla el servicio de forma no interactiva (pararlo o ligarlo a `127.0.0.1`) y registra la tarea manual pendiente en `/tmp/mitigation_todo.log`.
* **Comandos Permitidos:** Restricción estricta a comandos básicos de Ubuntu 8.04 (SysV init) como `sed`, `grep`, `iptables`, `invoke-rc-d`, `update-rc-d`, etc., prohibiendo herramientas modernas como `systemctl` o `nft`.

## Otros
Este agente usa exactamente el modelo gpt-4o de OpenAI. Si deseas cambiar el modelo por otro de tu elección, modifica la variable `MODEL` en el fichero `agent.py` (linea 36).