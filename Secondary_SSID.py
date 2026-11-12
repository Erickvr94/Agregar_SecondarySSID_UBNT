import os
import re
import sys
import time
import signal
import hashlib
import tkinter as tk
from tkinter import filedialog
from datetime import datetime

import pandas as pd
import paramiko

# ---------------------------------------------------------------------------
# AirOS (LiteBeam 5AC, etc.) usa Dropbear con algoritmos antiguos (ssh-rsa SHA1,
# ssh-dss). Paramiko >= 4 ya no los trae -> "no acceptable host key".
# Solución: pip install "paramiko>=3.4,<4"
# ---------------------------------------------------------------------------
if int(paramiko.__version__.split(".")[0]) >= 4:
    print(f"[!] Tienes Paramiko {paramiko.__version__}. Las antenas AirOS necesitan Paramiko 3.x:")
    print('        pip install "paramiko>=3.4,<4"')
    sys.exit(1)

CARPETA_BACKUPS = "backups_airos"
CARPETA_REGISTROS = "registros_secondary_ssid"
CARACTERES_PROHIBIDOS = set("'\"`$\\\n\r")
PREFIJO_N2 = "wpasupplicant.profile.1.network.2."
ANTENAS_PILOTO = 3   # en modo rápido, cuántas antenas se esperan/verifican una por una

LINEAS_FABRICA = [
    PREFIJO_N2 + "key_mgmt.1.name=NONE",
    PREFIJO_N2 + "priority=2",
    PREFIJO_N2 + "status=disabled",
]


def lineas_secondary(ssid, clave):
    return [
        PREFIJO_N2 + "status=enabled",
        PREFIJO_N2 + "eap.1.status=disabled",
        PREFIJO_N2 + "key_mgmt.1.name=WPA-PSK",
        PREFIJO_N2 + "pairwise.1.name=CCMP",
        PREFIJO_N2 + "proto.1.name=RSN",
        PREFIJO_N2 + f"ssid={ssid}",
        PREFIJO_N2 + f"psk={clave}",
        PREFIJO_N2 + "priority=2",
    ]


# ===========================================================================
# Lectura del Excel (encabezados y columnas variables)
# ===========================================================================
PATRONES_COLUMNAS = {
    # El orden importa: backup_ssid y clave_backup antes que ip/credenciales
    'backup_ssid': [r'(backu?p?t?|respaldo|secundari|secondary|2do|segund).*ssid',
                    r'ssid.*(backu?p?t?|respaldo|secundari|secondary|2|segund)'],
    'clave_backup': [r'(clave|pass|psk|key).*(backu?p|respaldo|secundari|secondary)',
                     r'(backu?p|respaldo|secundari|secondary).*(clave|pass|psk|key)'],
    'ip': [r'\bip\b', r'direcci?o?n\s*ip', r'\bhost\b'],
    'credenciales': [r'usuario\s*[/\\|]\s*(clave|contrase)', r'user\s*[/\\|]\s*pass', r'credencial'],
    'usuario': [r'^usuario$', r'^user(name)?$'],
    'clave_ssh': [r'^(clave|contrase[ñn]a|password|pass)$'],
    'nombre': [r'tablero', r'nombre', r'equipo', r'antena', r'dispositivo', r'device', r'name'],
}


def normalizar(txt):
    t = str(txt).lower().strip()
    for a, b in (("á", "a"), ("é", "e"), ("í", "i"), ("ó", "o"), ("ú", "u")):
        t = t.replace(a, b)
    return re.sub(r"\s+", " ", t)


def mapear_columnas(columnas):
    mapeo = {k: None for k in PATRONES_COLUMNAS}
    usadas = set()
    for clave, patrones in PATRONES_COLUMNAS.items():
        for col in columnas:
            if col in usadas or col is None or str(col).startswith("Unnamed"):
                continue
            n = normalizar(col)
            if any(re.search(p, n) for p in patrones):
                mapeo[clave] = col
                usadas.add(col)
                break
    return mapeo


def localizar_tabla(ruta_excel, filas_a_revisar=30):
    """Busca en todas las hojas la fila de encabezados que tenga columna IP y Backup SSID."""
    hojas = pd.read_excel(ruta_excel, sheet_name=None, header=None, nrows=filas_a_revisar)
    for nombre_hoja, df in hojas.items():
        for i in range(len(df)):
            valores = [v for v in df.iloc[i].tolist() if pd.notna(v)]
            m = mapear_columnas(valores)
            if m['ip'] and m['backup_ssid']:
                return nombre_hoja, i
    return None, None


def separar_credenciales(texto):
    texto = str(texto).strip()
    if not texto or texto.lower() == "nan":
        return None, None
    for sep in ("|", "\\", "/"):
        if sep in texto:
            u, _, c = texto.partition(sep)
            return (u.strip() or "ubnt"), c.strip()
    return "ubnt", texto


def celda(fila, col):
    if col is None:
        return ""
    v = fila[col]
    return "" if pd.isna(v) else str(v).strip()


def leer_equipos_excel(ruta_excel):
    hoja, fila_enc = localizar_tabla(ruta_excel)
    if hoja is None:
        print("[ERROR] No encontré una fila de encabezados con columna de IP y de Backup SSID.")
        return None, None
    df = pd.read_excel(ruta_excel, sheet_name=hoja, header=fila_enc)
    cols = mapear_columnas(df.columns)
    print(f"\nHoja '{hoja}', encabezados en la fila {fila_enc + 1}. Columnas detectadas:")
    for k, v in cols.items():
        if v is not None:
            print(f"  {k:<13} -> {v}")
    if not (cols['credenciales'] or cols['clave_ssh']):
        print("[ERROR] No encontré la columna de credenciales SSH (Usuario / Clave).")
        return None, None

    equipos, ips_vistas = [], set()
    for idx, fila in df.iterrows():
        ip = celda(fila, cols['ip'])
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
            continue
        if ip in ips_vistas:
            print(f"  [!] IP repetida en el Excel, se usa solo la primera: {ip}")
            continue
        ips_vistas.add(ip)
        if cols['credenciales']:
            usuario, clave = separar_credenciales(celda(fila, cols['credenciales']))
        else:
            usuario = celda(fila, cols['usuario']) or "ubnt"
            clave = celda(fila, cols['clave_ssh'])
        equipos.append({
            'fila_excel': idx + fila_enc + 2,
            'ip': ip,
            'nombre': celda(fila, cols['nombre']),
            'usuario': usuario,
            'clave': clave,
            'ssid_backup': celda(fila, cols['backup_ssid']),
            'clave_backup': celda(fila, cols['clave_backup']),
        })
    return equipos, cols


# ===========================================================================
# SSH
# ===========================================================================
def ejecutar(ssh, comando, timeout=20):
    stdin, stdout, stderr = ssh.exec_command(comando, timeout=timeout)
    salida = stdout.read().decode(errors="replace")
    error = stderr.read().decode(errors="replace")
    return stdout.channel.recv_exit_status(), salida, error


def conectar(ip, usuario, clave):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=ip, port=22, username=usuario, password=clave,
                timeout=10, banner_timeout=15, auth_timeout=15,
                look_for_keys=False, allow_agent=False)
    return ssh


def valor_cfg(texto_cfg, clave):
    m = re.search(rf"^{re.escape(clave)}=(.*)$", texto_cfg, re.M)
    return m.group(1).strip() if m else ""


def bloque_n2(texto_cfg):
    lineas = [l.strip() for l in texto_cfg.splitlines() if l.startswith(PREFIJO_N2)]
    valores = {}
    for l in lineas:
        k, _, v = l[len(PREFIJO_N2):].partition("=")
        valores[k] = v
    return lineas, valores


def ocultar(clave):
    """Muestra primer y último carácter y la longitud: suficiente para comparar sin exponerla."""
    if not clave:
        return "(sin clave)"
    if len(clave) <= 4:
        return f"{'*' * len(clave)} ({len(clave)} car.)"
    return f"{clave[0]}{'*' * (len(clave) - 2)}{clave[-1]} ({len(clave)} car.)"


def claves_equivalentes(psk_antena, clave, ssid):
    """Compara la clave de la antena con la del Excel. Contempla espacios sobrantes y el caso
    en que la antena guarde la PSK en hexadecimal (64 caracteres) en vez del texto."""
    a, c = psk_antena.strip(), clave.strip()
    if a == c:
        return True
    if re.fullmatch(r"[0-9a-fA-F]{64}", a):
        pmk = hashlib.pbkdf2_hmac("sha1", c.encode(), ssid.encode(), 4096, 32).hex()
        return pmk.lower() == a.lower()
    return False


NOMBRE_POLITICA = {
    "preguntar": "respondiste NO",
    "siempre": "Sobrescribir siempre",
    "incompletas": "Completar solo incompletas",
    "nunca": "Nunca sobrescribir",
}


def guardar_respaldo(ip, cfg_texto):
    os.makedirs(CARPETA_BACKUPS, exist_ok=True)
    ruta = os.path.join(CARPETA_BACKUPS,
                        f"{ip.replace('.', '_')}_{datetime.now():%Y%m%d_%H%M%S}.cfg")
    with open(ruta, "w", encoding="utf-8", newline="\n") as f:
        f.write(cfg_texto)
    return ruta


# ===========================================================================
# Diagnóstico del Secondary SSID existente
# ===========================================================================
INCOMPLETOS = {"MISMO_SSID_SIN_CLAVE", "OTRO_SSID_SIN_CLAVE", "CLAVE_SIN_SSID"}

DESCRIPCION_ESTADO = {
    "SIN_SECUNDARIO":        "No tenía Secondary SSID",
    "IGUAL":                 "Ya tenía el mismo Secondary SSID y clave",
    "IGUAL_DESHABILITADO":   "Tenía el mismo SSID y clave pero deshabilitado o con parámetros distintos",
    "MISMO_SSID_SIN_CLAVE":  "Tenía el mismo SSID del Excel pero sin clave",
    "MISMO_SSID_OTRA_CLAVE": "Tenía el mismo SSID del Excel pero con otra clave",
    "OTRO_SSID_SIN_CLAVE":   "Tenía otro Secondary SSID ({ssid}) sin clave",
    "OTRO_SSID":             "Tenía otro Secondary SSID ({ssid}) con clave",
    "CLAVE_SIN_SSID":        "Tenía clave pero sin nombre de SSID",
}


def diagnosticar(lineas_actuales, valores, ssid_nuevo, clave_nueva, lineas_nuevas):
    ssid, psk = valores.get("ssid", ""), valores.get("psk", "")
    if not ssid and not psk:
        return "SIN_SECUNDARIO"
    if not ssid:
        return "CLAVE_SIN_SSID"
    if ssid == ssid_nuevo:
        if not psk:
            return "MISMO_SSID_SIN_CLAVE"
        if not claves_equivalentes(psk, clave_nueva, ssid):
            return "MISMO_SSID_OTRA_CLAVE"
        parametros = {l for l in lineas_actuales if not re.search(r"\.(ssid|psk)=", l)}
        esperados = {l for l in lineas_nuevas if not re.search(r"\.(ssid|psk)=", l)}
        return "IGUAL" if parametros == esperados else "IGUAL_DESHABILITADO"
    return "OTRO_SSID_SIN_CLAVE" if not psk else "OTRO_SSID"


def permite_sobrescribir(ip, estado, politica):
    if estado in ("SIN_SECUNDARIO", "IGUAL_DESHABILITADO"):
        return True
    if politica == "siempre":
        return True
    if politica == "nunca":
        return False
    if politica == "incompletas":
        return estado in INCOMPLETOS
    return input(f"    ¿Sobrescribir el Secondary SSID de {ip}? (s/N): ").strip().lower() == "s"


# ===========================================================================
# Proceso por antena
# ===========================================================================
def nuevo_registro(eq, accion):
    return {
        "Fecha/Hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Fila Excel": eq.get("fila_excel", ""),
        "IP": eq["ip"],
        "Nombre (Excel)": eq.get("nombre", ""),
        "Hostname antena": "",
        "Modo radio": "",
        "Acción": accion,
        "SSID objetivo": eq.get("ssid_backup", ""),
        "Secondary SSID previo": "",
        "Clave previa": "",
        "Estado previo": "",
        "Resultado": "",
        "Observación": "",
        "Respaldo": "",
    }


def procesar_antena(eq, accion, politica):
    reg = nuevo_registro(eq, accion)
    ip = eq["ip"]
    obs = []

    if accion == "configurar":
        ssid_n, clave_n = eq["ssid_backup"], eq["clave_backup"]
        if not ssid_n:
            reg.update(Resultado="OMITIDA", Observación="Sin Backup SSID en el Excel")
            return reg, None
        if not clave_n:
            reg.update(Resultado="OMITIDA", Observación="Sin clave para el Backup SSID")
            return reg, None
        lineas_nuevas = lineas_secondary(ssid_n, clave_n)
    else:
        ssid_n = clave_n = None
        lineas_nuevas = LINEAS_FABRICA

    if not eq.get("clave"):
        reg.update(Resultado="OMITIDA", Observación="Sin credenciales SSH en el Excel")
        return reg, None

    print(f"\n[+] {ip} ({eq.get('nombre') or 'sin nombre'}): conectando...")
    try:
        ssh = conectar(ip, eq["usuario"], eq["clave"])
    except paramiko.AuthenticationException:
        reg.update(Resultado="ERROR", Observación="Usuario o clave SSH incorrectos")
        print("    [ERROR] Usuario o clave SSH incorrectos")
        return reg, None
    except Exception as e:
        reg.update(Resultado="ERROR", Observación=f"Sin conexión SSH: {e}")
        print(f"    [ERROR] Sin conexión SSH: {e}")
        return reg, None

    try:
        codigo, cfg, err = ejecutar(ssh, "cat /tmp/system.cfg")
        if codigo != 0 or "wireless" not in cfg:
            reg.update(Resultado="ERROR", Observación=f"No se pudo leer system.cfg {err.strip()}")
            return reg, None
        reg["Respaldo"] = guardar_respaldo(ip, cfg)

        hostname = valor_cfg(cfg, "resolv.host.1.name")
        modo_radio = valor_cfg(cfg, "radio.1.mode")
        reg["Hostname antena"] = hostname
        reg["Modo radio"] = modo_radio
        if eq.get("nombre") and hostname and normalizar(eq["nombre"]) != normalizar(hostname):
            obs.append(f"Nombre en Excel ({eq['nombre']}) distinto al hostname ({hostname})")

        if modo_radio != "managed":
            reg.update(Resultado="OMITIDA",
                       Observación="; ".join(obs + [f"No es estación (radio.1.mode={modo_radio}); "
                                                     "no se toca"]))
            print(f"    No es estación ({modo_radio}). Se omite.")
            return reg, None

        lineas_act, valores = bloque_n2(cfg)
        reg["Secondary SSID previo"] = valores.get("ssid", "")
        reg["Clave previa"] = ocultar(valores.get("psk", ""))
        if valores.get("status") == "enabled" and valores.get("ssid"):
            reg["Secondary SSID previo"] += " (habilitado)"
        elif valores.get("ssid"):
            reg["Secondary SSID previo"] += " (deshabilitado)"

        if accion == "configurar":
            estado = diagnosticar(lineas_act, valores, ssid_n, clave_n, lineas_nuevas)
            descripcion = DESCRIPCION_ESTADO[estado].format(ssid=valores.get("ssid", ""))
            reg["Estado previo"] = estado
            if estado in ("MISMO_SSID_OTRA_CLAVE", "OTRO_SSID", "CLAVE_SIN_SSID"):
                descripcion += (f" [clave en antena: {ocultar(valores.get('psk', ''))}"
                                f" / clave nueva: {ocultar(clave_n)}]")
            print(f"    {descripcion}")
            if estado == "IGUAL":
                reg.update(Resultado="SIN_CAMBIOS",
                           Observación="; ".join(obs + [descripcion + ". No se tocó (sin reinicio)"]))
                return reg, None
            if not permite_sobrescribir(ip, estado, politica):
                reg.update(Resultado="OMITIDA_POR_POLITICA",
                           Observación="; ".join(obs + [
                               f"{descripcion}. NO se modificó porque la política es "
                               f"'{NOMBRE_POLITICA[politica]}'"]))
                print("    Se deja como está.")
                return reg, None
            accion_txt = {
                "SIN_SECUNDARIO": "se agregó el nuevo",
                "IGUAL_DESHABILITADO": "se habilitó y corrigieron parámetros",
                "MISMO_SSID_SIN_CLAVE": "se agregó la clave",
                "MISMO_SSID_OTRA_CLAVE": "se actualizó la clave",
                "CLAVE_SIN_SSID": "se agregó el SSID y se reemplazó la clave",
            }.get(estado, f"se reemplazó por {ssid_n}")
            obs.append(f"{descripcion}; {accion_txt}")
        else:
            reg["Estado previo"] = "FABRICA" if set(lineas_act) == set(LINEAS_FABRICA) else "CONFIGURADO"
            if reg["Estado previo"] == "FABRICA":
                reg.update(Resultado="SIN_CAMBIOS",
                           Observación="; ".join(obs + ["Ya estaba deshabilitado de fábrica"]))
                print("    Ya estaba de fábrica. No se toca.")
                return reg, None
            obs.append(f"Se deshabilitó el Secondary SSID {valores.get('ssid', '')}".strip())

        # --- Escribir en RAM y verificar ---
        echos = "\n".join(f"echo '{l}' >> /tmp/system.cfg" for l in lineas_nuevas)
        script = ("cp /tmp/system.cfg /tmp/system.cfg.bak && "
                  "sed -i '/^wpasupplicant\\.profile\\.1\\.network\\.2\\./d' /tmp/system.cfg\n"
                  f"{echos}\n"
                  "grep '^wpasupplicant.profile.1.network.2.' /tmp/system.cfg")
        _, salida, err = ejecutar(ssh, script)
        if set(salida.strip().splitlines()) != set(lineas_nuevas):
            ejecutar(ssh, "cp /tmp/system.cfg.bak /tmp/system.cfg")
            reg.update(Resultado="ERROR",
                       Observación="; ".join(obs + ["La edición no quedó bien; se restauró en RAM"]))
            return reg, None

        # --- Guardar en flash y reiniciar ---
        # Guardar y programar el reinicio en UN solo comando: si el script se corta justo aquí,
        # la antena igual se reinicia (no queda guardada sin aplicar).
        _, salida, err = ejecutar(
            ssh, "cfgmtd -w -p /etc/ && echo GUARDADO_OK && "
                 "( (sleep 2; reboot) >/dev/null 2>&1 & )")
        if "GUARDADO_OK" not in salida:
            ejecutar(ssh, "cp /tmp/system.cfg.bak /tmp/system.cfg")
            reg.update(Resultado="ERROR",
                       Observación="; ".join(obs + [f"cfgmtd falló, no se reinició {err.strip()}"]))
            return reg, None
        print("    Guardado en flash. Reiniciando...")
        reg["Observación"] = "; ".join(obs)
        return reg, lineas_nuevas
    except Exception as e:
        reg.update(Resultado="ERROR", Observación="; ".join(obs + [f"Fallo: {e}"]))
        return reg, None
    finally:
        ssh.close()


def esperar_y_verificar(eq, lineas, espera_max=240, espera_inicial=45):
    ip = eq["ip"]
    print(f"    Esperando que {ip} regrese (hasta {espera_max}s)...")
    time.sleep(max(espera_inicial, 0))
    limite = time.time() + espera_max
    while time.time() < limite:
        try:
            ssh = conectar(ip, eq["usuario"], eq["clave"])
            _, cfg, _ = ejecutar(ssh, "cat /tmp/system.cfg")
            ssh.close()
            leidas, _ = bloque_n2(cfg)
            if set(leidas) == set(lineas):
                print("    [OK] Volvió y la configuración quedó guardada.")
                return "OK", "Verificado tras reinicio"
            print("    [!] Volvió pero network.2 no coincide.")
            return "NO_VERIFICADO", "Volvió pero network.2 no coincide con lo escrito"
        except Exception:
            time.sleep(10)
    print(f"    [ALERTA] {ip} NO volvió en {espera_max}s.")
    return "NO_VOLVIO", f"No respondió SSH {espera_max + 45}s después del reinicio. REVISAR"


# ===========================================================================
# Parada controlada con Ctrl+C
# ===========================================================================
PARADA = {"solicitada": 0}


def _manejar_ctrl_c(signum, frame):
    PARADA["solicitada"] += 1
    if PARADA["solicitada"] == 1:
        print("\n\n[!] PARADA SOLICITADA. Se termina la antena actual (para no dejarla a medias)")
        print("    y luego se verifican las que ya se reiniciaron. Ctrl+C otra vez = saltar esa verificación.\n")
    elif PARADA["solicitada"] == 2:
        print("\n[!] Se omitirá la verificación final. Ctrl+C una tercera vez = salir de inmediato.\n")
    else:
        raise KeyboardInterrupt


def confirmar_continuar(pilotos, restantes):
    print("\n" + "=" * 70)
    print(f"  PAUSA DE REVISIÓN: estas son las primeras {len(pilotos)} antenas con cambios")
    print("=" * 70)
    for r in pilotos:
        print(f"  {r['IP']:<16} {r['Nombre (Excel)'] or r['Hostname antena']:<18} {r['Resultado']}")
        print(f"      {r['Observación']}")
    print("\nRevísalas en su web (Wireless > Secondary SSID) y confirma que siguen")
    print("enlazadas a su AP principal antes de continuar.")
    print(f"Quedan {restantes} filas por procesar.")
    while True:
        resp = input("¿Continuar con el resto del lote? Escribe SI o NO: ").strip().upper()
        if resp in ("SI", "NO"):
            return resp == "SI"


# ===========================================================================
# Registro en Excel
# ===========================================================================
def _escribir_excel(registros, ruta):
    df = pd.DataFrame(registros)
    with pd.ExcelWriter(ruta, engine="openpyxl") as w:
        df.to_excel(w, index=False, sheet_name="Registro")
        ws = w.sheets["Registro"]
        for i, col in enumerate(df.columns, start=1):
            ancho = max([len(str(col))] + [len(str(v)) for v in df[col]]) + 2
            ws.column_dimensions[ws.cell(1, i).column_letter].width = min(ancho, 80)
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions


def guardar_registro(registros, ruta):
    """Intenta guardar el Excel. Si está abierto (bloqueado por Windows), NO detiene el
    proceso: avisa y lo reintenta en la siguiente antena. Los datos siguen en memoria
    y además quedan en el .txt."""
    try:
        _escribir_excel(registros, ruta)
        return True
    except PermissionError:
        print(f"    [!] No pude actualizar {os.path.basename(ruta)}: está abierto en Excel.")
        print("        Se reintentará en la siguiente antena. Para mirar el avance, abre el .txt.")
        return False
    except Exception as e:
        print(f"    [!] No pude actualizar el registro Excel: {e}")
        return False


def guardar_registro_final(registros, ruta):
    """Al terminar, insiste hasta poder guardar; si no, guarda con otro nombre."""
    for _ in range(5):
        if guardar_registro(registros, ruta):
            return ruta
        input("    Cierra el archivo de registro en Excel y presiona Enter para reintentar...")
    alterno = ruta.replace(".xlsx", f"_{datetime.now():%H%M%S}.xlsx")
    _escribir_excel(registros, alterno)
    return alterno


def anotar_txt(reg, ruta_txt):
    """Bitácora en texto plano, solo se agrega al final. Se puede abrir en el Bloc de notas
    mientras el script corre sin bloquear nada."""
    linea = " | ".join(f"{k}: {v}" for k, v in reg.items()
                       if k in ("Fecha/Hora", "IP", "Nombre (Excel)", "Estado previo",
                                "Resultado", "Observación") and v != "")
    try:
        with open(ruta_txt, "a", encoding="utf-8") as f:
            f.write(linea + "\n")
    except Exception as e:
        print(f"    [!] No pude escribir la bitácora .txt: {e}")


def pedir_texto_valido(mensaje, minimo=1, maximo=255):
    while True:
        v = input(mensaje).strip()
        if not (minimo <= len(v) <= maximo):
            print(f"    Debe tener entre {minimo} y {maximo} caracteres.")
        elif CARACTERES_PROHIBIDOS.intersection(v):
            print("    No uses comillas, $, ` ni \\.")
        else:
            return v


def seleccionar_excel():
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    ruta = filedialog.askopenfilename(title="Selecciona el archivo Excel de Antenas",
                                      filetypes=[("Archivos de Excel", "*.xlsx *.xls")])
    root.destroy()
    return ruta


# ===========================================================================
# MENÚ PRINCIPAL
# ===========================================================================
def main():
    print("==================================================")
    print("  SECONDARY SSID POR SSH (AirOS)")
    print(f"  Paramiko {paramiko.__version__}")
    print("==================================================")
    print(" [1] Cargar desde archivo Excel (Masivo)")
    print(" [2] Ingresar IP específica (Individual)")
    origen = input("\nOpción de origen (1 o 2): ").strip()

    print("\n--- ACCIÓN ---")
    print(" [1] Configurar Secondary SSID (guarda y reinicia)")
    print(" [2] Revertir: dejar Secondary SSID deshabilitado de fábrica (guarda y reinicia)")
    accion = {"1": "configurar", "2": "revertir"}.get(input("Elige (1 o 2): ").strip())
    if not accion:
        print("[!] Opción inválida."); return

    nombre_origen = "individual"
    if origen == "1":
        ruta = seleccionar_excel()
        if not ruta:
            print("[!] Operación cancelada."); return
        nombre_origen = os.path.splitext(os.path.basename(ruta))[0]
        equipos, _ = leer_equipos_excel(ruta)
        if not equipos:
            return
    elif origen == "2":
        ip = input("\nIP de la antena: ").strip()
        usuario = input("Usuario SSH [ubnt]: ").strip() or "ubnt"
        clave = input("Contraseña SSH: ").strip()
        if not ip or not clave:
            print("[!] IP y contraseña requeridas."); return
        nombre = input("Nombre de la antena (opcional): ").strip()
        ssid = pedir_texto_valido("Nombre del Secondary SSID: ", 1, 32) if accion == "configurar" else ""
        equipos = [{'fila_excel': '', 'ip': ip, 'nombre': nombre, 'usuario': usuario,
                    'clave': clave, 'ssid_backup': ssid, 'clave_backup': ''}]
    else:
        print("[!] Opción inválida."); return

    politica = None
    if accion == "configurar":
        # Validar SSID del Excel y pedir UNA clave por cada SSID distinto que no la traiga
        for eq in equipos:
            if eq['ssid_backup'] and (CARACTERES_PROHIBIDOS.intersection(eq['ssid_backup'])
                                      or len(eq['ssid_backup']) > 32):
                print(f"  [!] SSID inválido en {eq['ip']}: {eq['ssid_backup']} (se omitirá)")
                eq['ssid_backup'] = ''
        sin_clave = sorted({eq['ssid_backup'] for eq in equipos
                            if eq['ssid_backup'] and not eq['clave_backup']})
        claves = {}
        if sin_clave:
            print("\nBackup SSID encontrados que necesitan clave WPA:")
            ultima = None
            for s in sin_clave:
                n = sum(1 for e in equipos if e['ssid_backup'] == s)
                sufijo = " [Enter = misma que la anterior]" if ultima else ""
                v = input(f"  Clave WPA para '{s}' ({n} antenas){sufijo}: ").strip()
                if not v and ultima:
                    v = ultima
                while not (8 <= len(v) <= 63) or CARACTERES_PROHIBIDOS.intersection(v):
                    v = input("    Debe tener 8-63 caracteres, sin comillas, $, ` ni \\: ").strip()
                claves[s] = ultima = v
        for eq in equipos:
            if eq['ssid_backup'] and not eq['clave_backup']:
                eq['clave_backup'] = claves[eq['ssid_backup']]

        print("\n--- SI UNA ANTENA YA TIENE OTRO SECONDARY SSID ---")
        print(" (Las que no tienen secundario se configuran; las que ya tienen el mismo SSID y")
        print("  clave se saltan sin reiniciar)")
        print(" [1] Preguntarme en cada antena")
        print(" [2] Sobrescribir siempre")
        print(" [3] Completar solo las incompletas (sin clave o sin SSID); dejar las demás")
        print(" [4] Nunca sobrescribir")
        politica = {"1": "preguntar", "2": "siempre", "3": "incompletas", "4": "nunca"}.get(
            input("Elige (1-4) [1]: ").strip(), "preguntar")

    con_ssid = sum(1 for e in equipos if e['ssid_backup'])
    print(f"\nEquipos con IP: {len(equipos)}"
          + (f"  |  Con Backup SSID: {con_ssid}" if accion == "configurar" and origen == "1" else "")
          + f"  |  Acción: {accion.upper()}" + (f"  |  Política: {politica.upper()}" if politica else ""))
    print("Las antenas que no estén en modo estación (AP/PTP master) se omiten automáticamente.")

    print("\n--- VERIFICACIÓN DEL REINICIO ---")
    print(f" [1] Rápido: esperar y verificar solo las primeras {ANTENAS_PILOTO} antenas modificadas;")
    print("     las demás se reinician sin esperar y se verifican todas juntas al final")
    print(" [2] Seguro: esperar y verificar cada antena antes de pasar a la siguiente")
    modo_espera = "seguro" if input("Elige (1 o 2) [1]: ").strip() == "2" else "rapido"
    if input("Escribe SI para continuar: ").strip().upper() != "SI":
        print("[!] Cancelado."); return

    os.makedirs(CARPETA_REGISTROS, exist_ok=True)
    ruta_registro = os.path.join(CARPETA_REGISTROS,
                                 f"registro_{nombre_origen}_{accion}_{datetime.now():%Y%m%d_%H%M%S}.xlsx")
    ruta_txt = ruta_registro.replace(".xlsx", ".txt")
    print(f"\nRegistro: {os.path.abspath(ruta_registro)}")
    print("No abras el .xlsx mientras corre el lote; si quieres ver el avance abre el .txt.")
    print("Para detener el lote de forma segura presiona Ctrl+C (una vez).")
    signal.signal(signal.SIGINT, _manejar_ctrl_c)
    registros = []
    pendientes = []          # (registro, equipo, lineas, momento del reinicio)
    verificadas_ok = 0
    pilotos = []             # registros de las primeras antenas que recibieron cambios
    for i, eq in enumerate(equipos):
        if PARADA["solicitada"]:
            for pendiente in equipos[i:]:
                r = nuevo_registro(pendiente, accion)
                r.update(Resultado="NO_PROCESADA", Observación="Lote detenido por el usuario (Ctrl+C)")
                registros.append(r)
                anotar_txt(r, ruta_txt)
            guardar_registro(registros, ruta_registro)
            print(f"\n[!] Lote detenido. Procesadas: {i} de {len(equipos)}.")
            break
        reg, lineas = procesar_antena(eq, accion, politica)
        detener = False
        motivo_parada = "Lote detenido por el usuario"
        if lineas:
            if modo_espera == "seguro" or verificadas_ok < ANTENAS_PILOTO:
                resultado, nota = esperar_y_verificar(eq, lineas)
                reg["Resultado"] = resultado
                reg["Observación"] = "; ".join(x for x in (reg["Observación"], nota) if x)
                if resultado == "OK":
                    verificadas_ok += 1
                elif i < len(equipos) - 1 and not PARADA["solicitada"]:
                    detener = input("    ¿Detener el lote aquí? (S/n): ").strip().lower() != "n"
            else:
                reg["Resultado"] = "PENDIENTE_VERIFICAR"
                pendientes.append((reg, eq, lineas, time.time()))
                print("    Reinicio enviado. Se verificará al final.")
        registros.append(reg)
        anotar_txt(reg, ruta_txt)
        guardar_registro(registros, ruta_registro)   # se guarda después de cada antena

        # --- Pausa de revisión tras las primeras antenas modificadas ---
        if lineas and len(pilotos) < ANTENAS_PILOTO:
            pilotos.append(reg)
            if (len(pilotos) == ANTENAS_PILOTO and not detener
                    and not PARADA["solicitada"] and i < len(equipos) - 1):
                detener = not confirmar_continuar(pilotos, len(equipos) - i - 1)
                if detener:
                    motivo_parada = "Detenido tras revisar las antenas piloto"
        if detener:
            for pendiente in equipos[i + 1:]:
                r = nuevo_registro(pendiente, accion)
                r.update(Resultado="NO_PROCESADA", Observación=motivo_parada)
                registros.append(r)
                anotar_txt(r, ruta_txt)
            break

    if pendientes:
        print(f"\n=== Verificando {len(pendientes)} antenas reiniciadas sin esperar ===")
        for reg, eq, lineas, t_reinicio in pendientes:
            if PARADA["solicitada"] >= 2:
                reg["Observación"] = "; ".join(x for x in (reg["Observación"],
                    "Reiniciada pero NO verificada (verificación omitida por el usuario)") if x)
                continue
            transcurrido = time.time() - t_reinicio
            print(f"\n[+] {eq['ip']} ({eq.get('nombre') or 'sin nombre'})")
            resultado, nota = esperar_y_verificar(eq, lineas, espera_inicial=60 - transcurrido)
            reg["Resultado"] = resultado
            reg["Observación"] = "; ".join(x for x in (reg["Observación"], nota) if x)
            reg["Fecha/Hora"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            anotar_txt(reg, ruta_txt)
            guardar_registro(registros, ruta_registro)

    guardar_registro(registros, ruta_registro)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    print("\n================ RESUMEN ================")
    conteo = pd.Series([r["Resultado"] for r in registros]).value_counts()
    for resultado, n in conteo.items():
        print(f"  {resultado:<22} {n}")
    ruta_registro = guardar_registro_final(registros, ruta_registro)
    print(f"\nRegistro detallado: {os.path.abspath(ruta_registro)}")
    print(f"Bitácora de texto:  {os.path.abspath(ruta_txt)}")
    print("[!] Proceso finalizado.")


if __name__ == "__main__":
    main()