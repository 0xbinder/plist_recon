#!/usr/bin/env python3
"""
Info.plist Security Analyzer - Extract attack surface and security configs
Usage: python plist_parser.py <path_to_Info.plist>
"""

import sys
import plistlib
import argparse
from pathlib import Path
import time

# --- TERMINAL STYLING ---
class Style:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BG_RED  = '\033[41m'
    BG_GREEN = '\033[42m'
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    BLINK   = '\033[5m'

def glitch_print(text, delay=0.02):
    """Print with typing effect"""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def banner():
    print(f"""{Style.CYAN}{Style.BOLD}
    ██████╗ ██╗     ██╗███████╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██║     ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝██║     ██║███████╗   ██║       ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔═══╝ ██║     ██║╚════██║   ██║       ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║     ███████╗██║███████║   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝     ╚══════╝╚═╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    {Style.RESET}
    {Style.RED}╔════════════════════════════════════════════════════════════════════════════╗
    ║  {Style.BOLD}iOS/macOS Attack Surface Enumeration Tool{Style.RESET}{Style.RED}                               ║
    ║  {Style.DIM}Extract • Analyze • Exploit{Style.RESET}{Style.RED}                                              ║
    ╚════════════════════════════════════════════════════════════════════════════╝{Style.RESET}
    {Style.DIM}[*] Initializing reconnaissance modules...{Style.RESET}
    """)

def log(message, level="INFO"):
    if level == "INFO":
        print(f"{Style.BLUE}[*]{Style.RESET} {message}")
    elif level == "SUCCESS":
        print(f"{Style.GREEN}[+]{Style.RESET} {message}")
    elif level == "WARN":
        print(f"{Style.YELLOW}[!]{Style.RESET} {message}")
    elif level == "CRIT":
        print(f"{Style.RED}{Style.BOLD}[X]{Style.RESET} {message}")
    elif level == "VULN":
        print(f"{Style.RED}{Style.BLINK}[VULN]{Style.RESET} {message}")
    elif level == "EXPLOIT":
        print(f"{Style.MAGENTA}[>>]{Style.RESET} {message}")

def section(title, icon="▓"):
    print(f"\n{Style.CYAN}{icon * 3}[ {Style.BOLD}{title}{Style.RESET}{Style.CYAN} ]{icon * 3}{Style.RESET}")

def subsection(title):
    print(f"\n  {Style.YELLOW}┌─[ {title} ]{Style.RESET}")

def analyze_plist(file_path):
    section("TARGET ACQUISITION", "█")
    log(f"Locked on target: {Style.BOLD}{Style.GREEN}{file_path}{Style.RESET}")
    
    try:
        with open(file_path, 'rb') as fp:
            plist = plistlib.load(fp)
    except Exception as e:
        log(f"FATAL ERROR: Plist parse failure → {e}", "CRIT")
        sys.exit(1)
    
    log(f"Plist decoded successfully [{len(plist)} keys extracted]", "SUCCESS")
    time.sleep(0.3)
    
    # ═══════════════════════════════════════════════════════
    # 1. BASIC APP INFO
    # ═══════════════════════════════════════════════════════
    section("TARGET PROFILE", "▓")
    
    bundle_id = plist.get('CFBundleIdentifier', 'UNKNOWN')
    executable = plist.get('CFBundleExecutable', 'UNKNOWN')
    version = plist.get('CFBundleShortVersionString', '0.0')
    build = plist.get('CFBundleVersion', 'N/A')
    display_name = plist.get('CFBundleDisplayName', plist.get('CFBundleName', 'N/A'))
    
    print(f"""
  {Style.DIM}┌──────────────────────────────────────────────────────┐{Style.RESET}
  {Style.DIM}│{Style.RESET} {Style.BOLD}BINARY{Style.RESET}      : {executable:<40}{Style.DIM}│{Style.RESET}
  {Style.DIM}│{Style.RESET} {Style.BOLD}APP NAME{Style.RESET}    : {display_name:<40}{Style.DIM}│{Style.RESET}
  {Style.DIM}│{Style.RESET} {Style.BOLD}BUNDLE ID{Style.RESET}   : {Style.GREEN}{bundle_id:<40}{Style.RESET}{Style.DIM}│{Style.RESET}
  {Style.DIM}│{Style.RESET} {Style.BOLD}VERSION{Style.RESET}     : {version} (build {build}){' ' * (30 - len(version) - len(build))}{Style.DIM}│{Style.RESET}
  {Style.DIM}│{Style.RESET} {Style.BOLD}MIN OS{Style.RESET}      : {plist.get('MinimumOSVersion', plist.get('LSMinimumSystemVersion', 'N/A')):<40}{Style.DIM}│{Style.RESET}
  {Style.DIM}│{Style.RESET} {Style.BOLD}SDK{Style.RESET}         : {plist.get('DTSDKName', 'N/A'):<40}{Style.DIM}│{Style.RESET}
  {Style.DIM}└──────────────────────────────────────────────────────┘{Style.RESET}
    """)
    
    # Quick exploitation commands
    subsection("QUICK HOOKS")
    print(f"  {Style.DIM}│{Style.RESET}")
    print(f"  {Style.DIM}├──>{Style.RESET} {Style.MAGENTA}frida -U -f {bundle_id}{Style.RESET}")
    print(f"  {Style.DIM}├──>{Style.RESET} {Style.MAGENTA}objection --gadget \"{bundle_id}\" explore{Style.RESET}")
    print(f"  {Style.DIM}└──>{Style.RESET} {Style.MAGENTA}iproxy 2222 22 && ssh root@localhost -p 2222{Style.RESET}")
    
    # ═══════════════════════════════════════════════════════
    # 2. URL SCHEMES (CRITICAL ATTACK SURFACE)
    # ═══════════════════════════════════════════════════════
    section("ATTACK VECTORS :: URL HANDLERS", "▓")
    
    url_types = plist.get('CFBundleURLTypes', [])
    if url_types:
        log(f"Discovered {Style.RED}{Style.BOLD}{len(url_types)}{Style.RESET} custom URL scheme(s) - ATTACK SURFACE IDENTIFIED", "VULN")
        
        for idx, url_type in enumerate(url_types, 1):
            schemes = url_type.get('CFBundleURLSchemes', [])
            role = url_type.get('CFBundleTypeRole', 'Unknown')
            name = url_type.get('CFBundleURLName', 'N/A')
            
            for scheme in schemes:
                print(f"\n  {Style.RED}┏━━[ SCHEME #{idx} ]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET}")
                print(f"  {Style.RED}┃{Style.RESET} {Style.BOLD}{Style.YELLOW}{scheme}://{Style.RESET}")
                print(f"  {Style.RED}┃{Style.RESET} Role: {role} | Name: {name}")
                print(f"  {Style.RED}┣━[ PAYLOAD VECTORS ]{Style.RESET}")
                print(f"  {Style.RED}┃{Style.RESET}   {Style.DIM}XSS      :{Style.RESET} {scheme}://<script>alert(1)</script>")
                print(f"  {Style.RED}┃{Style.RESET}   {Style.DIM}Path Trav:{Style.RESET} {scheme}://../../etc/passwd")
                print(f"  {Style.RED}┃{Style.RESET}   {Style.DIM}SQLi     :{Style.RESET} {scheme}://user' OR '1'='1")
                print(f"  {Style.RED}┃{Style.RESET}   {Style.DIM}CMD Inj  :{Style.RESET} {scheme}://;cat /etc/passwd;")
                print(f"  {Style.RED}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET}")
    else:
        log("No custom URL schemes detected [HARDENED TARGET]", "INFO")
    
    # Query Schemes
    query_schemes = plist.get('LSApplicationQueriesSchemes', [])
    if query_schemes:
        subsection("CANARY APPS (FINGERPRINTING)")
        print(f"  {Style.DIM}│{Style.RESET} App performs reconnaissance on these schemes:")
        for scheme in query_schemes[:10]:
            print(f"  {Style.DIM}├──>{Style.RESET} {Style.CYAN}{scheme}://{Style.RESET}")
        if len(query_schemes) > 10:
            print(f"  {Style.DIM}└──>{Style.RESET} {Style.DIM}... and {len(query_schemes) - 10} more{Style.RESET}")
    
    # Universal Links
    associated_domains = plist.get('com.apple.developer.associated-domains', [])
    if associated_domains:
        subsection("UNIVERSAL LINKS (WEB ASSOCIATION)")
        for domain in associated_domains:
            print(f"  {Style.DIM}├──>{Style.RESET} {Style.GREEN}{domain}{Style.RESET}")
    
    # ═══════════════════════════════════════════════════════
    # 3. APP TRANSPORT SECURITY (ATS)
    # ═══════════════════════════════════════════════════════
    section("NETWORK SECURITY :: ATS AUDIT", "▓")
    
    ats = plist.get('NSAppTransportSecurity', {})
    allows_arbitrary = ats.get('NSAllowsArbitraryLoads', False)
    allows_local = ats.get('NSAllowsLocalNetworking', False)
    exception_domains = ats.get('NSExceptionDomains', {})
    
    if allows_arbitrary:
        print(f"""
  {Style.BG_RED}{Style.WHITE}{Style.BOLD}  ⚠ CRITICAL VULNERABILITY DETECTED ⚠  {Style.RESET}
  
  {Style.RED}╔════════════════════════════════════════════════════════════╗
  ║  NSAllowsArbitraryLoads = TRUE                             ║
  ║                                                             ║
  ║  {Style.BOLD}CLEARTEXT HTTP ALLOWED TO ALL DOMAINS{Style.RESET}{Style.RED}                  ║
  ║                                                             ║
  ║  → Man-in-the-Middle (MITM) attacks possible               ║
  ║  → Intercept traffic with mitmproxy/Burp Suite             ║
  ║  → No certificate pinning required                         ║
  ╚════════════════════════════════════════════════════════════╝{Style.RESET}
        """)
        log("EXPLOIT: Run 'mitmproxy -p 8080' and configure device proxy", "EXPLOIT")
    else:
        log("ATS ENFORCED → HTTPS mandatory [SECURE]", "SUCCESS")
    
    if allows_local:
        log("NSAllowsLocalNetworking = TRUE → LAN HTTP allowed", "WARN")
    
    if exception_domains:
        subsection(f"HTTP WHITELIST [{len(exception_domains)} domains]")
        for domain, config in list(exception_domains.items())[:10]:
            insecure = config.get('NSExceptionAllowsInsecureHTTPLoads', False)
            if insecure:
                print(f"  {Style.DIM}├──>{Style.RESET} {Style.RED}✗ {domain}{Style.RESET} {Style.DIM}[CLEARTEXT]{Style.RESET}")
            else:
                print(f"  {Style.DIM}├──>{Style.RESET} {Style.YELLOW}• {domain}{Style.RESET}")
        if len(exception_domains) > 10:
            print(f"  {Style.DIM}└──>{Style.RESET} {Style.DIM}... and {len(exception_domains) - 10} more{Style.RESET}")
    
    # ═══════════════════════════════════════════════════════
    # 4. PERMISSIONS & PRIVACY
    # ═══════════════════════════════════════════════════════
    section("SURVEILLANCE CAPABILITIES", "▓")
    
    permission_map = {
        "NSCameraUsageDescription": ("📷 CAMERA ACCESS", "RED", "HIGH"),
        "NSMicrophoneUsageDescription": ("🎤 MICROPHONE ACCESS", "RED", "HIGH"),
        "NSLocationAlwaysUsageDescription": ("📍 GPS TRACKING (24/7)", "RED", "CRITICAL"),
        "NSLocationAlwaysAndWhenInUseUsageDescription": ("📍 GPS TRACKING (ALWAYS)", "RED", "CRITICAL"),
        "NSLocationWhenInUseUsageDescription": ("📍 GPS (ACTIVE ONLY)", "YELLOW", "MED"),
        "NSPhotoLibraryUsageDescription": ("🖼️  PHOTO LIBRARY", "YELLOW", "MED"),
        "NSPhotoLibraryAddUsageDescription": ("📥 PHOTO UPLOAD", "BLUE", "LOW"),
        "NSContactsUsageDescription": ("👥 CONTACT LIST", "YELLOW", "MED"),
        "NSCalendarsUsageDescription": ("📅 CALENDAR ACCESS", "BLUE", "LOW"),
        "NSRemindersUsageDescription": ("✅ REMINDERS", "BLUE", "LOW"),
        "NSMotionUsageDescription": ("🏃 MOTION/FITNESS", "BLUE", "LOW"),
        "NSHealthShareUsageDescription": ("❤️  HEALTH DATA (READ)", "YELLOW", "MED"),
        "NSHealthUpdateUsageDescription": ("❤️  HEALTH DATA (WRITE)", "RED", "HIGH"),
        "NSBluetoothAlwaysUsageDescription": ("📡 BLUETOOTH", "BLUE", "LOW"),
        "NSLocalNetworkUsageDescription": ("🌐 LAN DISCOVERY", "YELLOW", "MED"),
        "NSSpeechRecognitionUsageDescription": ("🗣️  SPEECH ANALYSIS", "YELLOW", "MED"),
        "NSFaceIDUsageDescription": ("👤 BIOMETRIC (FACE ID)", "BLUE", "LOW"),
        "NSUserTrackingUsageDescription": ("🎯 TRACKING/ADS", "RED", "HIGH"),
        "NSAppleMusicUsageDescription": ("🎵 MUSIC LIBRARY", "BLUE", "LOW"),
        "NSSiriUsageDescription": ("🎙️  SIRI INTEGRATION", "BLUE", "LOW"),
    }
    
    found_permissions = []
    for key, value in plist.items():
        if key.endswith("UsageDescription"):
            found_permissions.append((key, value))
    
    if found_permissions:
        crit_count = sum(1 for k, _ in found_permissions if k in permission_map and permission_map[k][2] == "CRITICAL")
        high_count = sum(1 for k, _ in found_permissions if k in permission_map and permission_map[k][2] == "HIGH")
        
        log(f"Enumerated {Style.BOLD}{len(found_permissions)}{Style.RESET} permission(s) | "
            f"{Style.RED}{crit_count} CRITICAL{Style.RESET} | {Style.YELLOW}{high_count} HIGH{Style.RESET}", "WARN")
        
        for key, description in sorted(found_permissions):
            if key in permission_map:
                label, color, risk = permission_map[key]
                color_code = getattr(Style, color, Style.BLUE)
                risk_badge = f"[{risk}]"
                print(f"\n  {color_code}┏━[ {label} ]━ {risk_badge}{Style.RESET}")
                print(f"  {color_code}┃{Style.RESET} {Style.DIM}{description}{Style.RESET}")
            else:
                clean_name = key.replace("NS", "").replace("UsageDescription", "")
                print(f"\n  {Style.BLUE}┏━[ {clean_name} ]{Style.RESET}")
                print(f"  {Style.BLUE}┃{Style.RESET} {Style.DIM}{description}{Style.RESET}")
    else:
        log("No permissions declared → Minimal attack surface", "SUCCESS")
    
    # ═══════════════════════════════════════════════════════
    # 5. DATA EXPOSURE & FILE SHARING
    # ═══════════════════════════════════════════════════════
    section("DATA LEAKAGE VECTORS", "▓")
    
    file_sharing = plist.get('UIFileSharingEnabled', False)
    docs_in_place = plist.get('LSSupportsOpeningDocumentsInPlace', False)
    
    if file_sharing or docs_in_place:
        log("FILE SHARING ENABLED → Documents exposed via iTunes/Files", "VULN")
        print(f"""
  {Style.YELLOW}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  EXFILTRATION OPPORTUNITY DETECTED                       ┃
  ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{Style.RESET}""")
        if file_sharing:
            print(f"  {Style.YELLOW}┃{Style.RESET}  {Style.RED}UIFileSharingEnabled = TRUE{Style.RESET}")
            print(f"  {Style.YELLOW}┃{Style.RESET}  → Full /Documents/ folder accessible")
        if docs_in_place:
            print(f"  {Style.YELLOW}┃{Style.RESET}  {Style.RED}LSSupportsOpeningDocumentsInPlace = TRUE{Style.RESET}")
            print(f"  {Style.YELLOW}┃{Style.RESET}  → In-place file manipulation enabled")
        print(f"  {Style.YELLOW}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Style.RESET}")
        log("Check for: SQLite DBs, .plist configs, API keys, tokens", "EXPLOIT")
    else:
        log("File sharing disabled [SECURE]", "SUCCESS")
    
    # ═══════════════════════════════════════════════════════
    # 6. BACKGROUND CAPABILITIES
    # ═══════════════════════════════════════════════════════
    section("PERSISTENCE MECHANISMS", "▓")
    
    bg_modes = plist.get('UIBackgroundModes', [])
    if bg_modes:
        log(f"Background execution enabled [{len(bg_modes)} mode(s)]", "WARN")
        mode_descriptions = {
            'audio': '🎵 AUDIO PLAYBACK',
            'location': '📍 LOCATION UPDATES',
            'voip': '📞 VOIP CALLS',
            'fetch': '📥 BACKGROUND FETCH',
            'remote-notification': '🔔 PUSH WAKE-UP',
            'newsstand-content': '📰 NEWSSTAND',
            'external-accessory': '🔌 ACCESSORIES',
            'bluetooth-central': '📡 BLE CENTRAL',
            'bluetooth-peripheral': '📡 BLE PERIPHERAL',
            'processing': '⚙️  BACKGROUND PROCESSING',
        }
        
        for mode in bg_modes:
            desc = mode_descriptions.get(mode, mode.upper())
            print(f"  {Style.DIM}├──>{Style.RESET} {Style.CYAN}{desc}{Style.RESET}")
    else:
        log("No background modes → App terminates on suspend", "INFO")
    
    # ═══════════════════════════════════════════════════════
    # 7. EXPORTED SERVICES & DOCUMENT TYPES
    # ═══════════════════════════════════════════════════════
    section("FILE HANDLERS & EXTENSIONS", "▓")
    
    doc_types = plist.get('CFBundleDocumentTypes', [])
    if doc_types:
        log(f"Registered for {len(doc_types)} document type(s)", "INFO")
        for doc_type in doc_types[:5]:
            name = doc_type.get('CFBundleTypeName', 'Unknown')
            extensions = doc_type.get('CFBundleTypeExtensions', [])
            if extensions:
                print(f"  {Style.DIM}├──>{Style.RESET} {Style.GREEN}{name}{Style.RESET}: {Style.DIM}{', '.join(extensions)}{Style.RESET}")
        if len(doc_types) > 5:
            print(f"  {Style.DIM}└──>{Style.RESET} {Style.DIM}... +{len(doc_types) - 5} more types{Style.RESET}")
    
    # ═══════════════════════════════════════════════════════
    # 8. REVERSE ENGINEERING POINTERS
    # ═══════════════════════════════════════════════════════
    section("REVERSE ENGINEERING INTEL", "▓")
    
    # App Delegate
    app_delegate = plist.get('NSPrincipalClass', 'UIApplication')
    print(f"  {Style.GREEN}[CLASS]{Style.RESET} Principal      → {Style.BOLD}{app_delegate}{Style.RESET}")
    
    # Scene Delegate
    scene_manifest = plist.get('UIApplicationSceneManifest', {})
    if scene_manifest:
        try:
            scenes = scene_manifest['UISceneConfigurations']['UIWindowSceneSessionRoleApplication']
            if scenes:
                delegate = scenes[0].get('UISceneDelegateClassName')
                if delegate:
                    print(f"  {Style.GREEN}[CLASS]{Style.RESET} SceneDelegate  → {Style.BOLD}{delegate}{Style.RESET}")
                    print(f"         {Style.DIM}Hook: scene:openURLContexts: for URL handling{Style.RESET}")
        except:
            pass
    
    # Main Storyboard
    main_sb = plist.get('UIMainStoryboardFile', None)
    if main_sb:
        print(f"  {Style.GREEN}[VIEW]{Style.RESET}  Storyboard    → {Style.BOLD}{main_sb}.storyboard{Style.RESET}")
    
    # Launch Storyboard
    launch_sb = plist.get('UILaunchStoryboardName', None)
    if launch_sb:
        print(f"  {Style.GREEN}[VIEW]{Style.RESET}  LaunchScreen  → {Style.BOLD}{launch_sb}.storyboard{Style.RESET}")
    
    subsection("FRIDA HOOKS (RECOMMENDED)")
    print(f"""  {Style.DIM}│{Style.RESET}
  {Style.DIM}├──>{Style.RESET} {Style.MAGENTA}Interceptor.attach(Module.findExportByName(null, "open"), {{{Style.RESET}
  {Style.DIM}│{Style.RESET}   {Style.MAGENTA}onEnter: function(args) {{ console.log(args[0].readUtf8String()); }}{Style.RESET}
  {Style.DIM}│{Style.RESET}   {Style.MAGENTA}}});{Style.RESET}
  {Style.DIM}│{Style.RESET}
  {Style.DIM}└──>{Style.RESET} {Style.MAGENTA}objc_msgSend intercept for URL handling methods{Style.RESET}
    """)
    
    print(f"\n{Style.GREEN}{Style.BOLD}╔══════════════════════════════════════════════════════════════════════╗")
    print(f"║  RECONNAISSANCE COMPLETE                                             ║")
    print(f"║  Total metadata keys extracted: {len(plist):<40}║")
    print(f"╚══════════════════════════════════════════════════════════════════════╝{Style.RESET}\n")

def main():
    banner()
    time.sleep(0.5)
    
    parser = argparse.ArgumentParser(
        description='iOS/macOS Info.plist Attack Surface Analyzer',
        usage='python plist_parser.py <Info.plist>'
    )
    parser.add_argument('file', help='Path to Info.plist file')
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    plist_path = Path(args.file)
    
    if not plist_path.exists():
        log(f"Target not found: {plist_path}", "CRIT")
        sys.exit(1)
    
    analyze_plist(plist_path)

if __name__ == "__main__":
    main()
