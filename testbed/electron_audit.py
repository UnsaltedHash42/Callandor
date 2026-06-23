import os, glob, plistlib, subprocess, sys
SENT=b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
FUSES=["RunAsNode","EnableCookieEncryption","EnableNodeOptionsEnvironmentVariable",
"EnableNodeCliInspectArguments","EnableEmbeddedAsarIntegrityValidation","OnlyLoadAppFromAsar",
"LoadBrowserProcessSpecificV8Snapshot","GrantFileProtocolExtraPrivileges"]
def fw(app):
    g=glob.glob(app+"/Contents/Frameworks/Electron Framework.framework/Versions/*/Electron Framework")
    return g[0] if g else None
def fuses(path):
    d=open(path,"rb").read()
    i=d.find(SENT)
    if i<0: return None
    p=i+len(SENT); ver=d[p]; n=d[p+1]; states=d[p+2:p+2+n]
    out={}
    for k,b in enumerate(states):
        nm=FUSES[k] if k<len(FUSES) else f"fuse{k}"
        out[nm]= "ON" if b in (0x31,1) else ("OFF" if b in (0x30,0) else f"0x{b:02x}")
    return out
def writable(p): return os.access(p, os.W_OK)
for app in sorted(glob.glob("/Applications/*.app")):
    f=fw(app)
    if not f: continue
    name=os.path.basename(app)
    fz=fuses(f) or {}
    asar=app+"/Contents/Resources/app.asar"
    has_asar=os.path.exists(asar)
    # exploitability signals
    runasnode=fz.get("RunAsNode")=="ON"
    asar_integ=fz.get("EnableEmbeddedAsarIntegrityValidation")=="ON"
    nodeopts=fz.get("EnableNodeOptionsEnvironmentVariable")=="ON"
    inspect=fz.get("EnableNodeCliInspectArguments")=="ON"
    flags=[]
    if runasnode: flags.append("RunAsNode(ELECTRON_RUN_AS_NODE->RCE)")
    if nodeopts: flags.append("NODE_OPTIONS")
    if inspect: flags.append("--inspect")
    if not asar_integ: flags.append("no-asar-integrity")
    if has_asar and writable(asar): flags.append("asar-WRITABLE")
    verdict="EXPLOITABLE" if (runasnode or nodeopts or inspect or (has_asar and writable(asar) and not asar_integ)) else "hardened"
    print(f"{name:28} [{verdict}] "+", ".join(flags) if flags else f"{name:28} [{verdict}] (fuses locked)")
