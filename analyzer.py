import sys
import yaml
import re
import zipfile
from androguard.misc import AnalyzeAPK
from androguard.util import set_log

# some settings
scan_all = False
log_level = "WARNING"

def analyze_apk(apk_path):
    print(f"Analyzing file: {apk_path}")
    print(f"scan user code only: {not scan_all}")

    a, d, dx = AnalyzeAPK(apk_path)

    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()

    result = {
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": a.get_providers(),
        "main_activity": a.get_main_activity(),
        "permissions": a.get_permissions(),
        "intent_filters": {
            "activities": {act: a.get_intent_filters("activity", act) for act in activities},
            "services": {srv: a.get_intent_filters("service", srv) for srv in services},
            "receivers": {rcv: a.get_intent_filters("receiver", rcv) for rcv in receivers},
        },
        # "interesting_strings": extract_interesting_strings(dx),
        "native_libraries": extract_native_libraries(apk_path),
        "dynamic_code_loading": detect_dynamic_loading(dx),
        # "obfuscation_indicators": detect_obfuscation(dx),
        "dangerous_permissions": detect_dangerous_permissions(a.get_permissions()),
        # "risk_score": calculate_risk_score(a, dx),
    }

    return result


def is_user_code(class_name):
    if scan_all:
        return True
    return not (class_name.startswith("Landroid/") or
                class_name.startswith("Ljava/") or
                class_name.startswith("Lkotlin/") or
                class_name.startswith("Landroidx/") or
                class_name.startswith("Lcom/google/") or
                class_name.startswith("Lkotlinx/"))


def extract_interesting_strings(dx):
    pattern = re.compile(r"https?://|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|api[_-]?key|token", re.IGNORECASE)
    matches = []
    for sref in dx.get_string_references():
        method = sref.method
        if method.is_external():
            continue
        if is_user_code(method.class_name):
            s = sref.get_string()
            if pattern.search(s):
                matches.append(s)
    return list(set(matches))


def extract_native_libraries(apk_path):
    with zipfile.ZipFile(apk_path, 'r') as zipf:
        return [f for f in zipf.namelist() if f.startswith("lib/") and f.endswith(".so")]


def detect_dynamic_loading(dx):
    dynamic_related_calls = [
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;",
        "Ljava/lang/reflect/Method;",
        "Ljava/lang/Class;",
        "forName",
    ]
    findings = []
    for method in dx.get_methods():
        if method.is_external():
            continue
        class_name = method.class_name
        if not is_user_code(class_name):
            continue
        for bb in method.get_basic_blocks().get():
            for ins in bb.get_instructions():
                out = ins.get_output()
                if any(keyword in out for keyword in dynamic_related_calls):
                    findings.append({"class": class_name, "method": method.name, "instruction": out})
    return findings


def detect_obfuscation(dx):
    short_names = 0
    encrypted_strings = 0
    for cls in dx.get_classes():
        if not is_user_code(cls.name):
            continue
        if len(cls.name.split("/")) > 1:
            name_part = cls.name.split("/")[-1].strip(";")
            if len(name_part) <= 2:
                short_names += 1
    for ref in dx.get_string_references():
        method = ref.method
        if method.is_external() or not is_user_code(method.class_name):
            continue
        s = ref.get_string()
        if len(s) > 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", s):
            encrypted_strings += 1

    return {
        "short_named_classes": short_names,
        "potentially_encrypted_strings": encrypted_strings
    }


def detect_dangerous_permissions(permissions):
    dangerous_perms = [
        "SEND_SMS",
        "RECEIVE_SMS",
        "READ_SMS",
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "READ_PHONE_STATE",
        "RECORD_AUDIO",
        "ACCESS_FINE_LOCATION",
        "USE_CREDENTIALS"
    ]

    flagged = [p for p in permissions if any(d in p for d in dangerous_perms)]
    return flagged


def calculate_risk_score(a, dx):
    score = 0
    score += len(detect_dangerous_permissions(a.get_permissions())) * 2
    score += len(detect_dynamic_loading(dx))
    obf = detect_obfuscation(dx)
    score += obf["short_named_classes"] + obf["potentially_encrypted_strings"]
    return min(score, 10)


def print_help():
    print()
    print("Usage: python analyzer.py <path_to_apk_file> [-o output.json] [-l WARNING] [-a] [-h]")
    print("    -o: (optional) specify output file path.")
    print("        if not specified, print the logs on stdout only")
    print("    -l: (optional) specify logging level, default to WARNING")
    print("        can be one of (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)")
    print("    -h: show this help info")
    print()


def main():
    global scan_all, log_level

    if len(sys.argv) < 2 or '-h' in sys.argv:
        print_help()
        return

    apk_path = sys.argv[1]
    output_path = None
    scan_all = '-a' in sys.argv

    # (optional) specify output file path
    if '-o' in sys.argv:
        try:
            output_path = sys.argv[sys.argv.index('-o') + 1]
        except IndexError:
            print("Error: -o provided but no output file path specified")
            return
    # (optional) specify logging level, default to WARNING
    # can be one of (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
    if '-l' in sys.argv:
        try:
            log_level = sys.argv[sys.argv.index('-l') + 1]
        except IndexError:
            print("Error: -l provided but no log level specified")
            return

    # logging level
    set_log(log_level)

    result = analyze_apk(apk_path)
    yaml_result = yaml.dump(result, sort_keys=False, allow_unicode=True)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(yaml_result)
        print(f"result saved to {output_path}")
    else:
        print(yaml_result)


if __name__ == "__main__":
    main()
