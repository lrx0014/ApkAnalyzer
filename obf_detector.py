import re
import math

class ObfuscationDetector:
    def __init__(self, min_enc_len: int = 32, short_name_len: int = 2):
        self.min_enc_len = min_enc_len
        self.short_name_len = short_name_len
        # Hex
        self.hex_pattern = re.compile(rf'^[A-Fa-f0-9]{{{min_enc_len},}}$')
        # Base64
        self.b64_pattern = re.compile(rf'^[A-Za-z0-9+/]{{{min_enc_len},}}={0, 2}$')


    def classify_and_save(self, code_snippets, metas, output_path="snippets.txt"):
        results = []
        with open(output_path, 'w', encoding='utf-8') as f:
            for (cls, mth), snippet in zip(metas, code_snippets):
                # detect short class/method names
                simple_cls = cls[1:-1].split('/')[-1] if cls.startswith('L') and cls.endswith(';') else cls
                # some classes such as 'R' are built-in types
                # even though their class name is short, they shouldn't be considered as obfuscation.
                if simple_cls == "R" or simple_cls.startswith("R$") or simple_cls in ("BuildConfig", "Manifest"):
                    obf = False
                else:
                    obf = len(simple_cls) <= self.short_name_len or len(mth) <= self.short_name_len

                # detect if encrypted strings exist
                if not obf:
                    strs = re.findall(r'"(.*?)"', snippet)
                    for s in strs:
                        if len(s) < self.min_enc_len:
                            continue
                        # Hex type string detected
                        if self.hex_pattern.match(s):
                            obf = True
                            break
                        # Base64 type string detected
                        if self.b64_pattern.match(s):
                            obf = True
                            break

                tag = "MAY-BE-OBFUSCATED" if obf else "NOT-OBFUSCATED"

                f.write(f"// {simple_cls}.{mth} : {tag}\n")
                f.write(snippet + "\n\n")
                results.append(1 if obf else 0)

        print(f"saved {len(code_snippets)} code snippets to {output_path}")
        return results
