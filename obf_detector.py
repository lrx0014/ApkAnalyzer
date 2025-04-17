import re
import math

class ObfuscationDetector:
    def __init__(self, entropy_threshold=4.5, min_str_len=30, short_name_len=2):
        self.entropy_threshold = entropy_threshold
        self.min_str_len = min_str_len
        self.short_name_len = short_name_len

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        length = len(s)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def classify_and_save(self, code_snippets, metas, output_path="snippets.txt"):
        results = []
        with open(output_path, 'w', encoding='utf-8') as f:
            for (cls, mth), snippet in zip(metas, code_snippets):
                # short class/method name
                simple_cls = cls[1:-1].split('/')[-1] if cls.startswith('L') and cls.endswith(';') else cls
                obf = len(simple_cls) <= self.short_name_len or len(mth) <= self.short_name_len

                # otherwise
                # use entropy to determine whether a string may be randomly generated
                if not obf:
                    strs = re.findall(r'"(.*?)"', snippet)
                    for s in strs:
                        if len(s) > self.min_str_len and self.shannon_entropy(s) > self.entropy_threshold:
                            obf = True
                            break

                tag = "MAY-BE-OBFUSCATED" if obf else "NOT-OBFUSCATED"

                f.write(f"// {simple_cls}.{mth} : {tag}\n")
                f.write(snippet + "\n\n")
                results.append(1 if obf else 0)

        print(f"saved {len(code_snippets)} code snippets to {output_path}")
        return results
