import torch
from obfuscation_detection import ObfuscationClassifier, PlatformType

# tried to use an ML-based obfuscation_detection library,
# however, the pre-trained model this lib used, is mainly for CLI commands obf detection

class ObfuscationDetector:
    def __init__(self, platform: PlatformType = PlatformType.ALL):
        self._patch_torch_load()
        self._oc = ObfuscationClassifier(platform)

    @staticmethod
    def _patch_torch_load():
        orig_load = torch.load

        def patched_load(f, *args, **kwargs):
            kwargs.setdefault('weights_only', False)
            return orig_load(f, *args, **kwargs)

        torch.load = patched_load

    def classify(self, code_snippets: list[str]) -> list[int]:
        return self._oc(code_snippets)

    def classify_and_save(
            self,
            code_snippets: list[str],
            metas: list[tuple[str, str]],
            output_path: str = "snippets.txt"
    ) -> list[int]:

        results = self.classify(code_snippets)

        with open(output_path, "w", encoding="utf-8") as f:
            for (cls, name), snippet, res in zip(metas, code_snippets, results):
                tag = "MAY-BE-OBFUSCATED" if obf else "NOT-OBFUSCATED"

                f.write(f"// {cls} -> {name} : {tag}\n")
                f.write(snippet)
                f.write("\n\n")

        print(f"saved {len(code_snippets)} code snippets to {output_path}")
        return results

