# ApkAnalyzer

## How to Use
```shell
# python 3
# 1. install requirements, pytorch is required for the ML-based obfuscation detection
pip install -r requirements.txt

# 2. run the script to start your analysis
python analyzer.py ./your_app.apk -o result.yaml

# 3. more usage examples:
python analyzer.py -h

Usage: python analyzer.py <path_to_apk_file> [-o output.json] [-l WARNING] [-a] [-h]
    -o: (optional) specify output file path.
        if not specified, print the logs on stdout only
    -l: (optional) specify logging level, default to WARNING
        can be one of (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
    -h: show this help info
    
```

Two files will be generated:
- a result file specified by -o (optional)
- a snippets.txt will be generated in the current directory, recording the decompiled smali code, and each method is marked with the possibility of being obfuscated ('MAY-BE-OBFUSCATED' or 'NOT-OBFUSCATED')

