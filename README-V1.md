# ApkAnalyzer V1 (analysis with rating)

> ⚠️ **Warning:**  
> the [test_malicious_sample.apk](https://github.com/ashishb/android-malware/tree/master/benews) comes from the following repo:
> - https://github.com/ashishb/android-malware
> 
> It is a **REAL** piece of malware, so absolutely **DO NOT** install it on your real device! 

## How to Use
### Quick Start
- See Colab notebook: https://colab.research.google.com/drive/1SDxx3n3FZ6rqCgr_raEBA9lyhvRBGJIx

### Local run: Step-by-Step
```shell
# 0. a python-3 env is required.

# 1. install requirements, 
#    pytorch is required for the ML-based obfuscation detection (only if you want to use it)
#    import obf_ml_detector instead of obf_detector in rating_analyzer.py if you want to try an ML-based obf detector
pip install -r requirements.txt

# 2. run the script to start your analysis
python rating_analyzer.py ./malware_apks/test_malicious_sample.apk -o result.yaml

# 3. more usage examples:
python rating_analyzer.py -h

Usage: python rating_analyzer.py <path_to_apk_file> [-o output.yaml] [-l WARNING] [-a] [-h]
    -o: (optional) specify output file path.
        if not specified, print the results on stdout only
    -l: (optional) specify logging level, default to WARNING
        can be one of (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
    -h: show this help info
    
```

Two files will be generated:
- a [result](result.yaml) file specified by -o (optional)
- a [snippets.txt](snippets.txt) will be generated in the current directory, recording the decompiled smali code, and each method is marked with the possibility of being obfuscated ('MAY-BE-OBFUSCATED' or 'NOT-OBFUSCATED')

