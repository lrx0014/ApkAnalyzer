# ApkAnalyzer V2 (malware family analysis)

> ⚠️ **Warning:**  
> the [test_malicious_sample.apk](https://github.com/ashishb/android-malware/tree/master/benews) comes from the following repo:
> - https://github.com/ashishb/android-malware
> 
> It is a **REAL** piece of malware, so absolutely **DO NOT** install it on your real device! 

## How to Use
### Source Code for V2 (current branch)
[malware_analyzer.py](malware_analyzer.py)

### Source Code for V1 (previous assignment)
https://github.com/lrx0014/ApkAnalyzer/tree/v1

### Quick Start
- See Colab notebook: https://colab.research.google.com/drive/1CgMfLPtBts-KJ6K1fQ7YsicB_r5edZW0

### Local run: Step-by-Step
```shell
# 0. a python-3 env is required.

# 1. install requirements, 
pip install -r requirements.txt

# 2-a. run the script to start your analysis and output the results
python malware_analyzer.py ./malware_apks/test_malicious_sample.apk

# 2-b. or save the results to a file
python malware_analyzer.py ./malware_apks/test_malicious_sample.apk > result_malware_analysis.txt

# 3. more usage examples:
python malware_analyzer.py -h

Usage: python malware_analyzer.py <path_to_apk_file> [-l WARNING] [-h]
    -l: (optional) specify logging level, default to WARNING
        can be one of (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
    -h: show this help info
    
```

example output:
- a [result_malware_analysis.txt](result_malware_analysis.txt) file specified by -o (optional)
