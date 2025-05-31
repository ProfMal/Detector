# ProfMal

ProfMal: Detecting Malicious NPM Packages by the Synergy between Static and Dynamic Analysis

## Introduction

ProfMal is a unified graph-based detector that leverages the synergy between static and dynamic analysis for malicious NPM package detection.

## Prompt

The prompts used for malicious shell command detection in the Script Analyzer, as well as those employed by the Sensitivity Evaluator, are defined in [`llm.py`](./llm.py).

**Below are the contents of the two prompts mentioned in the paper**

+ **Prompt for malicious shell command detection (Script Analyzer)**

```text
You’re a security expert with extensive experience in Linux shell programming and security risk assessment. You will receive one input:
Shell Command: A string representing a Linux shell command.
Your task is to evaluate the degree of sensitivity (i.e., the potential maliciousness) of the provided shell command based on its behavior. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
Sensitivity Scoring:
0: Not sensitive at all.
0 to 0.5: Low sensitivity (acts as a warning).
0.5 to 1: High sensitivity (should be closely scrutinized).
1: Absolutely sensitive.
                
Only assign a high score if you are confident in your assessment
Guidelines for Analysis:
1. Data Exfiltration: If the command retrieves local data, such as user or system information (e.g., passwords, system logs), and sends it externally (e.g., to a remote server via URL, DNS lookup, or other network protocols), assign a high score. Additionally, if the command displays sensitive data (e.g., contents of /etc/passwd), even without sending it externally, this should also be considered severe and assigned a high score, reflecting the potential for exploitation or information leakage.
2. Execution of Scripts or Binaries: If the command executes shell scripts (.sh), batch files (.bat), or other executable binaries (.exe), assign a high score.
3. File Download without Execution: If the command downloads files but does not execute them, assign a low score.
4. Unusual URL: If the command contains a URL with suspicious patterns such as excessive hyphens, random strings, or originates from domains known for hosting malicious content, or if the URL is known or strongly suspected to act as a dropper (i.e., facilitates further malicious payload downloads), assign a high score.
5. Dropper Behavior: If a command accesses (e.g., pings or connects to) an unusual URL that serves as a dropper, meaning its primary purpose is to notify the attacker that this machine has downloaded a malicious package, thereby enabling the attacker to identify infected hosts and potentially launch follow-up attacks. This should be considered highly sensitive.
6. Download and Execute: If the command both downloads and executes files, assign a high score.
7. Tampering Critical Files: If the command modifies or injects entries into startup or security-sensitive files, such as crontab, /etc/rc.local, systemd unit files, user shell profiles (e.g., ~/.bashrc, ~/.profile), /etc/shadow, or ~/.ssh/authorized_keys, assign a high score.
8. Process Injection: If the command leverages techniques to inject or hijack execution within another process, e.g., using ptrace (via gdb, strace -p), LD_PRELOAD tricks, dlopen/dlsym, or calling debuggers to manipulate a running binary, assign a high score.
9. Data Obfuscation and Encoding: If the command applies transformations to payloads or exfiltrated data, such as base64 encoding/decoding, assign a high score.
10. NPM Package Download: If the command downloads a legitimate third-party NPM package, assign a risk score near 0. However, if the package name exhibits signs of typosquatting or contains other unusual naming patterns, assign a high score.
11. Reverse Shell Initiation: If the command initiates a reverse shell, assign a high score.
12. System Shutdown: If the command shuts down the system, assign high score.
13. Deletion of Uncritical Files: If the command only deletes files in non-critical directories such as dist, temp, cache or node_modules, its risk score should be set close to 0, ensuring that only deletion operations involving system or critical user paths are strictly evaluated.
14. Deletion of Critical Files: If the command deletes important files (such as user files, system files, or root files), assign a high score.
15. Local JavaScript Execution Only: If the command solely runs a local JavaScript file (e.g., .js, .cjs, .mjs files) without any additional risky operations, assign a score to 0.
16. Non-Typical Node Execution: If the command attempts to run a file with a non-standard extension for Node (e.g., “node note.md”), assign a high score.
17. Non-Malicious Shell Command: If the command does not show any maliciousness, assign a low score. 
18. Invalid Shell Command: If the command is not a valid Linux shell command, assign a score near 0.
If none of the above criteria clearly apply, use your expert judgment to assign a sensitivity score between 0 and 1.
                
Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
```
+ **Prompt for file reading sensitivity evaluation (Sensitivity Evaluator)**

```text
You’re a security expert. You are provided with two inputs:
1. File Path: A string representing the Linux file system path where data is being read.
2. File Content: The actual content read from the file.
Your task is to analyze both the file path and the file content to determine the sensitivity of the file reading behavior. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
            
Sensitivity Scoring:
0: Not sensitive at all.
0 to 0.5: Low sensitivity (acts as a warning).
0.5 to 1: High sensitivity (should be closely scrutinized).
1: Absolutely sensitive.
Only assign a high score if you are confident in your assessment

Cases for Analysis of Degree of Sensitivity
Path-Based Sensitivity:
1. npm/Node.js Core Files: Files located in directories related to npm, node_modules, or Node.js core may be sensitive if they contain configuration data or secrets.
2. System Configuration and Network Settings Files: Files such as /etc/sysctl.conf, /etc/network/interfaces, or /etc/resolv.conf typically contain system-level configurations for kernel parameters, network interfaces, and DNS settings. These files are critical to the system’s operation and could be targeted for tampering or exfiltration to exploit vulnerabilities or misconfigurations.
3. Shell Configurations and History Files: Files such as .bashrc, .zshrc, .bash_history, or .zsh_history often include user-specific configurations or command histories that could expose personal data and are sensitive.
4. Authentication Files: Files like /etc/passwd, /etc/shadow, or any file with “password” or “auth” in its name typically store sensitive account or authentication data, which is sensitive.
5. SSH/Key Files: Files in directories like .ssh or with names containing “key” should be scrutinized for private keys or credentials, which are sensitive.
6. Cryptocurrency Wallet Files: Files related to cryptocurrency wallets, such as Bitcoin wallets, typically contain private keys, seed phrases, or other sensitive information required for accessing and managing cryptocurrency holdings. Files in directories like .bitcoin, .ethereum, or other blockchain-related directories, as well as files with extensions like .dat, .json, or .wallet, should be considered sensitive.
7. Environment/Configuration Files: Files such as .env, .svn, or any file that might contain environment variables, API keys, or similar sensitive configurations.
8. Database, Secrets, and Certificate Files: Files like database.json, db.sqlite, db.conf, or files within /etc/ssl/ or with .crt, .pem, or .key extensions, which are sensitive.
9. Other Cases: Consider any file that may hold configuration settings, database connection strings, cryptographic keys, certificates, or other credentials.
            
Content-Based Analysis:
1. Credentials or Personal Data: Presence of usernames, passwords, tokens, API keys, or other secret data, which are considered sensitive.
2. Cryptographic Material: Private keys, certificates, or encoded strings resembling cryptographic data, which are considered sensitive.
3. Sensitive Configuration Data: Any details that suggest access control parameters, server configurations, or other sensitive system details.
4. Source Code with Embedded Secrets: Code files (JavaScript, JSON, YAML, Python, etc.) containing hard-coded secrets, tokens, or sensitive endpoint URLs—assign a high score.
        
If the file path does not clearly indicate sensitivity, use the file content to adjust the sensitivity score accordingly. Ensure your final judgment is based on expert security knowledge.
Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
```

## Sensitive API List

The sensitive API list is provided in [`sensitive_call.csv`](./sensitive_call.csv). 
The paper mentions an ARD field for marking APIs that require additional judgment, this functionality is implemented in the code through conditional statements rather than as an explicit field in the CSV.

## Structure

The key files and folders in this project are:

- `base_classes`: Defines the data structures for PDG and CPG, including node and edge definitions.

- `detector`: Contains the core implementation of the [HGT](https://github.com/acbull/pyHGT) model, including layer definitions, embedding procedures, input data construction, and graph classification.

- `npm_pipeline`: Provides code and corresponding  data structures for behavior graph generation.

  - `package.py`: The core component for constructing the behavior graph, implementing operations for different types of statements.

- `dynamic_helper.py`: Performs dynamic analysis using [NodeProf](https://github.com/Haiyang-Sun/nodeprof.js), an instrumentation and profiling framework for [Graal.js](https://github.com/graalvm/graaljs). We use NodeProf to generate dynamic call graphs and identify sensitive API invocations. Instrumentation callbacks are implemented in `dyn.js`,  following the approach used by Jelly for dynamic call graph construction. We extend their implementation for constructing call edges from *require* statements to their callees. Furthermore, we add an instrumentation callback for the *eval* function, which is frequently exploited by attackers to execute arbitrary code. This allows us to capture the evaluated source code and incorporate it into our behavior graph generation.

  Sensitive API identification is achieved by modifying the builtin module layer of the [Node.js](https://github.com/oracle/graaljs/tree/master/graal-nodejs/lib) runtime within Graal.js to support NodeProf-based tracking. As illustrated in the figure, the builtin module layer defines core module APIs accessed by the Node.js application.

  <img src="./Node.js framework.png" alt="Node.js framework" width = "500" />


+ `static_helper.py`: Performs static analysis by first downloading the required third-party libraries,  then uses Joern and Jelly to generate the CPG and call graph.

- `llm.py`: Implements interaction with LLMs. All **prompt** templates are defined here.

## Prerequisite

The detector runs only on Linux, to run the dynamic analysis, docker is necessary.

- Ubuntu 22.04
- [Docker](https://www.docker.com/)

## Setup

+ This implementation is based on Python 3.11, you can run the `pip install -r requirements.txt` to install all the dependencies.

+ The CPG is generated by [Joern](https://joern.io/). Since the default Joern settings ignore analysis of *node_modules*, we manually modified the source code of Joern 4.0.227. We release our customized joern-cli at [https://zenodo.org/records/15508850], which can be used directly.

+ The call graph generated by [Jelly](https://github.com/cs-au-dk/jelly) 0.10.0, install the Jelly via:

  ```bash
  npm install -g @cs-au-dk/jelly
  ```

- We release the Docker image at [https://zenodo.org/records/15508850] containing all the necessities for dynamic analysis. Before running the detector, load the image via:

  ```bash
  docker load -i dynamic_env.tar
  ```

+ ProfMal leverages [DeepSeek-V3](https://github.com/deepseek-ai/DeepSeek-V3), You can deploy the model on your own server or access it via an API. The implementation is at file `llm.py`, apply your solution at the `connect_with_retry` function.

+ Set up the `config.yaml`

  ```yaml
  joern_path: "/example_path/joern-cli-4.0.227/joern-cli"
  
  sudo_passwd: sudo_pass
  ```

  + Set the *Joern_path* to the joern-cli we provided, make sure the path is correct if you have a global Joern already.

  + The *sudo_passwd* is required to run *chmod* on dynamically executed files, as their file attributes may change after execution in Docker, occasionally leading to permission errors for subsequent processes. If you have a better solution for managing file permissions, feel free to adapt this step.

## Usage

Run the `main.py` with the following command:

```bash
python main.py \
  --package_path /example_path/target_package \
  --workspace_path /example_path/workspace \
  --overwrite
```

+ package_path: The location of the target package. Please ensure the package is unzipped before analysis.
+ workspace_path: The directory where Joern and Jelly will write their analysis results.
+ overwrite: If you do **not** want to overwrite previous results, simply omit the --overwrite flag.

