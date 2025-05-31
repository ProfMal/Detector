from openai import OpenAI
import yaml
import time
from loguru import logger
import tiktoken

with open('./config.yaml', 'r') as file:
    config = yaml.safe_load(file)

model_name = config['LLM']

api_key = config['API_KEY']

enc = tiktoken.get_encoding("o200k_base")


def llm_shell_command_interpret(shell_command):
    messages = [
        {
            "role": "system", "content": """
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
            """
        },
        {
            "role": "user", "content": f"""Shell Command: {shell_command}"""
        }
    ]
    logger.info(f"[LLM] Analyse the shell Command\n {shell_command}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the Shell Command Sensitivity is: {answer_flow}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_file_reading_sensitivity_interpret(file_path: str, content: str):
    messages = [
        {
            "role": "system", "content": """
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
                """
        },
        {
            "role": "user", "content": f"""File Path: {file_path}\nFile Content: {content}"""
        }
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Reading Sensitivity\n"
                f"File Path: {file_path}\n"
                f"Content: {content}")
    if max_token(content):
        logger.info(f"[LLM] Max Token, the degree of the File Reading Sensitivity is: 1")
        return 1.0
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Reading Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_file_writing_sensitivity_interpret(file_path: str, content: str):
    messages = [
        {
            "role": "system", "content": """
                You’re a security expert. You are provided with two inputs:
                1. File Path: A string representing the Linux file system path where data is being written.
                2. File Content: The actual content that is intended to be written to the file.
                Your task is to analyze both the file path and the file content to determine the sensitivity of the file writing. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                
                Sensitivity Scoring:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (acts as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                
                Only assign a high score if you are confident in your assessment
                Cases for Analysis of Degree of Sensitivity:
                Path-Based Sensitivity:
                1. System and Critical Configuration Files: Writing to files in system directories such as /etc, /var, or any file that is part of core system configurations (e.g., /etc/passwd, /etc/shadow, /etc/ssh/sshd_config) should be flagged as highly sensitive.
                2. User Configuration Files: Writing to user-specific configuration files like ~/.bashrc, ~/.zshrc, or history files like ~/.bash_history and ~/.zsh_history can expose personal data and should be treated as sensitive.
                3. Security-Related Files: Files related to SSH (such as those in the .ssh directory) or files containing keywords like “key” (e.g., private keys) are sensitive.
                4. Application and Environment Files: Files related to npm, Node.js core components, or environment settings (e.g., .env files) may contain credentials or configuration data, increasing sensitivity.
                5. Other Considerations: Evaluate any other files that could potentially hold sensitive information, such as database configuration files, certificate files, or files that may be used for logging sensitive operations.
                
                Content-Based Analysis:
                1. Inspect the content to determine if it includes sensitive data such as credentials, API keys, tokens, private keys, or any other secrets.
                2. Consider if the content being written could compromise system integrity or user privacy if exposed.
                3. If the content being written to the file contains source code, check whether the source code contains malicious behaviors; if it does, it is highly sensitive.
                
                If the file path does not clearly indicate sensitivity, use the file content to adjust the sensitivity score accordingly. Ensure your final judgment is based on expert security knowledge.
                Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
                   """
        },
        {
            "role": "user", "content": f"""File Path: {file_path}\nFile Content: {content}"""
        }
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Writing Sensitivity\n"
                f"File Path: {file_path}\n"
                f"Content: {content}")
    if max_token(content):
        logger.info(f"[LLM] Max Token, the degree of the File Writing Sensitivity is: 1")
        return 1.0
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Writing Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_dir_sensitivity_interpret(dir_path: str):
    messages = [
        {
            "role": "system", "content": """
                You’re a security expert. You are provided with a directory path as input.
                Your task is to analyze the sensitivity of the directory based on its name and location in the file system. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                Sensitivity Scoring:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (acts as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                
                Only assign a high score if you are confident in your assessment
                Cases for Analysis of the Degree of Sensitivity:
                1. System and Critical Configuration Directories: Directories like /etc, /var, /root, or those containing critical system configurations (e.g., /etc/ssh, /etc/passwd, /etc/shadow) should be flagged as highly sensitive.
                2. Database Directories: Directories related to databases, such as MySQL, PostgreSQL, MongoDB, LevelDB, or any other database systems (e.g., /var/lib/mysql, /var/lib/postgresql, or directories containing files like .db, .sqlite, .sql, .dump), should be considered highly sensitive. These directories may contain sensitive data such as personal information, user credentials, or application data.
                3.	User Configuration Directories: Directories containing user-specific configuration files (e.g., ~/.bashrc, ~/.zshrc, .bash_history, .zsh_history) are sensitive due to the potential exposure of user settings and command histories.
                4. Security-Related Directories: Directories like .ssh, .gnupg, or those containing files with names related to “key” (e.g., private SSH keys) should be flagged as sensitive.
                5. Cryptocurrency Wallet Directories: Directories related to cryptocurrency wallets (e.g., .bitcoin, .ethereum) or those containing wallet files (e.g., .dat, .json, .wallet) should be treated as highly sensitive.
                6. Application and Environment Directories: Directories related to npm, Node.js, or those containing configuration files like .env, .npmrc, or similar environment settings that might hold credentials or configuration data should be flagged as sensitive.
                7. Binary and Executable Directories: Directories like /usr/bin, /usr/local/bin, or those containing executable files (.exe, .sh, .bin, etc.) should be flagged as potentially sensitive due to the risks of executing malicious code.
                8. Other Considerations: Evaluate other directories that may store configuration settings, database connection strings, cryptographic certificates, or similar sensitive information.
                
                Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
                """
        },
        {
            "role": "user", "content": f"""File Path: {dir_path}"""
        }
    ]
    logger.info(f"[LLM] Analyze the Degree of the Dir Path Sensitivity\n"
                f"Dir Path: {dir_path}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the Dir Path Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_path_sensitivity_interpret(file_path: str):
    messages = [
        {
            "role": "system", "content": """
                You're a security expert, you are provided with one input:
                File Path: A string representing the Linux file system path where data is being read or written.
                Your task is to analyze the sensitivity based on the name of the path. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                Sensitivity Scoring:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (acts as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                
                Only assign a high score if you are confident in your assessment
                Cases for Analysis of the Degree of Sensitivity:
                1. System and Critical Configuration Files: A file path in system directories (e.g., /etc, /var) or core system configuration files (e.g., /etc/passwd, /etc/shadow, /etc/ssh/sshd_config) should be flagged as high sensitivity.
                2. Config File: A path that is a JSON file (e.g., package.json) which may serve as a configuration file is generally of low sensitivity.
                3. User Configuration Files: User-specific configuration files (e.g., ~/.bashrc, ~/.zshrc, ~/.bash_history, ~/.zsh_history) should be considered of high sensitivity due to the potential exposure of personal configurations and command histories.
                4. Security-Related Files: Files in directories such as .ssh or files with keywords like “key” (e.g., private keys) are inherently of high sensitivity.
                5. Cryptocurrency Wallet Files: Files related to cryptocurrency wallets, such as Bitcoin wallets, typically contain private keys, seed phrases, or other sensitive information required for accessing and managing cryptocurrency holdings. Files in directories like .bitcoin, .ethereum, or other blockchain-related directories, as well as files with extensions like .dat, .json, or .wallet, should be considered of high sensitivity.
                6. Application and Environment Files: Files related to npm, Node.js core components, or environment settings (e.g., .env files) that may hold credentials or configuration data are of high sensitivity.
                7. Binary and Executable Files: Binary or executable files (e.g., files with extensions like .exe, .sh, .bin, or files located in directories like /usr/bin, /usr/local/bin, etc.) may pose risks, as they can contain code that could execute arbitrary operations. These files should be treated as high sensitivity.
                8. Other Considerations: Evaluate any other file paths that may indicate storage of configuration settings, database connection strings, certificates, or similar sensitive information that could be used by attackers.
                
                Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
            """
        },
        {
            "role": "user", "content": f"""File Path: {file_path}"""
        }
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Path Sensitivity\n"
                f"File Path: {file_path}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Path Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_file_pattern_sensitivity_interpret(file_pattern: str):
    messages = [
        {
            "role": "system", "content": """
                You’re a security expert. You are provided with one input:
                File Pattern: A string representing a pattern used by functions like fs.glob to search for files in a Linux file system.
                Your task is to analyze the sensitivity based on the name of the pattern. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (acts as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                
                Only assign a high score if you are confident in your assessment
                Cases for Analysis of the Degree of Sensitivity:
                1. System and Critical Configuration Patterns: Patterns that target files in system directories (e.g., /etc, /var) or core system configuration files (such as /etc/passwd, /etc/shadow, /etc/ssh/sshd_config) should be flagged as highly sensitive.
                2. User Configuration Patterns: Patterns that target user-specific configuration files (e.g., ~/.bashrc, ~/.zshrc, ~/.bash_history, ~/.zsh_history) should be considered sensitive due to the potential exposure of personal configurations and command histories.
                3. Security-Related Patterns: Patterns that target directories like .ssh or files with keywords such as “key” (e.g., private keys) are inherently sensitive.
                4. Cryptocurrency Wallet Files: Patterns that target files related to cryptocurrency wallets, such as Bitcoin wallets, which typically contain private keys, seed phrases, or other sensitive information required for accessing and managing cryptocurrency holdings. Patterns matching directories like .bitcoin, .ethereum, or other blockchain-related directories, as well as files with extensions like .dat, .json, or .wallet, should be considered sensitive.
                5. Application and Environment Patterns: Patterns that target files related to npm, Node.js core components, or environment settings (e.g., .env files) that may hold credentials or configuration data are also sensitive.
                6. Other Considerations: Evaluate any other file patterns that may indicate access to configuration settings, personal code files, database connection strings, certificates, or similar sensitive information.

                Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
            """
        },
        {
            "role": "user", "content": f"""File Path: {file_pattern}"""
        }
    ]
    logger.info(f"[LLM] Analyse the Degree of the File Pattern Sensitivity\n"
                f"File Pattern: {file_pattern}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Pattern Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_rm_files_sensitivity_interpret(rm_files: str):
    messages = [
        {
            "role": "system", "content": """
                You’re a security expert. You are provided with one input:
                File Path: A string representing the Linux file system path of the file(s) that are being deleted.
                Your task is to analyze the sensitivity based on the path of the file. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (acts as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                    
                Only assign a high score if you are confident in your assessment
                Here are the cases for the analysis of the degree of sensitivity:
                1. Critical System Files: If the file path indicates deletion of core system files (e.g., files in /etc, /var, /bin, /usr/bin, or system-critical configuration files like /etc/passwd, /etc/shadow, /etc/ssh/sshd_config), the deletion is highly sensitive as it may cause the system to crash. Assign a score closer to 1.
                2. User and Security-Related Files: Deleting user configuration files (e.g., ~/.bashrc, ~/.zshrc, ~/.bash_history) or files related to security (e.g., files in the .ssh directory or files containing “key” in their names) should be considered sensitive.
                3. Cryptocurrency Wallet Files: Files related to cryptocurrency wallets, such as Bitcoin wallets, typically contain private keys, seed phrases, or other sensitive information required for accessing and managing cryptocurrency holdings. Files in directories like .bitcoin, .ethereum, or other blockchain-related directories, as well as files with extensions like .dat, .json, or .wallet, should be considered sensitive.
                3. Non-Critical Files: If the file path points to non-critical data, such as temporary files or cache (e.g., files in /tmp, /var/tmp), the deletion is generally low risk. Assign a score closer to 0.
                4. Expert Judgment: Evaluate the potential impact of the deletion based on the file path. If the deletion could lead to severe system instability, significant data loss, or a complete system crash, assign a higher sensitivity score. Routine deletions with minimal impact should receive a lower score.
                
                Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
                """
        },
        {
            "role": "user", "content": f"""File Path: {rm_files}"""
        }
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Deletion Sensitivity\n"
                f"Removed Files: {rm_files}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Deletion Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def llm_execute_file_interpret(file_name: str):
    messages = [
        {
            "role": "system", "content": """
                You’re an experienced Node.js programmer and security expert. You are provided with one input:
                File Name Parameter: A string representing the executable file to be run.
                Your task is to evaluate the degree of sensitivity (i.e., the potential maliciousness or suspicious nature) of executing this file based on its name and extension. Based on your expert analysis, assign a sensitivity score as a floating-point number in the range [0, 1] according to the following guidelines:
                0: Not sensitive at all.
                0 to 0.5: Low sensitivity (acts as a warning).
                0.5 to 1: High sensitivity (should be closely scrutinized).
                1: Absolutely sensitive.
                
                Only assign a high score if you are confident in your assessment
                Guidelines for Analysis:
                1. High-Risk Executables: If the file name ends with extensions such as .bat, .exe, or .sh, it should be treated as high sensitivity.
                2. Non-Standard File Extensions: If the file name ends with an extension that is not commonly associated with executable files (for example, .md), it should be treated as high sensitivity.
                3. Script Files: If the file name ends with script file extensions (e.g., .sh for shell scripts, .ps1 for PowerShell), it should be treated as high sensitivity.
                4. Interpreted Language Files: If the file name ends with extensions such as .py (Python) or .rb (Ruby), it should be considered moderate sensitivity.
                5. JavaScript Files: If the file name ends with .js and there are no additional suspicious indicators, it should be treated as low sensitivity and assign a score to 0, as these are common in Node.js.
                6. Other or Unknown Extensions: For file names with uncommon or unknown extensions, use your expert judgment to determine the sensitivity based on the likelihood that they might be used for executing malicious code.
                7. Suspicious Keywords: If the file name contains suspicious keywords (e.g., “malware”, “payload”, “virus”), increase the sensitivity score accordingly.
                
                Return only the final sensitivity score (a floating-point number between 0 and 1) as the output, with no additional explanation or text.
            """
        },
        {
            "role": "user", "content": f"""File Name: {file_name}"""
        }
    ]

    logger.info(f"[LLM] Analyse the Degree of the File Execution Sensitivity\n"
                f"File Name: {file_name}")
    try:
        answer = connect_with_retry(messages)
    except ConnectionError:
        answer = 0.5
    try:
        answer_flow = float(answer)
    except ValueError:
        logger.warning(f"[LLM] The return value is not a valid floating-point number: {answer}")
        answer_flow = 0.5
    logger.info(f"[LLM] The Degree of the File Execution Sensitivity is: {answer}")
    answer_flow = max(0.0, min(answer_flow, 1.0))
    return answer_flow


def max_token(input_string):
    tokens = enc.encode(str(input_string))
    if len(tokens) > 127000:
        return True
    else:
        return False


def connect_with_retry(prompt, max_attempts=5, delay=1):
    attempts = 0
    while attempts < max_attempts:
        try:
            # replace with your own implementation to get answer from LLM
            # answer = LLM.output(prompt)

            # Attempt to establish the connection here
            if attempts > max_attempts - 1:
                raise ConnectionError("Connection failed")
            else:
                return answer

        except Exception:
            attempts += 1
            if attempts < max_attempts:
                logger.warning(f"Retrying in {delay} seconds...")
                time.sleep(delay)

    # If max attempts are reached without successful connection, raise an exception
    raise ConnectionError("Failed to establish connection to OpenAI after maximum attempts")
